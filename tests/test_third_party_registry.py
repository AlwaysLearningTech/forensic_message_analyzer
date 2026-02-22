"""
Tests for ThirdPartyRegistry and OCR contact extraction.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from src.third_party_registry import ThirdPartyRegistry
from src.analyzers.screenshot_analyzer import ScreenshotAnalyzer, _EMAIL_RE, _PHONE_RE, _NAME_LINE_RE
from src.forensic_utils import ForensicRecorder
from src.config import Config


# ------------------------------------------------------------------
# ThirdPartyRegistry tests
# ------------------------------------------------------------------

class TestThirdPartyRegistry:
    """Tests for the ThirdPartyRegistry class."""

    @pytest.fixture
    def registry(self, tmp_path):
        recorder = ForensicRecorder(tmp_path)
        config = Config()
        return ThirdPartyRegistry(recorder, config)

    def test_register_and_get_all(self, registry):
        """Register a contact and retrieve it."""
        registry.register('outsider@example.com', source='email')
        contacts = registry.get_all()
        assert len(contacts) == 1
        assert contacts[0]['identifier'] == 'outsider@example.com'
        assert contacts[0]['sources'] == ['email']

    def test_dedup_same_identifier(self, registry):
        """Duplicate identifiers should not create multiple entries."""
        registry.register('outsider@example.com', source='email')
        registry.register('outsider@example.com', source='screenshot')
        contacts = registry.get_all()
        assert len(contacts) == 1
        assert set(contacts[0]['sources']) == {'email', 'screenshot'}

    def test_case_insensitive_dedup(self, registry):
        """Identifiers differing only in case should dedup."""
        registry.register('Outsider@Example.COM', source='email')
        registry.register('outsider@example.com', source='screenshot')
        assert len(registry.get_all()) == 1

    def test_resolve_third_party(self, registry):
        """resolve() should return 'Third Party: ...' for an unknown id."""
        registry.register('stranger@example.com', source='email')
        label = registry.resolve('stranger@example.com')
        assert label.startswith('Third Party:')

    def test_resolve_with_display_name(self, registry):
        """resolve() should prefer display_name when available."""
        registry.register('stranger@example.com', source='email', display_name='Jane Doe')
        label = registry.resolve('stranger@example.com')
        assert 'Jane Doe' in label

    def test_resolve_mapped_person(self, registry):
        """resolve() should return the mapped person name for known contacts."""
        config = registry.config
        # Pick the first mapped person and one of their identifiers
        for person_name, identifiers in config.contact_mappings.items():
            if identifiers:
                ident = identifiers[0]
                result = registry.resolve(ident)
                assert result == person_name
                break

    def test_is_mapped(self, registry):
        """is_mapped() should return True for configured contacts."""
        config = registry.config
        for person_name, identifiers in config.contact_mappings.items():
            if identifiers:
                assert registry.is_mapped(identifiers[0]) is True
                break
        assert registry.is_mapped('nobody@nowhere.com') is False

    def test_skip_mapped_on_register(self, registry):
        """Registering a mapped identifier should be a no-op."""
        config = registry.config
        for person_name, identifiers in config.contact_mappings.items():
            if identifiers:
                registry.register(identifiers[0], source='email')
                break
        assert len(registry.get_all()) == 0

    def test_get_summary(self, registry):
        """get_summary() should group counts by source."""
        registry.register('a@example.com', source='email')
        registry.register('b@example.com', source='email')
        registry.register('+15551234567', source='screenshot')
        summary = registry.get_summary()
        assert summary['total'] == 3
        assert summary['by_source']['email'] == 2
        assert summary['by_source']['screenshot'] == 1

    def test_empty_identifier_ignored(self, registry):
        """Empty or whitespace-only identifiers should be ignored."""
        registry.register('', source='email')
        registry.register('   ', source='email')
        assert len(registry.get_all()) == 0

    def test_context_tracking(self, registry):
        """Contexts should be accumulated across registrations."""
        registry.register('x@example.com', source='email', context='file1.eml')
        registry.register('x@example.com', source='email', context='file2.eml')
        entry = registry.get_all()[0]
        assert 'file1.eml' in entry['contexts']
        assert 'file2.eml' in entry['contexts']


# ------------------------------------------------------------------
# Screenshot contact extraction regex tests
# ------------------------------------------------------------------

class TestScreenshotContactExtraction:
    """Tests for the OCR contact extraction regex patterns."""

    def test_email_regex_basic(self):
        assert _EMAIL_RE.search('contact us at john@example.com today')
        assert _EMAIL_RE.search('john.doe+tag@sub.example.co.uk')

    def test_email_regex_no_match(self):
        assert _EMAIL_RE.search('not-an-email') is None
        assert _EMAIL_RE.search('@missing-local.com') is None

    def test_phone_regex_formats(self):
        assert _PHONE_RE.search('Call 206-555-1234')
        assert _PHONE_RE.search('(206) 555-1234')
        assert _PHONE_RE.search('+1 206 555 1234')
        assert _PHONE_RE.search('2065551234')

    def test_phone_regex_no_match(self):
        assert _PHONE_RE.search('123') is None

    def test_name_line_regex(self):
        m = _NAME_LINE_RE.search('From: Jane Doe')
        assert m and m.group(1).strip() == 'Jane Doe'
        m = _NAME_LINE_RE.search('To: John Smith')
        assert m and m.group(1).strip() == 'John Smith'
        m = _NAME_LINE_RE.search('Sender: Acme Corp')
        assert m and m.group(1).strip() == 'Acme Corp'

    def test_extract_contact_info_integration(self, tmp_path):
        """ScreenshotAnalyzer._extract_contact_info should find emails, phones, names."""
        recorder = ForensicRecorder(tmp_path)
        registry = ThirdPartyRegistry(recorder)
        analyzer = ScreenshotAnalyzer(recorder, third_party_registry=registry)

        text = (
            "From: Alice Johnson\n"
            "To: bob@company.com\n"
            "Hey, call me at (555) 234-5678.\n"
        )
        contacts = analyzer._extract_contact_info(text, 'test.png')

        types_found = {c['type'] for c in contacts}
        assert 'email' in types_found
        assert 'phone' in types_found
        assert 'name' in types_found

        # Registry should have recorded them
        assert len(registry.get_all()) >= 2  # email + phone + possibly name
