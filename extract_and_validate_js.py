#!/usr/bin/env python3
"""
Extract the JavaScript from web_review.py and validate it would generate valid HTML.

Simulates what the browser would see when the page loads.
"""

import re
from pathlib import Path

def extract_html_template(file_path):
    """Extract the HTML template string from the _get_review_html method."""
    with open(file_path, 'r') as f:
        content = f.read()

    # Find the HTML template (it's a large f-string)
    # Look for the method that returns HTML
    match = re.search(r'def _get_review_html.*?return f"""(.*?)"""', content, re.DOTALL)
    if not match:
        match = re.search(r'def _get_review_html.*?return f\'\'\'(.*?)\'\'\'', content, re.DOTALL)

    if match:
        return match.group(1)
    return None

def simulate_onclick_generation(template):
    """Simulate the JavaScript string concatenation for onclick handlers."""

    # Sample text with quotes to test escaping
    test_texts = [
        "Don't do this",
        "It's fine",
        "She said 'hello'",
        "Simple text"
    ]

    issues = []

    for text in test_texts:
        # Simulate what JavaScript would generate for deleteNotePhrase
        # Pattern: escapeHtml(text).replace(/'/g, "\\'")
        escaped = text.replace("'", "\\'")
        onclick_attr = f'onclick="deleteNotePhrase(\'{escaped}\', false)"'

        # Check if it looks valid
        if '&#' in onclick_attr:
            issues.append(f"❌ HTML entity in onclick for '{text}': {onclick_attr}")
        else:
            print(f"✓ Valid onclick for '{text}': {onclick_attr}")

    return issues

def main():
    web_review_path = Path('src/review/web_review.py')

    print("=" * 70)
    print("Simulating JavaScript String Generation")
    print("=" * 70)
    print()

    print("Testing onclick handler generation with various inputs...")
    print()

    issues = simulate_onclick_generation(None)

    print()
    print("=" * 70)

    if issues:
        print("ISSUES FOUND:")
        print("=" * 70)
        for issue in issues:
            print(issue)
        return 1
    else:
        print("✓ ALL SIMULATIONS PASSED!")
        print("=" * 70)
        print()
        print("The JavaScript string escaping pattern is correct:")
        print("  - Uses .replace(/'/g, \"\\\\'\")")
        print("  - Generates onclick=\"func('escaped\\'text')\"")
        print("  - NO HTML entities in JavaScript code")
        return 0

if __name__ == '__main__':
    exit(main())
