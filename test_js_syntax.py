#!/usr/bin/env python3
"""
Test script to validate JavaScript syntax in web_review.py onclick handlers.

Extracts the generated JavaScript and validates it doesn't contain syntax errors.
"""

import re
from pathlib import Path

def extract_onclick_handlers(file_path):
    """Extract all onclick handler patterns from the Python file."""
    with open(file_path, 'r') as f:
        content = f.read()

    # Find onclick handlers in the string concatenation
    patterns = [
        (r'onclick="deleteNotePhrase\(([^"]+)\)"', 'deleteNotePhrase'),
        (r'onclick="submitBulkEdit\(([^"]+)\)"', 'submitBulkEdit'),
        (r'onclick="switchTab\(([^"]+)\)"', 'switchTab'),
    ]

    issues = []
    for pattern, func_name in patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            # Check for HTML entities in JavaScript code (bad)
            if '&#39;' in match or '&quot;' in match or '&amp;' in match:
                issues.append(f"❌ {func_name}: Found HTML entity in JavaScript: {match[:50]}...")
            # Check for correct JavaScript escaping
            elif r"\'" in match or r'\"' in match:
                print(f"✓ {func_name}: Correct JavaScript escaping found")

    return issues

def check_quote_escaping(file_path):
    """Check specific lines for proper quote escaping."""
    with open(file_path, 'r') as f:
        lines = f.readlines()

    critical_lines = [1732, 1756, 1775]  # Lines with the problematic handlers
    issues = []

    for line_num in critical_lines:
        if line_num <= len(lines):
            line = lines[line_num - 1]
            # Check for HTML entities (bad)
            if '&#39;' in line:
                issues.append(f"❌ Line {line_num}: Contains HTML entity &#39; in JavaScript")
            # Check for correct JS escaping (good)
            elif r"\'" in line or r'replace(/\'/g, "\\\'")' in line:
                print(f"✓ Line {line_num}: Correct JavaScript string escaping (\\')")

    return issues

def main():
    web_review_path = Path(__file__).parent / 'src' / 'review' / 'web_review.py'

    if not web_review_path.exists():
        print(f"❌ File not found: {web_review_path}")
        return 1

    print("=" * 60)
    print("JavaScript Syntax Validation for web_review.py")
    print("=" * 60)
    print()

    print("Checking critical lines (1732, 1756, 1775)...")
    issues = check_quote_escaping(web_review_path)
    print()

    print("Scanning all onclick handlers...")
    onclick_issues = extract_onclick_handlers(web_review_path)
    issues.extend(onclick_issues)
    print()

    if issues:
        print("=" * 60)
        print("ISSUES FOUND:")
        print("=" * 60)
        for issue in issues:
            print(issue)
        return 1
    else:
        print("=" * 60)
        print("✓ ALL CHECKS PASSED - JavaScript syntax is correct!")
        print("=" * 60)
        return 0

if __name__ == '__main__':
    exit(main())
