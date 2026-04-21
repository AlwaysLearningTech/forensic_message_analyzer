# JavaScript String Escaping in onclick Attributes

## The Problem

When generating HTML with onclick attributes that contain JavaScript string literals, you must use **JavaScript string escaping**, not HTML entity escaping.

## Wrong Approach ❌

```javascript
// WRONG - HTML entities don't work in JavaScript strings
onclick="deleteNotePhrase('Don&#39;t do this', false)"
```

This generates a **syntax error** because `&#39;` is not recognized by the JavaScript parser. The browser sees the literal characters `&`, `#`, `3`, `9`, `;` instead of a quote.

## Correct Approach ✅

```javascript
// CORRECT - JavaScript backslash escaping
onclick="deleteNotePhrase('Don\'t do this', false)"
```

This is valid JavaScript. The `\'` is properly escaped for the JavaScript parser.

## Implementation Pattern

```javascript
escapeHtml(text).replace(/'/g, "\\'")
```

This pattern:
1. First escapes HTML entities (for display in the page)
2. Then escapes quotes for JavaScript string literals

## Validation

Run `python3 test_js_syntax.py` to validate that all onclick handlers use correct escaping.

## Why This Matters

- **HTML entities** (`&#39;`, `&quot;`, etc.) are for HTML context
- **JavaScript escaping** (`\'`, `\"`, `\\`) is for JavaScript context
- An onclick attribute contains **JavaScript code**, so it needs JavaScript escaping

## References

- Lines 1732, 1756, 1775 in `src/review/web_review.py`
- Commit 66241bf: Last working state with correct escaping
- Commits 6787ae8, e7e742f: Bad fixes that broke it by using HTML entities
