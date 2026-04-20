# Roadmap

Deferred work captured so it isn't lost. No commitments on ordering or timing.

## Redaction UI

Backend is complete. `src/review/redaction_manager.py` tracks append-only redactions with required reason, authority, examiner, and either a span or a regex pattern. Redactions are applied to message content at render time in `ForensicAnalyzer.run_reporting_phase`. Revokes append a new record; prior redactions are preserved in the audit trail.

What's missing is the reviewer-facing UI (mirror the Events tab shape that shipped in 4.6.0):

- **CLI** (`src/review/interactive_review.py`). Add a post-decision prompt on any `relevant` decision: "Redact any portion? [y/N]". When yes, show the content and collect `span` offsets or a regex, plus reason and authority. Store via `RedactionManager.redact()`.
- **Web review** (`src/review/web_review.py`). Add a "Redact selection" control in the item detail panel. Use the browser's text-selection API to capture the span in the content string, prompt for reason + authority, POST to a new `/api/redact` endpoint that calls `RedactionManager.redact()`. Badge any already-redacted item so the reviewer can see existing redactions and issue revokes. Use the existing `/api/events` endpoint pattern as a template.
- **Review summary** should list redactions alongside decisions so the legal team can audit them before the report is finalized.

Without the UI, redactions are Python-only — a reviewer has to issue them programmatically, which isn't realistic in a case.

## Signal and Telegram extractors

Signal and Telegram are increasingly used in family-law matters with privacy-conscious parties. Neither is currently supported.

- **Signal.** Desktop app stores messages in an encrypted SQLCipher database at `~/Library/Application Support/Signal/sql/db.sqlite`, keyed by a value in `config.json`. Mobile backups (Android) use a similarly-keyed format. Implementation needs a dependency on `pysqlcipher3` (or shelling out to the `sqlcipher` CLI) plus a schema mapper from Signal's `messages` and `conversations` tables to the `Message` TypedDict. Attachments live in `attachments.noindex/` and are referenced by a UUID that needs to be joined back to each message.
- **Telegram.** Desktop export is JSON (from Settings → Advanced → Export Telegram data) — straightforward to parse. Mobile is harder: iOS keeps everything in encrypted `.postbox` files, Android uses `cache4.db`. Start with the JSON export format since that's what examiners actually receive.

Both would extend `MessageExtractor` (`src/extractors/base.py`) and produce records matching the `Message` schema in `src/schema.py`, including sender/recipient normalization against `config.contact_mappings`.
