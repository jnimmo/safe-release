# safe-release Design

**Date:** 2026-02-25
**Status:** Approved

## Overview

A local Docker-based web application for service desk analysts to safely scan password-protected email attachments. The analyst drops in quarantined `.eml` files, provides the attachment password and an optional ticket reference, and the tool scans the content with ClamAV — before and after decryption — then releases clean files for download or in-browser preview.

## Architecture

Two containers via Docker Compose:

- **`app`** — Python FastAPI application serving the UI and handling all logic
- **`clamav`** — official `clamav/clamav` Docker image, exposes a daemon that the app connects to via `pyclamd`

Two Docker volumes:
- **`db`** — SQLite database (audit trail, persists across restarts)
- **`temp`** — decrypted files at `/tmp/safe-release/` (wiped on container start, TTL-cleaned during operation)

```
Browser → FastAPI app → pyclamd → ClamAV daemon
                      → qpdf CLI / 7z CLI / msoffcrypto-tool
                      → SQLite (audit log)
                      → /tmp/safe-release/<job-id>/ (temp files)
```

Single analyst, local machine. No authentication required.

## Supported File Types

- **PDF** — password removal via `qpdf` CLI subprocess
- **ZIP** — extraction via `7z` CLI subprocess
- **Office documents** — `.docx`, `.xlsx`, `.pptx` (modern OOXML formats) via `msoffcrypto-tool` Python library (no suitable CLI alternative exists)

Using CLI tools (`qpdf`, `7z`) for the highest-risk decryption operations isolates parser vulnerabilities from the app process. The container itself provides an additional isolation layer. All containers run as non-root with memory/CPU limits.

## Processing Pipeline

Each EML job passes through the following states:

```
queued → scanning → awaiting_password → scanning_decrypted → clean
                                                            → infected
                 → failed (bad EML, corrupt archive, ClamAV unavailable)
```

**1. Ingest**
- Analyst drops one or more `.eml` files, enters password + optional ticket reference per file
- EML parsed with Python `email` stdlib; `Subject`, `From`, and `Message-ID` extracted and stored
- Attachments written to `/tmp/safe-release/<job-id>/original/`

**2. First scan (original)**
- Each attachment scanned by ClamAV in its encrypted/original form
- `PUA.Encrypted.*` detections are expected and recorded but do not fail the job
- Result stored; this scan is not repeated if the analyst retries a password

**3. Decrypt / extract**
- `qpdf --password=<pw> --decrypt input.pdf output.pdf`
- `7z x -p<pw> archive.zip -o/tmp/safe-release/<job-id>/decrypted/`
- `msoffcrypto-tool` for Office documents
- On failure (wrong password): job moves to `awaiting_password`; analyst re-enters password inline; only steps 3–4 are re-run

**4. Second scan (decrypted)**
- All decrypted/extracted files scanned by ClamAV
- Any detection → job marked `infected`, files not released
- All clean → job marked `clean`

**5. Release**
- Clean files available for download or in-browser PDF preview
- Audit log entry written with full details

## Queue UI

Single-page UI, server-rendered with HTMX (polling every ~3 seconds for status updates).

Each queued EML renders as a card showing:
- **Subject**, **From**, **Message-ID** (from EML headers)
- **Ticket reference** (analyst-entered)
- **Status badge** reflecting current pipeline state
- **Attachment list** with per-file scan results once complete
- `clean` jobs: download button per file, inline PDF preview toggle
- `awaiting_password` jobs: inline password re-entry field
- `infected` / `failed` jobs: error detail and ClamAV finding

**Status bar:** ClamAV version and signature database date displayed persistently. Warning banner shown if signatures are older than 48 hours (configurable). Signature date is recorded on each audit log entry.

## Error Handling

| Condition | Behaviour |
|---|---|
| Wrong password | Job → `awaiting_password`; first scan result preserved |
| Unsupported attachment type | File skipped from decryption, scanned in original form, noted in audit log |
| ClamAV unavailable | Job fails with clear error; no files released |
| Decompression bomb / oversized output | `7z`/`qpdf` subprocess output size checked; job fails safely above configurable threshold (default 500 MB) |
| Corrupt / invalid EML | Caught at ingest; card shown with parse error |
| Malformed archive | Subprocess error caught; job marked `failed` with detail |
| Temp file cleanup | `/tmp/safe-release` wiped on container start; clean job files deleted after configurable TTL (default 1 hour) |

All outcomes recorded in the audit log regardless of success or failure.

## Audit Log (SQLite)

Fields per job record:
- `id`, `created_at`, `updated_at`
- `eml_filename`, `subject`, `from_address`, `message_id`
- `ticket_ref` (optional)
- `status` (final)
- `clamav_signature_date` (at time of scan)
- `attachments` (JSON array: filename, type, first_scan_result, second_scan_result)
- `error_detail` (if failed)

## Tech Stack

| Component | Choice |
|---|---|
| Backend | Python FastAPI |
| UI | HTMX (server-rendered templates via Jinja2) |
| Database | SQLite via SQLAlchemy |
| AV engine | ClamAV (official Docker image) |
| ClamAV client | `pyclamd` |
| PDF decryption | `qpdf` CLI |
| ZIP extraction | `7z` CLI |
| Office decryption | `msoffcrypto-tool` |
| EML parsing | Python `email` stdlib |
| Containerisation | Docker Compose |

## Testing

- **Unit tests** for pipeline steps (EML parsing, decryption subprocess wrappers, state transitions) using fixture files: a sample encrypted PDF, ZIP, and Office document
- **ClamAV integration test** using EICAR test string to verify detection end-to-end
- No UI testing — HTMX templates are simple enough for manual verification
