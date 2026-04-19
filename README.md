# safe-release

A web application for service desk analysts to safely scan password-protected email attachments before releasing them to end users.

Attachments in encrypted emails are a common malware delivery vector precisely because security tools cannot inspect their contents. **safe-release** solves this by decrypting attachments in an isolated container, scanning the decrypted content with ClamAV, and only releasing files that pass a clean bill of health — with a full audit trail of every decision.

---

## How It Works

An analyst receives a quarantined `.eml` file containing password-protected attachments. They upload the file to safe-release, provide the shared password, and the tool takes over:

1. **Ingest** — The EML is parsed. Email metadata (subject, sender, Message-ID) is recorded. Attachments are written to isolated temporary storage.
2. **First scan** — Each attachment is scanned by ClamAV in its original encrypted form. `PUA.Encrypted.*` detections are expected at this stage and are recorded but do not block the job.
3. **Decrypt** — Attachments are decrypted using purpose-appropriate tools:
   - PDF files → `qpdf` CLI
   - ZIP archives → `7z` CLI
   - Office documents (`.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`, `.ppt`) → `msoffcrypto-tool`
4. **Second scan** — Every decrypted file is scanned by ClamAV. Any detection marks the job `infected` and blocks all downloads.
5. **Release** — Only jobs with a `clean` status allow file downloads. Files are available for a configurable window (default: 1 hour) before automatic deletion.

If the wrong password is entered, the job pauses at `awaiting_password` and the analyst can retry inline. The first scan result is preserved so it is not repeated.

### Job Status Flow

```
queued → scanning → awaiting_password ──┐
                  │                     │ (retry password)
                  └─→ scanning_decrypted → clean
                                        → infected
       → failed  (bad EML, corrupt archive, ClamAV unavailable)
```

---

## Architecture

```
Browser
  │
  ▼
FastAPI app (Python)          ← serves UI, handles all logic
  ├── pyclamd ──────────────→ ClamAV daemon (separate container)
  ├── qpdf CLI subprocess    ← PDF decryption
  ├── 7z CLI subprocess      ← ZIP extraction
  ├── msoffcrypto-tool       ← Office document decryption
  ├── SQLite (SQLAlchemy)    ← audit log, persists across restarts
  └── /tmp/safe-release/     ← temp files, wiped on start + TTL-cleaned
```

Two containers:

| Container | Image | Role |
|-----------|-------|------|
| `app` | Python 3.12-slim (custom) | FastAPI application, UI, decryption |
| `clamav` | `clamav/clamav:stable` | AV daemon, signature updates via freshclam |

Two persistent volumes:

| Volume | Mount | Purpose |
|--------|-------|---------|
| `db_data` | `/data/safe_release.db` | SQLite audit database |
| `clamav_data` | `/var/lib/clamav` | ClamAV signature database |

Temporary files are stored in a third volume (`temp_data` → `/tmp/safe-release/`) and are wiped on container start and TTL-cleaned every 5 minutes during operation.

The UI is server-rendered HTML with HTMX polling every ~3 seconds for live status updates. No JavaScript framework, no client-side state.

---

## Security Design

### How safe-release addresses the core risk

Password-protected attachments bypass most email security gateways because the gateway cannot read the encrypted content. safe-release is positioned as a controlled release point: nothing reaches the analyst's desktop until it has been decrypted and scanned.

### Isolation by design

- **Process isolation for high-risk parsers** — PDF and ZIP decryption uses CLI subprocesses (`qpdf`, `7z`). A parser vulnerability in either tool cannot directly compromise the application process. The container provides a second isolation layer.
- **Non-root containers** — The app container runs as a dedicated `analyst` user (UID 1001). ClamAV runs under its own non-root user.
- **Resource limits** — Both containers are capped at 1 GB RAM via Docker deploy limits. This limits the blast radius of a decompression bomb or runaway process.
- **Decompression bomb protection** — Extracted ZIP content is measured against a configurable size limit (default 500 MB). Content exceeding the limit is deleted and the job fails safely.
- **No internet access required for the app** — Only the ClamAV container needs outbound access for signature updates.

### Scan-before-release guarantee

Files are only downloadable when `job.status == "clean"`. This check happens at the HTTP layer in the download route — not as a UI hint, but as a hard gate. Infected and failed jobs have no download path.

### Password handling

Passwords are stored in the database only for the duration of decryption and are set to `NULL` immediately after successful decryption. If decryption never succeeds, the password remains stored but is never logged or transmitted.

### Audit trail

Every job — including failures and infected detections — is written to a SQLite database with:

- Email metadata (filename, subject, sender, Message-ID)
- Ticket reference (analyst-entered, for correlation with ITSM)
- Final status and error detail
- ClamAV signature database version and date at time of scan
- Per-attachment scan results (both pre- and post-decryption)

The signature date recorded per job answers the question: *"Were the signatures current when this file was cleared?"*

### Signature freshness monitoring

The status bar in the UI displays the ClamAV version and signature date at all times. A warning banner is shown if signatures are older than 48 hours. ClamAV's `freshclam` daemon updates signatures automatically when the container starts and on a schedule.

### Temp file lifecycle

- All temp files are wiped on container start (no residue from previous sessions)
- Clean job files are deleted after 1 hour by default (configurable via `CLEAN_JOB_TTL_HOURS`)
- Infected and failed job files are cleaned on the same schedule

---

## Running Locally with Docker

### Prerequisites

- Docker Desktop (Mac/Windows) or Docker Engine + Compose plugin (Linux)
- Git

### Quick Start

```bash
git clone <repo-url>
cd safe-release
docker compose up --build
```

The app starts after ClamAV passes its health check (allow 2–3 minutes on first run while freshclam downloads signatures). Open [http://localhost:8000](http://localhost:8000).

> **Note:** ClamAV downloads ~250 MB of signature data on first start. Subsequent starts are fast because signatures are cached in the `clamav_data` volume.

### Configuration

Environment variables for the `app` service in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAMAV_HOST` | `clamav` | ClamAV daemon hostname |
| `CLAMAV_PORT` | `3310` | ClamAV daemon port |
| `CLEAN_JOB_TTL_HOURS` | `1` | Hours before clean job temp files are deleted |
| `MAX_OUTPUT_MB` | `500` | Maximum extracted size in MB before a job fails |
| `DATABASE_URL` | `sqlite:////data/safe_release.db` | SQLite connection string |

To change a value, edit `docker-compose.yml` under the `app.environment` block and run `docker compose up` again.

### Stopping and Data Persistence

```bash
# Stop containers (data volumes preserved)
docker compose down

# Stop and remove all data (full reset)
docker compose down -v
```

The SQLite audit database persists across restarts in the `db_data` volume. Temp files are always wiped on startup.

### Updating ClamAV Signatures Manually

```bash
docker compose exec clamav freshclam
```

---

## Running on Azure Container Apps

Azure Container Apps is suitable for teams where multiple analysts share a single instance, or where the tool needs to be available without requiring Docker Desktop on every workstation.

### Prerequisites

- Azure CLI: `az login`
- An Azure subscription
- Azure Container Registry (ACR) or Docker Hub to host the image

### 1. Build and Push the App Image

```bash
# Create a resource group and ACR
az group create --name safe-release-rg --location australiaeast
az acr create --resource-group safe-release-rg --name safereleasecr --sku Basic
az acr login --name safereleasecr

# Build and push
docker build -t safereleasecr.azurecr.io/safe-release-app:latest .
docker push safereleasecr.azurecr.io/safe-release-app:latest
```

### 2. Create a Container Apps Environment

```bash
az containerapp env create \
  --name safe-release-env \
  --resource-group safe-release-rg \
  --location australiaeast
```

### 3. Deploy ClamAV as a Container App

ClamAV runs as a companion app on the same environment. Azure Container Apps environments share a virtual network, so the app can reach ClamAV by its internal DNS name.

```bash
az containerapp create \
  --name clamav \
  --resource-group safe-release-rg \
  --environment safe-release-env \
  --image clamav/clamav:stable \
  --target-port 3310 \
  --ingress internal \
  --min-replicas 1 \
  --max-replicas 1 \
  --memory 2.0Gi \
  --cpu 1.0
```

> **Important:** ClamAV must be set to `--ingress internal` so it is not exposed to the internet. The app reaches it via its internal FQDN: `clamav.<environment-name>.<region>.azurecontainerapps.io`.

### 4. Provision Persistent Storage

The SQLite audit database needs to persist. Attach an Azure Files share to the environment:

```bash
# Create a storage account
az storage account create \
  --name safereleasestorage \
  --resource-group safe-release-rg \
  --sku Standard_LRS

STORAGE_KEY=$(az storage account keys list \
  --resource-group safe-release-rg \
  --account-name safereleasestorage \
  --query "[0].value" -o tsv)

az storage share create \
  --account-name safereleasestorage \
  --account-key $STORAGE_KEY \
  --name safe-release-db

# Add the storage to the Container Apps environment
az containerapp env storage set \
  --name safe-release-env \
  --resource-group safe-release-rg \
  --storage-name safe-release-db \
  --azure-file-account-name safereleasestorage \
  --azure-file-account-key $STORAGE_KEY \
  --azure-file-share-name safe-release-db \
  --access-mode ReadWrite
```

### 5. Deploy the App

```bash
CLAMAV_FQDN=$(az containerapp show \
  --name clamav \
  --resource-group safe-release-rg \
  --query "properties.configuration.ingress.fqdn" -o tsv)

az containerapp create \
  --name safe-release-app \
  --resource-group safe-release-rg \
  --environment safe-release-env \
  --image safereleasecr.azurecr.io/safe-release-app:latest \
  --registry-server safereleasecr.azurecr.io \
  --target-port 8000 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 1 \
  --memory 1.0Gi \
  --cpu 0.5 \
  --env-vars \
    CLAMAV_HOST="$CLAMAV_FQDN" \
    CLAMAV_PORT=3310 \
    DATABASE_URL="sqlite:////data/safe_release.db" \
    CLEAN_JOB_TTL_HOURS=1 \
    MAX_OUTPUT_MB=500 \
  --volume-mount "volumeName=db-volume,mountPath=/data"
```

### 6. Restrict Access (Recommended)

By default the app is reachable from the internet. Restrict it to your corporate network:

```bash
az containerapp ingress access-restriction set \
  --name safe-release-app \
  --resource-group safe-release-rg \
  --rule-name corporate-only \
  --ip-address <YOUR_OFFICE_EGRESS_IP>/32 \
  --action Allow
```

Or configure Azure AD authentication via the Portal under **Authentication** to require organisational login before accessing the app.

### Azure Deployment Notes

- **Scale to zero is not recommended** — ClamAV takes 2+ minutes to start due to signature loading. Set `--min-replicas 1` for both containers to keep them warm.
- **Temp files** — `/tmp/safe-release` does not need persistent storage. It is ephemeral by design. Do not mount a persistent volume there.
- **Signature updates** — ClamAV's built-in `freshclam` daemon handles this automatically. No additional configuration is required.
- **Cost** — At minimum replicas, the two containers will incur continuous compute costs. Review Azure Container Apps pricing for your region.

---

## Development

### Running Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests cover the pipeline state machine, EML parsing, decryption wrappers, and scan result handling. ClamAV integration tests use the EICAR test string to verify end-to-end detection without requiring real malware.

### Project Structure

```
app/
  main.py          # FastAPI routes, app lifecycle
  pipeline.py      # Job processing pipeline (scan → decrypt → scan)
  decryptors.py    # PDF, ZIP, Office decryption wrappers
  scanner.py       # ClamAV client via pyclamd
  eml_parser.py    # EML parsing, attachment extraction
  models.py        # SQLAlchemy Job model
  database.py      # SQLite connection and init
  cleanup.py       # Temp file lifecycle management
  templates/       # Jinja2 HTML templates (HTMX)
tests/             # pytest test suite
Dockerfile         # App container image
docker-compose.yml # Local two-container stack
```

---

## Threat Model Summary for Security Review

| Threat | Mitigation |
|--------|-----------|
| Malware in encrypted attachment bypasses gateway AV | Decrypted content scanned by ClamAV before release |
| Malicious archive exploits parser vulnerability | `qpdf`/`7z` run as CLI subprocesses, isolated from app process |
| Decompression bomb | Extracted size checked against configurable limit; excess deleted |
| Infected file released to analyst | Download gated at HTTP layer on `status == "clean"` only |
| Stale AV signatures | Signature date shown in UI; warning banner if >48 hours old |
| Temp files persist after session | Wiped on startup; TTL-cleaned every 5 minutes |
| Password retained after use | Set to NULL in database immediately after successful decryption |
| No audit trail | All jobs logged to SQLite with full metadata and scan results |
| Container escape / privilege escalation | App runs as non-root (UID 1001); memory limits enforced |
| Unsupported file type slips through unscanned | Unsupported types are copied to decrypted dir and scanned in original form; noted in audit log |
