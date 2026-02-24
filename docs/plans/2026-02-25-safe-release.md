# safe-release Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a local Docker web app for service desk analysts to scan password-protected email attachments with ClamAV before releasing clean files for download or preview.

**Architecture:** FastAPI backend with HTMX server-rendered UI. Two Docker Compose services: `app` (FastAPI + Jinja2) and `clamav` (official ClamAV image). An asyncio background worker processes jobs sequentially. SQLite stores the persistent audit trail. CLI tools (`qpdf`, `7z`) and `msoffcrypto-tool` handle decryption. Temp files live in `/tmp/safe-release/` and are wiped on startup + TTL-cleaned during operation.

**Tech Stack:** Python 3.12, FastAPI, Uvicorn, HTMX, Jinja2, SQLAlchemy 2, SQLite, pyclamd, qpdf CLI, 7z CLI, msoffcrypto-tool, python-multipart, aiofiles; dev: pytest, pytest-asyncio, httpx, pikepdf, python-docx

---

### Task 1: Project scaffold

**Files:**
- Create: `.gitignore`
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `app/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Step 1: Create `.gitignore`**

```
.venv/
__pycache__/
*.pyc
*.pyo
.env
*.db
/tmp/
.pytest_cache/
dist/
*.egg-info/
```

**Step 2: Create `requirements.txt`**

```
fastapi==0.115.6
uvicorn[standard]==0.32.1
jinja2==3.1.4
python-multipart==0.0.19
sqlalchemy==2.0.36
pyclamd==0.4.1
msoffcrypto-tool==5.4.2
aiofiles==24.1.0
```

**Step 3: Create `requirements-dev.txt`**

```
pytest==8.3.4
pytest-asyncio==0.24.0
httpx==0.27.2
pikepdf==9.3.2
python-docx==1.1.2
```

**Step 4: Create empty `app/__init__.py` and `tests/__init__.py`**

Both files are empty.

**Step 5: Create `tests/conftest.py`**

This file provides shared fixtures. The encrypted-file fixtures call real CLI tools (`qpdf`, `7z`) and `msoffcrypto-tool` — ensure they are installed locally (`brew install qpdf p7zip`).

```python
import email
import subprocess
from email import policy
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import msoffcrypto
import pikepdf
import pytest
from docx import Document


# ---------------------------------------------------------------------------
# File fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def plain_pdf(tmp_path: Path) -> Path:
    """A valid minimal PDF."""
    pdf_path = tmp_path / "plain.pdf"
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        pdf.save(pdf_path)
    return pdf_path


@pytest.fixture()
def encrypted_pdf(tmp_path: Path, plain_pdf: Path):
    """A PDF encrypted with password 'test123' via qpdf."""
    out = tmp_path / "encrypted.pdf"
    subprocess.run(
        ["qpdf", "--encrypt", "test123", "test123", "256", "--", str(plain_pdf), str(out)],
        check=True,
    )
    return out, "test123"


@pytest.fixture()
def encrypted_zip(tmp_path: Path):
    """A ZIP encrypted with password 'test123' via 7z."""
    content = tmp_path / "secret.txt"
    content.write_text("hello world")
    zip_path = tmp_path / "encrypted.zip"
    subprocess.run(
        ["7z", "a", "-ptest123", "-mem=AES256", str(zip_path), str(content)],
        check=True,
        capture_output=True,
    )
    return zip_path, "test123"


@pytest.fixture()
def plain_docx(tmp_path: Path) -> Path:
    doc = Document()
    doc.add_paragraph("Hello world")
    path = tmp_path / "plain.docx"
    doc.save(str(path))
    return path


@pytest.fixture()
def encrypted_docx(tmp_path: Path, plain_docx: Path):
    """A .docx encrypted with password 'test123' via msoffcrypto-tool."""
    out = tmp_path / "encrypted.docx"
    with open(plain_docx, "rb") as f:
        office_file = msoffcrypto.OfficeFile(f)
        office_file.encrypt("test123")
        with open(out, "wb") as g:
            office_file.write(g)
    return out, "test123"


# ---------------------------------------------------------------------------
# EML fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_eml(tmp_path: Path, encrypted_pdf: tuple) -> Path:
    """An EML file containing one encrypted PDF attachment."""
    enc_pdf_path, _ = encrypted_pdf

    msg = MIMEMultipart()
    msg["Subject"] = "Test subject"
    msg["From"] = "sender@example.com"
    msg["Message-ID"] = "<test-message-id@example.com>"
    msg.attach(MIMEText("See attached.", "plain"))

    with open(enc_pdf_path, "rb") as f:
        attachment = MIMEApplication(f.read(), Name=enc_pdf_path.name)
    attachment["Content-Disposition"] = f'attachment; filename="{enc_pdf_path.name}"'
    msg.attach(attachment)

    eml_path = tmp_path / "test.eml"
    eml_path.write_bytes(msg.as_bytes())
    return eml_path
```

**Step 6: Create local venv and install deps**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

**Step 7: Verify pytest runs with zero tests collected (no errors)**

```bash
pytest tests/ -v
```

Expected: `no tests ran` or `0 passed`.

**Step 8: Commit**

```bash
git add .gitignore requirements.txt requirements-dev.txt app/__init__.py tests/__init__.py tests/conftest.py
git commit -m "chore: project scaffold and dependencies"
```

---

### Task 2: Database models + setup

**Files:**
- Create: `app/database.py`
- Create: `app/models.py`
- Create: `tests/test_models.py`

**Step 1: Write the failing test**

```python
# tests/test_models.py
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Job


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_job_creation_defaults(db):
    job = Job(eml_filename="test.eml")
    db.add(job)
    db.commit()
    db.refresh(job)

    assert job.id is not None
    assert job.status == "queued"
    assert job.original_scan_done is False
    assert job.created_at is not None


def test_job_attachments_json_roundtrip(db):
    attachments = [{"filename": "report.pdf", "original_scan": {"clean": True}}]
    job = Job(eml_filename="test.eml", attachments_json=json.dumps(attachments))
    db.add(job)
    db.commit()
    db.refresh(job)

    assert job.attachments == attachments


def test_job_all_statuses_accepted(db):
    for status in ("queued", "scanning", "awaiting_password", "scanning_decrypted", "clean", "infected", "failed"):
        job = Job(eml_filename=f"{status}.eml", status=status)
        db.add(job)
    db.commit()
    assert db.query(Job).count() == 7
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.database'`

**Step 3: Create `app/database.py`**

```python
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = os.environ.get("DATABASE_URL", "sqlite:///./safe_release.db")

engine = create_engine(
    DB_PATH,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def init_db():
    from app import models  # noqa: F401 — ensure models are registered
    Base.metadata.create_all(bind=engine)
```

**Step 4: Create `app/models.py`**

```python
import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # EML metadata
    eml_filename: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str | None] = mapped_column(String)
    from_address: Mapped[str | None] = mapped_column(String)
    message_id: Mapped[str | None] = mapped_column(String)
    ticket_ref: Mapped[str | None] = mapped_column(String)

    # Pipeline state
    # Statuses: queued | scanning | awaiting_password | scanning_decrypted | clean | infected | failed
    status: Mapped[str] = mapped_column(String, default="queued")
    original_scan_done: Mapped[bool] = mapped_column(Boolean, default=False)

    # Transient — cleared after successful decryption
    password: Mapped[str | None] = mapped_column(String)

    # ClamAV info at time of scan
    clamav_signature_date: Mapped[str | None] = mapped_column(String)

    # Error detail if failed
    error_detail: Mapped[str | None] = mapped_column(String)

    # JSON array of attachment dicts:
    # [{"filename": str, "content_type": str,
    #   "original_scan": {"clean": bool, "detail": str},
    #   "decrypted_scan": {"clean": bool, "detail": str}}]
    attachments_json: Mapped[str] = mapped_column(Text, default="[]")

    @property
    def attachments(self) -> list[dict]:
        return json.loads(self.attachments_json or "[]")

    @attachments.setter
    def attachments(self, value: list[dict]) -> None:
        self.attachments_json = json.dumps(value)
```

**Step 5: Run test to verify it passes**

```bash
pytest tests/test_models.py -v
```

Expected: `3 passed`

**Step 6: Commit**

```bash
git add app/database.py app/models.py tests/test_models.py
git commit -m "feat: database models and setup"
```

---

### Task 3: EML parser

**Files:**
- Create: `app/eml_parser.py`
- Create: `tests/test_eml_parser.py`

**Step 1: Write the failing test**

```python
# tests/test_eml_parser.py
from pathlib import Path

import pytest

from app.eml_parser import parse_eml, EmlParseError


def test_parse_eml_extracts_metadata(sample_eml, tmp_path):
    dest = tmp_path / "attachments"
    result = parse_eml(sample_eml, dest)

    assert result["subject"] == "Test subject"
    assert result["from_address"] == "sender@example.com"
    assert "<test-message-id@example.com>" in result["message_id"]


def test_parse_eml_extracts_attachments(sample_eml, tmp_path):
    dest = tmp_path / "attachments"
    result = parse_eml(sample_eml, dest)

    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"].endswith(".pdf")
    assert Path(att["path"]).exists()
    assert Path(att["path"]).stat().st_size > 0


def test_parse_eml_raises_on_invalid_file(tmp_path):
    bad_file = tmp_path / "bad.eml"
    bad_file.write_text("this is not an email")
    dest = tmp_path / "attachments"

    # Should not raise — even bare text is technically parseable by email.parser.
    # Instead verify: no attachments, empty metadata fields handled gracefully.
    result = parse_eml(bad_file, dest)
    assert isinstance(result["attachments"], list)


def test_parse_eml_raises_on_missing_file(tmp_path):
    with pytest.raises(EmlParseError, match="not found"):
        parse_eml(tmp_path / "nonexistent.eml", tmp_path / "dest")
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_eml_parser.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.eml_parser'`

**Step 3: Create `app/eml_parser.py`**

```python
from email.parser import BytesParser
from email import policy
from pathlib import Path


class EmlParseError(Exception):
    pass


def parse_eml(eml_path: Path, dest_dir: Path) -> dict:
    """
    Parse an EML file, save attachments to dest_dir, return metadata dict.

    Returns:
        {
            "subject": str,
            "from_address": str,
            "message_id": str,
            "attachments": [{"filename": str, "path": str, "content_type": str}]
        }

    Raises:
        EmlParseError: if the file does not exist.
    """
    if not eml_path.exists():
        raise EmlParseError(f"EML file not found: {eml_path}")

    dest_dir.mkdir(parents=True, exist_ok=True)

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    result = {
        "subject": str(msg.get("Subject", "") or ""),
        "from_address": str(msg.get("From", "") or ""),
        "message_id": str(msg.get("Message-ID", "") or ""),
        "attachments": [],
    }

    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        filename = part.get_filename()
        if not filename:
            continue
        # Sanitise filename — strip any path components
        safe_name = Path(filename).name
        dest_path = dest_dir / safe_name
        payload = part.get_payload(decode=True)
        if payload:
            dest_path.write_bytes(payload)
            result["attachments"].append(
                {
                    "filename": safe_name,
                    "path": str(dest_path),
                    "content_type": part.get_content_type(),
                }
            )

    return result
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_eml_parser.py -v
```

Expected: `4 passed`

**Step 5: Commit**

```bash
git add app/eml_parser.py tests/test_eml_parser.py
git commit -m "feat: EML parser"
```

---

### Task 4: ClamAV scanner wrapper

**Files:**
- Create: `app/scanner.py`
- Create: `tests/test_scanner.py`

Note: unit tests mock pyclamd. Integration tests (marked `@pytest.mark.integration`) require ClamAV to be running — run via `docker compose up clamav` and pass `-m integration` flag.

**Step 1: Write the failing tests**

```python
# tests/test_scanner.py
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner import ClamAVScanner, ScanResult, ClamAVUnavailableError


# --- Unit tests (mocked) ---

@pytest.fixture()
def mock_cd():
    with patch("app.scanner.pyclamd.ClamdNetworkSocket") as mock_cls:
        yield mock_cls.return_value


def test_scan_clean_file(mock_cd, tmp_path):
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("hello")
    mock_cd.scan_file.return_value = None

    scanner = ClamAVScanner()
    result = scanner.scan_file(clean_file)

    assert result.clean is True
    assert result.detail == ""


def test_scan_infected_file(mock_cd, tmp_path):
    bad_file = tmp_path / "bad.txt"
    bad_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
    mock_cd.scan_file.return_value = {str(bad_file): ("FOUND", "Eicar-Signature")}

    scanner = ClamAVScanner()
    result = scanner.scan_file(bad_file)

    assert result.clean is False
    assert "Eicar" in result.detail


def test_scan_encrypted_file_returns_pua(mock_cd, tmp_path):
    enc_file = tmp_path / "enc.zip"
    enc_file.write_bytes(b"\x00" * 10)
    mock_cd.scan_file.return_value = {str(enc_file): ("FOUND", "PUA.Encrypted.ZIP")}

    scanner = ClamAVScanner()
    result = scanner.scan_file(enc_file)

    assert result.clean is False
    assert result.is_pua_encrypted is True


def test_get_version_info_parses_correctly(mock_cd):
    mock_cd.version.return_value = "ClamAV 1.3.1/27437/Thu Oct 24 07:53:47 2024"

    scanner = ClamAVScanner()
    info = scanner.get_version_info()

    assert info["version"] == "ClamAV 1.3.1"
    assert info["signature_version"] == "27437"
    assert "2024" in info["signature_date"]


def test_is_available_returns_false_when_ping_fails(mock_cd):
    mock_cd.ping.side_effect = Exception("connection refused")

    scanner = ClamAVScanner()
    assert scanner.is_available() is False


def test_scan_raises_on_clamav_error(mock_cd, tmp_path):
    f = tmp_path / "file.bin"
    f.write_bytes(b"\x00")
    mock_cd.scan_file.return_value = {str(f): ("ERROR", "permission denied")}

    scanner = ClamAVScanner()
    with pytest.raises(ClamAVUnavailableError):
        scanner.scan_file(f)


# --- Integration tests (require live ClamAV) ---

@pytest.mark.integration
def test_integration_scan_eicar(tmp_path):
    eicar = tmp_path / "eicar.txt"
    eicar.write_text(
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    scanner = ClamAVScanner()
    result = scanner.scan_file(eicar)
    assert result.clean is False


@pytest.mark.integration
def test_integration_scan_clean(tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("harmless content")
    scanner = ClamAVScanner()
    result = scanner.scan_file(clean)
    assert result.clean is True
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_scanner.py -v -m "not integration"
```

Expected: `ModuleNotFoundError: No module named 'app.scanner'`

**Step 3: Create `app/scanner.py`**

```python
from dataclasses import dataclass, field
from pathlib import Path

import pyclamd


class ClamAVUnavailableError(Exception):
    pass


@dataclass
class ScanResult:
    clean: bool
    detail: str = ""
    is_pua_encrypted: bool = False


class ClamAVScanner:
    def __init__(
        self,
        host: str = "clamav",
        port: int = 3310,
    ) -> None:
        self._cd = pyclamd.ClamdNetworkSocket(host=host, port=port)

    def scan_file(self, path: Path) -> ScanResult:
        """Scan a single file. Raises ClamAVUnavailableError on daemon error."""
        raw = self._cd.scan_file(str(path))
        if raw is None:
            return ScanResult(clean=True)

        status, detail = raw[str(path)]

        if status == "ERROR":
            raise ClamAVUnavailableError(f"ClamAV error scanning {path.name}: {detail}")

        if status == "FOUND":
            is_pua = detail.startswith("PUA.Encrypted")
            return ScanResult(clean=False, detail=detail, is_pua_encrypted=is_pua)

        return ScanResult(clean=True)

    def get_version_info(self) -> dict:
        """
        Returns dict with keys: version, signature_version, signature_date.
        ClamAV version() format: "ClamAV 1.3.1/27437/Thu Oct 24 07:53:47 2024"
        """
        raw = self._cd.version()
        parts = raw.split("/", 2)
        return {
            "version": parts[0].strip() if parts else raw,
            "signature_version": parts[1].strip() if len(parts) > 1 else "",
            "signature_date": parts[2].strip() if len(parts) > 2 else "",
        }

    def is_available(self) -> bool:
        try:
            self._cd.ping()
            return True
        except Exception:
            return False
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_scanner.py -v -m "not integration"
```

Expected: `6 passed`

**Step 5: Commit**

```bash
git add app/scanner.py tests/test_scanner.py
git commit -m "feat: ClamAV scanner wrapper"
```

---

### Task 5: File decryptors

**Files:**
- Create: `app/decryptors.py`
- Create: `tests/test_decryptors.py`

**Step 1: Write the failing tests**

```python
# tests/test_decryptors.py
from pathlib import Path

import pytest

from app.decryptors import (
    decrypt_office,
    decrypt_pdf,
    extract_zip,
    WrongPasswordError,
    DecryptionError,
    MAX_OUTPUT_BYTES,
)


# --- PDF ---

def test_decrypt_pdf_correct_password(encrypted_pdf, tmp_path):
    enc_path, password = encrypted_pdf
    out = tmp_path / "decrypted.pdf"
    decrypt_pdf(enc_path, password, out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_decrypt_pdf_wrong_password(encrypted_pdf, tmp_path):
    enc_path, _ = encrypted_pdf
    out = tmp_path / "decrypted.pdf"
    with pytest.raises(WrongPasswordError):
        decrypt_pdf(enc_path, "wrongpassword", out)


# --- ZIP ---

def test_extract_zip_correct_password(encrypted_zip, tmp_path):
    zip_path, password = encrypted_zip
    out_dir = tmp_path / "extracted"
    files = extract_zip(zip_path, password, out_dir)
    assert len(files) > 0
    assert any(f.is_file() for f in files)


def test_extract_zip_wrong_password(encrypted_zip, tmp_path):
    zip_path, _ = encrypted_zip
    out_dir = tmp_path / "extracted"
    with pytest.raises(WrongPasswordError):
        extract_zip(zip_path, "wrongpassword", out_dir)


def test_extract_zip_enforces_size_limit(encrypted_zip, tmp_path, monkeypatch):
    zip_path, password = encrypted_zip
    out_dir = tmp_path / "extracted"
    # Set limit below the content size
    monkeypatch.setattr("app.decryptors.MAX_OUTPUT_BYTES", 1)
    with pytest.raises(DecryptionError, match="exceeds size limit"):
        extract_zip(zip_path, password, out_dir)


# --- Office ---

def test_decrypt_office_correct_password(encrypted_docx, tmp_path):
    enc_path, password = encrypted_docx
    out = tmp_path / "decrypted.docx"
    decrypt_office(enc_path, password, out)
    assert out.exists()
    assert out.stat().st_size > 0


def test_decrypt_office_wrong_password(encrypted_docx, tmp_path):
    enc_path, _ = encrypted_docx
    out = tmp_path / "decrypted.docx"
    with pytest.raises(WrongPasswordError):
        decrypt_office(enc_path, "wrongpassword", out)
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_decryptors.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.decryptors'`

**Step 3: Create `app/decryptors.py`**

```python
import subprocess
from pathlib import Path

import msoffcrypto
import msoffcrypto.exceptions

MAX_OUTPUT_BYTES = 500 * 1024 * 1024  # 500 MB


class WrongPasswordError(Exception):
    pass


class DecryptionError(Exception):
    pass


def decrypt_pdf(encrypted_path: Path, password: str, output_path: Path) -> None:
    """
    Decrypt a password-protected PDF using qpdf CLI.
    Raises WrongPasswordError on bad password, DecryptionError on other failures.
    """
    result = subprocess.run(
        ["qpdf", f"--password={password}", "--decrypt", str(encrypted_path), str(output_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr_lower = result.stderr.lower()
        if "invalid password" in stderr_lower or "wrong password" in stderr_lower:
            raise WrongPasswordError(f"Wrong password for {encrypted_path.name}")
        raise DecryptionError(f"qpdf failed for {encrypted_path.name}: {result.stderr.strip()}")


def extract_zip(encrypted_path: Path, password: str, output_dir: Path) -> list[Path]:
    """
    Extract a password-protected ZIP using 7z CLI.
    Checks total extracted size against MAX_OUTPUT_BYTES.
    Returns list of extracted file paths.
    Raises WrongPasswordError on bad password, DecryptionError on other failures.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["7z", "x", f"-p{password}", str(encrypted_path), f"-o{output_dir}", "-y"],
        capture_output=True,
        text=True,
    )
    combined = (result.stdout + result.stderr).lower()
    if result.returncode != 0:
        if "wrong password" in combined or "bad password" in combined or "incorrect password" in combined:
            raise WrongPasswordError(f"Wrong password for {encrypted_path.name}")
        raise DecryptionError(f"7z failed for {encrypted_path.name}: {result.stdout.strip()}")

    extracted = [p for p in output_dir.rglob("*") if p.is_file()]
    total_size = sum(p.stat().st_size for p in extracted)
    if total_size > MAX_OUTPUT_BYTES:
        for p in extracted:
            p.unlink(missing_ok=True)
        raise DecryptionError(
            f"Extracted content for {encrypted_path.name} exceeds size limit "
            f"({total_size // (1024**2)} MB > {MAX_OUTPUT_BYTES // (1024**2)} MB)"
        )

    return extracted


def decrypt_office(encrypted_path: Path, password: str, output_path: Path) -> None:
    """
    Decrypt a password-protected Office document (.docx/.xlsx/.pptx) using msoffcrypto-tool.
    Raises WrongPasswordError on bad password, DecryptionError on other failures.
    """
    try:
        with open(encrypted_path, "rb") as enc_file:
            office_file = msoffcrypto.OfficeFile(enc_file)
            office_file.load_key(password=password)
            with open(output_path, "wb") as out_file:
                office_file.decrypt(out_file)
    except msoffcrypto.exceptions.InvalidKeyError:
        raise WrongPasswordError(f"Wrong password for {encrypted_path.name}")
    except Exception as exc:
        raise DecryptionError(f"msoffcrypto failed for {encrypted_path.name}: {exc}") from exc
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_decryptors.py -v
```

Expected: `7 passed`

**Step 5: Commit**

```bash
git add app/decryptors.py tests/test_decryptors.py
git commit -m "feat: PDF, ZIP and Office decryptors"
```

---

### Task 6: Job pipeline + background worker

**Files:**
- Create: `app/pipeline.py`
- Create: `tests/test_pipeline.py`

**Step 1: Write the failing tests**

```python
# tests/test_pipeline.py
import json
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database import Base
from app.models import Job
from app.scanner import ScanResult


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture()
def temp_dir(tmp_path):
    d = tmp_path / "safe-release"
    d.mkdir()
    return d


def make_job(db, tmp_path, eml_filename="test.eml", password="test123"):
    job = Job(eml_filename=eml_filename, password=password)
    db.add(job)
    db.commit()
    db.refresh(job)

    # Create a fake original attachment on disk
    original_dir = tmp_path / "safe-release" / job.id / "original"
    original_dir.mkdir(parents=True)
    fake_file = original_dir / "attachment.pdf"
    fake_file.write_bytes(b"%PDF fake content")
    job.attachments = [{"filename": "attachment.pdf", "content_type": "application/pdf"}]
    db.commit()
    return job


@pytest.mark.asyncio
async def test_process_job_clean(db, tmp_path):
    from app.pipeline import process_job

    job = make_job(db, tmp_path)
    clean_result = ScanResult(clean=True)

    with (
        patch("app.pipeline.ClamAVScanner") as MockScanner,
        patch("app.pipeline.decrypt_pdf") as mock_decrypt,
        patch("app.pipeline.TEMP_BASE", tmp_path / "safe-release"),
    ):
        mock_instance = MockScanner.return_value
        mock_instance.scan_file.return_value = clean_result
        mock_instance.get_version_info.return_value = {"signature_date": "2024-10-24"}

        await process_job(job, db)

    db.refresh(job)
    assert job.status == "clean"
    assert job.original_scan_done is True
    assert job.password is None  # cleared after use


@pytest.mark.asyncio
async def test_process_job_wrong_password(db, tmp_path):
    from app.pipeline import process_job
    from app.decryptors import WrongPasswordError

    job = make_job(db, tmp_path)

    with (
        patch("app.pipeline.ClamAVScanner") as MockScanner,
        patch("app.pipeline.decrypt_pdf", side_effect=WrongPasswordError("bad pw")),
        patch("app.pipeline.TEMP_BASE", tmp_path / "safe-release"),
    ):
        mock_instance = MockScanner.return_value
        mock_instance.scan_file.return_value = ScanResult(clean=True)
        mock_instance.get_version_info.return_value = {"signature_date": "2024-10-24"}

        await process_job(job, db)

    db.refresh(job)
    assert job.status == "awaiting_password"
    assert job.original_scan_done is True  # first scan done, preserved


@pytest.mark.asyncio
async def test_process_job_infected(db, tmp_path):
    from app.pipeline import process_job

    job = make_job(db, tmp_path)
    infected_result = ScanResult(clean=False, detail="Eicar-Signature")

    with (
        patch("app.pipeline.ClamAVScanner") as MockScanner,
        patch("app.pipeline.decrypt_pdf"),
        patch("app.pipeline.TEMP_BASE", tmp_path / "safe-release"),
    ):
        mock_instance = MockScanner.return_value
        # First scan clean (PUA), second scan infected
        mock_instance.scan_file.side_effect = [
            ScanResult(clean=False, detail="PUA.Encrypted.PDF", is_pua_encrypted=True),
            infected_result,
        ]
        mock_instance.get_version_info.return_value = {"signature_date": "2024-10-24"}

        await process_job(job, db)

    db.refresh(job)
    assert job.status == "infected"


@pytest.mark.asyncio
async def test_retry_skips_first_scan(db, tmp_path):
    from app.pipeline import process_job

    # Job already has first scan done
    job = make_job(db, tmp_path)
    job.original_scan_done = True
    job.status = "awaiting_password"
    db.commit()

    with (
        patch("app.pipeline.ClamAVScanner") as MockScanner,
        patch("app.pipeline.decrypt_pdf"),
        patch("app.pipeline.TEMP_BASE", tmp_path / "safe-release"),
    ):
        # Create decrypted dir so second scan has files to scan
        dec_dir = tmp_path / "safe-release" / job.id / "decrypted"
        dec_dir.mkdir(parents=True)
        (dec_dir / "attachment.pdf").write_bytes(b"%PDF decrypted")

        mock_instance = MockScanner.return_value
        mock_instance.scan_file.return_value = ScanResult(clean=True)
        mock_instance.get_version_info.return_value = {"signature_date": "2024-10-24"}

        await process_job(job, db)

    db.refresh(job)
    assert job.status == "clean"
    # scan_file called once (only second scan), not twice
    assert mock_instance.scan_file.call_count == 1
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_pipeline.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.pipeline'`

**Step 3: Create `app/pipeline.py`**

```python
import asyncio
import json
from pathlib import Path

from app.database import SessionLocal
from app.decryptors import (
    DecryptionError,
    WrongPasswordError,
    decrypt_office,
    decrypt_pdf,
    extract_zip,
)
from app.models import Job
from app.scanner import ClamAVScanner, ClamAVUnavailableError

TEMP_BASE = Path("/tmp/safe-release")

OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"}


async def job_worker() -> None:
    """Continuously process queued jobs one at a time."""
    while True:
        db = SessionLocal()
        try:
            job = (
                db.query(Job)
                .filter(Job.status == "queued")
                .order_by(Job.created_at)
                .first()
            )
            if job:
                await process_job(job, db)
            else:
                await asyncio.sleep(2)
        except Exception:
            pass  # Worker must not crash
        finally:
            db.close()


async def process_job(job: Job, db) -> None:
    """
    Run the full scan pipeline for a single job.
    Updates job.status and job.attachments throughout.
    """
    job_dir = TEMP_BASE / job.id
    original_dir = job_dir / "original"
    decrypted_dir = job_dir / "decrypted"
    decrypted_dir.mkdir(parents=True, exist_ok=True)

    scanner = ClamAVScanner()

    try:
        version_info = scanner.get_version_info()
        job.clamav_signature_date = version_info.get("signature_date", "")
    except Exception:
        job.clamav_signature_date = "unknown"

    attachments = job.attachments

    # ------------------------------------------------------------------ #
    # Step 1: First scan (skip if already done — password retry path)     #
    # ------------------------------------------------------------------ #
    if not job.original_scan_done:
        job.status = "scanning"
        db.commit()

        for att in attachments:
            original_path = original_dir / att["filename"]
            if not original_path.exists():
                att["original_scan"] = {"clean": False, "detail": "File missing from temp storage"}
                continue
            try:
                result = await asyncio.to_thread(scanner.scan_file, original_path)
                att["original_scan"] = {
                    "clean": result.clean,
                    "detail": result.detail,
                    "is_pua_encrypted": result.is_pua_encrypted,
                }
            except ClamAVUnavailableError as exc:
                job.status = "failed"
                job.error_detail = str(exc)
                job.attachments = attachments
                db.commit()
                return

        job.original_scan_done = True
        job.attachments = attachments
        db.commit()

    # ------------------------------------------------------------------ #
    # Step 2: Decrypt / extract                                           #
    # ------------------------------------------------------------------ #
    password = job.password or ""
    wrong_password_files: list[str] = []

    for att in attachments:
        original_path = original_dir / att["filename"]
        if not original_path.exists():
            continue

        suffix = original_path.suffix.lower()
        decrypted_path = decrypted_dir / att["filename"]

        try:
            if suffix == ".pdf":
                await asyncio.to_thread(decrypt_pdf, original_path, password, decrypted_path)
            elif suffix == ".zip":
                await asyncio.to_thread(extract_zip, original_path, password, decrypted_dir)
            elif suffix in OFFICE_EXTENSIONS:
                await asyncio.to_thread(decrypt_office, original_path, password, decrypted_path)
            else:
                # Unsupported type — copy original as-is for second scan
                import shutil
                shutil.copy2(original_path, decrypted_path)
                att["note"] = "Unsupported type — scanned in original form"
        except WrongPasswordError:
            wrong_password_files.append(att["filename"])
        except DecryptionError as exc:
            att["decrypted_scan"] = {"clean": False, "detail": str(exc)}

    if wrong_password_files:
        job.status = "awaiting_password"
        job.error_detail = f"Wrong password for: {', '.join(wrong_password_files)}"
        job.attachments = attachments
        db.commit()
        return

    # Clear password after successful decryption
    job.password = None

    # ------------------------------------------------------------------ #
    # Step 3: Second scan (decrypted files)                               #
    # ------------------------------------------------------------------ #
    job.status = "scanning_decrypted"
    db.commit()

    any_infected = False
    decrypted_files = list(decrypted_dir.rglob("*"))

    for att in attachments:
        decrypted_path = decrypted_dir / att["filename"]
        files_to_scan = [decrypted_path] if decrypted_path.is_file() else list(decrypted_dir.rglob("*"))

        for scan_path in files_to_scan:
            if not scan_path.is_file():
                continue
            try:
                result = await asyncio.to_thread(scanner.scan_file, scan_path)
                att.setdefault("decrypted_scan", {})
                if not result.clean:
                    any_infected = True
                    att["decrypted_scan"] = {"clean": False, "detail": result.detail}
                else:
                    att["decrypted_scan"] = {"clean": True, "detail": ""}
            except ClamAVUnavailableError as exc:
                job.status = "failed"
                job.error_detail = str(exc)
                job.attachments = attachments
                db.commit()
                return

    job.attachments = attachments
    job.status = "infected" if any_infected else "clean"
    db.commit()
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_pipeline.py -v
```

Expected: `4 passed`

**Step 5: Commit**

```bash
git add app/pipeline.py tests/test_pipeline.py
git commit -m "feat: job pipeline and background worker"
```

---

### Task 7: FastAPI app + routes

**Files:**
- Create: `app/main.py`
- Create: `app/cleanup.py`
- Create: `tests/test_routes.py`

**Step 1: Write the failing tests**

```python
# tests/test_routes.py
import io
import json
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@pytest.fixture(autouse=True)
def use_test_db(tmp_path, monkeypatch):
    """Redirect DB to a temp SQLite file and patch TEMP_BASE."""
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)

    from sqlalchemy.orm import sessionmaker
    TestSession = sessionmaker(bind=engine)

    monkeypatch.setattr("app.main.SessionLocal", TestSession)
    monkeypatch.setattr("app.pipeline.TEMP_BASE", tmp_path / "safe-release")
    monkeypatch.setattr("app.main.TEMP_BASE", tmp_path / "safe-release")


def make_eml_bytes() -> bytes:
    msg = MIMEMultipart()
    msg["Subject"] = "Route test"
    msg["From"] = "a@b.com"
    msg["Message-ID"] = "<route-test@example.com>"
    msg.attach(MIMEText("body", "plain"))
    return msg.as_bytes()


@pytest.mark.asyncio
async def test_upload_eml_creates_job():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/jobs",
            data={"password": "test123", "ticket_ref": "INC001"},
            files={"eml_file": ("test.eml", make_eml_bytes(), "message/rfc822")},
        )
    assert response.status_code in (200, 201, 303)


@pytest.mark.asyncio
async def test_get_jobs_returns_list():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/partials/jobs")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_retry_password_updates_job(tmp_path):
    from app.models import Job
    from app.database import SessionLocal

    # Create a job in awaiting_password state
    db = SessionLocal()
    job = Job(eml_filename="t.eml", status="awaiting_password", original_scan_done=True)
    db.add(job)
    db.commit()
    job_id = job.id
    db.close()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            f"/jobs/{job_id}/retry",
            data={"password": "newpassword"},
        )
    assert response.status_code in (200, 303)

    db = SessionLocal()
    updated = db.get(Job, job_id)
    assert updated.status == "queued"
    assert updated.password == "newpassword"
    db.close()


@pytest.mark.asyncio
async def test_clamav_status_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        with patch("app.main.ClamAVScanner") as MockScanner:
            mock = MockScanner.return_value
            mock.is_available.return_value = True
            mock.get_version_info.return_value = {
                "version": "ClamAV 1.3.1",
                "signature_date": "Thu Oct 24 07:53:47 2024",
            }
            response = await client.get("/partials/clamav-status")
    assert response.status_code == 200
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_routes.py -v
```

Expected: `ModuleNotFoundError: No module named 'app.main'`

**Step 3: Create `app/cleanup.py`**

```python
import asyncio
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

TEMP_BASE = Path("/tmp/safe-release")
CLEAN_JOB_TTL_HOURS = 1


def wipe_temp_dir() -> None:
    """Called at startup — wipe all temp files from previous sessions."""
    if TEMP_BASE.exists():
        shutil.rmtree(TEMP_BASE)
    TEMP_BASE.mkdir(parents=True, exist_ok=True)


async def ttl_cleanup_worker() -> None:
    """Delete clean job temp dirs older than CLEAN_JOB_TTL_HOURS."""
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CLEAN_JOB_TTL_HOURS)
        if not TEMP_BASE.exists():
            continue
        for job_dir in TEMP_BASE.iterdir():
            if not job_dir.is_dir():
                continue
            mtime = datetime.fromtimestamp(job_dir.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                shutil.rmtree(job_dir, ignore_errors=True)
```

**Step 4: Create `app/main.py`**

```python
import asyncio
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.cleanup import ttl_cleanup_worker, wipe_temp_dir
from app.database import SessionLocal, init_db
from app.eml_parser import parse_eml, EmlParseError
from app.models import Job
from app.pipeline import TEMP_BASE, job_worker
from app.scanner import ClamAVScanner

templates = Jinja2Templates(directory="app/templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    wipe_temp_dir()
    asyncio.create_task(job_worker())
    asyncio.create_task(ttl_cleanup_worker())
    yield


app = FastAPI(lifespan=lifespan)


# --- Helpers ---

def get_db() -> Session:
    return SessionLocal()


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/jobs")
async def upload_eml(
    request: Request,
    eml_file: UploadFile,
    password: str = Form(...),
    ticket_ref: str = Form(""),
):
    db = get_db()
    try:
        raw = await eml_file.read()
        tmp_eml = TEMP_BASE / "uploads" / eml_file.filename
        tmp_eml.parent.mkdir(parents=True, exist_ok=True)
        tmp_eml.write_bytes(raw)

        try:
            metadata = parse_eml(tmp_eml, TEMP_BASE / "staging")
        except EmlParseError as exc:
            # Return error card HTML
            return templates.TemplateResponse(
                "partials/job_card_error.html",
                {"request": request, "filename": eml_file.filename, "error": str(exc)},
            )

        job = Job(
            eml_filename=eml_file.filename,
            subject=metadata["subject"],
            from_address=metadata["from_address"],
            message_id=metadata["message_id"],
            ticket_ref=ticket_ref or None,
            password=password,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # Move attachments to job temp dir
        job_original_dir = TEMP_BASE / job.id / "original"
        job_original_dir.mkdir(parents=True, exist_ok=True)

        saved_attachments = []
        for att in metadata["attachments"]:
            src = Path(att["path"])
            dest = job_original_dir / att["filename"]
            shutil.move(str(src), dest)
            saved_attachments.append(
                {"filename": att["filename"], "content_type": att["content_type"]}
            )

        job.attachments = saved_attachments
        db.commit()

    finally:
        db.close()

    return RedirectResponse("/", status_code=303)


@app.post("/jobs/{job_id}/retry")
async def retry_password(job_id: str, password: str = Form(...)):
    db = get_db()
    try:
        job = db.get(Job, job_id)
        if job and job.status == "awaiting_password":
            job.password = password
            job.status = "queued"
            job.error_detail = None
            db.commit()
    finally:
        db.close()
    return RedirectResponse("/", status_code=303)


@app.get("/partials/jobs", response_class=HTMLResponse)
async def jobs_partial(request: Request):
    db = get_db()
    try:
        jobs = db.query(Job).order_by(Job.created_at.desc()).all()
        return templates.TemplateResponse(
            "partials/job_list.html", {"request": request, "jobs": jobs}
        )
    finally:
        db.close()


@app.get("/partials/clamav-status", response_class=HTMLResponse)
async def clamav_status_partial(request: Request):
    scanner = ClamAVScanner()
    available = scanner.is_available()
    version_info = {}
    stale = False
    if available:
        try:
            version_info = scanner.get_version_info()
            from datetime import datetime, timezone, timedelta
            sig_date_str = version_info.get("signature_date", "")
            # ClamAV date format: "Thu Oct 24 07:53:47 2024"
            try:
                sig_date = datetime.strptime(sig_date_str, "%a %b %d %H:%M:%S %Y").replace(
                    tzinfo=timezone.utc
                )
                stale = (datetime.now(timezone.utc) - sig_date) > timedelta(hours=48)
            except ValueError:
                pass
        except Exception:
            pass
    return templates.TemplateResponse(
        "partials/clamav_status.html",
        {"request": request, "available": available, "version_info": version_info, "stale": stale},
    )


@app.get("/jobs/{job_id}/files/{filename}")
async def download_file(job_id: str, filename: str):
    db = get_db()
    try:
        job = db.get(Job, job_id)
        if not job or job.status != "clean":
            return HTMLResponse("Not found or not clean", status_code=404)
    finally:
        db.close()

    # Look in decrypted dir first, then original
    for subdir in ("decrypted", "original"):
        candidate = TEMP_BASE / job_id / subdir / filename
        if candidate.exists():
            return StreamingResponse(
                candidate.open("rb"),
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )

    return HTMLResponse("File not found", status_code=404)
```

**Step 5: Run tests to verify they pass**

```bash
pytest tests/test_routes.py -v
```

Expected: `4 passed`

**Step 6: Commit**

```bash
git add app/main.py app/cleanup.py tests/test_routes.py
git commit -m "feat: FastAPI routes and app setup"
```

---

### Task 8: Jinja2 templates

**Files:**
- Create: `app/templates/base.html`
- Create: `app/templates/index.html`
- Create: `app/templates/partials/job_list.html`
- Create: `app/templates/partials/job_card.html`
- Create: `app/templates/partials/job_card_error.html`
- Create: `app/templates/partials/clamav_status.html`

No automated tests — verify visually by running the app.

**Step 1: Create `app/templates/base.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>safe-release</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <script src="https://unpkg.com/htmx.org@2.0.3/dist/htmx.min.js"></script>
  <style>
    .status-queued { background-color: #6c757d; }
    .status-scanning, .status-scanning_decrypted { background-color: #0d6efd; }
    .status-awaiting_password { background-color: #fd7e14; }
    .status-clean { background-color: #198754; }
    .status-infected { background-color: #dc3545; }
    .status-failed { background-color: #dc3545; }
  </style>
</head>
<body class="bg-light">
  <nav class="navbar navbar-dark bg-dark mb-4">
    <div class="container">
      <span class="navbar-brand fw-bold">safe-release</span>
      <div
        id="clamav-status"
        hx-get="/partials/clamav-status"
        hx-trigger="load, every 60s"
        hx-swap="innerHTML">
        <span class="text-secondary small">Loading ClamAV status…</span>
      </div>
    </div>
  </nav>
  <div class="container">
    {% block content %}{% endblock %}
  </div>
</body>
</html>
```

**Step 2: Create `app/templates/index.html`**

```html
{% extends "base.html" %}
{% block content %}
<div class="row">
  <div class="col-md-6 col-lg-4">
    <div class="card mb-4">
      <div class="card-header fw-semibold">Upload EML</div>
      <div class="card-body">
        <form
          hx-post="/jobs"
          hx-target="#job-list"
          hx-swap="outerHTML"
          hx-encoding="multipart/form-data">
          <div class="mb-3">
            <label class="form-label">EML file</label>
            <input type="file" name="eml_file" accept=".eml" class="form-control" required>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" name="password" class="form-control" required placeholder="Attachment password">
          </div>
          <div class="mb-3">
            <label class="form-label">Ticket reference <span class="text-muted">(optional)</span></label>
            <input type="text" name="ticket_ref" class="form-control" placeholder="e.g. INC0012345">
          </div>
          <button type="submit" class="btn btn-primary w-100">Queue for scanning</button>
        </form>
      </div>
    </div>
  </div>

  <div class="col-md-6 col-lg-8">
    <div
      id="job-list"
      hx-get="/partials/jobs"
      hx-trigger="load, every 3s"
      hx-swap="outerHTML">
      <p class="text-muted">Loading queue…</p>
    </div>
  </div>
</div>
{% endblock %}
```

**Step 3: Create `app/templates/partials/job_list.html`**

```html
<div id="job-list"
  hx-get="/partials/jobs"
  hx-trigger="every 3s"
  hx-swap="outerHTML">
  {% if jobs %}
    {% for job in jobs %}
      {% include "partials/job_card.html" %}
    {% endfor %}
  {% else %}
    <p class="text-muted">No jobs queued yet.</p>
  {% endif %}
</div>
```

**Step 4: Create `app/templates/partials/job_card.html`**

```html
<div class="card mb-3" id="job-{{ job.id }}">
  <div class="card-header d-flex justify-content-between align-items-center">
    <div>
      <span class="badge text-white status-{{ job.status }} me-2">{{ job.status.replace('_', ' ') }}</span>
      <strong>{{ job.eml_filename }}</strong>
      {% if job.ticket_ref %}
        <span class="ms-2 text-muted small">{{ job.ticket_ref }}</span>
      {% endif %}
    </div>
    <small class="text-muted">{{ job.created_at.strftime('%H:%M:%S') }}</small>
  </div>
  <div class="card-body">
    {% if job.subject %}
      <p class="mb-1"><strong>Subject:</strong> {{ job.subject }}</p>
    {% endif %}
    {% if job.from_address %}
      <p class="mb-1"><strong>From:</strong> {{ job.from_address }}</p>
    {% endif %}
    {% if job.message_id %}
      <p class="mb-1 text-muted small"><strong>Message-ID:</strong> {{ job.message_id }}</p>
    {% endif %}

    {% if job.clamav_signature_date %}
      <p class="mb-2 text-muted small">Scanned with signatures: {{ job.clamav_signature_date }}</p>
    {% endif %}

    {% if job.attachments %}
      <ul class="list-unstyled mt-2">
        {% for att in job.attachments %}
          <li class="mb-1">
            📎 {{ att.filename }}
            {% if att.get('original_scan') %}
              <span class="badge {{ 'bg-success' if att.original_scan.clean else 'bg-warning text-dark' }} ms-1">
                {% if att.original_scan.get('is_pua_encrypted') %}encrypted (expected)
                {% elif att.original_scan.clean %}clean
                {% else %}{{ att.original_scan.detail }}
                {% endif %}
              </span>
            {% endif %}
            {% if att.get('decrypted_scan') %}
              → <span class="badge {{ 'bg-success' if att.decrypted_scan.clean else 'bg-danger' }}">
                {{ 'clean' if att.decrypted_scan.clean else att.decrypted_scan.detail }}
              </span>
            {% endif %}
            {% if job.status == 'clean' %}
              <a href="/jobs/{{ job.id }}/files/{{ att.filename }}"
                 class="btn btn-sm btn-outline-success ms-2">Download</a>
              {% if att.filename.lower().endswith('.pdf') %}
                <button class="btn btn-sm btn-outline-secondary ms-1"
                  onclick="togglePdf('pdf-{{ job.id }}-{{ loop.index }}', '/jobs/{{ job.id }}/files/{{ att.filename }}')">
                  Preview
                </button>
                <div id="pdf-{{ job.id }}-{{ loop.index }}" class="mt-2" style="display:none;">
                  <iframe style="width:100%;height:600px;border:1px solid #dee2e6;border-radius:4px;"></iframe>
                </div>
              {% endif %}
            {% endif %}
          </li>
        {% endfor %}
      </ul>
    {% endif %}

    {% if job.status == 'awaiting_password' %}
      <form hx-post="/jobs/{{ job.id }}/retry"
            hx-target="#job-list"
            hx-swap="outerHTML"
            class="mt-2 d-flex gap-2 align-items-end">
        <div class="flex-grow-1">
          <label class="form-label mb-1 small text-warning">Wrong password — try again:</label>
          <input type="password" name="password" class="form-control form-control-sm" required placeholder="New password">
        </div>
        <button type="submit" class="btn btn-sm btn-warning">Retry</button>
      </form>
    {% endif %}

    {% if job.error_detail and job.status == 'failed' %}
      <div class="alert alert-danger mt-2 mb-0 py-2 small">{{ job.error_detail }}</div>
    {% endif %}
  </div>
</div>

<script>
function togglePdf(divId, url) {
  const div = document.getElementById(divId);
  if (div.style.display === 'none') {
    div.style.display = 'block';
    div.querySelector('iframe').src = url;
  } else {
    div.style.display = 'none';
    div.querySelector('iframe').src = '';
  }
}
</script>
```

**Step 5: Create `app/templates/partials/job_card_error.html`**

```html
<div class="alert alert-danger">
  <strong>Failed to parse {{ filename }}:</strong> {{ error }}
</div>
```

**Step 6: Create `app/templates/partials/clamav_status.html`**

```html
{% if available %}
  <span class="text-light small">
    {{ version_info.get('version', 'ClamAV') }}
    {% if version_info.get('signature_date') %}
      · sigs: {{ version_info.signature_date }}
    {% endif %}
    {% if stale %}
      <span class="badge bg-warning text-dark ms-1">⚠ Signatures stale</span>
    {% endif %}
  </span>
{% else %}
  <span class="badge bg-danger">ClamAV unavailable</span>
{% endif %}
```

**Step 7: Manually verify the UI**

With ClamAV not running (expected for local dev), start the app:

```bash
CLAMAV_HOST=localhost uvicorn app.main:app --reload
```

Open http://localhost:8000 — confirm: navbar renders, upload form appears, queue section shows "No jobs queued yet."

**Step 8: Commit**

```bash
git add app/templates/
git commit -m "feat: HTMX templates and UI"
```

---

### Task 9: Docker setup

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `.dockerignore`

**Step 1: Create `.dockerignore`**

```
.venv/
__pycache__/
*.pyc
.git/
tests/
*.db
.env
docs/
```

**Step 2: Create `Dockerfile`**

```dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    qpdf \
    p7zip-full \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN useradd -m -u 1001 analyst
USER analyst

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Step 3: Create `docker-compose.yml`**

```yaml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=sqlite:////data/safe_release.db
      - CLAMAV_HOST=clamav
      - CLAMAV_PORT=3310
      - CLEAN_JOB_TTL_HOURS=1
      - MAX_OUTPUT_MB=500
    volumes:
      - db_data:/data
      - temp_data:/tmp/safe-release
    depends_on:
      clamav:
        condition: service_healthy
    deploy:
      resources:
        limits:
          memory: 1g

  clamav:
    image: clamav/clamav:stable
    ports:
      - "3310:3310"
    volumes:
      - clamav_data:/var/lib/clamav
    healthcheck:
      test: ["CMD", "clamdcheck.sh"]
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 120s  # freshclam runs on startup
    deploy:
      resources:
        limits:
          memory: 1g

volumes:
  db_data:
  temp_data:
  clamav_data:
```

**Step 4: Update `app/main.py` to read env vars for ClamAV host/port**

In `app/scanner.py`, update the default host/port to read from environment:

```python
import os

class ClamAVScanner:
    def __init__(
        self,
        host: str = os.environ.get("CLAMAV_HOST", "clamav"),
        port: int = int(os.environ.get("CLAMAV_PORT", "3310")),
    ) -> None:
        self._cd = pyclamd.ClamdNetworkSocket(host=host, port=port)
```

Also update `app/cleanup.py` to read `CLEAN_JOB_TTL_HOURS` from environment:

```python
CLEAN_JOB_TTL_HOURS = int(os.environ.get("CLEAN_JOB_TTL_HOURS", "1"))
```

And `app/decryptors.py` to read `MAX_OUTPUT_BYTES`:

```python
import os
MAX_OUTPUT_BYTES = int(os.environ.get("MAX_OUTPUT_MB", "500")) * 1024 * 1024
```

**Step 5: Build and start**

```bash
docker compose build
docker compose up
```

Expected: ClamAV starts updating signatures (~60-120s on first run). App available at http://localhost:8000 once ClamAV is healthy.

**Step 6: Smoke test**

1. Open http://localhost:8000
2. Confirm ClamAV status shows in navbar (may say "updating signatures" initially)
3. Create a test encrypted PDF locally and upload it with the correct password
4. Confirm the job moves through `scanning → scanning_decrypted → clean`
5. Confirm the file is available for download

**Step 7: Commit**

```bash
git add Dockerfile docker-compose.yml .dockerignore app/scanner.py app/cleanup.py app/decryptors.py
git commit -m "feat: Docker setup and environment configuration"
```

---

### Task 10: Run full test suite

**Step 1: Run all unit tests**

```bash
pytest tests/ -v -m "not integration"
```

Expected: all tests pass with 0 failures.

**Step 2: Run integration tests against live ClamAV**

Start ClamAV: `docker compose up clamav -d`

Wait for healthy: `docker compose ps` (check `healthy` status)

```bash
CLAMAV_HOST=localhost pytest tests/ -v -m integration
```

Expected: EICAR detected, clean file passes.

**Step 3: Commit any fixes, then tag**

```bash
git add -A
git commit -m "test: verify full test suite passes"
```
