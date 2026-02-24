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
