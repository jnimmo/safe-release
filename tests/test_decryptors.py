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
