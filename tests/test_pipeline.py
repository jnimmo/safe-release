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
