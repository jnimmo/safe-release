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
    monkeypatch.setattr("app.database.SessionLocal", TestSession)
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
