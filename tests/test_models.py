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
