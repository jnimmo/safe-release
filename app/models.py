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
