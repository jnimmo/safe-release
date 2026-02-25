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
        if att.get("decryption_done"):
            continue  # already processed in a previous attempt

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
            att["decryption_done"] = True
        except WrongPasswordError:
            wrong_password_files.append(att["filename"])
        except DecryptionError as exc:
            att["decrypted_scan"] = {"clean": False, "detail": str(exc)}
            att["decryption_done"] = True  # error is final, don't retry

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

    for att in attachments:
        original_path = original_dir / att["filename"]
        suffix = original_path.suffix.lower() if original_path.exists() else ""
        decrypted_path = decrypted_dir / att["filename"]

        # ZIPs are extracted to decrypted_dir; other types produce a single output file
        if suffix == ".zip":
            files_to_scan = [p for p in decrypted_dir.rglob("*") if p.is_file()]
        else:
            files_to_scan = [decrypted_path]

        for scan_path in files_to_scan:
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
