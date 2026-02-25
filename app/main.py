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
    return templates.TemplateResponse(request, "index.html")


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
        try:
            tmp_eml.parent.mkdir(parents=True, exist_ok=True)
            tmp_eml.write_bytes(raw)
        except PermissionError as exc:
            return templates.TemplateResponse(
                request,
                "partials/job_card_error.html",
                {"filename": eml_file.filename, "error": f"Server storage error: {exc}"},
            )

        try:
            metadata = parse_eml(tmp_eml, TEMP_BASE / "staging")
        except EmlParseError as exc:
            # Return error card HTML
            return templates.TemplateResponse(
                request,
                "partials/job_card_error.html",
                {"filename": eml_file.filename, "error": str(exc)},
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

        jobs = db.query(Job).order_by(Job.created_at.desc()).all()
        return templates.TemplateResponse(
            request, "partials/job_list.html", {"jobs": jobs}
        )

    finally:
        db.close()


@app.post("/jobs/{job_id}/retry")
async def retry_password(request: Request, job_id: str, password: str = Form(...)):
    db = get_db()
    try:
        job = db.get(Job, job_id)
        if job and job.status == "awaiting_password":
            job.password = password
            job.status = "queued"
            job.error_detail = None
            db.commit()
        jobs = db.query(Job).order_by(Job.created_at.desc()).all()
        return templates.TemplateResponse(
            request, "partials/job_list.html", {"jobs": jobs}
        )
    finally:
        db.close()


@app.get("/partials/jobs", response_class=HTMLResponse)
async def jobs_partial(request: Request):
    db = get_db()
    try:
        jobs = db.query(Job).order_by(Job.created_at.desc()).all()
        return templates.TemplateResponse(
            request, "partials/job_list.html", {"jobs": jobs}
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
        request,
        "partials/clamav_status.html",
        {"available": available, "version_info": version_info, "stale": stale},
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
