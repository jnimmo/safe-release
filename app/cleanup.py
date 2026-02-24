import asyncio
import os
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

TEMP_BASE = Path("/tmp/safe-release")
CLEAN_JOB_TTL_HOURS = int(os.environ.get("CLEAN_JOB_TTL_HOURS", "1"))


def wipe_temp_dir() -> None:
    """Called at startup — wipe all temp files from previous sessions."""
    if TEMP_BASE.exists():
        try:
            shutil.rmtree(TEMP_BASE)
        except PermissionError:
            pass
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
