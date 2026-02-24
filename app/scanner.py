import os
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
        host: str = os.environ.get("CLAMAV_HOST", "clamav"),
        port: int = int(os.environ.get("CLAMAV_PORT", "3310")),
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
