from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner import ClamAVScanner, ScanResult, ClamAVUnavailableError


# --- Unit tests (mocked) ---

@pytest.fixture()
def mock_cd():
    with patch("app.scanner.pyclamd.ClamdNetworkSocket") as mock_cls:
        yield mock_cls.return_value


def test_scan_clean_file(mock_cd, tmp_path):
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("hello")
    mock_cd.scan_file.return_value = None

    scanner = ClamAVScanner()
    result = scanner.scan_file(clean_file)

    assert result.clean is True
    assert result.detail == ""


def test_scan_infected_file(mock_cd, tmp_path):
    bad_file = tmp_path / "bad.txt"
    bad_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")
    mock_cd.scan_file.return_value = {str(bad_file): ("FOUND", "Eicar-Signature")}

    scanner = ClamAVScanner()
    result = scanner.scan_file(bad_file)

    assert result.clean is False
    assert "Eicar" in result.detail


def test_scan_encrypted_file_returns_pua(mock_cd, tmp_path):
    enc_file = tmp_path / "enc.zip"
    enc_file.write_bytes(b"\x00" * 10)
    mock_cd.scan_file.return_value = {str(enc_file): ("FOUND", "PUA.Encrypted.ZIP")}

    scanner = ClamAVScanner()
    result = scanner.scan_file(enc_file)

    assert result.clean is False
    assert result.is_pua_encrypted is True


def test_get_version_info_parses_correctly(mock_cd):
    mock_cd.version.return_value = "ClamAV 1.3.1/27437/Thu Oct 24 07:53:47 2024"

    scanner = ClamAVScanner()
    info = scanner.get_version_info()

    assert info["version"] == "ClamAV 1.3.1"
    assert info["signature_version"] == "27437"
    assert "2024" in info["signature_date"]


def test_is_available_returns_false_when_ping_fails(mock_cd):
    mock_cd.ping.side_effect = Exception("connection refused")

    scanner = ClamAVScanner()
    assert scanner.is_available() is False


def test_scan_raises_on_clamav_error(mock_cd, tmp_path):
    f = tmp_path / "file.bin"
    f.write_bytes(b"\x00")
    mock_cd.scan_file.return_value = {str(f): ("ERROR", "permission denied")}

    scanner = ClamAVScanner()
    with pytest.raises(ClamAVUnavailableError):
        scanner.scan_file(f)


# --- Integration tests (require live ClamAV) ---

@pytest.mark.integration
def test_integration_scan_eicar(tmp_path):
    eicar = tmp_path / "eicar.txt"
    eicar.write_text(
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    scanner = ClamAVScanner()
    result = scanner.scan_file(eicar)
    assert result.clean is False


@pytest.mark.integration
def test_integration_scan_clean(tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("harmless content")
    scanner = ClamAVScanner()
    result = scanner.scan_file(clean)
    assert result.clean is True
