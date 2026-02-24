import os
import subprocess
from pathlib import Path

import msoffcrypto
import msoffcrypto.exceptions

MAX_OUTPUT_BYTES = int(os.environ.get("MAX_OUTPUT_MB", "500")) * 1024 * 1024


class WrongPasswordError(Exception):
    pass


class DecryptionError(Exception):
    pass


def decrypt_pdf(encrypted_path: Path, password: str, output_path: Path) -> None:
    """
    Decrypt a password-protected PDF using qpdf CLI.
    Raises WrongPasswordError on bad password, DecryptionError on other failures.
    """
    result = subprocess.run(
        ["qpdf", f"--password={password}", "--decrypt", str(encrypted_path), str(output_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr_lower = result.stderr.lower()
        if "invalid password" in stderr_lower or "wrong password" in stderr_lower:
            raise WrongPasswordError(f"Wrong password for {encrypted_path.name}")
        raise DecryptionError(f"qpdf failed for {encrypted_path.name}: {result.stderr.strip()}")


def extract_zip(encrypted_path: Path, password: str, output_dir: Path) -> list[Path]:
    """
    Extract a password-protected ZIP using 7z CLI.
    Checks total extracted size against MAX_OUTPUT_BYTES.
    Returns list of extracted file paths.
    Raises WrongPasswordError on bad password, DecryptionError on other failures.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["7z", "x", f"-p{password}", str(encrypted_path), f"-o{output_dir}", "-y"],
        capture_output=True,
        text=True,
    )
    combined = (result.stdout + result.stderr).lower()
    if result.returncode != 0:
        if "wrong password" in combined or "bad password" in combined or "incorrect password" in combined:
            raise WrongPasswordError(f"Wrong password for {encrypted_path.name}")
        raise DecryptionError(f"7z failed for {encrypted_path.name}: {result.stdout.strip()}")

    extracted = [p for p in output_dir.rglob("*") if p.is_file()]
    total_size = sum(p.stat().st_size for p in extracted)
    if total_size > MAX_OUTPUT_BYTES:
        for p in extracted:
            p.unlink(missing_ok=True)
        raise DecryptionError(
            f"Extracted content for {encrypted_path.name} exceeds size limit "
            f"({total_size // (1024**2)} MB > {MAX_OUTPUT_BYTES // (1024**2)} MB)"
        )

    return extracted


def decrypt_office(encrypted_path: Path, password: str, output_path: Path) -> None:
    """
    Decrypt a password-protected Office document (.docx/.xlsx/.pptx) using msoffcrypto-tool.
    Raises WrongPasswordError on bad password, DecryptionError on other failures.
    """
    try:
        with open(encrypted_path, "rb") as enc_file:
            office_file = msoffcrypto.OfficeFile(enc_file)
            office_file.load_key(password=password)
            with open(output_path, "wb") as out_file:
                office_file.decrypt(out_file)
    except msoffcrypto.exceptions.InvalidKeyError:
        raise WrongPasswordError(f"Wrong password for {encrypted_path.name}")
    except Exception as exc:
        raise DecryptionError(f"msoffcrypto failed for {encrypted_path.name}: {exc}") from exc
