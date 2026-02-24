from email.parser import BytesParser
from email import policy
from pathlib import Path


class EmlParseError(Exception):
    pass


def parse_eml(eml_path: Path, dest_dir: Path) -> dict:
    """
    Parse an EML file, save attachments to dest_dir, return metadata dict.

    Returns:
        {
            "subject": str,
            "from_address": str,
            "message_id": str,
            "attachments": [{"filename": str, "path": str, "content_type": str}]
        }

    Raises:
        EmlParseError: if the file does not exist.
    """
    if not eml_path.exists():
        raise EmlParseError(f"EML file not found: {eml_path}")

    dest_dir.mkdir(parents=True, exist_ok=True)

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    result = {
        "subject": str(msg.get("Subject", "") or ""),
        "from_address": str(msg.get("From", "") or ""),
        "message_id": str(msg.get("Message-ID", "") or ""),
        "attachments": [],
    }

    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        filename = part.get_filename()
        if not filename:
            continue
        # Sanitise filename — strip any path components
        safe_name = Path(filename).name
        dest_path = dest_dir / safe_name
        payload = part.get_payload(decode=True)
        if payload:
            dest_path.write_bytes(payload)
            result["attachments"].append(
                {
                    "filename": safe_name,
                    "path": str(dest_path),
                    "content_type": part.get_content_type(),
                }
            )

    return result
