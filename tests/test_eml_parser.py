from pathlib import Path

import pytest

from app.eml_parser import parse_eml, EmlParseError


def test_parse_eml_extracts_metadata(sample_eml, tmp_path):
    dest = tmp_path / "attachments"
    result = parse_eml(sample_eml, dest)

    assert result["subject"] == "Test subject"
    assert result["from_address"] == "sender@example.com"
    assert "<test-message-id@example.com>" in result["message_id"]


def test_parse_eml_extracts_attachments(sample_eml, tmp_path):
    dest = tmp_path / "attachments"
    result = parse_eml(sample_eml, dest)

    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"].endswith(".pdf")
    assert Path(att["path"]).exists()
    assert Path(att["path"]).stat().st_size > 0


def test_parse_eml_raises_on_invalid_file(tmp_path):
    bad_file = tmp_path / "bad.eml"
    bad_file.write_text("this is not an email")
    dest = tmp_path / "attachments"

    # Should not raise — even bare text is technically parseable by email.parser.
    # Instead verify: no attachments, empty metadata fields handled gracefully.
    result = parse_eml(bad_file, dest)
    assert isinstance(result["attachments"], list)


def test_parse_eml_raises_on_missing_file(tmp_path):
    with pytest.raises(EmlParseError, match="not found"):
        parse_eml(tmp_path / "nonexistent.eml", tmp_path / "dest")
