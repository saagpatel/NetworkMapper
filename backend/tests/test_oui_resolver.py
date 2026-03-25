"""Tests for oui/resolver.py — OUI lookup and MAC normalization."""

from pathlib import Path
from unittest.mock import patch, MagicMock

from oui.resolver import OUIResolver

FIXTURE_CSV = """\
Registry,Assignment,Organization Name,Organization Address
MA-L,001A2B,Ayecom Technology Co. Ltd.,"Some Address"
MA-L,AABBCC,Test Vendor Inc.,"123 Test St"
MA-L,112233,Another Corp.,"456 Another Ave"
"""


def _create_resolver_with_fixture(data_dir: Path) -> OUIResolver:
    """Create an OUIResolver with a fixture CSV instead of downloading."""
    oui_path = data_dir / "oui.csv"
    oui_path.write_text(FIXTURE_CSV, encoding="utf-8")
    return OUIResolver(data_dir)


def test_lookup_known_prefix(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.lookup("00:1A:2B:DD:EE:FF") == "Ayecom Technology Co. Ltd."


def test_lookup_unknown_prefix(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.lookup("FF:FF:FF:DD:EE:FF") is None


def test_lookup_case_insensitive(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.lookup("aa:bb:cc:dd:ee:ff") == "Test Vendor Inc."


def test_lookup_dash_delimited(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.lookup("11-22-33-DD-EE-FF") == "Another Corp."


def test_lookup_dot_delimited(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.lookup("001A.2BDD.EEFF") == "Ayecom Technology Co. Ltd."


def test_lookup_no_delimiter(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.lookup("AABBCCDDEEFF") == "Test Vendor Inc."


def test_entry_count(tmp_path: Path) -> None:
    resolver = _create_resolver_with_fixture(tmp_path)
    assert resolver.entry_count == 3


def test_download_on_first_run(tmp_path: Path) -> None:
    """If no OUI CSV exists, resolver should attempt to download it."""
    mock_response = MagicMock()
    mock_response.iter_content.return_value = [FIXTURE_CSV.encode("utf-8")]
    mock_response.raise_for_status.return_value = None

    with patch("oui.resolver.requests.get", return_value=mock_response) as mock_get:
        resolver = OUIResolver(tmp_path)
        mock_get.assert_called_once()
        assert resolver.entry_count == 3


def test_graceful_failure_on_download_error(tmp_path: Path) -> None:
    """If download fails, resolver should still work with an empty table."""
    import requests

    with patch("oui.resolver.requests.get", side_effect=requests.RequestException("Network error")):
        resolver = OUIResolver(tmp_path)
        assert resolver.entry_count == 0
        assert resolver.lookup("00:1A:2B:DD:EE:FF") is None
