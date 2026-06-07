"""Shared test fixtures."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture()
def tmp_data_dir(tmp_path: Path) -> Path:
    """Provide a temporary data directory and set NETMAPPER_DATA_DIR."""
    data_dir = tmp_path / "netmapper_test"
    data_dir.mkdir()
    with patch.dict(os.environ, {"NETMAPPER_DATA_DIR": str(data_dir)}):
        yield data_dir


@pytest.fixture()
def db_path(tmp_data_dir: Path) -> Path:
    """Provide an initialized test database."""
    from db.schema import init_db

    path = tmp_data_dir / "netmapper.db"
    init_db(path)
    return path


@pytest.fixture()
def app_config(db_path: Path):
    """Provide an AppConfig instance backed by the test database."""
    from config import AppConfig

    return AppConfig(db_path)


@pytest.fixture()
def test_client(tmp_data_dir: Path, db_path: Path) -> TestClient:
    """Provide a FastAPI TestClient with a test database and mocked OUI resolver."""
    from unittest.mock import MagicMock

    from main import app

    # Pre-populate app state so lifespan doesn't download OUI
    from config import AppConfig

    app.state.db_path = str(db_path)
    app.state.config = AppConfig(db_path)
    app.state.scan_queues = {}

    mock_resolver = MagicMock()
    mock_resolver.entry_count = 0
    mock_resolver.lookup.return_value = None
    app.state.oui_resolver = mock_resolver
    app.state.cve_index = None
    app.state.cve_downloading = False
    app.state.cve_download_progress = None

    return TestClient(app, raise_server_exceptions=True)
