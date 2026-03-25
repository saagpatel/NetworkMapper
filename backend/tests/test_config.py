"""Tests for config.py — AppConfig and data directory management."""

import json
from pathlib import Path

from config import AppConfig
from db.schema import init_db


def test_default_whitelist_seeded(db_path: Path) -> None:
    config = AppConfig(db_path)
    assert config.whitelist_cidrs == ["192.168.1.0/24"]


def test_get_returns_none_for_unknown_key(db_path: Path) -> None:
    config = AppConfig(db_path)
    assert config.get("nonexistent_key") is None


def test_set_and_get_roundtrip(db_path: Path) -> None:
    config = AppConfig(db_path)
    config.set("test_key", "test_value")
    assert config.get("test_key") == "test_value"


def test_set_overwrites_existing(db_path: Path) -> None:
    config = AppConfig(db_path)
    config.set("test_key", "first")
    config.set("test_key", "second")
    assert config.get("test_key") == "second"


def test_whitelist_cidrs_property(db_path: Path) -> None:
    config = AppConfig(db_path)
    config.set("whitelist_cidrs", json.dumps(["10.0.0.0/8", "172.16.0.0/12"]))
    assert config.whitelist_cidrs == ["10.0.0.0/8", "172.16.0.0/12"]


def test_nvd_download_complete_default(db_path: Path) -> None:
    config = AppConfig(db_path)
    assert config.nvd_download_complete is False


def test_nvd_download_complete_set(db_path: Path) -> None:
    config = AppConfig(db_path)
    config.set("nvd_download_complete", "1")
    assert config.nvd_download_complete is True


def test_schedule_cron_default_none(db_path: Path) -> None:
    config = AppConfig(db_path)
    assert config.schedule_cron is None


def test_nvd_last_updated_default_none(db_path: Path) -> None:
    config = AppConfig(db_path)
    assert config.nvd_last_updated is None


def test_seed_defaults_idempotent(db_path: Path) -> None:
    config = AppConfig(db_path)
    config.set("whitelist_cidrs", json.dumps(["10.0.0.0/8"]))
    # Re-creating AppConfig should NOT overwrite existing values
    config2 = AppConfig(db_path)
    assert config2.whitelist_cidrs == ["10.0.0.0/8"]
