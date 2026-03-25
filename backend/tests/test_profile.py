"""Tests for scanner/profile.py — scan profile definitions."""

import pytest

from scanner.profile import PROFILES, get_profile


def test_get_profile_quick() -> None:
    p = get_profile("quick")
    assert p.name == "quick"
    assert p.arp_only is False
    assert p.top_ports == 100
    assert p.os_detection is False
    assert p.version_detection is False
    assert "-T3" in p.nmap_args


def test_get_profile_standard() -> None:
    p = get_profile("standard")
    assert p.version_detection is True
    assert p.os_detection is False
    assert p.top_ports == 1000
    assert "-sV" in p.nmap_args


def test_get_profile_deep() -> None:
    p = get_profile("deep")
    assert p.os_detection is True
    assert p.version_detection is True
    assert p.top_ports is None
    assert "-O" in p.nmap_args


def test_get_profile_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unknown scan profile"):
        get_profile("nonexistent")


def test_profiles_dict_has_three_entries() -> None:
    assert set(PROFILES.keys()) == {"quick", "standard", "deep"}
