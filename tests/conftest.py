"""Shared test helpers: build a disposable config tree from fixtures."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

# Flat package layout: mcpsec/ is in the repo root, not under src/.
sys.path.insert(0, str(Path(__file__).parent.parent))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def config_root(tmp_path: Path) -> Path:
    """Empty root for scans (CLI + per-check tests share it)."""
    return tmp_path / "configs"


def install(repo_root: Path, rel_path: str, fixture_name: str) -> Path:
    """Copy one fixture file into the config tree at rel_path."""
    dest = repo_root / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / fixture_name, dest)
    return dest


def ff() -> Path:
    return FIXTURES


def nf(name: str) -> str:
    """Fixture filename helper."""
    return name
