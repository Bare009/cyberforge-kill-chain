"""Shared test setup."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(scope="session", autouse=True)
def _schemas_dir(tmp_path_factory):
    """Mappings the schema stage saves (python -m killchain run / schema in a subprocess) go to a temporary
    folder, not the repo's config/schemas."""
    old = os.environ.get("KILLCHAIN_SCHEMAS_DIR")
    os.environ["KILLCHAIN_SCHEMAS_DIR"] = str(tmp_path_factory.mktemp("schemas"))
    yield
    if old is None:
        os.environ.pop("KILLCHAIN_SCHEMAS_DIR", None)
    else:
        os.environ["KILLCHAIN_SCHEMAS_DIR"] = old
