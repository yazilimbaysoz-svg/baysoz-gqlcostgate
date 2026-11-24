"""Baysöz Labs <baysozlabs@proton.me> — shared deterministic test fixtures."""

from pathlib import Path

import pytest

from gqlcostgate.policy import default_policy, load_policy
from gqlcostgate.schema import load_schema

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def policy():
    return default_policy()


@pytest.fixture
def strict_policy():
    return load_policy(FIXTURES / "policy.json")


@pytest.fixture
def schema():
    return load_schema(FIXTURES / "schema.graphql")
