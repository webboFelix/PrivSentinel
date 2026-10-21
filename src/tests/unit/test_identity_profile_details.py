from datetime import UTC, datetime

import numpy as np
import pytest

from src.storage.database import SQLiteDatabase
from src.storage.repositories.identity_repository import IdentityRepository


class _SecretStore:
    def __init__(self):
        self.values = {}

    def get(self, name):
        return self.values.get(name)

    def set(self, name, value):
        self.values[name] = value

    def delete(self, name):
        return self.values.pop(name, None) is not None


def test_optional_enrollment_details_are_loaded_from_secret_store(tmp_path):
    secrets = _SecretStore()
    repository = IdentityRepository(
        SQLiteDatabase(tmp_path / "local.sqlite3"), secrets
    )

    profile = repository.enroll(
        "Ada Lovelace",
        np.arange(1, 33, dtype=np.float32),
        "test-model",
        datetime.now(UTC),
        {
            "email": "ada@example.com",
            "department": "Research",
            "employee_id": "E-123",
            "machine_user": "ada",
        },
    )

    assert profile.email == "ada@example.com"
    assert profile.department == "Research"
    assert profile.employee_id == "E-123"
    assert profile.machine_user == "ada"
    assert repository.profile() == profile
    assert "identity-profile" in secrets.values


def test_enrollment_rejects_invalid_optional_email_before_writing(tmp_path):
    secrets = _SecretStore()
    repository = IdentityRepository(
        SQLiteDatabase(tmp_path / "local.sqlite3"), secrets
    )

    with pytest.raises(ValueError, match="valid email"):
        repository.enroll(
            "Ada Lovelace",
            np.arange(1, 33, dtype=np.float32),
            "test-model",
            datetime.now(UTC),
            {"email": "not-an-email"},
        )

    assert repository.profile() is None
    assert secrets.values == {}


def test_deleting_enrollment_removes_protected_profile_details(tmp_path):
    secrets = _SecretStore()
    repository = IdentityRepository(
        SQLiteDatabase(tmp_path / "local.sqlite3"), secrets
    )
    repository.enroll(
        "Ada Lovelace",
        np.arange(1, 33, dtype=np.float32),
        "test-model",
        datetime.now(UTC),
        {"department": "Research"},
    )

    assert repository.delete_profile()
    assert secrets.values == {}
