import base64
import sqlite3
from datetime import UTC, datetime
from io import BytesIO

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
            "phone": "+1 (555) 123-4567",
            "profile_image": base64.b64encode(
                b"encrypted profile photo"
            ).decode("ascii"),
            "department": "Research",
            "employee_id": "E-123",
            "machine_user": "ada",
        },
        enrollment_quality=0.91,
    )

    assert profile.email == "ada@example.com"
    assert profile.phone == "+1 (555) 123-4567"
    assert profile.profile_image == base64.b64encode(
        b"encrypted profile photo"
    ).decode("ascii")
    assert profile.department == "Research"
    assert profile.employee_id == "E-123"
    assert profile.machine_user == "ada"
    assert profile.enrollment_quality == 0.91
    assert repository.profile() == profile
    assert repository.templates().shape == (1, 32)
    assert "identity-profile" in secrets.values


def test_two_pose_templates_are_encrypted_and_loaded_normalized(tmp_path):
    secrets = _SecretStore()
    repository = IdentityRepository(
        SQLiteDatabase(tmp_path / "local.sqlite3"), secrets
    )
    templates = np.stack(
        [
            np.arange(1, 33, dtype=np.float32),
            np.arange(32, 0, -1, dtype=np.float32),
        ]
    )

    profile = repository.enroll(
        "Ada Lovelace",
        templates,
        "test-model",
        datetime.now(UTC),
    )

    loaded = repository.templates()
    assert loaded is not None
    assert loaded.shape == (2, 32)
    assert np.allclose(np.linalg.norm(loaded, axis=1), 1.0)
    assert profile.template_dimensions == 32
    assert repository.template().shape == (32,)


def test_legacy_single_template_remains_usable(tmp_path):
    secrets = _SecretStore()
    repository = IdentityRepository(
        SQLiteDatabase(tmp_path / "local.sqlite3"), secrets
    )
    legacy_stream = BytesIO()
    np.save(legacy_stream, np.ones(32, dtype=np.float32), allow_pickle=False)
    secrets.set("face-template", legacy_stream.getvalue())

    templates = repository.templates()

    assert templates is not None
    assert templates.shape == (1, 32)
    assert np.allclose(np.linalg.norm(templates, axis=1), 1.0)


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


@pytest.mark.parametrize(
    ("details", "message"),
    [
        ({"phone": "call me"}, "valid phone"),
        ({"profile_image": "not base64!"}, "Profile image data is invalid"),
    ],
)
def test_enrollment_rejects_invalid_contact_or_image_data(tmp_path, details, message):
    secrets = _SecretStore()
    repository = IdentityRepository(
        SQLiteDatabase(tmp_path / "local.sqlite3"), secrets
    )

    with pytest.raises(ValueError, match=message):
        repository.enroll(
            "Ada Lovelace",
            np.arange(1, 33, dtype=np.float32),
            "test-model",
            datetime.now(UTC),
            details,
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


def test_existing_identity_profile_schema_is_migrated(tmp_path):
    database_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE identity_profile (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                display_name TEXT NOT NULL,
                enrolled_at TEXT NOT NULL,
                model_name TEXT NOT NULL,
                template_dimensions INTEGER NOT NULL,
                consent_recorded_at TEXT NOT NULL
            )
            """
        )

    database = SQLiteDatabase(database_path)

    columns = {
        row["name"] for row in database.fetchall("PRAGMA table_info(identity_profile)")
    }
    assert "enrollment_quality" in columns
