
"""Tests for SQLite database creation, key storage, and expiration filtering."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from jwks_server.database import connect, load_keys, open_database, save_key
from jwks_server.keys import generate_key


def test_database_creates_required_schema(tmp_path: Path):
    """Verify that the SQLite database has the required keys table."""
    db_path = tmp_path / "totally_not_my_privateKeys.db"

    connection = connect(db_path)

    try:
        assert db_path.exists()

        columns = connection.execute("PRAGMA table_info(keys)").fetchall()

        assert [column[1] for column in columns] == [
            "kid",
            "key",
            "exp",
        ]

        assert columns[0][2].upper() == "INTEGER"
        assert columns[0][5] == 1

        assert columns[1][2].upper() == "BLOB"
        assert columns[1][3] == 1

        assert columns[2][2].upper() == "INTEGER"
        assert columns[2][3] == 1
    finally:
        connection.close()


def test_save_key_stores_private_key_as_pem(tmp_path: Path):
    """Verify RSA private keys are serialized and saved in SQLite."""
    db_path = tmp_path / "keys.db"
    expiry = datetime.now(UTC) + timedelta(hours=2)

    record = generate_key(expiry)

    with open_database(db_path) as connection:
        kid = save_key(connection, record)

        row = connection.execute(
            "SELECT kid, key, exp FROM keys WHERE kid = ?",
            (kid,),
        ).fetchone()

        assert row is not None

        stored_kid, pem, stored_exp = row

        assert stored_kid == kid
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        assert stored_exp == int(expiry.timestamp())

        restored_key = serialization.load_pem_private_key(
            pem,
            password=None,
        )

        assert (
            restored_key.public_key().public_numbers()
            == record.private_key.public_key().public_numbers()
        )


def test_load_keys_filters_expired_and_valid(tmp_path: Path):
    """Verify expired and valid keys are loaded separately."""
    db_path = tmp_path / "keys.db"
    now = datetime.now(UTC).replace(microsecond=0)

    expired_record = generate_key(now - timedelta(hours=1))
    valid_record = generate_key(now + timedelta(hours=2))

    with open_database(db_path) as connection:
        expired_kid = save_key(connection, expired_record)
        valid_kid = save_key(connection, valid_record)

        expired_keys = load_keys(
            connection,
            expired=True,
            now=now,
        )

        valid_keys = load_keys(
            connection,
            expired=False,
            now=now,
        )

        assert len(expired_keys) == 1
        assert len(valid_keys) == 1

        assert expired_keys[0].kid == str(expired_kid)
        assert valid_keys[0].kid == str(valid_kid)

        assert expired_keys[0].is_expired(now)
        assert not valid_keys[0].is_expired(now)


def test_database_persists_after_connection_closes(tmp_path: Path):
    """Verify saved keys remain available after reconnecting."""
    db_path = tmp_path / "persistent.db"
    now = datetime.now(UTC).replace(microsecond=0)

    record = generate_key(now + timedelta(hours=2))

    with open_database(db_path) as connection:
        saved_kid = save_key(connection, record)

    with open_database(db_path) as connection:
        loaded_keys = load_keys(
            connection,
            expired=False,
            now=now,
        )

        assert len(loaded_keys) == 1
        assert loaded_keys[0].kid == str(saved_kid)

        assert (
            loaded_keys[0].private_key.public_key().public_numbers()
            == record.private_key.public_key().public_numbers()
        )


def test_database_uses_auto_increment_ids(tmp_path: Path):
    """Verify SQLite assigns unique, increasing integer key IDs."""
    db_path = tmp_path / "keys.db"
    expiry = datetime.now(UTC) + timedelta(hours=2)

    with open_database(db_path) as connection:
        first_id = save_key(connection, generate_key(expiry))
        second_id = save_key(connection, generate_key(expiry))

        assert isinstance(first_id, int)
        assert isinstance(second_id, int)
        assert second_id > first_id


def test_open_database_closes_connection(tmp_path: Path):
    """Verify the database context manager closes its connection."""
    db_path = tmp_path / "keys.db"

    with open_database(db_path) as connection:
        connection.execute("SELECT 1")

    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        pass
    else:
        raise AssertionError("Database connection was not closed")
