
"""SQLite database operations for persistent RSA private key storage."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from jwks_server.keys import KeyRecord

DB_PATH = Path("totally_not_my_privateKeys.db")


def connect(db_path: str | Path = DB_PATH) -> sqlite3.Connection:
    """Connect to SQLite and create the keys table if it doesn't exist."""
    connection = sqlite3.connect(db_path)

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        connection.commit()
        return connection
    except Exception:
        connection.close()
        raise


@contextmanager
def open_database(
    db_path: str | Path = DB_PATH,
) -> Iterator[sqlite3.Connection]:
    """Manage a database connection and close it after use."""
    connection = connect(db_path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def save_key(
    connection: sqlite3.Connection,
    record: KeyRecord,
) -> int:
    """Serialize an RSA private key and save it to SQLite."""
    pem = record.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cursor = connection.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (pem, int(record.expires_at.timestamp())),
    )
    connection.commit()

    return int(cursor.lastrowid)


def load_keys(
    connection: sqlite3.Connection,
    *,
    expired: bool,
    now: datetime | None = None,
) -> list[KeyRecord]:
    """Retrieve expired or unexpired RSA keys from SQLite."""
    if now is None:
        now = datetime.now(UTC)

    timestamp = now.timestamp()

    if expired:
        rows = connection.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp <= ?
            ORDER BY exp DESC
            """,
            (timestamp,),
        ).fetchall()
    else:
        rows = connection.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp > ?
            ORDER BY exp DESC
            """,
            (timestamp,),
        ).fetchall()

    records = []

    for kid, pem, exp in rows:
        private_key = serialization.load_pem_private_key(
            pem,
            password=None,
        )

        records.append(
            KeyRecord(
                kid=str(kid),
                private_key=private_key,
                expires_at=datetime.fromtimestamp(exp, UTC),
            )
        )

    return records
