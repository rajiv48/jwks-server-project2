
"""RSA key generation, SQLite-backed storage, and JWK serialization."""

from __future__ import annotations

import base64
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537
DEFAULT_KEY_LIFETIME = timedelta(hours=1)

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


def _b64url_uint(value: int) -> str:
    """Encode an integer as unpadded Base64URL."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class KeyRecord:
    """RSA private key with its identifier and expiration time."""

    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        """Check whether the key has expired."""
        return self.expires_at <= now

    def to_jwk(self) -> dict[str, str]:
        """Convert the RSA public key into JWK format."""
        numbers = self.private_key.public_key().public_numbers()

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


def generate_key(expires_at: datetime) -> KeyRecord:
    """Generate a new RSA-2048 private key."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
    )

    return KeyRecord(
        kid=uuid.uuid4().hex,
        private_key=private_key,
        expires_at=expires_at,
    )


class KeyStore:
    """Manage RSA private keys stored persistently in SQLite."""

    def __init__(
        self,
        lifetime: timedelta = DEFAULT_KEY_LIFETIME,
        clock: Clock = utcnow,
        db_path: str | Path = "totally_not_my_privateKeys.db",
    ) -> None:
        """Initialize the database and ensure valid/expired keys exist."""
        from jwks_server.database import (
            load_keys,
            open_database,
            save_key,
        )

        self._lifetime = lifetime
        self._clock = clock
        self._lock = threading.Lock()
        self._db_path = db_path

        with open_database(self._db_path) as connection:
            now = self._clock()

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

            if not expired_keys:
                expired_record = generate_key(
                    now - lifetime
                )
                save_key(connection, expired_record)

            if not valid_keys:
                valid_record = generate_key(
                    now + lifetime + timedelta(seconds=2)
                )
                save_key(connection, valid_record)

    def now(self) -> datetime:
        """Return the current time."""
        return self._clock()

    def unexpired_keys(self) -> list[KeyRecord]:
        """Retrieve all valid RSA keys from SQLite."""
        from jwks_server.database import (
            load_keys,
            open_database,
            save_key,
        )

        with self._lock:
            with open_database(self._db_path) as connection:
                now = self._clock()

                valid_keys = load_keys(
                    connection,
                    expired=False,
                    now=now,
                )

                if not valid_keys:
                    new_record = generate_key(
                        now + self._lifetime + timedelta(seconds=2)
                    )
                    save_key(connection, new_record)

                    valid_keys = load_keys(
                        connection,
                        expired=False,
                        now=now,
                    )

                return valid_keys

    def active_key(self) -> KeyRecord:
        """Return the valid RSA key with the latest expiration."""
        valid_keys = self.unexpired_keys()

        return max(
            valid_keys,
            key=lambda key: key.expires_at,
        )

    def expired_key(self) -> KeyRecord:
        """Retrieve the most recently expired RSA key."""
        from jwks_server.database import (
            load_keys,
            open_database,
        )

        with self._lock:
            with open_database(self._db_path) as connection:
                expired_keys = load_keys(
                    connection,
                    expired=True,
                    now=self._clock(),
                )

                return max(
                    expired_keys,
                    key=lambda key: key.expires_at,
                )
