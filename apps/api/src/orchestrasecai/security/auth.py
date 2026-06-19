from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import JWTError, jwt

from orchestrasecai.config import get_settings

_ph = PasswordHasher()
_settings = get_settings()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        _ph.verify(password_hash, password)
        if _ph.check_needs_rehash(password_hash):
            return True
        return True
    except VerifyMismatchError:
        return False


def create_access_token(subject: str, org_id: str, role: str, extra: dict | None = None) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=_settings.jwt_access_expire_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "org_id": org_id,
        "role": role,
        "type": "access",
        "exp": expire,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _settings.jwt_secret, algorithm=ALGORITHM)


def create_refresh_token(subject: str) -> str:
    expire = datetime.now(UTC) + timedelta(days=_settings.jwt_refresh_expire_days)
    payload = {"sub": subject, "type": "refresh", "exp": expire}
    return jwt.encode(payload, _settings.jwt_secret, algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, _settings.jwt_secret, algorithms=[ALGORITHM])


def parse_uuid(value: str) -> UUID:
    return UUID(value)
