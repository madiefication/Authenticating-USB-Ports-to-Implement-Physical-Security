"""Local application-level password authentication.

This is a defense-in-depth access-control layer for *who* is allowed to
operate this tool, layered on top of (not a replacement for) the Windows
Administrator privilege check in core.registry.is_admin(). Anyone with
local admin rights can still bypass it by editing the registry directly,
running a different tool, or deleting config/auth.json to reset it. It
exists to slow down casual misuse of this specific tool, not to provide a
real multi-user security boundary.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path

from core import audit

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
AUTH_FILE = CONFIG_DIR / "auth.json"

PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16


class AuthError(Exception):
    """Raised for authentication configuration or verification failures."""


def is_configured():
    """Return True if an application password has already been set up."""
    return AUTH_FILE.exists()


def _hash_password(password, salt, iterations=PBKDF2_ITERATIONS):
    """Derive a PBKDF2-HMAC-SHA256 digest for the given password and salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def set_password(password):
    """Hash and persist a new application password, overwriting any existing one.

    Raises:
        AuthError: if the password is empty or the config cannot be saved.
    """
    if not password or not password.strip():
        raise AuthError("Password cannot be empty.")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_BYTES)
    digest = _hash_password(password, salt)

    record = {
        "salt": salt.hex(),
        "hash": digest.hex(),
        "iterations": PBKDF2_ITERATIONS,
    }
    try:
        with AUTH_FILE.open("w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
    except OSError as exc:
        raise AuthError(f"Failed to save password configuration: {exc}") from exc

    audit.log_event("PASSWORD_SET")


def verify_password(password):
    """Check a supplied password against the stored hash, logging the outcome.

    Returns:
        True if the password matches, False otherwise.

    Raises:
        AuthError: if no password has been configured yet, or the config is corrupt.
    """
    if not is_configured():
        raise AuthError("No password has been configured yet.")

    try:
        with AUTH_FILE.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
        salt = bytes.fromhex(record["salt"])
        expected = bytes.fromhex(record["hash"])
        iterations = record.get("iterations", PBKDF2_ITERATIONS)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        raise AuthError(f"Password configuration is corrupt: {exc}") from exc

    actual = _hash_password(password, salt, iterations)
    matches = hmac.compare_digest(actual, expected)
    audit.log_event("LOGIN_SUCCESS" if matches else "LOGIN_FAILED")
    return matches
