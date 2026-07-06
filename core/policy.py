"""USB storage policy enforcement: status checks, enable/disable, and rollback."""

import json
from datetime import datetime, timezone
from pathlib import Path

from core import audit
from core.registry import (
    START_DISABLED,
    START_ENABLED,
    RegistryError,
    get_usb_start_value,
    is_admin,
    set_usb_start_value,
)

BACKUP_DIR = Path(__file__).resolve().parent.parent / "backups"
BACKUP_FILE = BACKUP_DIR / "registry_backup.json"

STATE_LABELS = {
    START_ENABLED: "ENABLED",
    START_DISABLED: "DISABLED",
}


class PolicyError(Exception):
    """Raised when a policy operation cannot be completed."""


def describe_state(raw_value):
    """Translate a raw registry Start value into a human-readable label."""
    return STATE_LABELS.get(raw_value, f"UNKNOWN ({raw_value})")


def get_status():
    """Query the current USB storage policy state and log the query.

    Returns:
        dict with keys: raw_value, label.

    Raises:
        PolicyError: if the registry cannot be read.
    """
    try:
        raw_value = get_usb_start_value()
    except RegistryError as exc:
        raise PolicyError(str(exc)) from exc

    audit.log_event("STATUS_QUERY", previous_value=raw_value, new_value=raw_value)
    return {"raw_value": raw_value, "label": describe_state(raw_value)}


def _require_admin():
    """Raise PolicyError if the current process lacks administrator privileges."""
    if not is_admin():
        raise PolicyError(
            "Administrator privileges are required to change USB policy. "
            "Re-launch your terminal with 'Run as administrator' and try again."
        )


def _backup_current_value(raw_value, action):
    """Persist the current registry value to backups/registry_backup.json before a change."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "previous_value": raw_value,
    }
    try:
        with BACKUP_FILE.open("w", encoding="utf-8") as handle:
            json.dump(backup_record, handle, indent=2)
    except OSError as exc:
        raise PolicyError(f"Failed to write registry backup: {exc}") from exc


def _apply_value(new_value, action):
    """Shared logic for enable/disable: backup, admin check, write, and audit log."""
    _require_admin()
    try:
        current_value = get_usb_start_value()
    except RegistryError as exc:
        raise PolicyError(str(exc)) from exc

    if current_value == new_value:
        audit.log_event(action, previous_value=current_value, new_value=new_value)
        return {"raw_value": new_value, "label": describe_state(new_value), "changed": False}

    _backup_current_value(current_value, action)

    try:
        set_usb_start_value(new_value)
    except RegistryError as exc:
        raise PolicyError(str(exc)) from exc

    audit.log_event(action, previous_value=current_value, new_value=new_value)
    return {"raw_value": new_value, "label": describe_state(new_value), "changed": True}


def disable_usb():
    """Disable USB mass storage by setting the USBSTOR Start value to 4.

    Backs up the previous value before writing. Requires administrator privileges.
    """
    return _apply_value(START_DISABLED, "DISABLE")


def enable_usb():
    """Enable USB mass storage by setting the USBSTOR Start value to 3.

    Backs up the previous value before writing. Requires administrator privileges.
    """
    return _apply_value(START_ENABLED, "ENABLE")


def rollback():
    """Restore the USBSTOR Start value from the last saved backup.

    Raises:
        PolicyError: if no backup exists, privileges are insufficient, or the write fails.
    """
    _require_admin()

    if not BACKUP_FILE.exists():
        raise PolicyError("No backup found. Nothing to roll back.")

    try:
        with BACKUP_FILE.open("r", encoding="utf-8") as handle:
            backup_record = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Failed to read registry backup: {exc}") from exc

    restore_value = backup_record.get("previous_value")
    if restore_value not in (START_ENABLED, START_DISABLED):
        raise PolicyError(f"Backup file contains an invalid value: {restore_value}")

    try:
        current_value = get_usb_start_value()
        set_usb_start_value(restore_value)
    except RegistryError as exc:
        raise PolicyError(str(exc)) from exc

    audit.log_event("ROLLBACK", previous_value=current_value, new_value=restore_value)
    return {"raw_value": restore_value, "label": describe_state(restore_value), "changed": True}
