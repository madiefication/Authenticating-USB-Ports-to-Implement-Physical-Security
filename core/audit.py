"""Audit logging for USB policy queries and changes."""

import getpass
import platform
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_FILE = LOG_DIR / "usb_policy.log"
LOG_FIELD_COUNT = 6  # timestamp, action, previous_value, new_value, user, machine_name


def ensure_log_dir():
    """Create the logs directory if it does not already exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def log_event(action, previous_value=None, new_value=None):
    """Append a single pipe-delimited audit entry to the log file.

    Args:
        action: short label for what happened, e.g. "STATUS_QUERY", "DISABLE", "ENABLE", "ROLLBACK".
        previous_value: the registry value before the action (or None if not applicable).
        new_value: the registry value after the action (or None if not applicable).
    """
    ensure_log_dir()
    timestamp = datetime.now(timezone.utc).isoformat()
    user = getpass.getuser()
    machine_name = platform.node()
    prev_str = "N/A" if previous_value is None else str(previous_value)
    new_str = "N/A" if new_value is None else str(new_value)

    line = f"{timestamp} | {action} | {prev_str} | {new_str} | {user} | {machine_name}\n"
    try:
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError as exc:
        raise RuntimeError(f"Failed to write audit log entry: {exc}") from exc


def read_last_entries(count=20):
    """Return the last `count` audit log entries as a list of strings (oldest first).

    Returns an empty list if the log file does not yet exist.
    """
    if not LOG_FILE.exists():
        return []
    try:
        with LOG_FILE.open("r", encoding="utf-8") as handle:
            lines = [line.rstrip("\n") for line in handle if line.strip()]
    except OSError as exc:
        raise RuntimeError(f"Failed to read audit log: {exc}") from exc
    return lines[-count:]


def read_all_entries():
    """Return every audit log entry as a list of strings (oldest first)."""
    if not LOG_FILE.exists():
        return []
    try:
        with LOG_FILE.open("r", encoding="utf-8") as handle:
            return [line.rstrip("\n") for line in handle if line.strip()]
    except OSError as exc:
        raise RuntimeError(f"Failed to read audit log: {exc}") from exc


def count_policy_changes():
    """Return the number of ENABLE/DISABLE/ROLLBACK actions recorded in the log."""
    change_actions = {"ENABLE", "DISABLE", "ROLLBACK"}
    changes = 0
    for entry in read_all_entries():
        fields = entry.split(" | ")
        if len(fields) == LOG_FIELD_COUNT and fields[1] in change_actions:
            changes += 1
    return changes


def last_change_entry():
    """Return the most recent ENABLE/DISABLE/ROLLBACK log entry as a dict, or None."""
    change_actions = {"ENABLE", "DISABLE", "ROLLBACK"}
    for entry in reversed(read_all_entries()):
        fields = entry.split(" | ")
        if len(fields) == LOG_FIELD_COUNT and fields[1] in change_actions:
            return {
                "timestamp": fields[0],
                "action": fields[1],
                "previous_value": fields[2],
                "new_value": fields[3],
                "user": fields[4],
                "machine_name": fields[5],
            }
    return None
