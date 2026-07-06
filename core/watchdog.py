"""Policy watchdog: detects and auto-remediates unauthorized USB policy drift.

A "drift" is any mismatch between the live registry value and the
administrator-configured enforced policy — e.g. someone manually flips
the registry back to ENABLED after an admin locked it to DISABLED. The
watchdog periodically checks and, on drift, automatically reverts the
registry and logs both the drift and the remediation for the audit trail.
"""

import json
import time
from pathlib import Path

from core import audit
from core.policy import describe_state
from core.registry import (
    START_DISABLED,
    START_ENABLED,
    RegistryError,
    get_usb_start_value,
    set_usb_start_value,
)

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
WATCHDOG_CONFIG_FILE = CONFIG_DIR / "watchdog_config.json"

DEFAULT_INTERVAL_SECONDS = 30


class WatchdogError(Exception):
    """Raised for watchdog configuration or remediation failures."""


def set_enforced_policy(state_label):
    """Persist the policy ('ENABLED' or 'DISABLED') the watchdog should maintain.

    Raises:
        WatchdogError: if state_label is invalid or the config cannot be saved.
    """
    state_label = state_label.upper()
    if state_label not in ("ENABLED", "DISABLED"):
        raise WatchdogError("Enforced policy must be ENABLED or DISABLED.")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    record = {"enforced_state": state_label}
    try:
        with WATCHDOG_CONFIG_FILE.open("w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
    except OSError as exc:
        raise WatchdogError(f"Failed to save watchdog configuration: {exc}") from exc

    audit.log_event("POLICY_LOCK_SET", new_value=state_label)


def get_enforced_policy():
    """Return the configured enforced policy label ('ENABLED'/'DISABLED'), or None."""
    if not WATCHDOG_CONFIG_FILE.exists():
        return None
    try:
        with WATCHDOG_CONFIG_FILE.open("r", encoding="utf-8") as handle:
            record = json.load(handle)
        return record.get("enforced_state")
    except (OSError, json.JSONDecodeError):
        return None


def check_and_remediate():
    """Compare the live registry value to the enforced policy and auto-revert drift.

    Returns:
        dict: {"drift": bool, "current": label, "enforced": label}

    Raises:
        WatchdogError: if no enforced policy is configured or the registry is inaccessible.
    """
    enforced_label = get_enforced_policy()
    if enforced_label is None:
        raise WatchdogError(
            "No enforced policy configured. Set one first with --lock-policy enable|disable."
        )

    try:
        current_raw = get_usb_start_value()
    except RegistryError as exc:
        raise WatchdogError(str(exc)) from exc

    current_label = describe_state(current_raw)

    if current_label == enforced_label:
        return {"drift": False, "current": current_label, "enforced": enforced_label}

    enforced_raw = START_ENABLED if enforced_label == "ENABLED" else START_DISABLED
    audit.log_event("DRIFT_DETECTED", previous_value=current_raw, new_value=enforced_raw)

    try:
        set_usb_start_value(enforced_raw)
    except RegistryError as exc:
        raise WatchdogError(f"Drift detected but remediation failed: {exc}") from exc

    audit.log_event("AUTO_REMEDIATED", previous_value=current_raw, new_value=enforced_raw)
    return {"drift": True, "current": current_label, "enforced": enforced_label}


def run_watchdog(interval_seconds=DEFAULT_INTERVAL_SECONDS, on_check=None, stop_event=None):
    """Run the watchdog loop until interrupted or stop_event is set.

    Args:
        interval_seconds: seconds to wait between checks.
        on_check: optional callback invoked with either the check result dict
            or a WatchdogError instance after each check.
        stop_event: optional threading.Event; when set, the loop exits after
            its current wait. If omitted, the loop runs until a KeyboardInterrupt.
    """
    while True:
        try:
            result = check_and_remediate()
            if on_check:
                on_check(result)
        except WatchdogError as exc:
            if on_check:
                on_check(exc)

        if stop_event is not None:
            if stop_event.wait(interval_seconds):
                break
        else:
            time.sleep(interval_seconds)
