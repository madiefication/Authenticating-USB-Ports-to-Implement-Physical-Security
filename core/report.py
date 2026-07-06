"""Compliance report generation for the USB Port Policy Enforcer."""

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from core import audit, policy

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORT_FILE = REPORT_DIR / "usb_compliance_report.json"


class ReportError(Exception):
    """Raised when a compliance report cannot be generated or saved."""


def build_report():
    """Assemble the compliance report data as a dict.

    Includes current policy state, last change info, total change count,
    and machine identification details.

    Raises:
        ReportError: if the current policy state cannot be read.
    """
    try:
        status = policy.get_status()
    except policy.PolicyError as exc:
        raise ReportError(str(exc)) from exc

    last_change = audit.last_change_entry()

    report = {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "current_policy_state": status["label"],
        "current_policy_raw_value": status["raw_value"],
        "last_changed_timestamp": last_change["timestamp"] if last_change else None,
        "last_changed_by": last_change["user"] if last_change else None,
        "last_changed_action": last_change["action"] if last_change else None,
        "total_policy_changes": audit.count_policy_changes(),
        "machine_hostname": platform.node(),
        "os_version": platform.platform(),
    }
    return report


def save_report(report=None):
    """Generate (if needed) and save the compliance report to reports/usb_compliance_report.json.

    Args:
        report: an already-built report dict, or None to build a fresh one.

    Returns:
        The Path to the saved report file.

    Raises:
        ReportError: if the report cannot be built or written to disk.
    """
    if report is None:
        report = build_report()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with REPORT_FILE.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
    except OSError as exc:
        raise ReportError(f"Failed to write compliance report: {exc}") from exc

    return REPORT_FILE
