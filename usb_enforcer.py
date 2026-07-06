#!/usr/bin/env python3
"""USB Port Policy Enforcer - CLI entrypoint.

Enforces USB mass-storage device policy at the OS level via the Windows
Registry (HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR), with audit
logging, JSON compliance reporting, and safe rollback.
"""

import argparse
import getpass
import sys

from colorama import Fore, Style, init as colorama_init

from core import audit, auth, report, watchdog
from core.policy import PolicyError, disable_usb, enable_usb, get_status, rollback
from core.registry import RegistryError, ensure_windows_platform, is_admin

colorama_init(autoreset=True)


def print_success(message):
    """Print a message in green to indicate success or an enabled state."""
    print(Fore.GREEN + message + Style.RESET_ALL)


def print_danger(message):
    """Print a message in red to indicate a disabled state or failure."""
    print(Fore.RED + message + Style.RESET_ALL)


def print_warning(message):
    """Print a message in yellow to indicate a warning."""
    print(Fore.YELLOW + message + Style.RESET_ALL)


def print_info(message):
    """Print a plain informational message."""
    print(message)


def handle_status(_args):
    """Handle the --status flag: print the current USB policy state."""
    try:
        result = get_status()
    except PolicyError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    if result["label"] == "ENABLED":
        print_success(f"USB storage policy: {result['label']} (Start={result['raw_value']})")
    elif result["label"] == "DISABLED":
        print_danger(f"USB storage policy: {result['label']} (Start={result['raw_value']})")
    else:
        print_warning(f"USB storage policy: {result['label']}")
    return 0


def handle_disable(_args):
    """Handle the --disable flag: disable USB mass storage."""
    try:
        result = disable_usb()
    except PolicyError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    if result["changed"]:
        print_danger(f"USB storage has been DISABLED (Start={result['raw_value']}).")
        print_info("A previous value backup was saved to backups/registry_backup.json.")
    else:
        print_warning("USB storage was already DISABLED. No change made.")
    return 0


def handle_enable(_args):
    """Handle the --enable flag: enable USB mass storage."""
    try:
        result = enable_usb()
    except PolicyError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    if result["changed"]:
        print_success(f"USB storage has been ENABLED (Start={result['raw_value']}).")
        print_info("A previous value backup was saved to backups/registry_backup.json.")
    else:
        print_warning("USB storage was already ENABLED. No change made.")
    return 0


def handle_rollback(_args):
    """Handle the --rollback flag: restore the last backed-up registry value."""
    try:
        result = rollback()
    except PolicyError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    print_success(f"Rollback complete. USB storage policy restored to {result['label']}.")
    return 0


def handle_log(args):
    """Handle the --log flag: print the last 20 (or --count) audit log entries."""
    try:
        entries = audit.read_last_entries(args.count)
    except RuntimeError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    if not entries:
        print_warning("No audit log entries found yet.")
        return 0

    print_info(f"Last {len(entries)} audit log entries:\n")
    for entry in entries:
        print_info(entry)
    return 0


def handle_export_report(_args):
    """Handle the --export-report flag: build and save the JSON compliance report."""
    try:
        report_path = report.save_report()
    except report.ReportError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    print_success(f"Compliance report saved to {report_path}")
    return 0


def handle_set_password(_args):
    """Handle --set-password: interactively create or replace the application password."""
    pw1 = getpass.getpass("New password: ")
    pw2 = getpass.getpass("Confirm new password: ")
    if pw1 != pw2:
        print_danger("[ERROR] Passwords did not match.")
        return 1
    try:
        auth.set_password(pw1)
    except auth.AuthError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1
    print_success("Password updated successfully.")
    return 0


def handle_lock_policy(args):
    """Handle --lock-policy: set the policy state the watchdog should enforce."""
    label = "ENABLED" if args.lock_policy == "enable" else "DISABLED"
    try:
        watchdog.set_enforced_policy(label)
    except watchdog.WatchdogError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1
    print_success(f"Enforced policy set to {label}. Start monitoring with --watch.")
    return 0


def handle_watch(args):
    """Handle --watch: run the policy watchdog loop in the foreground until Ctrl+C."""
    if watchdog.get_enforced_policy() is None:
        print_danger("[ERROR] No enforced policy configured. Run --lock-policy enable|disable first.")
        return 1

    def on_check(result):
        if isinstance(result, watchdog.WatchdogError):
            print_danger(f"[WATCHDOG ERROR] {result}")
        elif result["drift"]:
            print_warning(
                f"[DRIFT DETECTED] Registry was {result['current']}, "
                f"expected {result['enforced']}. Auto-remediated."
            )
        else:
            print_info(f"[OK] Policy is compliant ({result['current']}).")

    print_info(f"Starting watchdog (interval={args.watch_interval}s). Press Ctrl+C to stop.")
    try:
        watchdog.run_watchdog(interval_seconds=args.watch_interval, on_check=on_check)
    except KeyboardInterrupt:
        print_info("\nWatchdog stopped.")
    return 0


def handle_gui(_args):
    """Handle --gui: launch the Tkinter desktop application."""
    from gui.app import launch_app

    launch_app()
    return 0


def authenticate():
    """Prompt for the application password, creating one on first run.

    Returns:
        True if the caller is authenticated and may proceed, False otherwise.
    """
    if not auth.is_configured():
        print_warning("No application password has been configured yet.")
        first = getpass.getpass("Create a new password: ")
        confirm = getpass.getpass("Confirm password: ")
        if first != confirm:
            print_danger("[ERROR] Passwords did not match.")
            return False
        try:
            auth.set_password(first)
        except auth.AuthError as exc:
            print_danger(f"[ERROR] {exc}")
            return False
        print_success("Password configured successfully.")
        return True

    entered = getpass.getpass("Enter password: ")
    try:
        if auth.verify_password(entered):
            return True
    except auth.AuthError as exc:
        print_danger(f"[ERROR] {exc}")
        return False

    print_danger("[ERROR] Incorrect password.")
    return False


def build_parser():
    """Construct and return the argparse.ArgumentParser for the CLI."""
    parser = argparse.ArgumentParser(
        prog="usb_enforcer.py",
        description="Enforce and audit USB storage device policy via the Windows Registry.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="Show current USB policy state")
    group.add_argument("--disable", action="store_true", help="Disable USB storage devices")
    group.add_argument("--enable", action="store_true", help="Enable USB storage devices")
    group.add_argument(
        "--log", action="store_true", help="Print the most recent audit log entries"
    )
    group.add_argument(
        "--export-report", action="store_true", help="Generate a JSON compliance report"
    )
    group.add_argument(
        "--rollback", action="store_true", help="Restore the last backed-up registry value"
    )
    group.add_argument(
        "--set-password", action="store_true", help="Create or replace the application password"
    )
    group.add_argument(
        "--lock-policy",
        choices=["enable", "disable"],
        help="Set the policy state the watchdog should continuously enforce",
    )
    group.add_argument(
        "--watch",
        action="store_true",
        help="Run the policy watchdog in the foreground (auto-remediates drift; Ctrl+C to stop)",
    )
    group.add_argument(
        "--gui", action="store_true", help="Launch the desktop GUI"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of audit log entries to show with --log (default: 20)",
    )
    parser.add_argument(
        "--watch-interval",
        type=int,
        default=30,
        help="Seconds between watchdog checks with --watch (default: 30)",
    )
    return parser


def main():
    """Parse CLI arguments, dispatch to the matching handler, and return an exit code."""
    try:
        ensure_windows_platform()
    except RegistryError as exc:
        print_danger(f"[ERROR] {exc}")
        return 1

    parser = build_parser()
    args = parser.parse_args()

    write_operations = args.disable or args.enable or args.rollback or args.watch or args.lock_policy is not None
    admin_required = write_operations or args.set_password

    if admin_required and not is_admin():
        print_danger(
            "[ERROR] This action requires Administrator privileges.\n"
            "Right-click PowerShell/Command Prompt and choose 'Run as administrator', "
            "then re-run this command."
        )
        return 1

    if write_operations and not authenticate():
        return 1

    if args.status:
        return handle_status(args)
    if args.disable:
        return handle_disable(args)
    if args.enable:
        return handle_enable(args)
    if args.log:
        return handle_log(args)
    if args.export_report:
        return handle_export_report(args)
    if args.rollback:
        return handle_rollback(args)
    if args.set_password:
        return handle_set_password(args)
    if args.lock_policy:
        return handle_lock_policy(args)
    if args.watch:
        return handle_watch(args)
    if args.gui:
        return handle_gui(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
