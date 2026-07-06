"""Tkinter desktop GUI for the USB Port Policy Enforcer.

Provides a password-gated dashboard over the same core.* modules used by
the CLI: live policy status, enable/disable/rollback, compliance report
export, audit log viewing, and a toggle for the policy watchdog.
"""

import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from core import audit, auth, report, watchdog
from core.policy import PolicyError, disable_usb, enable_usb, get_status, rollback
from core.registry import is_admin

APP_TITLE = "USB Port Policy Enforcer"
COLOR_ENABLED = "#1a7f37"
COLOR_DISABLED = "#c62828"
COLOR_WARNING = "#b8860b"


def relaunch_as_admin():
    """Re-launch this process elevated via the Windows UAC prompt, then exit."""
    try:
        import ctypes

        params = " ".join(f'"{arg}"' for arg in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    except Exception as exc:
        messagebox.showerror(APP_TITLE, f"Failed to relaunch as administrator: {exc}")
        return
    sys.exit(0)


class SetupFrame(ttk.Frame):
    """First-run screen: create the application password."""

    def __init__(self, master, on_success):
        """Build the password-setup form; call on_success() once a password is saved."""
        super().__init__(master)
        self.on_success = on_success

        ttk.Label(self, text=APP_TITLE, font=("Segoe UI", 16, "bold")).pack(pady=(0, 4))
        ttk.Label(self, text="No password is configured yet.\nCreate one to continue.").pack(
            pady=(0, 12)
        )

        ttk.Label(self, text="New password").pack()
        self.pw1_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.pw1_var, show="*", width=30).pack(pady=4)

        ttk.Label(self, text="Confirm password").pack()
        self.pw2_var = tk.StringVar()
        confirm_entry = ttk.Entry(self, textvariable=self.pw2_var, show="*", width=30)
        confirm_entry.pack(pady=4)
        confirm_entry.bind("<Return>", lambda _e: self._create())

        self.error_label = ttk.Label(self, text="", foreground=COLOR_DISABLED)
        self.error_label.pack(pady=4)
        ttk.Button(self, text="Create Password", command=self._create).pack(pady=8)

    def _create(self):
        """Validate and persist the new password, then advance to the dashboard."""
        pw1, pw2 = self.pw1_var.get(), self.pw2_var.get()
        if pw1 != pw2:
            self.error_label.config(text="Passwords do not match.")
            return
        try:
            auth.set_password(pw1)
        except auth.AuthError as exc:
            self.error_label.config(text=str(exc))
            return
        self.on_success()


class LoginFrame(ttk.Frame):
    """Login screen shown when a password is already configured."""

    def __init__(self, master, on_success):
        """Build the login form; call on_success() once the password is verified."""
        super().__init__(master)
        self.on_success = on_success

        ttk.Label(self, text=APP_TITLE, font=("Segoe UI", 16, "bold")).pack(pady=(0, 4))
        ttk.Label(self, text="Enter password to continue").pack(pady=(0, 12))

        self.password_var = tk.StringVar()
        entry = ttk.Entry(self, textvariable=self.password_var, show="*", width=30)
        entry.pack(pady=4)
        entry.bind("<Return>", lambda _e: self._attempt())
        entry.focus_set()

        self.error_label = ttk.Label(self, text="", foreground=COLOR_DISABLED)
        self.error_label.pack(pady=4)
        ttk.Button(self, text="Log In", command=self._attempt).pack(pady=8)

        admin = is_admin()
        admin_text = (
            "Running as Administrator"
            if admin
            else "NOT running as Administrator — policy changes will be blocked"
        )
        ttk.Label(self, text=admin_text, foreground=COLOR_ENABLED if admin else COLOR_WARNING).pack(
            pady=(16, 0)
        )
        if not admin:
            ttk.Button(self, text="Relaunch as Administrator", command=relaunch_as_admin).pack(
                pady=4
            )

    def _attempt(self):
        """Verify the entered password and advance to the dashboard on success."""
        password = self.password_var.get()
        try:
            ok = auth.verify_password(password)
        except auth.AuthError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        if ok:
            self.on_success()
        else:
            self.error_label.config(text="Incorrect password.")
            self.password_var.set("")


class DashboardFrame(ttk.Frame):
    """Main authenticated dashboard: status, actions, watchdog, and audit log."""

    def __init__(self, master):
        """Build the dashboard layout and load the initial status and log."""
        super().__init__(master)
        self.app = master
        self._build_status_section()
        self._build_action_buttons()
        self._build_watchdog_section()
        self._build_log_section()
        self.refresh_status()

    def _build_status_section(self):
        """Build the panel showing the live USB policy state and privilege level."""
        frame = ttk.LabelFrame(self, text="Current Policy")
        frame.pack(fill="x", pady=(0, 8))
        self.status_label = ttk.Label(frame, text="Checking...", font=("Segoe UI", 14, "bold"))
        self.status_label.pack(pady=8)
        admin_text = "Administrator" if is_admin() else "Standard user (read-only)"
        ttk.Label(frame, text=f"Privilege level: {admin_text}").pack(pady=(0, 8))

    def _build_action_buttons(self):
        """Build the row of policy action buttons."""
        frame = ttk.LabelFrame(self, text="Actions")
        frame.pack(fill="x", pady=(0, 8))
        row = ttk.Frame(frame)
        row.pack(pady=6)
        ttk.Button(row, text="Refresh", command=self.refresh_status).grid(row=0, column=0, padx=4)
        ttk.Button(row, text="Enable USB", command=self._do_enable).grid(row=0, column=1, padx=4)
        ttk.Button(row, text="Disable USB", command=self._do_disable).grid(row=0, column=2, padx=4)
        ttk.Button(row, text="Rollback", command=self._do_rollback).grid(row=0, column=3, padx=4)
        ttk.Button(row, text="Export Report", command=self._do_export_report).grid(
            row=0, column=4, padx=4
        )

    def _build_watchdog_section(self):
        """Build the panel for configuring and toggling the auto-remediation watchdog."""
        frame = ttk.LabelFrame(self, text="Watchdog (auto-remediation)")
        frame.pack(fill="x", pady=(0, 8))
        row = ttk.Frame(frame)
        row.pack(pady=6)
        ttk.Label(row, text="Enforce:").grid(row=0, column=0, padx=4)
        self.enforce_var = tk.StringVar(value=watchdog.get_enforced_policy() or "DISABLED")
        ttk.Combobox(
            row, textvariable=self.enforce_var, values=["ENABLED", "DISABLED"], width=10,
            state="readonly",
        ).grid(row=0, column=1, padx=4)
        self.watchdog_toggle_btn = ttk.Button(
            row, text="Start Watchdog", command=self._toggle_watchdog
        )
        self.watchdog_toggle_btn.grid(row=0, column=2, padx=4)
        self.watchdog_status_label = ttk.Label(frame, text="Watchdog stopped.")
        self.watchdog_status_label.pack(pady=(0, 6))

    def _build_log_section(self):
        """Build the scrollable audit log viewer panel."""
        frame = ttk.LabelFrame(self, text="Recent Audit Log")
        frame.pack(fill="both", expand=True)
        self.log_text = scrolledtext.ScrolledText(
            frame, height=10, state="disabled", font=("Consolas", 9)
        )
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)
        self.refresh_log()

    def refresh_status(self):
        """Re-query the registry and update the status label and audit log view."""
        try:
            result = get_status()
        except PolicyError as exc:
            self.status_label.config(text=f"ERROR: {exc}", foreground=COLOR_WARNING)
            self.refresh_log()
            return
        label = result["label"]
        color = (
            COLOR_ENABLED
            if label == "ENABLED"
            else COLOR_DISABLED if label == "DISABLED" else COLOR_WARNING
        )
        self.status_label.config(text=f"USB Storage: {label}", foreground=color)
        self.refresh_log()

    def refresh_log(self):
        """Reload the last 20 audit log entries into the log viewer."""
        entries = audit.read_last_entries(20)
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, "\n".join(entries) if entries else "No audit log entries yet.")
        self.log_text.config(state="disabled")

    def _guard_admin(self):
        """Show a warning and return False if the process is not elevated."""
        if not is_admin():
            messagebox.showwarning(
                APP_TITLE,
                "This action requires Administrator privileges. "
                "Close the app and relaunch it as Administrator.",
            )
            return False
        return True

    def _do_enable(self):
        """Handle the Enable USB button."""
        if not self._guard_admin():
            return
        try:
            result = enable_usb()
        except PolicyError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        messagebox.showinfo(APP_TITLE, f"USB storage is now {result['label']}.")
        self.refresh_status()

    def _do_disable(self):
        """Handle the Disable USB button."""
        if not self._guard_admin():
            return
        try:
            result = disable_usb()
        except PolicyError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        messagebox.showinfo(APP_TITLE, f"USB storage is now {result['label']}.")
        self.refresh_status()

    def _do_rollback(self):
        """Handle the Rollback button, after a confirmation prompt."""
        if not self._guard_admin():
            return
        if not messagebox.askyesno(APP_TITLE, "Restore the last backed-up registry value?"):
            return
        try:
            result = rollback()
        except PolicyError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        messagebox.showinfo(APP_TITLE, f"Rolled back to {result['label']}.")
        self.refresh_status()

    def _do_export_report(self):
        """Handle the Export Report button."""
        try:
            path = report.save_report()
        except report.ReportError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return
        messagebox.showinfo(APP_TITLE, f"Compliance report saved to:\n{path}")

    def _toggle_watchdog(self):
        """Start or stop the background watchdog thread."""
        app = self.app
        if app.watchdog_thread and app.watchdog_thread.is_alive():
            app.watchdog_stop_event.set()
            self.watchdog_toggle_btn.config(text="Start Watchdog")
            self.watchdog_status_label.config(text="Watchdog stopped.")
            return

        if not self._guard_admin():
            return

        try:
            watchdog.set_enforced_policy(self.enforce_var.get())
        except watchdog.WatchdogError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return

        app.watchdog_stop_event.clear()

        def on_check(result):
            if isinstance(result, watchdog.WatchdogError):
                text = f"Watchdog error: {result}"
            elif result["drift"]:
                text = f"Drift auto-remediated ({result['current']} -> {result['enforced']})."
            else:
                text = f"Compliant ({result['current']})."
            self.after(0, lambda: self.watchdog_status_label.config(text=text))
            self.after(0, self.refresh_status)

        def loop():
            watchdog.run_watchdog(interval_seconds=30, on_check=on_check, stop_event=app.watchdog_stop_event)

        app.watchdog_thread = threading.Thread(target=loop, daemon=True)
        app.watchdog_thread.start()
        self.watchdog_toggle_btn.config(text="Stop Watchdog")
        self.watchdog_status_label.config(text="Watchdog running...")


class App(tk.Tk):
    """Top-level Tkinter application window managing screen transitions."""

    def __init__(self):
        """Initialize the window and show the login or first-run setup screen."""
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("620x560")
        self.resizable(False, False)
        self.watchdog_thread = None
        self.watchdog_stop_event = threading.Event()
        self._show_login_or_setup()

    def _clear(self):
        """Remove all widgets from the window before rendering a new screen."""
        for widget in self.winfo_children():
            widget.destroy()

    def _show_login_or_setup(self):
        """Render the setup screen on first run, or the login screen otherwise."""
        self._clear()
        if auth.is_configured():
            LoginFrame(self, on_success=self._show_dashboard).pack(fill="both", expand=True, padx=24, pady=24)
        else:
            SetupFrame(self, on_success=self._show_dashboard).pack(fill="both", expand=True, padx=24, pady=24)

    def _show_dashboard(self):
        """Render the authenticated dashboard screen."""
        self._clear()
        DashboardFrame(self).pack(fill="both", expand=True, padx=16, pady=16)

    def on_close(self):
        """Stop any running watchdog thread and close the window."""
        self.watchdog_stop_event.set()
        self.destroy()


def launch_app():
    """Create and run the Tkinter application main loop."""
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
