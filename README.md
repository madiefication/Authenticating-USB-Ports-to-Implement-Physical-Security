# USB Port Policy Enforcer

A lightweight Windows endpoint security control that enforces USB mass-storage
device policy directly at the OS level via the Windows Registry — with audit
logging, JSON compliance reporting, safe rollback, a password-gated desktop
GUI, and a background watchdog that auto-remediates policy tampering. Built
as a portfolio project demonstrating practical endpoint-hardening tooling of
the kind a SOC analyst or security engineer would deploy in the field.

Two ways to use it:

- **CLI** (`usb_enforcer.py`) — scriptable, for automation and remote execution.
- **Desktop GUI** (`--gui`) — a password-protected Tkinter dashboard for
  interactive use, with the same underlying logic.

## Why this matters

USB storage devices are one of the oldest and still most effective vectors for:

- **Data exfiltration** — an insider or compromised endpoint copying sensitive
  data to a thumb drive.
- **Malware introduction** — "BadUSB" and autorun-style attacks delivered via
  removable media plugged into a corporate machine.
- **Compliance violations** — many regulatory frameworks (PCI-DSS, HIPAA, NIST
  800-53 MP-7) require organizations to control or restrict removable media.

Enterprise EDR/MDM suites (Microsoft Intune, CrowdStrike device control, etc.)
implement this exact control under the hood by toggling the `USBSTOR` driver's
`Start` value. This tool reproduces that mechanism directly and transparently,
with a full audit trail, so it can be understood, inspected, and deployed on a
single host without a management platform.

## How it works under the hood

Windows loads the USB mass-storage driver (`USBSTOR.SYS`) via a standard
Windows service definition stored in the registry at:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR
```

The `Start` DWORD value on that key controls how the service is started:

| Value | Meaning                | Effect                                          |
|-------|------------------------|--------------------------------------------------|
| `3`   | `SERVICE_DEMAND_START` | Driver loads on demand — USB storage **enabled**  |
| `4`   | `SERVICE_DISABLED`     | Driver is prevented from loading — **disabled**   |

Setting `Start` to `4` stops Windows from loading the mass-storage driver the
next time a USB storage device is plugged in, blocking it at the driver level
before it ever gets a drive letter. Devices already mounted before the change
are not force-ejected; unplugging and replugging (or a reboot) makes the new
policy take effect for that device — this is a real limitation of the registry
mechanism, not of this tool, and is called out explicitly under
[Security Considerations](#security-considerations).

This tool only ever touches that single `Start` value, using Python's built-in
`winreg` module — no third-party registry libraries are involved in the core
logic.

## Project structure

```
usb-policy-enforcer/
├── usb_enforcer.py        # main CLI entrypoint
├── core/
│   ├── registry.py        # all Windows Registry read/write logic
│   ├── policy.py          # policy enforcement logic (enable/disable/rollback)
│   ├── audit.py           # audit logging functions
│   ├── report.py          # compliance report generator
│   ├── auth.py            # local password authentication (PBKDF2-HMAC-SHA256)
│   └── watchdog.py        # policy drift detection + auto-remediation
├── gui/
│   └── app.py             # Tkinter desktop GUI (login → dashboard)
├── logs/                  # auto-created — usb_policy.log audit trail
├── reports/                # auto-created — usb_compliance_report.json
├── backups/                # auto-created — registry_backup.json for rollback
├── config/                 # auto-created — auth.json, watchdog_config.json
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Windows 10 or Windows 11
- Python 3.9+
- `colorama` (for colored terminal output)
- `tkinter` — for the GUI only. Ships with the standard python.org Windows
  installer, so no `pip install` is needed; only relevant if you built Python
  from a minimal/embeddable distribution.

> **Note on `pywin32`:** the original design considered `pywin32` for the
> admin-privilege check, but that check (`IsUserAnAdmin`) is available through
> the standard-library `ctypes` module, so no extra dependency is required for
> that either. Only `colorama` is installed.

Install dependencies:

```powershell
pip install -r requirements.txt
```

## Usage

All commands are run from inside the `usb-policy-enforcer/` directory.
**Enabling, disabling, and rolling back require an elevated (Administrator)
terminal** — right-click PowerShell or Command Prompt and choose
**"Run as administrator"**. Read-only commands (`--status`, `--log`,
`--export-report`) work from a normal, non-elevated terminal.

### Check current policy state

```powershell
python usb_enforcer.py --status
```

```
USB storage policy: ENABLED (Start=3)
```

### Disable USB storage (requires admin)

```powershell
python usb_enforcer.py --disable
```

```
USB storage has been DISABLED (Start=4).
A previous value backup was saved to backups/registry_backup.json.
```

### Enable USB storage (requires admin)

```powershell
python usb_enforcer.py --enable
```

```
USB storage has been ENABLED (Start=3).
A previous value backup was saved to backups/registry_backup.json.
```

### View the audit log

```powershell
python usb_enforcer.py --log
```

```
Last 3 audit log entries:

2026-07-06T10:12:03.221+00:00 | STATUS_QUERY | 3 | 3 | madie | DESKTOP-ABC123
2026-07-06T10:14:47.905+00:00 | DISABLE | 3 | 4 | madie | DESKTOP-ABC123
2026-07-06T10:16:02.114+00:00 | STATUS_QUERY | 4 | 4 | madie | DESKTOP-ABC123
```

Use `--count N` to show a different number of entries (default 20).

### Generate a JSON compliance report

```powershell
python usb_enforcer.py --export-report
```

```
Compliance report saved to reports\usb_compliance_report.json
```

Example report contents:

```json
{
  "report_generated_at": "2026-07-06T10:20:11.503+00:00",
  "current_policy_state": "DISABLED",
  "current_policy_raw_value": 4,
  "last_changed_timestamp": "2026-07-06T10:14:47.905+00:00",
  "last_changed_by": "madie",
  "last_changed_action": "DISABLE",
  "total_policy_changes": 1,
  "machine_hostname": "DESKTOP-ABC123",
  "os_version": "Windows-10-10.0.26200-SP0"
}
```

### Roll back to the previous value (requires admin)

```powershell
python usb_enforcer.py --rollback
```

```
Rollback complete. USB storage policy restored to ENABLED.
```

Rollback restores whatever value was in the registry immediately before the
**most recent** `--enable`/`--disable` change (stored in
`backups/registry_backup.json`). It is a single-step undo, not a full history.

### Authentication

Any command that changes policy (`--disable`, `--enable`, `--rollback`,
`--lock-policy`, `--watch`) is gated by an **application password**, on top of
the OS-level Administrator check. On the very first protected command (or the
first GUI login), you'll be prompted to create one:

```powershell
python usb_enforcer.py --disable
```

```
No application password has been configured yet.
Create a new password: ********
Confirm password: ********
Password configured successfully.
USB storage has been DISABLED (Start=4).
```

From then on, that same command prompts for the password before proceeding.
To change it later:

```powershell
python usb_enforcer.py --set-password
```

The password is stored as a salted PBKDF2-HMAC-SHA256 hash in
`config/auth.json` — never in plaintext — and every login attempt (success or
failure) is written to the audit log as `LOGIN_SUCCESS` / `LOGIN_FAILED`.

> This is a defense-in-depth control on *who is allowed to operate this tool*,
> not a substitute for Windows account security — see
> [Security Considerations](#security-considerations).

### Desktop GUI

```powershell
python usb_enforcer.py --gui
```

Opens a Tkinter window with the same login/first-run-setup flow as the CLI,
followed by a dashboard showing:

- Live policy status (green = enabled, red = disabled) with a manual refresh
- Enable / Disable / Rollback / Export Report buttons
- A "Relaunch as Administrator" button if the GUI wasn't started elevated
  (triggers the standard Windows UAC prompt)
- A watchdog panel to pick an enforced state and start/stop monitoring
- A live view of the last 20 audit log entries

Like the CLI, changing policy from the GUI requires the process to actually
be elevated — launch it from an administrator terminal, or use the in-app
relaunch button.

### Policy watchdog / auto-remediation (requires admin)

The watchdog continuously compares the live registry value against an
administrator-configured "enforced" state and automatically reverts any
unauthorized drift (e.g. someone manually flips `Start` back after a
`--disable`), logging both the drift and the fix.

```powershell
python usb_enforcer.py --lock-policy disable
python usb_enforcer.py --watch --watch-interval 30
```

```
Enforced policy set to DISABLED. Start monitoring with --watch.
Starting watchdog (interval=30s). Press Ctrl+C to stop.
[OK] Policy is compliant (DISABLED).
[DRIFT DETECTED] Registry was ENABLED, expected DISABLED. Auto-remediated.
[OK] Policy is compliant (DISABLED).
```

`--watch` runs in the foreground until you press Ctrl+C; the same monitoring
loop is also available as a background thread from the GUI's watchdog panel.
Every check that finds drift logs a `DRIFT_DETECTED` entry followed by an
`AUTO_REMEDIATED` entry once the value is restored.

> The watchdog only runs while the process is alive — it does not install
> itself as a Windows service. For persistence across reboots, wrap
> `python usb_enforcer.py --watch` in a Windows Task Scheduler task that runs
> at logon with highest privileges (not created automatically by this tool).

### Screenshots

_Add terminal screenshots here once captured, e.g.:_
<img width="787" height="732" alt="image" src="https://github.com/user-attachments/assets/4b0fbcc1-a397-4400-b812-c330f16d8f2e" />


## Security considerations

- **This is a local, single-host control**, not a replacement for enterprise
  device-control/DLP tooling. It has no central management, no tamper
  protection for its own log/backup files, and no protection against a local
  administrator simply reverting the registry value by hand.
- **Requires local admin to change policy** — by design, since writing to
  `HKEY_LOCAL_MACHINE` requires elevation. The tool checks this explicitly and
  refuses to proceed silently.
- **Audit log integrity** — `logs/usb_policy.log` is a plain text file with no
  cryptographic signing. In a real deployment, ship it to a centralized log
  pipeline (SIEM) rather than trusting the local copy as the system of record.
- **Already-mounted devices are not affected retroactively** — disabling the
  policy blocks *new* USB storage enumeration; a device already mounted before
  the change stays mounted until unplugged/replugged or the machine reboots.
- **Backups are single-slot** — `backups/registry_backup.json` is overwritten
  on every change, so `--rollback` only undoes the most recent action.
- **The application password is a usage gate, not a security boundary** —
  it restricts who can drive *this specific tool*, but anyone with local
  Administrator rights can already write to the registry directly, delete
  `config/auth.json` to reset the password, or run `--set-password` (which
  only requires admin, not the old password) to take it over. There is no
  login-attempt lockout or rate limiting in this version.
- **Watchdog persistence is process-lifetime only** — closing the terminal or
  GUI stops monitoring; it is not installed as a Windows service, so a
  determined local user can simply wait for it to not be running before
  reverting the policy. Pair it with Task Scheduler for real persistence.

## Use cases

- **IT policy enforcement** — quickly apply a "no removable storage" policy
  across a fleet via a script or remote execution tool (e.g. PsExec, Intune
  script deployment) without needing a full device-control product.
- **Endpoint hardening** — part of a baseline hardening checklist for
  workstations handling sensitive data (finance, legal, R&D).
- **Incident response** — during an active incident on a compromised host, an
  analyst can immediately disable USB storage to cut off a potential
  exfiltration or malware-delivery path, with the action automatically logged
  for the incident timeline.
- **Tamper resistance during a shift** — an analyst can lock a policy in with
  `--lock-policy` and run `--watch` for the duration of an investigation, so
  any attempt to re-enable USB storage on that host is automatically reverted
  and recorded.
- **Non-technical / interactive use** — the GUI lets someone unfamiliar with
  the command line (e.g. a help-desk technician) apply the same controls
  through buttons instead of flags, without weakening the underlying audit
  trail.

## Limitations / not implemented

- No centralized/fleet management — this is a single-host tool (CLI or GUI).
- No protection against a user manually editing the registry outside this
  tool between watchdog checks (though `--status` will always reflect the
  true current state, and the next watchdog cycle will catch and revert it).
- Only the `USBSTOR` service `Start` value is managed; it does not enumerate
  or manage individual USB device IDs, nor does it cover other removable-media
  classes (e.g. USB network adapters, MTP devices).
- No login lockout/backoff after repeated failed password attempts.
- The watchdog does not persist across reboots or logoff on its own (see
  [Security Considerations](#security-considerations)).
