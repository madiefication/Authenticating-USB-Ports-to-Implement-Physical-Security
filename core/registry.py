"""Low-level Windows Registry access for the USBSTOR service policy.

All reads/writes to HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR
are isolated here so the rest of the codebase never touches winreg directly.
"""

import ctypes
import platform

try:
    import winreg
except ImportError:  # pragma: no cover - only triggers on non-Windows platforms
    winreg = None

# Registry location of the USB mass-storage driver service.
USBSTOR_KEY_PATH = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
USBSTOR_VALUE_NAME = "Start"
USBSTOR_HIVE = "HKEY_LOCAL_MACHINE"

# Windows service "Start" values relevant to this tool.
START_ENABLED = 3   # SERVICE_DEMAND_START - driver loads when a USB storage device is plugged in
START_DISABLED = 4  # SERVICE_DISABLED - driver is prevented from loading


class RegistryError(Exception):
    """Raised when a registry read or write operation fails."""


def ensure_windows_platform():
    """Raise a RegistryError immediately if not running on Windows.

    This tool depends on the winreg module, which only exists on Windows.
    """
    if winreg is None or platform.system() != "Windows":
        raise RegistryError(
            "This tool requires Windows (winreg module not available on this platform)."
        )


def is_admin():
    """Return True if the current process is running with administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        # If the privilege check itself fails, fail closed (treat as non-admin).
        return False


def get_usb_start_value():
    """Read and return the current 'Start' DWORD value of the USBSTOR service key.

    Raises:
        RegistryError: if the key or value cannot be read.
    """
    ensure_windows_platform()
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY_PATH, 0, winreg.KEY_READ
        ) as key:
            value, _reg_type = winreg.QueryValueEx(key, USBSTOR_VALUE_NAME)
            return value
    except FileNotFoundError as exc:
        raise RegistryError(
            f"USBSTOR registry key not found: {USBSTOR_HIVE}\\{USBSTOR_KEY_PATH}"
        ) from exc
    except PermissionError as exc:
        raise RegistryError(
            "Access denied while reading the USBSTOR registry key. "
            "Try running as Administrator."
        ) from exc
    except OSError as exc:
        raise RegistryError(f"Unexpected error reading USBSTOR registry key: {exc}") from exc


def set_usb_start_value(new_value):
    """Write a new 'Start' DWORD value to the USBSTOR service key.

    Args:
        new_value: START_ENABLED (3) or START_DISABLED (4).

    Raises:
        RegistryError: if the value cannot be written (e.g. insufficient privileges).
    """
    ensure_windows_platform()
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY_PATH, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, USBSTOR_VALUE_NAME, 0, winreg.REG_DWORD, new_value)
    except FileNotFoundError as exc:
        raise RegistryError(
            f"USBSTOR registry key not found: {USBSTOR_HIVE}\\{USBSTOR_KEY_PATH}"
        ) from exc
    except PermissionError as exc:
        raise RegistryError(
            "Access denied while writing the USBSTOR registry key. "
            "This operation requires Administrator privileges."
        ) from exc
    except OSError as exc:
        raise RegistryError(f"Unexpected error writing USBSTOR registry key: {exc}") from exc
