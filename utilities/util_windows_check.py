import sys
import winreg
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup



def _read_registry_value(name: str) -> str:
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    access = winreg.KEY_READ
    if hasattr(winreg, "KEY_WOW64_64KEY"):
        access |= winreg.KEY_WOW64_64KEY
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access) as key:
            val, _ = winreg.QueryValueEx(key, name)
        return str(val)
    except Exception as e:
        logger.exception(f"Unable to read registry value {name}: {e}")
        raise



def check_windows_11_home_or_pro() -> str:
    if sys.platform != "win32":
        show_error_popup(
            "Unsupported OS detected.\n"
            "This tool requires Windows 11 Home or Professional.",
            allow_continue=False
        )
    try:
        product_name = _read_registry_value("ProductName")
        build_str    = _read_registry_value("CurrentBuildNumber")
        build_num    = int(build_str)
    except Exception:
        show_error_popup(
            "Failed to determine Windows version.\n"
            "This tool requires Windows 11 Home or Professional.",
            allow_continue=False
        )
    is_win11 = (
        product_name.startswith("Windows 11")
        or (product_name.startswith("Windows 10") and build_num >= 22000)
    )
    if not is_win11:
        show_error_popup(
            f"Incompatible Windows version detected:\n"
            f"  {product_name} (build {build_num})\n"
            "This tool requires Windows 11 Home or Professional.",
            allow_continue=False
        )
    if "Home" in product_name:
        edition = "Home"
    elif "Professional" in product_name or "Pro" in product_name:
        edition = "Professional"
    else:
        show_error_popup(
            f"Unsupported Windows 11 edition detected:\n"
            f"  {product_name}\n"
            "Only Home or Professional editions are supported.",
            allow_continue=False
        )
    logger.info(f"Detected OS: {product_name} (build {build_num}); edition: {edition}")
    return edition



if __name__ == "__main__":
    ed = check_windows_11_home_or_pro()
    print(f"Windows 11 {ed} detected. Continuing…")
