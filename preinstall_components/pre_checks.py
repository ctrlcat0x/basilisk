import os
import tempfile
import urllib.request
import urllib.error
import subprocess
from utilities.util_defender_check import ensure_defender_disabled
from utilities.util_windows_check import check_windows_11_home_or_pro
from utilities.util_error_popup import show_error_popup
from utilities.util_logger import logger
from utilities.util_ssl import create_ssl_context

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')

def _check_domain_reachable(url: str) -> bool:
    ctx = create_ssl_context()
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=10, context=ctx):
            return True
    except Exception as e:
        logger.error(f"Connectivity check failed for {url}: {e}")
        show_error_popup(
            "Basilisk could not reach code.ravendevteam.org.\n"
            "Please check your internet connection or contact your ISP.",
            allow_continue=True,
        )
        return False

def _check_temp_writable() -> bool:
    temp_root = os.environ.get("TEMP", tempfile.gettempdir())
    basilisk_dir = os.path.join(temp_root, "basilisk")
    try:
        os.makedirs(basilisk_dir, exist_ok=True)
        test_path = os.path.join(basilisk_dir, "_write_test")
        with open(test_path, "w") as f:
            f.write("test")
        os.remove(test_path)
        return True
    except Exception as e:
        logger.error(f"Temp dir check failed: {e}")
        show_error_popup(
            f"Basilisk could not write files to {basilisk_dir}.\n"
            "Please free up disk space or check permissions.",
            allow_continue=True,
        )
        return False

def _run_test_script(script_path: str) -> bool:
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            ),
        )
        output = result.stdout.strip()
        logger.debug(f"Test script output: {output}")
        if result.returncode == 0 and "Hello, World!" in output:
            return True
    except Exception as e:
        logger.error(f"Running test PowerShell script failed: {e}")
    show_error_popup(
        "Failed to run test PowerShell script. Powershell may be disabled.",
        allow_continue=True,
    )
    return False

def _run_local_test_script() -> bool:
    script_path = os.path.join(SCRIPTS_DIR, "dry_run_test.ps1")
    if not os.path.exists(script_path):
        logger.error(f"Test script not found: {script_path}")
        show_error_popup(
            f"Test script not found:\n{script_path}",
            allow_continue=True,
        )
        return False
    return _run_test_script(script_path)

def main() -> None:
    ensure_defender_disabled()
    check_windows_11_home_or_pro()
    _check_domain_reachable("https://code.ravendevteam.org")
    _check_temp_writable()
    _run_local_test_script()

if __name__ == "__main__":
    main()
