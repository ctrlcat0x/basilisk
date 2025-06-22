import json
import os
import subprocess
from utilities.util_powershell_handler import run_powershell_command
import sys
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup


def _get_defender_exclusions() -> list[str]:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        "Get-MpPreference | ConvertTo-Json -Compress",
    ]
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags |= subprocess.CREATE_NO_WINDOW
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            creationflags=creationflags,
        )
        data = json.loads(result.stdout)
        paths = data.get("ExclusionPath") or []
        if isinstance(paths, str):
            paths = [paths]
        return [os.path.normpath(p).rstrip("\\") for p in paths]
    except Exception as e:
        logger.exception(f"Failed to query Defender exclusions: {e}")
        raise



def is_c_drive_excluded() -> bool:
    exclusions = _get_defender_exclusions()
    for path in exclusions:
        if path.lower() in {"c:", "c:"}:
            return True
    return False



def ensure_defender_disabled() -> None:
    logger.debug("Checking Windows Defender exclusions")
    try:
        if is_c_drive_excluded():
            logger.info("C: drive exclusion detected in Windows Defender")
            return
    except Exception as e:
        show_error_popup(
            f"Unable to check Windows Defender exclusions:\n{e}",
            allow_continue=False,
        )
    logger.error("C: drive is not excluded in Windows Defender")
    show_error_popup(
        "Basilisk needs your C: drive added as an excluded folder in Windows Defender "
        "to ensure Defender won't cause problems during the installation process.\n\n"
        "Please add 'C:\\' as an exclusion before continuing. It is highly recommended "
        "to remove this exclusion once the installation is complete.",
        allow_continue=False,
    )



def is_path_excluded(path: str) -> bool:
    norm = os.path.normpath(path).rstrip("\\").lower()
    try:
        for p in _get_defender_exclusions():
            if norm == p.lower():
                return True
    except Exception:
        pass
    return False



def add_defender_exclusion(path: str) -> None:
    norm = os.path.normpath(path).rstrip("\\")
    if is_path_excluded(norm):
        logger.debug(f"Path already excluded in Defender: {norm}")
        return
    try:
        logger.info(f"Adding Defender exclusion for {norm}")
        run_powershell_command(
            f"Add-MpPreference -ExclusionPath '{norm}'",
            allow_continue_on_fail=True,
        )
        logger.info(f"Added Defender exclusion for {norm}")
    except SystemExit:
        pass
    except Exception as e:
        logger.error(f"Failed to add Defender exclusion {norm}: {e}")
        show_error_popup(
            f"Failed to add Windows Defender exclusion:\n{norm}\n{e}",
            allow_continue=True,
        )



if __name__ == "__main__":
    ensure_defender_disabled()
    print("C: drive exclusion detected. Continuing…")
