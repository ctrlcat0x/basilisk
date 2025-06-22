import os
import sys
from utilities.util_logger import logger
from utilities.util_powershell_handler import run_powershell_script
from utilities.util_error_popup import show_error_popup

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')

def main():
    scripts = [
        "edge_vanisher.ps1",
        "uninstall_oo.ps1",
    ]
    for script in scripts:
        script_path = os.path.join(SCRIPTS_DIR, script)
        if not os.path.exists(script_path):
            logger.error(f"Required script not found: {script_path}")
            show_error_popup(
                f"Required script not found:\n{script_path}",
                allow_continue=False
            )
            sys.exit(1)
        logger.info(f"Executing PowerShell script: {script_path}")
        try:
            run_powershell_script(script_path)
            logger.info(f"✔ Successfully executed {script}")
        except Exception as e:
            logger.error(f"✖ Failed to execute {script}: {e}")
            try:
                show_error_popup(
                    f"Failed to execute PowerShell script:\n{script}\n\n{e}",
                    allow_continue=False
                )
            except Exception:
                pass
            sys.exit(1)
    logger.info("All debloat scripts executed successfully.")

if __name__ == "__main__":
    main()
