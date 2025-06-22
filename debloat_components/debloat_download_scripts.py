import os
import sys
from utilities.util_logger import logger
from utilities.util_download_handler import download_file
from utilities.util_error_popup import show_error_popup

SCRIPTS = [
    "edge_vanisher.ps1",
    "uninstall_oo.ps1",
    "update_policy_changer.ps1",
    "update_policy_changer_pro.ps1",
    "win_functions.ps1",
    "dry_run_test.ps1",
]
SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts')
GITHUB_REPO = "ctrlcat0x/basilisk"
GITHUB_RAW_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/scripts/"

def main():
    for script in SCRIPTS:
        script_path = os.path.join(SCRIPTS_DIR, script)
        if not os.path.exists(script_path):
            logger.warning(f"{script} not found locally, attempting to fetch from GitHub...")
            url = GITHUB_RAW_URL + script
            if not download_file(url, dest_name=script, dest_dir=SCRIPTS_DIR):
                show_error_popup(
                    f"Required script not found and could not be downloaded:\n{script}",
                    allow_continue=False
                )
                sys.exit(1)
        logger.info(f"Script available: {script_path}")
    logger.info("All required debloat scripts are available.")

if __name__ == "__main__":
    main()
