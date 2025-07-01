import os
import sys
from utilities.util_logger import logger
from utilities.util_download_handler import download_file
from utilities.util_error_popup import show_error_popup
import tempfile

SCRIPTS = [
    "edge_vanisher.ps1",
    "uninstall_oo.ps1",
    "update_policy_changer.ps1",
    "update_policy_changer_pro.ps1",
    "win_functions.ps1",
    "dry_run_test.ps1"
]
SCRIPTS_DIR = os.path.join(tempfile.gettempdir(), 'basilisk')
GITHUB_RAW_URL = f"https://raw.githubusercontent.com/ctrlcat0x/basilisk/master/scripts/"

MEDIA_FILES = [
    "background.jpeg",
]
MEDIA_DIR = os.path.join(tempfile.gettempdir(), 'basilisk', 'media')
GITHUB_MEDIA_URL = "https://raw.githubusercontent.com/ctrlcat0x/basilisk/master/media/"

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
    # Download media files
    if not os.path.exists(MEDIA_DIR):
        os.makedirs(MEDIA_DIR, exist_ok=True)
    for media_file in MEDIA_FILES:
        media_path = os.path.join(MEDIA_DIR, media_file)
        if not os.path.exists(media_path):
            logger.warning(f"{media_file} not found locally, attempting to fetch from GitHub...")
            url = GITHUB_MEDIA_URL + media_file
            if not download_file(url, dest_name=media_file, dest_dir=MEDIA_DIR):
                show_error_popup(
                    f"Required media file not found and could not be downloaded:\n{media_file}",
                    allow_continue=False
                )
                sys.exit(1)
        logger.info(f"Media file available: {media_path}")
    logger.info("All required debloat scripts and media files are available.")

if __name__ == "__main__":
    main()
