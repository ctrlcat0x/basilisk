import os
import sys
import ctypes
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup

def main():
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        components_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(components_dir)
    media_dir = os.path.join(base_path, 'media')
    wallpaper_path = os.path.join(media_dir, 'background.png')
    logger.info(f"Setting desktop background: {wallpaper_path}")
    if not os.path.exists(wallpaper_path):
        msg = f"Wallpaper file not found: {wallpaper_path}"
        logger.error(msg)
        show_error_popup(msg, allow_continue=False)
        sys.exit(1)
    SPI_SETDESKWALLPAPER = 20
    SPIF_UPDATEINIFILE   = 0x01
    SPIF_SENDCHANGE      = 0x02
    try:
        result = ctypes.windll.user32.SystemParametersInfoW(
            SPI_SETDESKWALLPAPER,
            0,
            wallpaper_path,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
        )
        if not result:
            raise ctypes.WinError()
        logger.info("Desktop background set successfully.")
    except Exception as e:
        logger.error(f"Failed to set desktop background: {e}")
        show_error_popup(f"Failed to set desktop background:\n{e}", allow_continue=False)
        sys.exit(1)



if __name__ == "__main__":
    main()
