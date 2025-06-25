import os
import sys
import ctypes
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup
from utilities.util_load_resource import get_resource_path
import tempfile
import subprocess

def install_apps_with_winget():
    apps = [
        "Brave.Brave",
        "7zip.7zip",
        "VideoLAN.VLC",
        "Microsoft.DotNet.DesktopRuntime.8",
        "Microsoft.DotNet.DesktopRuntime.9",
        "Microsoft.WindowsTerminal",
        "Microsoft.VCRedist.2015+.x86",
        "Microsoft.VCRedist.2015+.x64",
        "Microsoft.EdgeWebView2Runtime",
        "Microsoft.DirectX"
    ]
    for app in apps:
        try:
            logger.info(f"Installing {app} via winget (admin PowerShell)...")
            ps_command = f'Start-Process winget -ArgumentList "install --id {app} --silent --accept-package-agreements --accept-source-agreements" -Verb RunAs -Wait'
            result = subprocess.run([
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command
            ], capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Successfully installed {app} via winget.")
            else:
                logger.error(f"Failed to install {app} via winget. Output: {result.stdout}\nError: {result.stderr}")
        except Exception as e:
            logger.error(f"Exception while installing {app} via winget: {e}")

def main():
    if getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    else:
        components_dir = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(components_dir)
    media_dir = os.path.join(base_path, 'media')
    temp_wallpaper = os.path.join(tempfile.gettempdir(), "basilisk", "media", "background.jpeg")
    if os.path.exists(temp_wallpaper):
        wallpaper_path = temp_wallpaper
    else:
        wallpaper_path = get_resource_path('media/background.jpeg')
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
        # Install apps before setting background
        install_apps_with_winget()
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
