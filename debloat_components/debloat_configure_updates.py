import sys
import winreg
from utilities.util_logger import logger
from utilities.util_powershell_handler import run_powershell_script
from utilities.util_error_popup import show_error_popup



def _get_product_name() -> str:
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    access = winreg.KEY_READ
    if hasattr(winreg, "KEY_WOW64_64KEY"):
        access |= winreg.KEY_WOW64_64KEY
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access) as key:
        val, _ = winreg.QueryValueEx(key, "ProductName")
        return str(val)



def main():
    try:
        product_name = _get_product_name()
        logger.info(f"Detected product name: {product_name}")
    except Exception as e:
        logger.error(f"Failed to read Windows edition: {e}")
        show_error_popup(
            f"Failed to determine Windows edition:\n{e}",
            allow_continue=False,
        )
        sys.exit(1)
    if any(x in product_name for x in ("Professional", "Pro", "Enterprise")):
        script = "update_policy_changer_pro.ps1"
    else:
        script = "update_policy_changer.ps1"

    logger.info(f"Executing PowerShell script: {script}")
    try:
        run_powershell_script(script)
        logger.info(f"\u2714 Successfully executed {script}")
    except Exception as e:
        logger.error(f"\u2716 Failed to execute {script}: {e}")
        try:
            show_error_popup(
                f"Failed to execute PowerShell script:\n{script}\n\n{e}",
                allow_continue=False,
            )
        except Exception:
            pass
        sys.exit(1)
    logger.info("Windows update policy configured successfully.")



if __name__ == "__main__":
    main()
