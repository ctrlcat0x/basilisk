import sys
import winreg
from utilities.util_logger import logger
from utilities.util_error_popup import show_error_popup
from utilities.util_modify_registry import set_value



def main():
    registry_modifications = [
        # Visual Improvements
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
         "TaskbarAl", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
         "AppsUseLightTheme", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
         "SystemUsesLightTheme", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
         "HideFileExt", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
         "EnableTransparency", winreg.REG_DWORD, 1),

        # Game DVR and Gaming
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
         "AppCaptureEnabled", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR",
         "Value", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"System\GameConfigStore",
         "GameDVR_Enabled", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"System\GameConfigStore",
         "GameDVR_FSEBehaviorMode", winreg.REG_DWORD, 2),
        (winreg.HKEY_CURRENT_USER,
         r"System\GameConfigStore",
         "AllowGameDVR", winreg.REG_DWORD, 0),
        
        
        # Explorer and File System
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
         "Hidden", winreg.REG_DWORD, 1),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
         "HideDrivesWithNoMedia", winreg.REG_DWORD, 0),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
         "ShowSuperHidden", winreg.REG_DWORD, 1),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
         "AlwaysShowMenus", winreg.REG_DWORD, 1),
        
        # Network and Internet
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
         "Tcp1323Opts", winreg.REG_DWORD, 1),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
         "TcpTimedWaitDelay", winreg.REG_DWORD, 30),
        
        # Memory Management
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
         "LargeSystemCache", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
         "IoPageLockLimit", winreg.REG_DWORD, 983040),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
         "ClearPageFileAtShutdown", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
         "DisablePagingExecutive", winreg.REG_DWORD, 1),
        
        # Prefetch and SuperFetch
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
         "EnablePrefetcher", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
         "EnableSuperfetch", winreg.REG_DWORD, 0),
        
        # Multimedia System Profile for Gaming
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
         "SystemResponsiveness", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
         "GPU Priority", winreg.REG_DWORD, 8),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
         "Priority", winreg.REG_DWORD, 6),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
         "Scheduling Category", winreg.REG_SZ, "High"),
        
        # Graphics Drivers
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
         "HwSchMode", winreg.REG_DWORD, 2),
        
        # Disable Hibernation
        (winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Power",
         "HibernateEnabled", winreg.REG_DWORD, 0),
        
        # Disable Automatic Maintenance
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance",
         "MaintenanceDisabled", winreg.REG_DWORD, 1),
        
        # Disable Timeline
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Policies\Microsoft\Windows\System",
         "EnableActivityFeed", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Policies\Microsoft\Windows\System",
         "PublishUserActivities", winreg.REG_DWORD, 0),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Policies\Microsoft\Windows\System",
         "UploadUserActivities", winreg.REG_DWORD, 0),
        
        # Disable Location Services
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
         "Value", winreg.REG_SZ, "Deny"),
    ]
    for hive, key_path, name, value_type, value in registry_modifications:
        try:
            logger.info(f"Applying registry tweak: {key_path}\\{name} = {value!r} (type={value_type})")
            set_value(hive, key_path, name, value, value_type)
            logger.info(f"Successfully set {name}")
        except Exception as e:
            logger.error(f"Failed to apply registry tweak {name}: {e}")
            try:
                show_error_popup(
                    f"Failed to apply registry tweak:\n{key_path}\\{name}\n\n{e}",
                    allow_continue=False
                )
            except Exception:
                pass
            sys.exit(1)

    logger.info("All registry tweaks applied successfully.")



if __name__ == "__main__":
    main()
