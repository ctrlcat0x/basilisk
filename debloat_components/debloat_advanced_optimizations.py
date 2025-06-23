"""
Advanced Windows Optimization Functions
Integrates additional optimization functions from win.ps1
"""

import subprocess
import os
from utilities.util_logger import logger
from utilities.util_powershell_handler import run_powershell_command


def create_system_restore_point():
    """Create a system restore point before making changes."""
    try:
        logger.info("Creating system restore point...")
        
        # First, check if System Restore service is running
        check_service_command = 'Get-Service -Name "VSS" | Where-Object {$_.Status -eq "Running"} | Select-Object -First 1'
        service_running = run_powershell_command(check_service_command, allow_continue_on_fail=True)
        
        # If service is not running, try to enable it
        if service_running != 0:
            logger.info("System Restore service is not running, attempting to enable it...")
            enable_service_commands = [
                'Set-Service -Name "VSS" -StartupType Automatic -ErrorAction SilentlyContinue',
                'Start-Service -Name "VSS" -ErrorAction SilentlyContinue'
            ]
            
            for cmd in enable_service_commands:
                result = run_powershell_command(cmd, allow_continue_on_fail=True)
                if result == 0:
                    logger.info("System Restore service enabled successfully")
                    break
            else:
                logger.warning("Could not enable System Restore service - continuing without restore point")
                return True  # Continue anyway
        
        # Now try to create the restore point
        command = 'Checkpoint-Computer -Description "Basilisk Restore Point" -RestorePointType "MODIFY_SETTINGS"'
        result = run_powershell_command(command, allow_continue_on_fail=True)
        
        if result == 0:
            logger.info("System restore point created successfully")
        else:
            logger.warning("Failed to create system restore point - continuing without it")
        
        return True  # Continue anyway, don't fail the entire process
            
    except Exception as e:
        logger.error(f"Error creating restore point: {e}")
        logger.warning("Continuing without system restore point")
        return True  # Continue anyway, don't fail the entire process


def set_ultimate_power_plan():
    """Enable Ultimate Performance power plan."""
    try:
        logger.info("Setting Ultimate Performance power plan...")
        
        # Check if Ultimate Performance plan exists in the list
        list_command = 'powercfg /list | Select-String "Ultimate Performance"'
        list_result = run_powershell_command(list_command, allow_continue_on_fail=True)
        
        # If Ultimate Performance is NOT in the list, try to add it
        if list_result != 0:
            logger.info("Ultimate Performance plan not found, attempting to add it...")
            
            # Try to duplicate the Ultimate Performance scheme (this only works if it exists in the system)
            duplicate_command = 'powercfg -duplicatescheme 06306d31-12c8-4900-86c3-92406571b6fe'
            duplicate_result = run_powershell_command(duplicate_command, allow_continue_on_fail=True)
            
            if duplicate_result == 0:
                logger.info("Ultimate Performance plan added successfully")
                # Now try to enable it
                enable_command = 'powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe'
                enable_result = run_powershell_command(enable_command, allow_continue_on_fail=True)
                if enable_result == 0:
                    logger.info("Ultimate Performance power plan enabled")
                else:
                    logger.warning("Failed to enable Ultimate Performance power plan")
            else:
                logger.info("Ultimate Performance plan is not available on this system")
                # Try to enable it directly anyway (in case it exists but wasn't found by name)
                enable_command = 'powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe'
                enable_result = run_powershell_command(enable_command, allow_continue_on_fail=True)
                if enable_result == 0:
                    logger.info("Ultimate Performance power plan enabled via GUID")
                else:
                    logger.info("Ultimate Performance plan is not available on this system")
        else:
            # Ultimate Performance is in the list, check if it's already active
            current_plan_command = 'powercfg /getactivescheme | Select-String "06306d31-12c8-4900-86c3-92406571b6fe"'
            current_result = run_powershell_command(current_plan_command, allow_continue_on_fail=True)
            
            if current_result != 0:
                # Enable Ultimate Performance plan
                enable_command = 'powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe'
                result = run_powershell_command(enable_command, allow_continue_on_fail=True)
                if result == 0:
                    logger.info("Ultimate Performance power plan enabled")
                else:
                    logger.warning("Failed to enable Ultimate Performance power plan")
            else:
                logger.info("Ultimate Performance power plan already active")
        
        return True
    except Exception as e:
        logger.error(f"Error setting Ultimate Performance power plan: {e}")
        return False


def uninstall_uwp_apps():
    """Uninstall pre-installed UWP apps."""
    logger.info("Uninstalling UWP apps...")
    try:
        apps_to_remove_set = {
            # General Microsoft Bloatware
            "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp",
            "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes", "Microsoft.MixedReality.Portal", "Microsoft.MSPaint",
            "Microsoft.Office.OneNote", "Microsoft.People", "Microsoft.SkypeApp",
            "Microsoft.WindowsAlarms", "Microsoft.WindowsMaps",
            "Microsoft.WindowsSoundRecorder", "Microsoft.YourPhone", "Microsoft.Wallet", 
            "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub", "Microsoft.OneConnect",
            "Microsoft.Print3D", "Microsoft.Whiteboard", "Microsoft.WindowsFeedbackHub",
            "Microsoft.WindowsReadingList", "Microsoft.ZuneVideo", "Microsoft.ZuneMusic",
            "Microsoft.549981C3F5F10", "Microsoft.Todos", "Microsoft.PowerAutomateDesktop",
            "Microsoft.Clipchamp", "MicrosoftTeams",

            # Specific Xbox / Gaming apps (safer to remove)
            "Microsoft.Xbox.TCUI", 
            "Microsoft.XboxApp", 
            "Microsoft.XboxSpeechToTextOverlay",
            
            # OEM Bloatware
            "E046963F.LenovoCompanion", "E046963F.LenovoSettings", "E046963F.LenovoID",
            "E2A4F912.LenovoUtility", "DellInc.PartnerPromo", "ASUSTeKComputerInc.ZenLink", 
            "ASUSTeKComputerInc.MyASUS", "AcerIncorporated.AcerPortal", "AcerIncorporated.AcerExplorer"
        }
        apps_to_remove = sorted(list(apps_to_remove_set))
        for app in apps_to_remove:
            logger.debug(f"Attempting to remove {app}...")
            command = f'Get-AppxPackage -Name "{app}" | Remove-AppxPackage -ErrorAction SilentlyContinue; Get-AppxPackage -AllUsers -Name "{app}" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue'
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result == 0:
                logger.info(f"Removed {app}")
            else:
                logger.debug(f"Could not remove {app} (possibly not installed or system app)")
        logger.info("UWP apps uninstallation completed")
        return True
    except Exception as e:
        logger.error(f"Error uninstalling UWP apps: {e}")
        return True  # Only return False on a true Python exception, but do not stop the debloat sequence


def disable_cortana():
    """Disable Cortana and Windows Search."""
    try:
        logger.info("Disabling Cortana...")
        
        commands = [
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" -Name "CortanaConsent" -Type DWord -Value 0 -ErrorAction SilentlyContinue',
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Cortana disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling Cortana: {e}")
        return False


def disable_telemetry():
    """Disable telemetry and data collection."""
    try:
        logger.info("Disabling telemetry...")
        
        commands = [
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" -Name "CommercialDataOptIn" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\WindowsSelfHost\\Applicability" -Name "TelemetryConsent" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue',
            'Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue',
            'Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Telemetry disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling telemetry: {e}")
        return False


def disable_ads_tracking():
    """Disable targeted ads and tracking."""
    try:
        logger.info("Disabling ads and tracking...")
        
        commands = [
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Ads and tracking disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling ads and tracking: {e}")
        return False


def disable_search_indexing():
    """Disable search indexing on all drives."""
    try:
        logger.info("Disabling search indexing...")
        
        command = '''
        Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 -and $_.IndexingEnabled -eq $true } | ForEach-Object {
            $_.IndexingEnabled = $false
            $_.Put() | Out-Null
        }
        Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
        '''
        
        result = run_powershell_command(command, allow_continue_on_fail=True)
        if result == 0:
            logger.info("Search indexing disabled")
        else:
            logger.warning("Failed to disable search indexing")
        
        return result == 0
    except Exception as e:
        logger.error(f"Error disabling search indexing: {e}")
        return False


def clean_temp_files():
    """Clean temporary files and system cache."""
    try:
        logger.info("Cleaning temporary files... (Note: Some files may be in use and cannot be deleted, this is normal)")
        
        commands = [
            # The error in your log comes from here. Files can be locked by the system.
            # This is not a critical failure. The command will skip locked files.
            'Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue',
            'Get-ChildItem -Path "$env:SystemRoot\\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue',
            'Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase'
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"A cleanup command reported a non-critical issue (e.g. file in use): {command}")
        
        logger.info("Temporary files cleaned.")
        return True
    except Exception as e:
        logger.error(f"Error cleaning temp files: {e}")
        return False


def disable_delivery_optimization():
    """Disable Windows Delivery Optimization."""
    try:
        logger.info("Disabling delivery optimization...")
        
        commands = [
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config" -Name "DODownloadMode" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization" -Name "DOMaxBackgroundUploadBandwidth" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization" -Name "DOMaxForegroundUploadBandwidth" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Delivery optimization disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling delivery optimization: {e}")
        return False


def disable_suggested_content():
    """Disable suggested content and tips."""
    try:
        logger.info("Disabling suggested content...")
        
        commands = [
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            run_powershell_command(command, allow_continue_on_fail=True)
        
        logger.info("Suggested content disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling suggested content: {e}")
        return False


def clear_dns_cache():
    """Clear DNS cache."""
    try:
        logger.info("Clearing DNS cache...")
        # Use the native PowerShell cmdlet which is more reliable than ipconfig
        result = run_powershell_command('Clear-DnsClientCache', allow_continue_on_fail=True)
        if result == 0:
            logger.info("DNS cache cleared")
        else:
            logger.warning("Failed to clear DNS cache (this may happen if the DNS Client service is not running)")
        return True # Always continue
    except Exception as e:
        logger.error(f"Error clearing DNS cache: {e}")
        return True # Continue anyway



def disable_automatic_maintenance():
    """Disable automatic maintenance."""
    try:
        logger.info("Disabling automatic maintenance...")
        command = 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance" -Name "MaintenanceDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue'
        result = run_powershell_command(command, allow_continue_on_fail=True)
        if result == 0:
            logger.info("Automatic maintenance disabled")
        else:
            logger.warning("Failed to disable automatic maintenance")
        return True
    except Exception as e:
        logger.error(f"Error disabling automatic maintenance: {e}")
        return False


def disable_non_essential_services():
    """Disable non-essential Windows services."""
    try:
        logger.info("Disabling non-essential services...")
        
        services = [
            "Fax", "RemoteRegistry", "Print Spooler", "TabletInputService", "DiagTrack",
            "dmwappushservice", "SysMain", "DoSvc", "lfsvc", "XblGameSave",
            "XboxGipSvc", "XboxNetApiSvc", "GamingServices", "GamingServicesNet",
            "PimIndexMaintenanceSvc", "UserDataSvc", "UnistoreSvc"
        ]
        
        for service in services:
            command = f'Set-Service -Name "{service}" -StartupType Disabled -ErrorAction SilentlyContinue'
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.debug(f"Failed to disable service: {service} (it may not exist on this system)")
        
        logger.info("Non-essential services disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling non-essential services: {e}")
        return False


def optimize_network_settings():
    """Optimize network settings for better performance."""
    try:
        logger.info("Optimizing network settings...")
        
        commands = [
            'netsh int tcp set global autotuninglevel=normal',
            'netsh int tcp set global chimney=enabled',
            'netsh int tcp set global ecncapability=enabled',
            'netsh int tcp set global timestamps=disabled',
            'netsh int tcp set global rss=enabled',
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.debug(f"Network command failed: {command}")
        
        logger.info("Network settings optimized")
        return True
    except Exception as e:
        logger.error(f"Error optimizing network settings: {e}")
        return False


def optimize_disk_performance():
    """Optimize disk performance settings."""
    try:
        logger.info("Optimizing disk performance...")
        
        commands = [
            # Optimize NTFS settings for performance by disabling last access timestamps
            'fsutil behavior set disablelastaccess 1',
            'fsutil behavior set memoryusage 2',
            
            # NOTE: Pagefile modifications were removed due to risk.
            # Hardcoding a pagefile size is dangerous and can cause system instability.
            # Pagefile is now set to 'System Managed' in the optimize_memory function for safety.
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Disk optimization command failed: {command}")
        
        logger.info("Disk performance optimized")
        return True
    except Exception as e:
        logger.error(f"Error optimizing disk performance: {e}")
        return False


def optimize_memory_settings():
    """Optimize memory and virtual memory settings."""
    try:
        logger.info("Optimizing memory settings...")
        
        commands = [
            # Disable memory compression (can improve performance on some systems)
            'Disable-MMAgent -mc',
            # Set virtual memory (pagefile) to be managed by the system.
            # This is the safest setting and avoids issues with fixed-size pagefiles.
            'wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True',
            # Optimize memory management
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Memory optimization command failed: {command}")
        
        logger.info("Memory settings optimized")
        return True
    except Exception as e:
        logger.error(f"Error optimizing memory settings: {e}")
        return False


def optimize_gaming_settings():
    """Optimize settings for gaming performance."""
    try:
        logger.info("Optimizing gaming settings...")
        
        commands = [
              # Disable unnecessary startup services
            'Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-Service -Name "TabletInputService" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-Service -Name "WbioSrvc" -StartupType Disabled -ErrorAction SilentlyContinue',
            # Disable Game DVR and Game Bar via registry
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            
            # Prioritize games for system resources
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "GPU Priority" -Type DWord -Value 8 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Priority" -Type DWord -Value 6 -Force -ErrorAction SilentlyContinue',
        ]
        
        for command in commands:
            run_powershell_command(command, allow_continue_on_fail=True)
        
        logger.info("Gaming settings optimized")
        return True
    except Exception as e:
        logger.error(f"Error optimizing gaming settings: {e}")
        return False


def optimize_privacy_settings():
    """Enhance privacy settings beyond basic telemetry."""
    try:
        logger.info("Enhancing privacy settings...")
        
        commands = [
            # Disable app access to sensitive info
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\contacts" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\appointments" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable timeline (activity feed)
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "EnableActivityFeed" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "PublishUserActivities" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "UploadUserActivities" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            run_powershell_command(command, allow_continue_on_fail=True)
        
        logger.info("Privacy settings enhanced")
        return True
    except Exception as e:
        logger.error(f"Error enhancing privacy settings: {e}")
        return False


def optimize_ssd():
    """Optimize Windows for SSD drives."""
    try:
        logger.info("Optimizing system for SSD...")
        commands = [
            # Ensure TRIM is enabled
            'fsutil behavior set DisableDeleteNotify 0',
            # Disable scheduled defrag task for SSDs
            'schtasks /Change /TN "Microsoft\\Windows\\Defrag\\ScheduledDefrag" /Disable',
            # Disable Superfetch (SysMain)
            'Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue',
            'Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue',
        ]
        for command in commands:
            result = run_powershell_command(command, allow_continue_on_fail=True)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        logger.info("SSD optimization complete.")
        return True
    except Exception as e:
        logger.error(f"Error optimizing SSD: {e}")
        return False


def main():
    """Run all advanced optimizations."""
    logger.info("Starting advanced Windows optimizations...")
    
    # Run all optimizations
    optimizations = [
        set_ultimate_power_plan,
        uninstall_uwp_apps,
        disable_cortana,
        disable_telemetry,
        disable_ads_tracking,
        disable_search_indexing,
        clean_temp_files,
        disable_delivery_optimization,
        disable_suggested_content,
        clear_dns_cache,
        disable_automatic_maintenance,
        disable_non_essential_services,
        optimize_network_settings,
        optimize_disk_performance,
        optimize_memory_settings,
        optimize_gaming_settings,
        optimize_privacy_settings,
        optimize_ssd
    ]
    
    for optimization in optimizations:
        try:
            success = optimization()
            if not success:
                logger.warning(f"Optimization '{optimization.__name__}' encountered an error but the script will continue.")
        except Exception as e:
            logger.error(f"A critical error occurred in optimization '{optimization.__name__}': {e}")
    
    logger.info("Advanced optimizations completed")


if __name__ == "__main__":
    main() 