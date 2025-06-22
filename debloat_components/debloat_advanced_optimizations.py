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
        command = 'Checkpoint-Computer -Description "Basilisk Restore Point" -RestorePointType "MODIFY_SETTINGS"'
        result = run_powershell_command(command)
        if result == 0:
            logger.info("System restore point created successfully")
        else:
            logger.warning("Failed to create system restore point")
        return result == 0
    except Exception as e:
        logger.error(f"Error creating restore point: {e}")
        return False


def set_ultimate_power_plan():
    """Enable Ultimate Performance power plan if available."""
    try:
        logger.info("Setting Ultimate Performance power plan...")
        
        # Check if Ultimate Performance plan exists in the list
        list_command = 'powercfg /list | Select-String "Ultimate Performance"'
        list_result = run_powershell_command(list_command)
        
        # If Ultimate Performance is NOT in the list, try to add it
        if list_result != 0:
            logger.info("Ultimate Performance plan not found, attempting to add it...")
            
            # Try to duplicate the Ultimate Performance scheme (this only works if it exists in the system)
            duplicate_command = 'powercfg -duplicatescheme 06306d31-12c8-4900-86c3-92406571b6fe'
            duplicate_result = run_powershell_command(duplicate_command)
            
            if duplicate_result == 0:
                logger.info("Ultimate Performance plan added successfully")
                # Now try to enable it
                enable_command = 'powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe'
                enable_result = run_powershell_command(enable_command)
                if enable_result == 0:
                    logger.info("Ultimate Performance power plan enabled")
                else:
                    logger.warning("Failed to enable Ultimate Performance power plan")
            else:
                logger.info("Ultimate Performance plan is not available on this system")
                # Try to enable it directly anyway (in case it exists but wasn't found by name)
                enable_command = 'powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe'
                enable_result = run_powershell_command(enable_command)
                if enable_result == 0:
                    logger.info("Ultimate Performance power plan enabled via GUID")
                else:
                    logger.info("Ultimate Performance plan is not available on this system")
        else:
            # Ultimate Performance is in the list, check if it's already active
            current_plan_command = 'powercfg /getactivescheme | Select-String "06306d31-12c8-4900-86c3-92406571b6fe"'
            current_result = run_powershell_command(current_plan_command)
            
            if current_result != 0:
                # Enable Ultimate Performance plan
                enable_command = 'powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe'
                result = run_powershell_command(enable_command)
                if result == 0:
                    logger.info("Ultimate Performance power plan enabled")
                else:
                    logger.warning("Failed to enable Ultimate Performance power plan")
            else:
                logger.info("Ultimate Performance power plan already active")
        
        return True
    except Exception as e:
        logger.error(f"Error setting power plan: {e}")
        return False


def disable_windows_defender():
    """Disable Windows Defender and add exclusions."""
    try:
        logger.info("Disabling Windows Defender...")
        
        commands = [
            'Stop-Service -Name "WinDefend" -Force -ErrorAction SilentlyContinue',
            'Set-Service -Name "WinDefend" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue',
            'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features" -Name "TamperProtection" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue',
            'New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "DisableAntiVirus" -Value 1 -ErrorAction SilentlyContinue'
        ]
        
        # Add drive exclusions
        drives_command = '''
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Provider -eq 'Microsoft.PowerShell.Core\\FileSystem' }
        foreach ($drive in $drives) {
            Set-MpPreference -ExclusionPath "$($drive.Name):\\" -ErrorAction SilentlyContinue
        }
        '''
        commands.append(drives_command)
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Windows Defender disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling Windows Defender: {e}")
        return False


def uninstall_uwp_apps():
    """Uninstall pre-installed UWP apps."""
    try:
        logger.info("Uninstalling UWP apps...")
        
        apps_to_remove = [
            "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp",
            "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes", "Microsoft.MixedReality.Portal", "Microsoft.MSPaint",
            "Microsoft.Office.OneNote", "Microsoft.People", "Microsoft.SkypeApp",
            "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", "Microsoft.WindowsMaps",
            "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.ZuneVideo", "Microsoft.ZuneMusic"
        ]
        
        for app in apps_to_remove:
            command = f'Get-AppxPackage -Name "{app}" | Remove-AppxPackage -ErrorAction SilentlyContinue; Get-AppxPackage -AllUsers -Name "{app}" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue'
            result = run_powershell_command(command)
            if result == 0:
                logger.info(f"Removed {app}")
            else:
                logger.debug(f"Could not remove {app} (possibly not installed)")
        
        logger.info("UWP apps uninstallation completed")
        return True
    except Exception as e:
        logger.error(f"Error uninstalling UWP apps: {e}")
        return False


def disable_cortana():
    """Disable Cortana and Windows Search."""
    try:
        logger.info("Disabling Cortana...")
        
        commands = [
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search" -Name "CortanaConsent" -Type DWord -Value 0 -ErrorAction SilentlyContinue',
            'Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue',
            'Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
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
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Telemetry disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling telemetry: {e}")
        return False


def remove_onedrive():
    """Remove OneDrive integration."""
    try:
        logger.info("Removing OneDrive...")
        
        commands = [
            'taskkill /f /im OneDrive.exe /fi "STATUS eq RUNNING" >$null 2>&1',
            'if (Test-Path "$env:SystemRoot\\SysWOW64\\OneDriveSetup.exe") { & "$env:SystemRoot\\SysWOW64\\OneDriveSetup.exe" /uninstall }',
            'if (Test-Path "$env:SystemRoot\\System32\\OneDriveSetup.exe") { & "$env:SystemRoot\\System32\\OneDriveSetup.exe" /uninstall }',
            'Remove-Item -Path "$env:LocalAppData\\Microsoft\\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue',
            'Remove-Item -Path "$env:ProgramData\\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCR:\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCR:\\Wow6432Node\\CLSID\\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("OneDrive removed")
        return True
    except Exception as e:
        logger.error(f"Error removing OneDrive: {e}")
        return False


def disable_taskbar_icons():
    """Disable taskbar icons and features."""
    try:
        logger.info("Disabling taskbar icons...")
        
        commands = [
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings" -Name "NOC_GLOBAL_SETTING_MEETNOW_ENABLED" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Taskbar icons disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling taskbar icons: {e}")
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
            result = run_powershell_command(command)
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
        
        result = run_powershell_command(command)
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
        logger.info("Cleaning temporary files...")
        
        commands = [
            'Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            'Remove-Item -Path "$env:SystemRoot\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            'Remove-Item -Path "$env:HomeDrive\\Users\\Default\\AppData\\Local\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            'Remove-Item -Path "$env:HomeDrive\\Users\\Public\\AppData\\Local\\Temp\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            'Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase -ErrorAction SilentlyContinue',
            'Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue',
            'Remove-Item -Path "$env:SystemRoot\\SoftwareDistribution\\Download\\*" -Recurse -Force -ErrorAction SilentlyContinue',
            'Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Temporary files cleaned")
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
            result = run_powershell_command(command)
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
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338390Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SubscribedContent-338391Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        
        logger.info("Suggested content disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling suggested content: {e}")
        return False


def clear_dns_cache():
    """Clear DNS cache."""
    try:
        logger.info("Clearing DNS cache...")
        result = run_powershell_command('ipconfig /flushdns')
        if result == 0:
            logger.info("DNS cache cleared")
        else:
            logger.warning("Failed to clear DNS cache")
        return result == 0
    except Exception as e:
        logger.error(f"Error clearing DNS cache: {e}")
        return False


def disable_fast_startup():
    """Disable fast startup."""
    try:
        logger.info("Disabling fast startup...")
        result = run_powershell_command('powercfg /h off')
        if result == 0:
            logger.info("Fast startup disabled")
        else:
            logger.warning("Failed to disable fast startup")
        return result == 0
    except Exception as e:
        logger.error(f"Error disabling fast startup: {e}")
        return False


def disable_automatic_maintenance():
    """Disable automatic maintenance."""
    try:
        logger.info("Disabling automatic maintenance...")
        command = 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance" -Name "MaintenanceDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue'
        result = run_powershell_command(command)
        if result == 0:
            logger.info("Automatic maintenance disabled")
        else:
            logger.warning("Failed to disable automatic maintenance")
        return result == 0
    except Exception as e:
        logger.error(f"Error disabling automatic maintenance: {e}")
        return False


def disable_non_essential_services():
    """Disable non-essential Windows services."""
    try:
        logger.info("Disabling non-essential services...")
        
        services = [
            "Fax", "RemoteRegistry", "Print Spooler", "TabletInputService", "DiagTrack",
            "dmwappushservice", "SysMain", "DoSvc", "cbdhsvc", "lfsvc", "XblGameSave",
            "XboxGipSvc", "XboxNetApiSvc", "GamingServices", "GamingServicesNet",
            "PimIndexMaintenanceSvc", "UserDataSvc", "UnistoreSvc"
        ]
        
        for service in services:
            command = f'Set-Service -Name "{service}" -StartupType Disabled -ErrorAction SilentlyContinue'
            result = run_powershell_command(command)
            if result != 0:
                logger.debug(f"Failed to disable service: {service}")
        
        logger.info("Non-essential services disabled")
        return True
    except Exception as e:
        logger.error(f"Error disabling non-essential services: {e}")
        return False


def main():
    """Run all advanced optimizations."""
    logger.info("Starting advanced Windows optimizations...")
    
    # Create restore point first
    create_system_restore_point()
    
    # Run all optimizations
    optimizations = [
        set_ultimate_power_plan,
        disable_windows_defender,
        uninstall_uwp_apps,
        disable_cortana,
        disable_telemetry,
        remove_onedrive,
        disable_taskbar_icons,
        disable_ads_tracking,
        disable_search_indexing,
        clean_temp_files,
        disable_delivery_optimization,
        disable_suggested_content,
        clear_dns_cache,
        disable_fast_startup,
        disable_automatic_maintenance,
        disable_non_essential_services
    ]
    
    for optimization in optimizations:
        try:
            optimization()
        except Exception as e:
            logger.error(f"Error in optimization {optimization.__name__}: {e}")
    
    logger.info("Advanced optimizations completed")


if __name__ == "__main__":
    main() 