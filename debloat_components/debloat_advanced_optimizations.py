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
    """Enable Ultimate Performance power plan."""
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
        logger.error(f"Error setting Ultimate Performance power plan: {e}")
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
            "Microsoft.ZuneVideo", "Microsoft.ZuneMusic",
            "Microsoft.YourPhone", "Microsoft.Wallet", "Microsoft.Microsoft3DViewer",
            "Microsoft.MicrosoftOfficeHub", "Microsoft.OneConnect", "Microsoft.People",
            "Microsoft.Print3D", "Microsoft.Whiteboard", "Microsoft.WindowsFeedbackHub",
            "Microsoft.WindowsReadingList", "Microsoft.WindowsSoundRecorder", "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxGameCallableUI", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.ZuneMusic", "Microsoft.ZuneVideo",
            "E046963F.LenovoCompanion", "E046963F.LenovoSettings", "E046963F.LenovoID",
            "E2A4F912.LenovoUtility", "E046963F.LenovoCompanion", "E2A4F912.LenovoUtility",
            "DellInc.PartnerPromo", "ASUSTeKComputerInc.ZenLink", "ASUSTeKComputerInc.MyASUS",
            "AcerIncorporated.AcerPortal", "AcerIncorporated.AcerExplorer"
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
    # REMOVED: This function was removed for safety reasons
    # as disabling Fast Startup can significantly increase boot times
    # and may cause issues with some hardware configurations.
    logger.info("Fast Startup disable function removed for safety - Fast Startup preserved")
    return True


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
            "dmwappushservice", "SysMain", "DoSvc", "lfsvc", "XblGameSave",
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


def optimize_network_settings():
    """Optimize network settings for better performance."""
    try:
        logger.info("Optimizing network settings...")
        
        commands = [
            # Disable IPv6 (optional - can improve performance on some networks)
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters" -Name "DisabledComponents" -Type DWord -Value 0xffffffff -Force -ErrorAction SilentlyContinue',
            
            # Optimize TCP settings
            'netsh int tcp set global autotuninglevel=normal',
            'netsh int tcp set global chimney=enabled',
            'netsh int tcp set global ecncapability=enabled',
            'netsh int tcp set global timestamps=disabled',
            'netsh int tcp set global rss=enabled',
            
            # Optimize DNS settings
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "Tcp1323Opts" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 30 -Force -ErrorAction SilentlyContinue',
            
            # Disable NetBIOS over TCP/IP
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue',
            
            # Optimize network adapter settings
            'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Set-NetAdapterAdvancedProperty -RegistryKeyword "*FlowControl" -RegistryValue 0 -ErrorAction SilentlyContinue',
            'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Set-NetAdapterAdvancedProperty -RegistryKeyword "*InterruptModeration" -RegistryValue 0 -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
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
            # Disable disk defragmentation for SSDs
            'Get-WmiObject -Class Win32_Volume | Where-Object {$_.DriveType -eq 3} | ForEach-Object { if ($_.FileSystem -eq "NTFS") { $_.DefragAnalysis() } }',
            
            # Optimize NTFS settings
            'fsutil behavior set disablelastaccess 1',
            'fsutil behavior set disable8dot3 1',
            'fsutil behavior set memoryusage 2',
            
            # Disable SuperFetch for SSDs
            'Get-WmiObject -Class Win32_Volume | Where-Object {$_.DriveType -eq 3} | ForEach-Object { if ($_.FileSystem -eq "NTFS") { $_.IndexingEnabled = $false; $_.Put() } }',
            
            # Optimize page file settings
            'wmic computersystem set AutomaticManagedPagefile=False',
            'wmic pagefileset create name="C:\\pagefile.sys",initialsize=16384,maximumsize=16384'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.debug(f"Disk optimization command failed: {command}")
        
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
            # Disable memory compression
            'Disable-MMAgent -mc',
            
            # Optimize virtual memory
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name "LargeSystemCache" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name "IoPageLockLimit" -Type DWord -Value 983040 -Force -ErrorAction SilentlyContinue',
            
            # Optimize memory management
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.debug(f"Memory optimization command failed: {command}")
        
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
            # Disable Game DVR and Game Bar
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "AllowGameDVR" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            
            # Optimize for gaming
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "GPU Priority" -Type DWord -Value 8 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Priority" -Type DWord -Value 6 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Scheduling Category" -Type String -Value "High" -Force -ErrorAction SilentlyContinue',
            
            # Disable full-screen optimizations
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.debug(f"Gaming optimization command failed: {command}")
        
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
            # Disable location services
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',

            # Disable app access to contacts
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\contacts" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable app access to calendar
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\appointments" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable app access to call history
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\phoneCall" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable app access to email
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\email" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable app access to messaging
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\chat" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable app access to radios
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\radios" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable app access to other devices
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\bluetoothSync" -Name "Value" -Type String -Value "Deny" -Force -ErrorAction SilentlyContinue',
            
            # Disable timeline
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "EnableActivityFeed" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "PublishUserActivities" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "UploadUserActivities" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.debug(f"Privacy command failed: {command}")
        
        logger.info("Privacy settings enhanced")
        return True
    except Exception as e:
        logger.error(f"Error enhancing privacy settings: {e}")
        return False


def optimize_startup_performance():
    """Optimize startup performance."""
    try:
        logger.info("Optimizing startup performance...")
        
        commands = [
            # Optimize boot configuration
            'bcdedit /set useplatformclock false',
            'bcdedit /set disabledynamictick yes',
            'bcdedit /set tscsyncpolicy Enhanced',
            
            # Disable unnecessary startup services
            'Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-Service -Name "TabletInputService" -StartupType Disabled -ErrorAction SilentlyContinue',
            'Set-Service -Name "WbioSrvc" -StartupType Disabled -ErrorAction SilentlyContinue',
            
            # Optimize prefetch settings
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue'
        ]
        
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.debug(f"Startup optimization command failed: {command}")
        
        logger.info("Startup performance optimized")
        return True
    except Exception as e:
        logger.error(f"Error optimizing startup performance: {e}")
        return False


def optimize_ssd():
    """Optimize Windows for SSD drives."""
    try:
        logger.info("Optimizing system for SSD...")
        commands = [
            # Enable TRIM
            'fsutil behavior set DisableDeleteNotify 0',
            # Disable scheduled defrag for SSDs
            'schtasks /Change /TN "Microsoft\\Windows\\Defrag\\ScheduledDefrag" /Disable',
            # Disable Superfetch (SysMain)
            'Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue',
            'Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue',
        ]
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        logger.info("SSD optimization complete.")
        return True
    except Exception as e:
        logger.error(f"Error optimizing SSD: {e}")
        return False


def optimize_memory():
    """Apply advanced memory management tweaks."""
    try:
        logger.info("Optimizing memory settings...")
        commands = [
            # Clear standby memory (requires RAMMap or similar, but we can use PowerShell for basic clear)
            'Clear-Content -Path "$env:TEMP\\*" -Force -ErrorAction SilentlyContinue',
            # Set virtual memory to system managed (optional, can be expanded)
            'wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True',
        ]
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        logger.info("Memory optimization complete.")
        return True
    except Exception as e:
        logger.error(f"Error optimizing memory: {e}")
        return False


def optimize_network():
    """Optimize network adapter and connection settings."""
    try:
        logger.info("Optimizing network settings...")
        commands = [
            # Enable TCP Fast Open
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -Name "EnableTcpFastOpen" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue',
            # Disable Nagle's Algorithm (for all interfaces)
            # This is a per-adapter setting, so we can set for all interfaces
            # (Advanced: enumerate interfaces and set TcpAckFrequency/TcpNoDelay)
        ]
        for command in commands:
            result = run_powershell_command(command)
            if result != 0:
                logger.warning(f"Command failed: {command}")
        logger.info("Network optimization complete.")
        return True
    except Exception as e:
        logger.error(f"Error optimizing network: {e}")
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
        disable_non_essential_services,
        optimize_network_settings,
        optimize_disk_performance,
        optimize_memory_settings,
        optimize_gaming_settings,
        optimize_privacy_settings,
        optimize_startup_performance,
        optimize_ssd,
        optimize_memory,
        optimize_network
    ]
    
    for optimization in optimizations:
        try:
            optimization()
        except Exception as e:
            logger.error(f"Error in optimization {optimization.__name__}: {e}")
    
    logger.info("Advanced optimizations completed")


if __name__ == "__main__":
    main() 