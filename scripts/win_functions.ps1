# Winzilla Functions - Clean PowerShell Functions for Windows Optimization
# Removed all UI components, keeping only the core optimization functions

function ultimatePowerPlan {
    Write-Host "Executing ultimatePowerPlan function..."
    Write-Host "Checking if Ultimate Performance plan is available..."

    $powerPlans = powercfg /list

    if ($powerPlans -notmatch "Ultimate Performance") {
        $currentPlan = powercfg /getactivescheme

        if ($currentPlan -notmatch "06306d31-12c8-4900-86c3-92406571b6fe") {
            Write-Host "Enabling Ultimate Performance plan..."
            powercfg -setactive 06306d31-12c8-4900-86c3-92406571b6fe
            Write-Host "================================="
            Write-Host "--- Set Ultimate Power Plan ---"
            Write-Host "================================="
        }
        else {
            Write-Host "Ultimate Performance plan is already active."
        }
    }
    else {
        Write-Host "Ultimate Performance plan is not available on this system."
    }
    Write-Host "ultimatePowerPlan function completed."
}

function defenderTweaks {
    Write-Host "Executing defenderTweaks function..."
    Stop-Service -Name "WinDefend" -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue

    Set-Service -Name "WinDefend" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue

    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -ErrorAction SilentlyContinue
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Provider -eq 'Microsoft.PowerShell.Core\FileSystem' }

    foreach ($drive in $drives) {
        Write-Host "Adding $($drive.Name):\ to Windows Defender exclusions..."
        Set-MpPreference -ExclusionPath "$($drive.Name):\" -ErrorAction SilentlyContinue
    }

    Write-Host "All detected drives have been added to Windows Defender exclusions."
    Write-Host "Windows Defender has been disabled permanently."
    Write-Host "defenderTweaks function completed."
}

function uninstallUWPApps {
    Write-Host "Executing uninstallUWPApps function..."
    $appsToRemove = @(
        "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.GetHelp",
        "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MicrosoftStickyNotes", "Microsoft.MixedReality.Portal", "Microsoft.MSPaint",
        "Microsoft.Office.OneNote", "Microsoft.People", "Microsoft.SkypeApp",
        "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera", "Microsoft.WindowsMaps",
        "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI", "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.ZuneVideo", "Microsoft.ZuneMusic"
    )

    foreach ($app in $appsToRemove) {
        Write-Host "Attempting to remove $app..."
        Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        if ($LASTEXITCODE -eq 0) {
            Write-Host "$app removed successfully."
        }
        else {
            Write-Host "Could not remove $app (possibly not installed or already removed)." -ForegroundColor Yellow
        }
    }
    Write-Host "uninstallUWPApps function completed."
}

function disableCortana {
    Write-Host "Executing disableCortana function..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Cortana has been disabled."
    Write-Host "disableCortana function completed."
}

function disableTelemetry {
    Write-Host "Executing disableTelemetry function..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "CommercialDataOptIn" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\Applicability" -Name "TelemetryConsent" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "Telemetry and Data Collection disabled."
    Write-Host "disableTelemetry function completed."
}

function disableTaskbarIcons {
    Write-Host "Executing disableTaskbarIcons function..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_MEETNOW_ENABLED" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Write-Host "Meet Now and News and Interests taskbar icons disabled."
    Write-Host "disableTaskbarIcons function completed."
}

function disableAdsTracking {
    Write-Host "Executing disableAdsTracking function..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Write-Host "Targeted Ads and Tracking disabled."
    Write-Host "disableAdsTracking function completed."
}

function disableSearchIndexing {
    Write-Host "Executing disableSearchIndexing function..."
    Get-WmiObject -Class Win32_Volume | Where-Object { $_.DriveType -eq 3 -and $_.IndexingEnabled -eq $true } | ForEach-Object {
        Write-Host "Disabling indexing on drive $($_.DriveLetter)..."
        $_.IndexingEnabled = $false
        $_.Put() | Out-Null
    }
    Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name "WSearch" -Force -ErrorAction SilentlyContinue
    Write-Host "Search Indexing disabled on all local drives."
    Write-Host "disableSearchIndexing function completed."
}

function cleanTempFiles {
    Write-Host "Executing cleanTempFiles function..."
    $tempPaths = @(
        "$env:TEMP\*"
        "$env:SystemRoot\Temp\*"
        "$env:HomeDrive\Users\Default\AppData\Local\Temp\*"
        "$env:HomeDrive\Users\Public\AppData\Local\Temp\*"
    )

    foreach ($path in $tempPaths) {
        Write-Host "Cleaning $path..."
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "Cleaning WinSxS (Component Store)..."
    Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase -ErrorAction SilentlyContinue

    Write-Host "Cleaning Windows Update Cache..."
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service -Name "wuauserv" -ErrorAction SilentlyContinue

    Write-Host "Temporary files and system files cleaned."
    Write-Host "cleanTempFiles function completed."
}

function disableDeliveryOptimization {
    Write-Host "Executing disableDeliveryOptimization function..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMaxBackgroundUploadBandwidth" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DOMaxForegroundUploadBandwidth" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Write-Host "Delivery Optimization disabled."
    Write-Host "disableDeliveryOptimization function completed."
}

function disableSuggestedContent {
    Write-Host "Executing disableSuggestedContent function..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338390Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338391Enabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
    Write-Host "Suggested content and tips disabled."
    Write-Host "disableSuggestedContent function completed."
}

function clearDNSCache {
    Write-Host "Executing clearDNSCache function..."
    ipconfig /flushdns
    Write-Host "DNS Cache cleared."
    Write-Host "clearDNSCache function completed."
}

function disableFastStartup {
    Write-Host "Executing disableFastStartup function..."
    powercfg /h off
    Write-Host "Fast Startup disabled."
    Write-Host "disableFastStartup function completed."
}

function disableAutomaticMaintenance {
    Write-Host "Executing disableAutomaticMaintenance function..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
    Write-Host "Automatic Maintenance disabled."
    Write-Host "disableAutomaticMaintenance function completed."
}

function disableMoreNonEssentialServices {
    Write-Host "Executing disableMoreNonEssentialServices function..."

    Set-Service -Name "Fax" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "Print Spooler" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "TabletInputService" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "DoSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "cbdhsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "lfsvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "XblGameSave" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "XboxGipSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "XboxNetApiSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "GamingServices" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "GamingServicesNet" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "PimIndexMaintenanceSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "UserDataSvc" -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service -Name "UnistoreSvc" -StartupType Disabled -ErrorAction SilentlyContinue

    Write-Host "Non-essential services disabled."
    Write-Host "disableMoreNonEssentialServices function completed."
}

# Main optimization function that runs all optimizations
function runAllOptimizations {
    Write-Host "Starting comprehensive Windows optimization..."
    
    ultimatePowerPlan
    defenderTweaks
    uninstallUWPApps
    disableCortana
    disableTelemetry
    disableTaskbarIcons
    disableAdsTracking
    disableSearchIndexing
    cleanTempFiles
    disableDeliveryOptimization
    disableSuggestedContent
    clearDNSCache
    disableFastStartup
    disableAutomaticMaintenance
    disableMoreNonEssentialServices
    
    Write-Host "All optimizations completed successfully!"
} 