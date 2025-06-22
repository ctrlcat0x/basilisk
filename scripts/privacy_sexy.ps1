#requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ProgressPreference = 'SilentlyContinue' 

function Show-SectionHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )
    Write-Host "`n--- $($Title.Trim()) ---" -ForegroundColor Yellow
}

function Clear-DirectoryContents {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$TakeOwnership
    )

    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($Path)
    $targetPath = $expandedPath.TrimEnd('\', '/')
    
    if (-not (Test-Path -LiteralPath $targetPath)) {
        Write-Host "Skipping, path does not exist: $targetPath"
        return
    }
    
    Write-Host "Clearing contents of: $targetPath"
    
    if ($TakeOwnership) {
        Write-Host "Attempting to take ownership of '$targetPath'..."
        try {
            takeown.exe /F $targetPath /R /A /D Y *>&1 | Out-Null
            icacls.exe $targetPath /grant "Administrators:F" /T /C /Q *>&1 | Out-Null
            Write-Verbose "Ownership and permissions applied."
        } catch {
            Write-Warning "Failed to take ownership for '$targetPath'. Deletion may fail. Error: $_"
        }
    }
    
    # Get all child items (files and directories)
    # Sort by FullName length descending to delete contents before their parent folders
    $items = Get-ChildItem -Path $targetPath -Force -Recurse -ErrorAction SilentlyContinue | Sort-Object { $_.FullName.Length } -Descending

    if ($null -eq $items) {
        Write-Host "Directory is already empty or no items found."
        return
    }

    $deletedCount = 0
    $failedCount = 0
    foreach ($item in $items) {
        try {
            Remove-Item -LiteralPath $item.FullName -Force -Recurse -ErrorAction Stop
            Write-Verbose "Successfully deleted: $($item.FullName)"
            $deletedCount++
        }
        catch {
            Write-Warning "Unable to delete: $($item.FullName). Error: $($_.Exception.Message)"
            $failedCount++
        }
    }
    Write-Host "Operation complete. Deleted: $deletedCount, Failed: $failedCount." -ForegroundColor Green
}

function Remove-FileSystemItem {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$TakeOwnership
    )

    $expandedPath = [System.Environment]::ExpandEnvironmentVariables($Path)
    
    if (-not (Test-Path -LiteralPath $expandedPath -PathType Any)) {
        Write-Host "Skipping removal, item does not exist: $expandedPath"
        return
    }
    
    Write-Host "Removing file system item: $expandedPath"
    
    if ($TakeOwnership) {
        Write-Host "Attempting to take ownership of '$expandedPath'..."
        try {
            takeown.exe /F $expandedPath /R /A /D Y *>&1 | Out-Null
            icacls.exe $expandedPath /grant "Administrators:F" /T /C /Q *>&1 | Out-Null
            Write-Verbose "Ownership and permissions applied."
        } catch {
            Write-Warning "Failed to take ownership for '$expandedPath'. Deletion may fail. Error: $_"
        }
    }

    try {
        Remove-Item -LiteralPath $expandedPath -Force -Recurse -ErrorAction Stop
        Write-Host "Successfully removed: $expandedPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to remove '$expandedPath'. Error: $($_.Exception.Message)"
    }
}

function Clear-RegistryKeyValues {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$Recurse
    )
    
    $psPath = $Path -replace '^HKCU', 'HKCU:' -replace '^HKLM', 'HKLM:'
    
    if (-not (Test-Path -LiteralPath $psPath)) {
        Write-Host "Skipping registry clear, key does not exist: $psPath"
        return
    }
    Write-Host "Clearing values from registry key: $psPath"

    try {
        $item = Get-Item -LiteralPath $psPath -ErrorAction Stop
        $valueNames = $item.GetValueNames() | Where-Object { $_ } # Exclude the '(Default)' value

        if ($valueNames.Count -eq 0) {
            Write-Host "Key has no values to clear."
        } else {
            foreach ($valueName in $valueNames) {
                Remove-ItemProperty -LiteralPath $psPath -Name $valueName -Force -ErrorAction SilentlyContinue
            }
            Write-Host "Successfully cleared $($valueNames.Count) values from '$psPath'." -ForegroundColor Green
        }

        if ($Recurse) {
            Get-ChildItem -LiteralPath $psPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                # Recurse manually to provide better logging for each subkey
                Clear-RegistryKeyValues -Path $_.PSPath -Recurse:$false 
            }
        }
    } catch {
        Write-Warning "Could not process registry key '$psPath'. Error: $($_.Exception.Message)"
    }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        $Value,
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryValueKind]$Type
    )
    $psPath = $Path -replace '^HKCU', 'HKCU:' -replace '^HKLM', 'HKLM:'
    Write-Host "Setting registry value '$Name' at '$psPath'."

    try {
        if (-not (Test-Path -LiteralPath $psPath)) {
            New-Item -Path $psPath -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created new registry key: $psPath"
        }
        
        # PowerShell expects a string array for MultiString, not a single string with null chars
        if ($Type -eq 'MultiString' -and $Value -is [string] -and $Value -eq '\0') {
            $Value = @("")
        }

        Set-ItemProperty -LiteralPath $psPath -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Write-Host "Successfully set value." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to set registry value at '$psPath'. Error: $($_.Exception.Message)"
    }
}

function Remove-RegistryKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    $psPath = $Path -replace '^HKCU', 'HKCU:' -replace '^HKLM', 'HKLM:'
    if (-not (Test-Path -LiteralPath $psPath)) {
        Write-Host "Skipping removal, registry key does not exist: $psPath"
        return
    }
    
    Write-Host "Removing registry key: $psPath"
    try {
        Remove-Item -LiteralPath $psPath -Recurse -Force -ErrorAction Stop
        Write-Host "Successfully removed key '$psPath'." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to remove key '$psPath'. Error: $($_.Exception.Message)"
    }
}

function Set-ServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Disabled', 'Stopped', 'Started')]
        [string]$State
    )
    
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "Skipping service '$Name', not found."
        return
    }

    $actionMap = @{
        'Disabled' = 'Disabling'
        'Stopped' = 'Stopping'
        'Started' = 'Starting'
    }
    Write-Host "$($actionMap[$State]) service: $Name"
    
    try {
        switch ($State) {
            'Stopped' {
                if ($service.Status -ne 'Running') { Write-Host "Skipping, service is not running."; return }
                Stop-Service -Name $Name -Force -ErrorAction Stop
                $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
            }
            'Started' {
                if ($service.Status -eq 'Running') { Write-Host "Skipping, service is already running."; return }
                Start-Service -Name $Name -ErrorAction Stop
            }
            'Disabled' {
                if ($service.StartType -eq 'Disabled') { Write-Host "Skipping, service is already disabled."; return }
                if ($service.Status -eq 'Running') { 
                    Stop-Service -Name $Name -Force -ErrorAction Stop | Out-Null
                    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
                }
                Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
            }
        }
        Write-Host "Successfully set service '$Name' state to '$State'." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to set service '$Name' state to '$State'. Error: $($_.Exception.Message)"
    }
}

function Set-ScheduledTaskState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Disabled')]
        [string]$State
    )
    
    $task = Get-ScheduledTask -TaskPath $Path -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Host "Skipping task '$Path$Name', not found."
        return
    }

    Write-Host "$($State)ing scheduled task: '$Path$Name'"
    if ($task.State -eq 'Disabled') {
        Write-Host "Skipping, task is already disabled."
        return
    }

    try {
        $task | Disable-ScheduledTask -ErrorAction Stop
        Write-Host "Task disabled successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to disable task '$Path$Name'. Error: $_"
    }
}

function Remove-AppxPackageAndProvisioning {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [switch]$Deprovision
    )
    $packages = Get-AppxPackage -AllUsers -Name $Name -ErrorAction SilentlyContinue
    if (-not $packages) {
        Write-Host "Skipping Appx package '$Name', not found."
        return
    }

    Write-Host "Removing Appx package: $Name"
    foreach ($package in $packages) {
        try {
            Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
            Write-Host "Removed package: $($package.PackageFullName)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to remove package $($package.PackageFullName). Error: $_"
        }
    }

    if ($Deprovision) {
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $Name }
        if ($provisioned) {
            try {
                Write-Host "Deprovisioning package '$Name' to prevent re-installation."
                Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction Stop
                Write-Host "Successfully deprovisioned '$Name'." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to deprovision package '$Name'. Error: $_"
            }
        }
    }
}

function Add-HostsEntry {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    $hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $comment = "# managed by privacy.sexy"
    $ipv4Entry = "0.0.0.0`t$Domain`t$comment"
    $ipv6Entry = "::1`t`t$Domain`t$comment"
    
    try {
        $content = Get-Content $hostsFilePath -Raw -ErrorAction SilentlyContinue
        $updated = $false
        
        if ($content -notmatch "0\.0\.0\.0\s+$([regex]::escape($Domain))") {
            Add-Content -Path $hostsFilePath -Value $ipv4Entry
            $updated = $true
        }
        if ($content -notmatch "::1\s+$([regex]::escape($Domain))") {
            Add-Content -Path $hostsFilePath -Value $ipv6Entry
            $updated = $true
        }
        
        if ($updated) {
            Write-Host "Blocked domain '$Domain' in hosts file." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Could not update hosts file for '$Domain'. Error: $_"
    }
}

#endregion Helper Functions


# --- Main Script Body ---

Write-Host "Starting Privacy.sexy Windows Hardening Script..." -ForegroundColor Cyan
# This is the line that was fixed. The original had incorrect parenthesis and enum syntax.
Write-Host "Running as Administrator: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

#region File and Registry Cleanup
Show-SectionHeader "Clear Quick Access recent files"
Clear-DirectoryContents -Path "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations"

Show-SectionHeader "Clear Quick Access pinned items"
Clear-DirectoryContents -Path "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations"

Show-SectionHeader "Clear Windows Registry last-accessed key"
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value "" -Type String

Show-SectionHeader "Clear Windows Registry favorite locations"
Clear-RegistryKeyValues -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites"

Show-SectionHeader "Clear recent application history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy"

Show-SectionHeader "Clear Adobe recent file history"
Remove-RegistryKey -Path "HKCU\Software\Adobe\MediaBrowser\MRU"

Show-SectionHeader "Clear Microsoft Paint recent files history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List"

Show-SectionHeader "Clear WordPad recent file history"
Clear-RegistryKeyValues -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List"

Show-SectionHeader "Clear network drive mapping history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU"

Show-SectionHeader "Clear Windows Search history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Search Assistant\ACMru" -Recurse
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SearchHistory" -Recurse
Clear-DirectoryContents -Path "%LOCALAPPDATA%\Microsoft\Windows\ConnectedSearch\History"

Show-SectionHeader "Clear recent files and folders history"
Clear-RegistryKeyValues -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" -Recurse
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" -Recurse
Clear-DirectoryContents -Path "%APPDATA%\Microsoft\Windows\Recent Items"

Show-SectionHeader "Clear Windows Media Player recent activity history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList"
Clear-RegistryKeyValues -Path "HKCU\Software\Gabest\Media Player Classic\Recent File List"

Show-SectionHeader "Clear DirectX recent application history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Direct3D\MostRecentApplication"

Show-SectionHeader "Clear Windows Run command history"
Clear-RegistryKeyValues -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

Show-SectionHeader "Clear File Explorer address bar history"
Clear-RegistryKeyValues -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

Show-SectionHeader "Clear temporary system folder"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Temp"

Show-SectionHeader "Clear temporary user folder"
Clear-DirectoryContents -Path "%TEMP%"

Show-SectionHeader "Clear prefetch folder"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Prefetch"

Show-SectionHeader "Clear Windows update and SFC scan logs"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Temp\CBS"

Show-SectionHeader "Clear Windows Update Medic Service logs"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Logs\waasmedic"

Show-SectionHeader 'Clear "Cryptographic Services" diagnostic traces'
Remove-FileSystemItem -Path "%SYSTEMROOT%\System32\catroot2\dberr.txt"
Remove-FileSystemItem -Path "%SYSTEMROOT%\System32\catroot2.log"
Remove-FileSystemItem -Path "%SYSTEMROOT%\System32\catroot2.jrs"
Remove-FileSystemItem -Path "%SYSTEMROOT%\System32\catroot2.edb"
Remove-FileSystemItem -Path "%SYSTEMROOT%\System32\catroot2.chk"

Show-SectionHeader "Clear Server-initiated Healing Events system logs"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Logs\SIH"

Show-SectionHeader "Clear Windows Update logs"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Traces\WindowsUpdate"

Show-SectionHeader "Clear Optional Component Manager and COM+ components logs"
Remove-FileSystemItem -Path "%SYSTEMROOT%\comsetup.log"

Show-SectionHeader 'Clear "Distributed Transaction Coordinator (DTC)" logs'
Remove-FileSystemItem -Path "%SYSTEMROOT%\DtcInstall.log"

Show-SectionHeader "Clear logs for pending/unsuccessful file rename operations"
Remove-FileSystemItem -Path "%SYSTEMROOT%\PFRO.log"

Show-SectionHeader "Clear Windows update installation logs"
Remove-FileSystemItem -Path "%SYSTEMROOT%\setupact.log"
Remove-FileSystemItem -Path "%SYSTEMROOT%\setuperr.log"

Show-SectionHeader "Clear Windows setup logs"
Remove-FileSystemItem -Path "%SYSTEMROOT%\setupapi.log"
Remove-FileSystemItem -Path "%SYSTEMROOT%\inf\setupapi.app.log"
Remove-FileSystemItem -Path "%SYSTEMROOT%\inf\setupapi.dev.log"
Remove-FileSystemItem -Path "%SYSTEMROOT%\inf\setupapi.offline.log"
Clear-DirectoryContents -Path "%SYSTEMROOT%\Panther"

Show-SectionHeader 'Clear "Windows System Assessment Tool (`WinSAT`)" logs'
Remove-FileSystemItem -Path "%SYSTEMROOT%\Performance\WinSAT\winsat.log"

Show-SectionHeader "Clear password change events"
Remove-FileSystemItem -Path "%SYSTEMROOT%\debug\PASSWD.LOG"

Show-SectionHeader "Clear user web cache database"
Clear-DirectoryContents -Path "%LOCALAPPDATA%\Microsoft\Windows\WebCache"

Show-SectionHeader "Clear system temp folder when not logged in"
Clear-DirectoryContents -Path "%SYSTEMROOT%\ServiceProfiles\LocalService\AppData\Local\Temp"

Show-SectionHeader "Clear DISM (Deployment Image Servicing and Management) system logs"
Remove-FileSystemItem -Path "%SYSTEMROOT%\Logs\CBS\CBS.log"
Remove-FileSystemItem -Path "%SYSTEMROOT%\Logs\DISM\DISM.log"

Show-SectionHeader "Clear thumbnail cache"
Remove-FileSystemItem -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db"
#endregion

#region Service and Advanced Cleanup
Show-SectionHeader "Clear Windows update files"
Set-ServiceState -Name 'wuauserv' -State 'Stopped'
Clear-DirectoryContents -Path "%SYSTEMROOT%\SoftwareDistribution" -TakeOwnership
Set-ServiceState -Name 'wuauserv' -State 'Started'

Show-SectionHeader "Clear diagnostics tracking logs"
Set-ServiceState -Name 'DiagTrack' -State 'Stopped'
Remove-FileSystemItem -Path "%PROGRAMDATA%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" -TakeOwnership
Remove-FileSystemItem -Path "%PROGRAMDATA%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\AutoLogger-Diagtrack-Listener.etl" -TakeOwnership
Set-ServiceState -Name 'DiagTrack' -State 'Started'

Show-SectionHeader "Clear event logs in Event Viewer application"
wevtutil.exe sl Microsoft-Windows-LiveId/Operational /ca:O:BAG:SYD:(A;;0x1;;;SY)(A;;0x5;;;BA)(A;;0x1;;;LA) *>&1 | Out-Null
$eventLogs = wevtutil.exe el
foreach ($log in $eventLogs) {
    Write-Verbose "Clearing event log: $log"
    wevtutil.exe cl $log 2>$null # Redirect errors as some logs can't be cleared
}
Write-Host "Finished clearing event logs." -ForegroundColor Green

Show-SectionHeader "Clear Defender scan (protection) history"
Clear-DirectoryContents -Path "%ProgramData%\Microsoft\Windows Defender\Scans\History" -TakeOwnership

Show-SectionHeader "Remove the controversial `default0` user"
net.exe user defaultuser0 /delete 2>$null

Show-SectionHeader "Remove associations of default apps"
dism.exe /online /Remove-DefaultAppAssociations
#endregion

#region Application Privacy Settings
Show-SectionHeader "Disable app access to 'Documents' folder"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to 'Pictures' folder"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to 'Videos' folder"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to 'Music' folder"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to personal files"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to call history"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCallHistory' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to phone calls (breaks phone calls through Phone Link)"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessPhone' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to messaging (SMS / MMS)"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMessaging' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to paired Bluetooth devices"
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" -Name "Value" -Value "Deny" -Type String

Show-SectionHeader "Disable app access to unpaired Bluetooth devices"
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Value "Deny" -Type String

Show-SectionHeader "Disable app access to voice activation"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsActivateWithVoice' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps' -Name 'AgentActivationEnabled' -Value 0 -Type DWord

Show-SectionHeader "Disable app access to voice activation on locked system"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsActivateWithVoiceAboveLock' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps' -Name 'AgentActivationOnLockScreenEnabled' -Value 0 -Type DWord

Show-SectionHeader "Disable app access to location"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Value 'Deny' -Type String
Set-RegistryValue -Path 'HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Value 0 -Type DWord

Show-SectionHeader "Disable app access to account information, name, and picture"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to motion activity"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMotion' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to trusted devices"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessTrustedDevices' -Value 2 -Type DWord

Show-SectionHeader "Disable app access to unpaired wireless devices"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsSyncWithDevices' -Value 2 -Type DWord

Show-SectionHeader "Disable app access to camera"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCamera' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to microphone (breaks Sound Recorder)"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMicrophone' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to information about other apps"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsGetDiagnosticInfo' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to your contacts"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessContacts' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to notifications"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessNotifications' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to calendar"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCalendar' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to email"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessEmail' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to tasks"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessTasks' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to radios"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessRadios' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to physical movement"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessBackgroundSpatialPerception' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\spatialPerception' -Name 'Value' -Value 'Deny' -Type String
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\backgroundSpatialPerception' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to eye tracking"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessGazeInput' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to human presence"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessHumanPresence' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanPresence' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to screen capture"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessGraphicsCaptureProgrammatic' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic' -Name 'Value' -Value 'Deny' -Type String

Show-SectionHeader "Disable app access to background activity (breaks Cortana, Search, live tiles, notifications)"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsRunInBackground' -Value 2 -Type DWord
Set-RegistryValue -Path 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -Name 'GlobalUserDisabled' -Value 1 -Type DWord

Show-SectionHeader "Disable app access to input devices"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice' -Name 'Value' -Value 'Deny' -Type String
#endregion

#region Telemetry and Data Collection
Show-SectionHeader "Disable server customer experience data assistant"
Set-ScheduledTaskState -Path '\Microsoft\Windows\Customer Experience Improvement Program\Server\' -Name 'ServerCeipAssistant' -State 'Disabled'

Show-SectionHeader "Disable server role telemetry collection"
Set-ScheduledTaskState -Path '\Microsoft\Windows\Customer Experience Improvement Program\Server\' -Name 'ServerRoleCollector' -State 'Disabled'

Show-SectionHeader "Disable disk diagnostic data collection"
Set-ScheduledTaskState -Path '\Microsoft\Windows\DiskDiagnostic\' -Name 'Microsoft-Windows-DiskDiagnosticDataCollector' -State 'Disabled'

Show-SectionHeader "Disable customer experience data consolidation"
Set-ScheduledTaskState -Path '\Microsoft\Windows\Customer Experience Improvement Program\' -Name 'Consolidator' -State 'Disabled'

Show-SectionHeader "Disable customer experience data uploads"
Set-ScheduledTaskState -Path '\Microsoft\Windows\Customer Experience Improvement Program\' -Name 'Uploader' -State 'Disabled'

Show-SectionHeader "Disable Customer Experience Improvement Program data collection"
Set-RegistryValue -Path 'HKLM\Software\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value 0 -Type DWord
Set-RegistryValue -Path 'HKLM\Software\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value 0 -Type DWord

Show-SectionHeader "Disable active connectivity tests (breaks internet connection status, captive portals)"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' -Name 'NoActiveProbe' -Value 1 -Type DWord
Set-RegistryValue -Path 'HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -Name 'EnableActiveProbing' -Value 0 -Type DWord

Show-SectionHeader "Disable passive connectivity tests (breaks internet connection status)"
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "DisablePassivePolling" -Value 1 -Type DWord

Show-SectionHeader "Block Microsoft connectivity check hosts (breaks internet connection status, captive portals)"
Add-HostsEntry -Domain "msftncsi.com"
Add-HostsEntry -Domain "dns.msftncsi.com"
Add-HostsEntry -Domain "ipv6.msftncsi.com"
Add-HostsEntry -Domain "msftconnecttest.com"
Add-HostsEntry -Domain "www.msftconnecttest.com"
Add-HostsEntry -Domain "ipv6.msftconnecttest.com"

Show-SectionHeader "Disable Recall"
Set-RegistryValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "DisableAIDataAnalysis" -Value 1 -Type DWord

Show-SectionHeader "Opt out of Windows privacy consent"
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord

Show-SectionHeader "Disable Windows feedback collection"
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord

Show-SectionHeader "Disable typing feedback (sends typing data)"
Set-RegistryValue -Path "HKLM\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
Set-RegistryValue -Path "HKCU\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
#endregion

#region Vendor-Specific Settings (Office, VS, Nvidia, etc.)
Show-SectionHeader "Disable participation in Visual Studio Customer Experience Improvement Program (VSCEIP)"
Set-RegistryValue -Path 'HKLM\Software\Policies\Microsoft\VisualStudio\SQM' -Name 'OptIn' -Value 0 -Type DWord

Show-SectionHeader "Disable Visual Studio telemetry"
Set-RegistryValue -Path 'HKCU\Software\Microsoft\VisualStudio\Telemetry' -Name 'TurnOffSwitch' -Value 1 -Type DWord

Show-SectionHeader "Disable 'NVIDIA Telemetry Report' task"
Set-ScheduledTaskState -Path '\' -Name 'NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' -State 'Disabled'

Show-SectionHeader "Disable 'NVIDIA Telemetry Report on Logon' task"
Set-ScheduledTaskState -Path '\' -Name 'NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' -State 'Disabled'

Show-SectionHeader "Disable 'NVIDIA telemetry monitor' task"
Set-ScheduledTaskState -Path '\' -Name 'NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}' -State 'Disabled'

Show-SectionHeader "Disable participation in Nvidia telemetry"
Set-RegistryValue -Path 'HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client' -Name 'OptInOrOutPreference' -Value 0 -Type DWord

Show-SectionHeader 'Disable "Nvidia Telemetry Container" service'
Set-ServiceState -Name 'NvTelemetryContainer' -State 'Disabled'

Show-SectionHeader "Disable Microsoft Office client telemetry"
Set-RegistryValue -Path 'HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry' -Name 'DisableTelemetry' -Value 1 -Type DWord
Set-RegistryValue -Path 'HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry' -Name 'DisableTelemetry' -Value 1 -Type DWord

Show-SectionHeader "Disable user participation in Office Customer Experience Improvement Program (CEIP)"
Set-RegistryValue -Path 'HKCU\Software\Policies\Microsoft\Office\16.0\Common' -Name 'QMEnable' -Value 0 -Type DWord

Show-SectionHeader "Disable Dropbox and Google Update Services"
Set-ServiceState -Name 'dbupdate' -State 'Disabled'
Set-ServiceState -Name 'dbupdatem' -State 'Disabled'
Set-ServiceState -Name 'gupdate' -State 'Disabled'
Set-ServiceState -Name 'gupdatem' -State 'Disabled'
Set-ScheduledTaskState -Path '\' -Name 'DropboxUpdateTaskMachineUA' -State 'Disabled'
Set-ScheduledTaskState -Path '\' -Name 'GoogleUpdateTaskMachineCore' -State 'Disabled'

Show-SectionHeader "Configure Visual Studio Code Privacy Settings"
$vsCodeSettingsFile = Join-Path $env:APPDATA "Code\User\settings.json"
if (Test-Path $vsCodeSettingsFile) {
    try {
        $settings = Get-Content $vsCodeSettingsFile -Raw | ConvertFrom-Json
        $settings.'telemetry.enableTelemetry' = $false
        $settings.'telemetry.enableCrashReporter' = $false
        $settings.'workbench.enableExperiments' = $false
        $settings.'update.mode' = 'manual'
        $settings.'extensions.autoCheckUpdates' = $false
        $settings.'git.autofetch' = $false
        $settings | ConvertTo-Json -Depth 10 | Set-Content $vsCodeSettingsFile
        Write-Host "VS Code settings.json updated successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Could not parse or update VS Code settings.json. It might be empty or malformed. Error: $_"
    }
}
#endregion

#region UI and Feature Disabling
Show-SectionHeader "Disable online tips and wizards"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowOnlineTips' -Value 0 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoInternetOpenWith' -Value 1 -Type DWord
Set-RegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoOnlinePrintsWizard' -Value 1 -Type DWord

Show-SectionHeader "Disable lock screen app notifications"
Set-RegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLockScreenAppNotifications' -Value 1 -Type DWord

Show-SectionHeader "Disable the display of recently used files in Quick Access"
Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Type DWord

Show-SectionHeader "Remove 'Widgets' from taskbar and disable functionality"
Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord
Remove-AppxPackageAndProvisioning -Name 'MicrosoftWindows.Client.WebExperience' -Deprovision

Show-SectionHeader "Disable and remove Copilot"
Set-RegistryValue -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type DWord
Set-RegistryValue -Path 'HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' -Name 'TurnOffWindowsCopilot' -Value 1 -Type DWord
Set-RegistryValue -Path 'HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat' -Name 'IsUserEligible' -Value 0 -Type DWord
#endregion

Write-Host "`n----------------------------------" -ForegroundColor Cyan
Write-Host "  SCRIPT EXECUTION COMPLETE" -ForegroundColor Cyan
Write-Host "----------------------------------" -ForegroundColor Cyan
Write-Host "`nA system restart is recommended for all changes to take full effect."
Write-Host "The script has finished and will now exit."
