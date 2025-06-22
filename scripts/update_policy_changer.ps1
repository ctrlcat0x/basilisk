# Update Policy Changer
# filename: update_policy_changer.ps1
#
# This script makes a few small tweaks to ensure that Windows only receives security updates, leaving out "feature" updates, for 365 days.
# This prevents Windows from reinstalling any extra applications or changes that the user doesn't want, ensuring only necessary changes.
# This update script will work on Home systems. It is recommended to use the "Pro" variant of this script on Pro or above Windows systems,
# as that script essentially does the same thing, but permanently rather than only 365 days.

# Massive thanks to DTLegit for this script!

# Define the registry path
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

# Define the registry values
$RegistrySettings = @{
    "DeferQualityUpdates"              = 1
    "DeferQualityUpdatesPeriodInDays"  = 4
    "ProductVersion"                   = "Windows 11"
    "TargetReleaseVersion"             = 1
    "TargetReleaseVersionInfo"         = "24H2"
}

# Ensure the registry path exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the registry values
foreach ($Name in $RegistrySettings.Keys) {
    $Value = $RegistrySettings[$Name]

    # Determine the value type (DWORD or String)
    $Type = if ($Value -is [int]) { "DWord" } else { "String" }

    # Set the registry value
    Set-ItemProperty -Path $RegPath -Name $Name -Value $Value -Type $Type -Force
    Write-Host "Set $Name to $Value ($Type)"
}

Write-Host "`nRegistry settings applied successfully."