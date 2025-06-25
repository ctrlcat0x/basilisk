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