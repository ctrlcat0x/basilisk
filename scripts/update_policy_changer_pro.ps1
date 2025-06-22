# Update Policy Changer Pro
# filename: update_policy_changer_pro.ps1
#
# This script makes a few small tweaks to ensure that Windows only receives security updates, leaving out "feature" updates, permanently.
# This prevents Windows from reinstalling any extra applications or changes that the user doesn't want, ensuring only necessary changes.
# This update script will work on Pro or above systems. It is recommended to use the regular variant of this script on Windows Home systems,
# as that script essentially does the same thing, but only for 365 days.

# Massive thanks to Skull Crusher (zombiehunternr1) for this script!

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

# Exclude non-security classifications (including drivers)
$excludedClassifications = @(
    "{e6cf1350-c01b-414d-a61f-263d3d4dd9f9}",  # Critical Updates
    "{e0789628-ce08-4437-be74-2495b842f43b}",  # Definition Updates
    "{b54e7d24-7add-49f4-88bb-9837d47477fb}",  # Feature Packs
    "{68c5b0a3-d1a6-4553-ae49-01d3a7827828}",  # Service Packs
    "{b4832bd8-e735-4766-9727-7d0ffa644277}",  # Tools
    "{28bc8804-5382-4bae-93aa-13c905f28542}",  # Update Rollups
    "{cd5ffd1e-e257-4a05-9d88-c83a7125d4c9}",  # Updates
    "{0f1afbec-90ef-4651-9e37-030fedc944c8}",  # Non-critical
    "{ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0}",  # Drivers
    "{9920c092-3d99-4a1b-865a-673135c5a4fc}"   # Feature Updates
) -join ";"

# Create registry keys if missing
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Configure classifications + block drivers in Optional Updates
Set-ItemProperty -Path $registryPath -Name "ExcludeUpdateClassifications" -Value $excludedClassifications -Type String -Force
Set-ItemProperty -Path $registryPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force  # Block drivers
Set-ItemProperty -Path $registryPath -Name "AUOptions" -Value 2 -Type DWord -Force  # Notify before install

# Restart Windows Update service
Restart-Service -Name wuauserv -Force

Write-Host "Security updates only. Drivers are blocked, including Optional Updates."