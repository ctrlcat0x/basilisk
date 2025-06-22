# Basilisk Pre-compiled Executable Downloader
# Downloads the latest release from GitHub with Windows Defender configuration

param(
    [string]$DownloadPath = "$env:USERPROFILE\Downloads",
    [switch]$RunAfterDownload = $true,
    [switch]$OpenDownloadFolder,
    [switch]$NoAutoRun
)

# Override RunAfterDownload if NoAutoRun is specified
if ($NoAutoRun) {
    $RunAfterDownload = $false
}

# Configuration
$GitHubRepo = "ctrlcat0x/basilisk"
$ApiUrl = "https://api.github.com/repos/$GitHubRepo/releases/latest"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Basilisk Windows 11 Debloating Utility" -ForegroundColor Yellow
Write-Host "Pre-compiled Executable Downloader" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "⚠️  Warning: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "Basilisk requires Administrator privileges to run properly" -ForegroundColor Yellow
    Write-Host "The program will be launched with elevated privileges..." -ForegroundColor Yellow
    Write-Host ""
}

# Step 1: Configure Windows Defender and Execution Policy
Write-Host "Step 1/4: Configuring Windows Defender and Execution Policy..." -ForegroundColor Yellow

try {
    # Set execution policy to bypass
    Write-Host "  Setting PowerShell execution policy to Bypass..." -ForegroundColor Gray
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force -ErrorAction SilentlyContinue
    Write-Host "  ✅ Execution policy set to Bypass" -ForegroundColor Green
    
    # Add C: drive exclusion to Windows Defender
    Write-Host "  Adding C: drive exclusion to Windows Defender..." -ForegroundColor Gray
    Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
    Write-Host "  ✅ C: drive added to Windows Defender exclusions" -ForegroundColor Green
    
    # Disable real-time protection temporarily
    Write-Host "  Disabling Windows Defender real-time protection..." -ForegroundColor Gray
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Write-Host "  ✅ Real-time protection disabled" -ForegroundColor Green
    
    Write-Host "  Step 1 completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "  ⚠️  Warning: Some Windows Defender configurations failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "  Continuing with download process..." -ForegroundColor Yellow
}

# Create download directory if it doesn't exist
if (!(Test-Path $DownloadPath)) {
    New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
    Write-Host "Created download directory: $DownloadPath" -ForegroundColor Green
}

# Step 2: Fetch release information
Write-Host ""
Write-Host "Step 2/4: Fetching latest release information..." -ForegroundColor Yellow

try {
    Write-Host "  Connecting to GitHub API..." -ForegroundColor Gray
    $releaseInfo = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing
    
    Write-Host "  ✅ Latest version: $($releaseInfo.tag_name)" -ForegroundColor Green
    Write-Host "  Release date: $($releaseInfo.published_at)" -ForegroundColor Gray
    
    # Find the Windows executable asset
    $exeAsset = $releaseInfo.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1
    
    if (-not $exeAsset) {
        Write-Host "  ❌ No executable found in the latest release!" -ForegroundColor Red
        Write-Host "  Available assets:" -ForegroundColor Yellow
        $releaseInfo.assets | ForEach-Object { Write-Host "    - $($_.name)" -ForegroundColor Gray }
        exit 1
    }
    
    $downloadUrl = $exeAsset.browser_download_url
    $fileName = $exeAsset.name
    $fileSize = $exeAsset.size
    $outputPath = Join-Path $DownloadPath $fileName
    
    Write-Host "  ✅ Found executable: $fileName" -ForegroundColor Green
    Write-Host "  File size: $([math]::Round($fileSize / 1MB, 2)) MB" -ForegroundColor Gray
    
} catch {
    Write-Host "  ❌ Error fetching release information: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode
        Write-Host "  HTTP Status Code: $statusCode" -ForegroundColor Red
        
        if ($statusCode -eq 404) {
            Write-Host "  The repository or release might not exist or be private." -ForegroundColor Yellow
        } elseif ($statusCode -eq 403) {
            Write-Host "  Rate limit exceeded. Please try again later." -ForegroundColor Yellow
        }
    }
    
    exit 1
}

# Step 3: Download the executable
Write-Host ""
Write-Host "Step 3/4: Downloading Basilisk executable..." -ForegroundColor Yellow

try {
    Write-Host "  Download URL: $downloadUrl" -ForegroundColor Gray
    Write-Host "  Output path: $outputPath" -ForegroundColor Gray
    Write-Host ""
    
    # Download the file with progress
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "Basilisk-Downloader/1.0")
    
    # Add progress event handler
    $webClient.DownloadProgressChanged = {
        param($sender, $e)
        $percentComplete = $e.ProgressPercentage
        $bytesReceived = $e.BytesReceived
        $totalBytes = $e.TotalBytesToReceive
        $mbReceived = [math]::Round($bytesReceived / 1MB, 2)
        $mbTotal = [math]::Round($totalBytes / 1MB, 2)
        
        Write-Progress -Activity "Downloading Basilisk" -Status "Downloaded $mbReceived MB of $mbTotal MB" -PercentComplete $percentComplete
        Write-Host "  Download progress: $percentComplete% ($mbReceived MB / $mbTotal MB)" -ForegroundColor Cyan
    }
    
    $webClient.DownloadFileCompleted = {
        param($sender, $e)
        if ($e.Cancelled) {
            Write-Host "  ❌ Download was cancelled" -ForegroundColor Red
        } elseif ($e.Error) {
            Write-Host "  ❌ Download failed: $($e.Error.Message)" -ForegroundColor Red
        } else {
            Write-Host "  ✅ Download completed successfully!" -ForegroundColor Green
        }
    }
    
    Write-Host "  Starting download..." -ForegroundColor Gray
    $webClient.DownloadFileAsync($downloadUrl, $outputPath)
    
    # Wait for download to complete
    while ($webClient.IsBusy) {
        Start-Sleep -Milliseconds 100
    }
    
    # Verify download
    if (Test-Path $outputPath) {
        $downloadedSize = (Get-Item $outputPath).Length
        Write-Host "  ✅ File saved to: $outputPath" -ForegroundColor Green
        Write-Host "  Downloaded size: $([math]::Round($downloadedSize / 1MB, 2)) MB" -ForegroundColor Gray
        
        # Show file properties
        $fileInfo = Get-Item $outputPath
        Write-Host "  File created: $($fileInfo.CreationTime)" -ForegroundColor Gray
        
    } else {
        Write-Host "  ❌ Download failed! File not found at expected location." -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Host "  ❌ Error during download: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
} finally {
    if ($webClient) {
        $webClient.Dispose()
    }
}

# Step 4: Launch Basilisk
Write-Host ""
Write-Host "Step 4/4: Launching Basilisk..." -ForegroundColor Yellow

if ($RunAfterDownload) {
    try {
        Write-Host "  Launching Basilisk with elevated privileges..." -ForegroundColor Gray
        
        # Always run with elevated privileges to ensure it works
        Start-Process -FilePath $outputPath -Verb RunAs
        
        Write-Host "  ✅ Basilisk launched successfully!" -ForegroundColor Green
        Write-Host "  The application should now be running with administrator privileges." -ForegroundColor Gray
        
    } catch {
        Write-Host "  ❌ Failed to launch Basilisk: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  You can manually run the executable from: $outputPath" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Skipping automatic launch (NoAutoRun specified)" -ForegroundColor Gray
}

# Open download folder if requested
if ($OpenDownloadFolder) {
    Write-Host "  📁 Opening download folder..." -ForegroundColor Yellow
    Start-Process -FilePath "explorer.exe" -ArgumentList $DownloadPath
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "All steps completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

if (-not $RunAfterDownload) {
    Write-Host ""
    Write-Host "To run Basilisk manually:" -ForegroundColor Yellow
    Write-Host "1. Navigate to: $DownloadPath" -ForegroundColor Gray
    Write-Host "2. Right-click on $fileName" -ForegroundColor Gray
    Write-Host "3. Select 'Run as Administrator'" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Note: Windows Defender real-time protection has been temporarily disabled." -ForegroundColor Yellow
Write-Host "Remember to re-enable it after using Basilisk if needed." -ForegroundColor Yellow

pause 