Write-Host "[*] Initiating GhostPort OS Deployment Protocol..." -ForegroundColor Cyan

# 1. Define Paths
$SourceExe = ".\build\Release\shadow.exe"
$InstallDir = "$env:LOCALAPPDATA\GhostPort"
$TargetExe = "$InstallDir\ghostport.exe"

# 2. Check if the Release build exists
if (-Not (Test-Path $SourceExe)) {
    Write-Host "[!] ERROR: Could not find the Release build at $SourceExe." -ForegroundColor Red
    Write-Host "[!] Please ensure you selected 'Release' in CMake and built the project." -ForegroundColor Yellow
    Exit
}

# 3. Create the Installation Directory
Write-Host "[*] Creating secure installation directory at $InstallDir..."
if (-Not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# 4. Deploy the Executable
Write-Host "[*] Injecting optimized binary into OS..."
Copy-Item -Path $SourceExe -Destination $TargetExe -Force

# 5. Update Windows PATH (User Level)
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "[*] Modifying Windows Environment Registry..."
    $NewPath = $UserPath + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    Write-Host "[+] GhostPort successfully added to System PATH!" -ForegroundColor Green
} else {
    Write-Host "[+] GhostPort is already registered in the System PATH." -ForegroundColor Green
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " DEPLOYMENT COMPLETE " -ForegroundColor Green -BackgroundColor Black
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Please restart your terminal to apply the registry changes."
Write-Host "You can now launch the tool from anywhere by typing: ghostport" -ForegroundColor Yellow