Write-Host "[*] Initiating GhostPort OS Deployment Protocol..." -ForegroundColor Cyan

# 1. Search for binary in standard locations
$PossiblePaths = @(
    "$PSScriptRoot\ghostport.exe",
    "$PSScriptRoot\shadow.exe",
    "$PSScriptRoot\dist\ghostport.exe",
    "$PSScriptRoot\build\Release\shadow.exe",
    "$PSScriptRoot\build\shadow.exe",
    ".\build\Release\shadow.exe",
    ".\build\shadow.exe",
    ".\shadow.exe"
)

$SourceExe = $null
foreach ($path in $PossiblePaths) {
    if (Test-Path $path) {
        $SourceExe = (Resolve-Path $path).Path
        break
    }
}

if (-Not $SourceExe) {
    Write-Host "[!] ERROR: Could not find GhostPort executable." -ForegroundColor Red
    Write-Host "[!] Please ensure project is compiled or binary is in the deployment folder." -ForegroundColor Yellow
    Exit 1
}

Write-Host "[+] Found executable at: $SourceExe" -ForegroundColor Green

# 2. Define Installation Target
$InstallDir = "$env:LOCALAPPDATA\GhostPort"
$TargetExe = "$InstallDir\ghostport.exe"

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
    $NewPath = $UserPath.TrimEnd(';') + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    Write-Host "[+] GhostPort successfully added to System PATH!" -ForegroundColor Green
} else {
    Write-Host "[+] GhostPort is already registered in the System PATH." -ForegroundColor Green
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host " GHOSTPORT OS DEPLOYMENT COMPLETE " -ForegroundColor Green -BackgroundColor Black
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "Please restart your terminal to apply the registry changes."
Write-Host "You can now launch the tool from anywhere by typing: ghostport" -ForegroundColor Yellow
