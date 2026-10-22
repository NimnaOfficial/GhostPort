[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Purge
)

$GREEN = "Green"
$CYAN = "Cyan"
$YELLOW = "Yellow"
$RED = "Red"

# ── 0. Handle Uninstallation ──────────────────────────────────────────────────
if ($Uninstall -or $Purge) {
    Write-Host "[*] Initiating GhostPort OS System Purge..." -ForegroundColor $YELLOW

    # Try binary uninstaller first
    if (Get-Command ghostport.exe -ErrorAction SilentlyContinue) {
        & ghostport.exe --uninstall
        Exit 0
    }

    $InstallDir = "$env:LOCALAPPDATA\GhostPort"
    $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath) {
        $CleanParts = $UserPath -split ';' | Where-Object { $_ -ne $InstallDir -and $_ -ne '' }
        [Environment]::SetEnvironmentVariable("PATH", ($CleanParts -join ';'), "User")
        Write-Host "[+] Removed GhostPort from User PATH." -ForegroundColor $GREEN
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Purged directory: $InstallDir" -ForegroundColor $GREEN
    }

    Write-Host "=======================================================" -ForegroundColor $CYAN
    Write-Host "   GHOSTPORT OS PURGE COMPLETE" -ForegroundColor $GREEN
    Write-Host "=======================================================" -ForegroundColor $CYAN
    Exit 0
}

Write-Host "[*] Initiating GhostPort OS Deployment Protocol..." -ForegroundColor $CYAN

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
    Write-Host "[!] ERROR: Could not find GhostPort executable." -ForegroundColor $RED
    Write-Host "[!] Please ensure project is compiled or binary is in the deployment folder." -ForegroundColor $YELLOW
    Exit 1
}

Write-Host "[+] Found executable at: $SourceExe" -ForegroundColor $GREEN

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
    Write-Host "[+] GhostPort successfully added to System PATH!" -ForegroundColor $GREEN
} else {
    Write-Host "[+] GhostPort is already registered in the System PATH." -ForegroundColor $GREEN
}

Write-Host "=======================================================" -ForegroundColor $CYAN
Write-Host " GHOSTPORT OS DEPLOYMENT COMPLETE " -ForegroundColor $GREEN -BackgroundColor Black
Write-Host "=======================================================" -ForegroundColor $CYAN
Write-Host "Please restart your terminal to apply the registry changes."
Write-Host "You can now launch the tool from anywhere by typing: ghostport" -ForegroundColor $YELLOW
Write-Host "To uninstall at any time: .\deploy.ps1 -Uninstall or ghostport --uninstall" -ForegroundColor $CYAN
