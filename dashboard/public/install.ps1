Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " 🛡️ jarsWAF Agent Installation (Windows)" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

$ControllerIp = $env:CONTROLLER_IP
if ([string]::IsNullOrWhiteSpace($ControllerIp)) {
    Write-Host "Error: CONTROLLER_IP environment variable not set." -ForegroundColor Red
    Write-Host "Usage: `$env:CONTROLLER_IP=`"192.168.1.10:8080`"; iwr http://192.168.1.10:8080/install.ps1 -useb | iex" -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Connecting to jarsWAF Central Controller at: $ControllerIp"

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Error: Please run PowerShell as Administrator to install the agent." -ForegroundColor Red
    exit 1
}

$InstallDir = "C:\Program Files\jarsWAFWAF"
Write-Host "[*] Creating installation directory at $InstallDir..."
if (!(Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

Write-Host "[*] Downloading jarsWAF Agent binary..."
# Note: This is a PoC. In production, this would download the actual compiled binary (.exe)
# Invoke-WebRequest -Uri "http://$ControllerIp/bin/jarswaf-agent-windows-amd64.exe" -OutFile "$InstallDir\jarswaf-agent.exe"

Write-Host "[*] Generating Agent Configuration (config.toml)..."
$ConfigContent = @"
mode = `"agent`"
controller_url = `"http://$ControllerIp`"
port = 80
"@
Set-Content -Path "$InstallDir\config.toml" -Value $ConfigContent

Write-Host "[*] Registering Windows Scheduled Task for Autostart..."
$TaskName = "jarsWAFWAFAgent"

# Remove existing task if any
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$Action = New-ScheduledTaskAction -Execute "$InstallDir\jarswaf-agent.exe" -Argument "--config `"$InstallDir\config.toml`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host " ✅ jarsWAF Agent installation completed!" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "The agent will start automatically on next boot."
Write-Host "To start immediately, run: Start-ScheduledTask -TaskName `"$TaskName`""
