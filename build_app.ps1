param(
  [string]$Version = "",
  [switch]$NoInstall
)

$ErrorActionPreference = "Stop"

Set-Location -LiteralPath $PSScriptRoot

function Get-AppVersion {
  if ($Version.Trim()) {
    return $Version.Trim()
  }
  $versionPath = Join-Path $PSScriptRoot "VERSION"
  if (Test-Path -LiteralPath $versionPath) {
    $value = (Get-Content -LiteralPath $versionPath -Raw).Trim()
    if ($value) {
      return $value
    }
  }
  return (Get-Date -Format "yyyy.MM.dd.HHmm")
}

function Set-StableConfig {
  param([string]$Path)

  $config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  $protocol = $config.proxy_protocol
  if (-not $protocol) {
    $protocol = "socks5"
  }
  $proxyOnly = [ordered]@{
    listen_host = $(if ($config.listen_host) { $config.listen_host } else { "127.0.0.1" })
    listen_port = $(if ($config.listen_port) { $config.listen_port } else { 15000 })
    transparent_bind_host = $(if ($config.transparent_bind_host) { $config.transparent_bind_host } else { "0.0.0.0" })
    transparent_listen_port = $(if ($config.transparent_listen_port) { $config.transparent_listen_port } else { 15001 })
    redirect_map_path = $(if ($config.redirect_map_path) { $config.redirect_map_path } else { "redirect_map.json" })
    target_process_name = $(if ($config.target_process_name) { $config.target_process_name } else { "PixelWorlds.exe" })
    target_remote_port = $(if ($config.target_remote_port) { $config.target_remote_port } else { 10001 })
    target_remote_ports = $(if ($config.target_remote_ports) { @($config.target_remote_ports) } else { @(10001) })
    default_route = $(if ($config.default_route) { $config.default_route } else { "proxy-1" })
    max_pids_per_proxy = $(if ($config.max_pids_per_proxy) { $config.max_pids_per_proxy } else { 3 })
    auto_assign_routes = $(if ($null -ne $config.auto_assign_routes) { $config.auto_assign_routes } else { $true })
    verbose = $(if ($null -ne $config.verbose) { $config.verbose } else { $false })
    color_logs = $(if ($null -ne $config.color_logs) { $config.color_logs } else { $true })
    hide_proxy_in_list = $(if ($null -ne $config.hide_proxy_in_list) { $config.hide_proxy_in_list } else { $false })
    tcp_nodelay = $(if ($null -ne $config.tcp_nodelay) { $config.tcp_nodelay } else { $true })
    socket_keepalive = $(if ($null -ne $config.socket_keepalive) { $config.socket_keepalive } else { $true })
    socket_buffer_size = $(if ($config.socket_buffer_size) { $config.socket_buffer_size } else { 131072 })
    relay_buffer_size = $(if ($config.relay_buffer_size) { $config.relay_buffer_size } else { 131072 })
    connect_timeout_seconds = $(if ($config.connect_timeout_seconds) { $config.connect_timeout_seconds } else { 10 })
    summary_interval_seconds = $(if ($config.summary_interval_seconds) { $config.summary_interval_seconds } else { 1.0 })
    ipv6_target_action = $(if ($config.ipv6_target_action) { $config.ipv6_target_action } else { "bypass" })
    no_reply_warn_seconds = $(if ($config.no_reply_warn_seconds) { $config.no_reply_warn_seconds } else { 8.0 })
    no_reply_close_seconds = $(if ($config.no_reply_close_seconds) { $config.no_reply_close_seconds } else { 30.0 })
    debug_log_path = $(if ($config.debug_log_path) { $config.debug_log_path } else { "network_debug.log" })
    tracked_login_hosts = $(if ($config.tracked_login_hosts) { @($config.tracked_login_hosts) } else { @("11ef5c.playfabapi.com", "pw-auth.pw.sclfrst.com") })
    proxy_protocol = $protocol
    routes = @()
    upstreams = @($config.upstreams)
  }
  $json = $proxyOnly | ConvertTo-Json -Depth 20
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText((Resolve-Path -LiteralPath $Path), $json, $encoding)
}

function Copy-AppSupportFiles {
  param([string]$OutputPath)

  Copy-Item -LiteralPath config.json -Destination (Join-Path $OutputPath "config.json") -Force
  Set-StableConfig -Path (Join-Path $OutputPath "config.json")
  Copy-Item -LiteralPath README.md -Destination (Join-Path $OutputPath "README.md") -Force

  $launcher = @'
@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~dp0PixelProxyInjectorUI.exe' -WorkingDirectory '%~dp0' -Verb RunAs"
'@
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText((Join-Path $OutputPath "run_ui_as_admin.bat"), $launcher, $encoding)
}

$appVersion = Get-AppVersion
$targetRoot = Join-Path $PSScriptRoot "target"
$versionsRoot = Join-Path $targetRoot "versions"
$distPath = Join-Path $versionsRoot "PixelProxyInjectorUI-v$appVersion"
$workPath = Join-Path $targetRoot "build"

New-Item -ItemType Directory -Force -Path $versionsRoot | Out-Null
New-Item -ItemType Directory -Force -Path $workPath | Out-Null

if (-not $NoInstall) {
  python -m pip install -r requirements.txt
}

if (Test-Path -LiteralPath $distPath) {
  try {
    Remove-Item -LiteralPath $distPath -Recurse -Force
  }
  catch {
    $suffix = Get-Date -Format "yyyyMMdd-HHmmss"
    $distPath = Join-Path $versionsRoot "PixelProxyInjectorUI-v$appVersion-$suffix"
    Write-Warning "Existing version folder is locked; building to $distPath instead."
  }
}

$pydivertDllPath = python -c "import pathlib, pydivert; p=pathlib.Path(pydivert.__file__).parent / 'windivert_dll'; print(p)"
$addBinary = "$pydivertDllPath;pydivert/windivert_dll"

python -m PyInstaller `
  --noconfirm `
  --clean `
  --onedir `
  --windowed `
  --name PixelProxyInjectorUI `
  --distpath $distPath `
  --workpath $workPath `
  --add-binary $addBinary `
  --hidden-import pydivert.windivert_dll `
  ui_app.py

if ($LASTEXITCODE -ne 0) {
  throw "PyInstaller build failed. Close PixelProxyInjectorUI.exe and any Explorer window inside target, then run build_app.ps1 again."
}

$appPath = Join-Path $distPath "PixelProxyInjectorUI"
Copy-AppSupportFiles -OutputPath $appPath

$latestPath = Join-Path $targetRoot "latest"
try {
  if (Test-Path -LiteralPath $latestPath) {
    Remove-Item -LiteralPath $latestPath -Recurse -Force
  }
  Copy-Item -LiteralPath $appPath -Destination $latestPath -Recurse -Force
}
catch {
  Write-Warning "Could not update target\latest because it is locked. Close the running app and rebuild to refresh latest."
}

Write-Host ""
Write-Host "Build complete:"
Write-Host "  $appPath\PixelProxyInjectorUI.exe"
Write-Host ""
if (Test-Path -LiteralPath (Join-Path $latestPath "PixelProxyInjectorUI.exe")) {
  Write-Host "Latest copy:"
  Write-Host "  $latestPath\PixelProxyInjectorUI.exe"
}
Write-Host ""
Write-Host "Run it as Administrator because WinDivert needs driver access."
