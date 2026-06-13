@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~dp0PixelProxyInjector.exe' -WorkingDirectory '%~dp0' -Verb RunAs"
