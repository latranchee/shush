@echo off
rem shush CLI shim: lets `shush ...` work from any shell once this folder
rem is on PATH. All arguments pass through to secret_manager.ps1.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0secret_manager.ps1" %*
exit /b %ERRORLEVEL%
