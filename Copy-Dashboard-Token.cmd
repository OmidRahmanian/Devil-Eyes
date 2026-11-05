@echo off
rem Only needed to sign in from another device; on this PC the dashboard opens without a token.
if not defined DEVILS_EYES_DISTRO set DEVILS_EYES_DISTRO=Ubuntu-24.04
wsl.exe -d %DEVILS_EYES_DISTRO% --cd ~ -- .local/share/watchtower/app/.venv/bin/python .local/share/watchtower/app/deploy/windows/dashboard-token.py
if errorlevel 1 goto failed
pause
exit /b 0
:failed
echo Could not copy the login token. Check the message above.
pause
exit /b 1
