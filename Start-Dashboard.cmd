@echo off
title Devils Eyes Dashboard
if not defined DEVILS_EYES_DISTRO set DEVILS_EYES_DISTRO=Ubuntu-24.04
wsl.exe -d %DEVILS_EYES_DISTRO% -u root -- service postgresql start
if errorlevel 1 goto failed
echo Dashboard: http://localhost:8080
echo Opens without a token on this PC. Scans and AI reviews you start in the dashboard run in this window.
echo Keep this window open. Press Ctrl+C to stop the dashboard.
wsl.exe -d %DEVILS_EYES_DISTRO% --cd ~ -- bash .local/share/watchtower/start.sh dashboard
if errorlevel 1 goto failed
exit /b 0
:failed
echo Dashboard could not start. Review the message above.
pause
exit /b 1
