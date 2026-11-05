@echo off
title Devils Eyes
if not defined DEVILS_EYES_DISTRO set DEVILS_EYES_DISTRO=Ubuntu-24.04
wsl.exe -d %DEVILS_EYES_DISTRO% -u root -- service postgresql start
if errorlevel 1 goto failed
wsl.exe -d %DEVILS_EYES_DISTRO% --cd ~ -- bash .local/share/watchtower/start.sh menu
if errorlevel 1 goto failed
exit /b 0
:failed
echo Devils Eyes could not start. Review the message above.
pause
exit /b 1
