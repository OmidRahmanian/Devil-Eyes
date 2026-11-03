@echo off
title Devils Eyes
wsl.exe -d Ubuntu-24.04 -u root -- service postgresql start
if errorlevel 1 goto failed
wsl.exe -d Ubuntu-24.04 -- bash /home/omid/.local/share/watchtower/start.sh menu
if errorlevel 1 goto failed
exit /b 0
:failed
echo Devils Eyes could not start. Review the message above.
pause
exit /b 1
