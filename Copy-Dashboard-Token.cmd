@echo off
wsl.exe -d Ubuntu-24.04 -- /home/omid/.local/share/watchtower/app/.venv/bin/python /home/omid/.local/share/watchtower/dashboard-token.py
if errorlevel 1 goto failed
pause
exit /b 0
:failed
echo Could not copy the login token. Check the message above.
pause
exit /b 1
