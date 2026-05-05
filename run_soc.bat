@echo off
echo ================================
echo   Running Mini SOC Alert Tool
echo ================================
echo.

REM Go to the folder where this .bat is located
cd /d "%~dp0"

REM Run the Python SOC script
py mini_soc_alert.py

echo.
echo Opening SOC alert report...
start "" "%~dp0soc_alert_report.txt"

echo.
echo Done.
pause