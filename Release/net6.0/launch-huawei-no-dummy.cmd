@echo off
cd /d "%~dp0"
Il2CppDumper.exe --version huawei --no-dummy-dll
if errorlevel 1 echo Huawei exit code: %errorlevel%
echo.
pause
