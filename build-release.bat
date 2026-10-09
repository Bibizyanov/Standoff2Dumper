@echo off
setlocal
cd /d "%~dp0"
where dotnet >nul 2>nul
if errorlevel 1 (
  echo ERROR: dotnet SDK not found. Install .NET 7 SDK or build the solution in Visual Studio.
  exit /b 1
)

echo [1/2] Restoring...
dotnet restore Il2CppDumper\Il2CppDumper.csproj || exit /b 1

echo [2/2] Publishing net7.0...
if exist Release\net7.0-watermarked rmdir /s /q Release\net7.0-watermarked
dotnet publish Il2CppDumper\Il2CppDumper.csproj -c Release -f net7.0 -o Release\net7.0-watermarked || exit /b 1

echo.
echo Done: Release\net7.0-watermarked
endlocal
