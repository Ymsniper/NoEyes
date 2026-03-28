@echo off
setlocal enabledelayedexpansion
:: install.bat - NoEyes Windows installer

echo.
echo   NoEyes -- Windows Installer
echo.

set PYTHON=

:: Try common Python executables
for %%C in (python python3 py) do (
    if not defined PYTHON (
        %%C -c "import sys; exit(0 if sys.version_info>=(3,8) else 1)" 2>nul
        if !errorlevel! == 0 (
            set PYTHON=%%C
        )
    )
)

:: Try Windows Store python3 shim
if not defined PYTHON (
    if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\python3.exe" (
        "%LOCALAPPDATA%\Microsoft\WindowsApps\python3.exe" -c "import sys; exit(0 if sys.version_info>=(3,8) else 1)" 2>nul
        if !errorlevel! == 0 (
            set PYTHON=%LOCALAPPDATA%\Microsoft\WindowsApps\python3.exe
        )
    )
)

if not defined PYTHON (
    echo   [!] Python 3.8+ not found.
    echo.
    echo   Please install Python from https://www.python.org/downloads/
    echo   Check "Add Python to PATH" during installation.
    echo   Then re-run this script.
    echo.
    where winget >nul 2>&1
    if !errorlevel! == 0 (
        echo   Attempting: winget install Python.Python.3.12
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        echo.
        echo   Python installed. Please close this window and re-run install.bat
    )
    goto :end
)

:: Show Python version
for /f "tokens=*" %%v in ('"%PYTHON%" -c "import sys; v=sys.version_info; print(str(v.major)+chr(46)+str(v.minor)+chr(46)+str(v.micro))"') do set PYVER=%%v
echo   Python %PYVER% found

:: Run install.py directly - no PowerShell needed
set INSTALLER=%~dp0install.py
if not exist "%INSTALLER%" (
    echo   [!] install.py not found in %~dp0
    goto :end
)

echo   Launching install.py...
echo.

"%PYTHON%" "%INSTALLER%" %*

:end
pause
