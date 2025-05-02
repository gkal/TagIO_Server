@echo off
echo ============================
echo = TagIO Remote Desktop App =
echo ============================
echo.

REM Set the path to the executable
set TAGIO_EXE=target\release\tagio.exe

REM Check if the executable exists
if not exist %TAGIO_EXE% (
    echo Error: Executable not found at %TAGIO_EXE%
    echo Please make sure you have built the application using:
    echo cargo build --release
    pause
    exit /b 1
)

REM Run the application
echo Starting TagIO Client...
echo.

:: Run without pausing at the end
start "" /B %TAGIO_EXE% %* 