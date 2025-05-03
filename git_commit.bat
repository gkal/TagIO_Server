git status
git add .

@echo off
:: Use %* to capture the entire command line
set "commit_msg=%*"

:: Display the message for verification
echo.
echo Committing with message: "%commit_msg%"
echo.

:: Wait for user confirmation
set /p confirm="Proceed with commit? (Y/N): "
if /i not "%confirm%"=="Y" (
    echo Commit canceled.
    exit /b
)

:: Perform the commit
git commit -m "%commit_msg%"

:: Push the changes
git push origin main

echo.
echo Changes committed and pushed successfully.
echo. 
