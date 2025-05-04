:: Use %* to capture the entire command line
set "commit_msg=%*"

:: Check if commit message is empty
if "%commit_msg%"=="" (
    echo.
    echo No commit message provided. Usage: git_commit.bat "Your commit message here"
    echo.
    exit /b 1
)

:: Show status and add files
git status
git add .

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
