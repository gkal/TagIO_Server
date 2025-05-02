@echo off
REM Git automation batch file
REM Usage: git_commit.bat "Your commit message here"

echo Running git status...
git status

echo.
echo Adding all files...
git add .

echo.
echo Committing with message: %1
git commit -m "%~1"

echo.
echo Pushing to origin main...
git push origin main

echo.
echo Git operations completed. 