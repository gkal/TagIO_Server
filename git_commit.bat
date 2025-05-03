@echo off

git status

git add .

:: Initialize commit message variable
set "commit_msg=%~1"

:: Process all remaining arguments
:loop
shift
if "%~1"=="" goto endloop
set "commit_msg=%commit_msg% %~1"
goto loop
:endloop

:: Display the message for verification
echo.
echo Committing with message: "%commit_msg%"
echo.

:: Perform the commit
git commit -m "%commit_msg%"

:: Push the changes
git push origin main 
