@echo off

git status
PAUSE
git add .
PAUSE
git commit -m "%~1" 
PAUSE
git push origin main 2>&1 | findstr /v "warning:"
