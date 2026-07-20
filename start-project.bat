@echo off
setlocal
set "ROOT=%~dp0"

echo Starting backend...
start "Shadow IT Backend" cmd /k "cd /d "%ROOT%backend" && python app.py"

echo Starting frontend...
start "Shadow IT Frontend" cmd /k "cd /d "%ROOT%frontend" && npm run dev"

echo.
echo Backend should open at http://localhost:5000
set /p dummy=Press Enter to close this window...
