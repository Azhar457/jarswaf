@echo off
echo ===================================================
echo   Aegis WAF Development Launcher (Windows)
echo ===================================================
echo.

:: No database setup needed for SQLite! WAF Controller initializes database automatically.

echo.
echo Step 3: Starting WAF Controller in a new window...
start "Aegis Controller" cmd /k cargo run -- controller

echo.
echo Step 4: Starting WAF Agent (connecting to Controller) in a new window...
start "Aegis Agent" cmd /k cargo run -- agent --controller http://localhost:8080

echo.
echo Step 5: Starting Dashboard Vite Dev Server in a new window...
start "Aegis Dashboard" cmd /c "cd dashboard && npm run dev"

echo.
echo All processes started! 
echo Dashboard UI available at: http://localhost:5173/
echo Controller API available at: http://localhost:8080/
echo ===================================================
pause
