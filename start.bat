@echo off
echo ===================================================
echo   jarsWAF Development Launcher (Windows)
echo ===================================================
echo.
echo NOTE: jarsWAF Agent requires Linux/WSL2 (due to Pingora proxy engine).
echo Only the WAF Controller and Dashboard will be started on Windows natively.
echo To run the Agent, please compile and run it inside WSL2 (Ubuntu).
echo.

echo Step 1: Starting WAF Controller in a new window...
start "jarsWAF Controller" cmd /k cargo run -- controller

echo.
echo Step 2: Starting Dashboard Vite Dev Server in a new window...
start "jarsWAF Dashboard" cmd /c "cd dashboard && npm run dev"

echo.
echo All Windows native processes started! 
echo Dashboard UI available at: http://localhost:5173/
echo Controller API available at: http://localhost:8080/
echo ===================================================
pause
