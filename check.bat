@echo off
echo ===================================================
echo   jarsWAF Code Verification and Linting Tool
echo ===================================================
echo.

echo [INFO] Step 1: Checking Rust code formatting...
cargo fmt --check
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Rust code is not formatted. Running formatting tool...
    cargo fmt
)

echo.
echo [INFO] Step 2: Running cargo clippy...
cargo clippy --all-targets --all-features -- -D warnings
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Clippy linter found errors.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [INFO] Step 3: Running Rust cargo tests...
cargo test
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Rust unit tests failed.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [INFO] Step 4: Formatting dashboard code (Prettier)...
cd dashboard
call npm run format
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Prettier formatting failed.
)

echo.
echo [INFO] Step 5: Checking dashboard types & Svelte (svelte-check)...
call npm run check
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Dashboard check failed.
    cd ..
    pause
    exit /b %ERRORLEVEL%
)

cd ..
echo.
echo ===================================================
echo [SUCCESS] All checks passed successfully!
echo ===================================================
pause
