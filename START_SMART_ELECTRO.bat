@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js is not installed. Install Node.js LTS first.&pause&exit /b 1)
if not exist node_modules (
  echo Installing dependencies...
  call npm install
  if errorlevel 1 (echo npm install failed.&pause&exit /b 1)
)
echo Starting Smart Electro on http://localhost:3000
start "Smart Electro Server" cmd /k "npm start"
timeout /t 3 /nobreak >nul
start "" "http://localhost:3000"
