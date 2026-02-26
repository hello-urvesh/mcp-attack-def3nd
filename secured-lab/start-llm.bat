@echo off
echo Starting Secured LLM Gateway...

cd /d "%~dp0phase4-llm\compose"
docker compose up -d --build

echo.
echo [+] Secured LLM Gateway started at http://localhost:8080
pause
