@echo off
echo Stopping Secured MCP Lab...

cd /d "%~dp0phase4-llm\compose"
docker compose down 2>nul

cd /d "%~dp0phase3-attacker\compose"
docker compose down 2>nul

cd /d "%~dp0phase2-mcp\compose"
docker compose down 2>nul

cd /d "%~dp0phase1-elk\compose"
docker compose down 2>nul

echo.
echo [+] All containers stopped.
pause
