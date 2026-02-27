@echo off
echo ==============================================
echo   Stopping Nullcon MCP Security Lab
echo ==============================================
echo.

set "ROOT=%~dp0"

echo [*] Stopping LLM Gateway...
cd /d "%ROOT%phase4-llm\compose" 2>nul
docker compose down 2>nul

echo [*] Stopping Attacker...
cd /d "%ROOT%phase3-attacker\compose"
docker compose down 2>nul

echo [*] Stopping MCP Server...
cd /d "%ROOT%phase2-mcp\compose"
docker compose down 2>nul

echo [*] Stopping ELK...
cd /d "%ROOT%phase1-elk\compose"
docker compose down 2>nul

echo.
echo [+] All containers stopped.
echo.

cd /d "%ROOT%"
pause
