@echo off
echo ==============================================
echo   Starting LLM Gateway (Phase 4)
echo ==============================================
echo.

set "ROOT=%~dp0"

REM Check prerequisites
echo [*] Checking prerequisites...

REM Check if main lab network exists
docker network ls | findstr "nullcon-mcp-elk_default" >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Lab network not found.
    echo [!] Please run start-lab.bat first.
    pause
    exit /b 1
)

REM Check if MCP server is running
docker ps --filter "name=mcp-ref" --filter "status=running" | findstr "mcp-ref" >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: MCP server not running.
    echo [!] Please run start-lab.bat first.
    pause
    exit /b 1
)

REM Check Ollama
curl -s "http://localhost:11434/api/tags" >nul 2>&1
if errorlevel 1 (
    echo [!] ERROR: Ollama not running at localhost:11434
    echo.
    echo [!] Please start Ollama:
    echo        - Open Ollama app from Start Menu, OR
    echo        - Run: ollama serve
    echo.
    echo [!] If not installed:
    echo        1. Download from https://ollama.ai
    echo        2. Run: ollama pull llama3.2
    pause
    exit /b 1
)

echo [+] All prerequisites met.
echo.

REM Build and start
echo [*] Building LLM Gateway (no-cache)...
cd /d "%ROOT%phase4-llm\compose"
docker compose build --no-cache

echo.
echo [*] Starting LLM Gateway...
docker compose up -d

echo.
echo [+] LLM Gateway started!
echo [+] Open: http://localhost:8080
echo.

cd /d "%ROOT%"
pause
