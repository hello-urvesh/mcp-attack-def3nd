@echo off
setlocal enabledelayedexpansion

echo ==============================================
echo   Nullcon MCP Security Lab - Full Setup
echo ==============================================
echo.

set "ROOT=%~dp0"

REM Phase 1: Start ELK Stack
echo [Phase 1/4] Starting ELK Stack...
cd /d "%ROOT%phase1-elk\compose"
docker compose up -d

echo.
echo [*] Waiting for Elasticsearch...
:wait_es
timeout /t 3 /nobreak >nul
curl -fsS "http://localhost:9200" >nul 2>&1
if errorlevel 1 (
    echo    Still waiting for Elasticsearch...
    goto wait_es
)
echo [+] Elasticsearch ready.

echo.
echo [*] Seeding data...
cd /d "%ROOT%phase1-elk\seed"
curl -fsS -X DELETE "http://localhost:9200/analyst-notes" >nul 2>&1
curl -fsS -H "Content-Type: application/x-ndjson" --data-binary "@soc-alerts.bulk.ndjson" "http://localhost:9200/_bulk?refresh=true" >nul
curl -fsS -H "Content-Type: application/x-ndjson" --data-binary "@analyst-notes.bulk.ndjson" "http://localhost:9200/_bulk?refresh=true" >nul
echo [+] Data seeded.

REM Phase 2: Start MCP Server
echo.
echo [Phase 2/4] Starting MCP Server...
cd /d "%ROOT%phase2-mcp\compose"
docker compose up -d --build
echo [+] MCP Server started.

REM Phase 3: Start Attacker Container
echo.
echo [Phase 3/4] Starting Attacker container...
cd /d "%ROOT%phase3-attacker\compose"
docker compose up -d --build
echo [+] Attacker container started.

REM Phase 4: Check Ollama and start LLM Gateway
echo.
echo [Phase 4/4] Starting LLM Gateway...

curl -s "http://localhost:11434/api/tags" >nul 2>&1
if errorlevel 1 (
    echo [!] WARNING: Ollama not running at localhost:11434
    echo [!] LLM Chat interface will NOT work.
    echo [!] To enable:
    echo        1. Install Ollama from https://ollama.ai
    echo        2. Run: ollama pull llama3.2
    echo        3. Start Ollama app or run: ollama serve
    echo        4. Then run: start-llm.bat
    echo.
    goto :skip_llm
)

echo [+] Ollama detected. Building LLM Gateway...
cd /d "%ROOT%phase4-llm\compose"

REM Build with --no-cache to avoid cache corruption
docker compose build --no-cache >nul 2>&1
if errorlevel 1 (
    echo [!] Build failed. Clearing cache and retrying...
    docker builder prune -af >nul 2>&1
    docker compose build --no-cache
)

docker compose up -d
if errorlevel 1 (
    echo [!] Failed to start LLM Gateway. Run manually:
    echo     cd phase4-llm\compose
    echo     docker compose up -d --build
) else (
    echo [+] LLM Gateway started.
)

:skip_llm

echo.
echo ==============================================
echo   Lab Ready!
echo ==============================================
echo.
echo   Web Interfaces:
echo     - LLM Chat UI:   http://localhost:8080
echo     - Kibana:        http://localhost:5601
echo     - Elasticsearch: http://localhost:9200
echo.
echo   CLI Attack Tool (use -a KEY=VALUE for args):
echo     docker exec -it attacker python mcp_hound.py discover
echo     docker exec -it attacker python mcp_hound.py call get_alert_details -a alert_id=A-0001
echo     docker exec -it attacker python mcp_hound.py call search_alerts -a severity=critical
echo.
echo   For complex payloads, exec into the container:
echo     docker exec -it attacker bash
echo     python mcp_hound.py call calculate_risk_score -j '{"alert_id":"A-0001","formula":"..."}'
echo.
echo   Utilities:
echo     reseed-data.bat  - Reset all data
echo     stop-lab.bat     - Stop all containers
echo.
echo ==============================================

cd /d "%ROOT%"
pause
