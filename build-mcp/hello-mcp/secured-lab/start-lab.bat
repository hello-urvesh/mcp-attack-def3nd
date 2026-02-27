@echo off
setlocal enabledelayedexpansion

echo ==============================================
echo   Nullcon MCP Security Lab - SECURED Setup
echo ==============================================
echo.
echo   All OWASP MCP Top 10 vulnerabilities FIXED
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
echo [Phase 2/4] Starting SECURED MCP Server...
cd /d "%ROOT%phase2-mcp\compose"
docker compose up -d --build
echo [+] Secured MCP Server started.

REM Phase 3: Start Attacker Container
echo.
echo [Phase 3/4] Starting Attacker container (for testing)...
cd /d "%ROOT%phase3-attacker\compose"
docker compose up -d --build
echo [+] Attacker container started.

REM Phase 4: Check Ollama and start LLM Gateway
echo.
echo [Phase 4/4] Starting SECURED LLM Gateway...

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

docker compose build --no-cache >nul 2>&1
if errorlevel 1 (
    echo [!] Build failed. Clearing cache and retrying...
    docker builder prune -af >nul 2>&1
    docker compose build --no-cache
)

docker compose up -d
if errorlevel 1 (
    echo [!] Failed to start LLM Gateway.
) else (
    echo [+] Secured LLM Gateway started.
)

:skip_llm

echo.
echo ==============================================
echo   SECURED Lab Ready!
echo ==============================================
echo.
echo   All security controls ENABLED:
echo     - Authentication required (no fallback)
echo     - Field allowlist on profile updates
echo     - Predefined formulas only (no eval)
echo     - URL allowlist for IOC enrichment
echo     - Tenant-isolated context storage
echo     - Comprehensive audit logging
echo     - Prompt injection detection
echo.
echo   Web Interfaces:
echo     - LLM Chat UI:   http://localhost:8080
echo     - Kibana:        http://localhost:5601
echo     - Elasticsearch: http://localhost:9200
echo.
echo   Test that attacks are BLOCKED:
echo     docker exec -it attacker python mcp_hound.py call get_debug_info
echo     (Should NOT show secrets)
echo.
echo     docker exec -it attacker python mcp_hound.py call search_alerts
echo     (Should require auth_token)
echo.
echo ==============================================

cd /d "%ROOT%"
pause
