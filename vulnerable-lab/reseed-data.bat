@echo off
echo ==============================================
echo   Reseed Lab Data
echo ==============================================
echo.

set "ROOT=%~dp0"
cd /d "%ROOT%phase1-elk\seed"

echo [*] Clearing analyst-notes index...
curl -fsS -X DELETE "http://localhost:9200/analyst-notes" >nul 2>&1

echo [*] Seeding SOC alerts...
curl -fsS -H "Content-Type: application/x-ndjson" --data-binary "@soc-alerts.bulk.ndjson" "http://localhost:9200/_bulk?refresh=true" >nul

echo [*] Seeding analyst notes...
curl -fsS -H "Content-Type: application/x-ndjson" --data-binary "@analyst-notes.bulk.ndjson" "http://localhost:9200/_bulk?refresh=true" >nul

echo.
echo [+] Data reset complete.
echo.

cd /d "%ROOT%"
pause
