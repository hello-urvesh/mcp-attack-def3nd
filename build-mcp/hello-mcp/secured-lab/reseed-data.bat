@echo off
echo Reseeding Secured Lab data...

set "ROOT=%~dp0"

cd /d "%ROOT%phase1-elk\seed"

echo [*] Deleting existing indices...
curl -fsS -X DELETE "http://localhost:9200/soc-alerts-*" >nul 2>&1
curl -fsS -X DELETE "http://localhost:9200/analyst-notes" >nul 2>&1

echo [*] Seeding alerts...
curl -fsS -H "Content-Type: application/x-ndjson" --data-binary "@soc-alerts.bulk.ndjson" "http://localhost:9200/_bulk?refresh=true" >nul

echo [*] Seeding analyst notes...
curl -fsS -H "Content-Type: application/x-ndjson" --data-binary "@analyst-notes.bulk.ndjson" "http://localhost:9200/_bulk?refresh=true" >nul

echo.
echo [+] Data reseeded successfully.
pause
