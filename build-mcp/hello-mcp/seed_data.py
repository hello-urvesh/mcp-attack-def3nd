"""Seed sample security logs into Elasticsearch"""
import httpx
import time

ES_URL = "http://localhost:9201"

print("=" * 50)
print("Seeding Elasticsearch with sample data")
print("=" * 50)

# Wait for ES to be ready
print("\nWaiting for Elasticsearch...")
for i in range(30):
    try:
        r = httpx.get(f"{ES_URL}/_cluster/health", timeout=5)
        if r.status_code == 200:
            print(f"Elasticsearch is ready! Status: {r.json().get('status')}")
            break
    except Exception as e:
        pass
    print(f"  Waiting... ({i+1}/30)")
    time.sleep(2)
else:
    print("\nERROR: Cannot connect to Elasticsearch")
    print(f"Make sure ES is running: docker compose up -d")
    print(f"Check: curl {ES_URL}")
    exit(1)

# Sample security logs
logs = [
    {"timestamp": "2025-02-21T10:15:00Z", "event": "login_success", "user": "admin", "ip": "192.168.1.100", "message": "User login successful"},
    {"timestamp": "2025-02-21T10:16:00Z", "event": "login_failed", "user": "admin", "ip": "10.0.0.55", "message": "Invalid password"},
    {"timestamp": "2025-02-21T10:16:30Z", "event": "login_failed", "user": "admin", "ip": "10.0.0.55", "message": "Invalid password"},
    {"timestamp": "2025-02-21T10:17:00Z", "event": "login_failed", "user": "admin", "ip": "10.0.0.55", "message": "Account locked"},
    {"timestamp": "2025-02-21T10:20:00Z", "event": "file_access", "user": "jsmith", "ip": "192.168.1.50", "message": "Accessed /etc/passwd"},
    {"timestamp": "2025-02-21T10:25:00Z", "event": "alert", "user": "system", "ip": "203.0.113.50", "message": "SSH brute force detected"},
]

print(f"\nCreating {len(logs)} security logs...")
for i, log in enumerate(logs):
    r = httpx.post(f"{ES_URL}/security-logs/_doc", json=log)
    print(f"  [{i+1}/{len(logs)}] {log['event']}: {log['message'][:40]}")

# Refresh index
httpx.post(f"{ES_URL}/security-logs/_refresh")

print(f"\n✅ Done! {len(logs)} logs created.")
print(f"\nView in Kibana: http://localhost:5602")
print(f"Or query directly: curl '{ES_URL}/security-logs/_search?pretty'")
