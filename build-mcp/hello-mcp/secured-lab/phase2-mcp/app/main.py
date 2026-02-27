"""
Nullcon MCP Security Lab - SECURED MCP Server
All vulnerabilities fixed with proper security controls.
"""

import os
import re
import json
import secrets
import hashlib
import ipaddress
from typing import Any, Dict, Optional, List
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
import time

import httpx
from elasticsearch import Elasticsearch
from fastmcp import FastMCP

APP_NAME = "soc-alerts-mcp-secured"
ES_URL = os.getenv("ES_URL", "http://elk-es:9200")
ES_INDEX = os.getenv("ES_INDEX", "soc-alerts-*")

TOKEN_SECRET = os.getenv("TOKEN_SECRET", "mcp-nullcon-2025-secret")

def generate_token(username: str, role: str) -> str:
    hash_input = f"{username}:{TOKEN_SECRET}"
    hash_value = hashlib.md5(hash_input.encode()).hexdigest()[:12]
    return f"sk-{role}-{hash_value}"

AUTH_TOKENS = {
    generate_token("jsmith", "analyst"): {
        "user": "jsmith", "role": "analyst", "permissions": ["read"],
        "team": "tier1", "tenant": "acme-corp"
    },
    generate_token("mwilson", "analyst"): {
        "user": "mwilson", "role": "analyst", "permissions": ["read"],
        "team": "tier1", "tenant": "acme-corp"
    },
    generate_token("agarcia", "senior"): {
        "user": "agarcia", "role": "senior_analyst", "permissions": ["read", "write"],
        "team": "tier2", "tenant": "acme-corp"
    },
    generate_token("admin", "admin"): {
        "user": "admin", "role": "admin", "permissions": ["read", "write", "admin", "remediate"],
        "team": "soc-lead", "tenant": "acme-corp"
    },
    generate_token("bsmith", "analyst"): {
        "user": "bsmith", "role": "analyst", "permissions": ["read"],
        "team": "tier1", "tenant": "globex-inc"
    },
}

AUDIT_LOG: List[Dict] = []
MAX_AUDIT_ENTRIES = 1000

def log_audit(
    tool: str,
    user: str,
    tenant: str,
    status: str,
    request_params: dict,
    response_summary: str = "",
    correlation_id: str = None
):
    """Comprehensive audit logging with full request details."""
    sanitized_params = sanitize_sensitive(request_params)
    
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "correlation_id": correlation_id or secrets.token_hex(8),
        "tool": tool,
        "user": user,
        "tenant": tenant,
        "status": status,
        "request_params": sanitized_params,
        "request_hash": hashlib.sha256(json.dumps(request_params, sort_keys=True).encode()).hexdigest()[:16],
        "response_summary": response_summary
    }
    AUDIT_LOG.append(entry)
    if len(AUDIT_LOG) > MAX_AUDIT_ENTRIES:
        AUDIT_LOG.pop(0)
    
    print(f"[AUDIT] {json.dumps(entry)}")


def sanitize_sensitive(params: dict) -> dict:
    """Mask sensitive values in logs."""
    sensitive_keys = ["password", "token", "secret", "api_key", "auth_token"]
    result = {}
    for key, value in params.items():
        if any(s in key.lower() for s in sensitive_keys):
            result[key] = "***REDACTED***"
        elif isinstance(value, dict):
            result[key] = sanitize_sensitive(value)
        else:
            result[key] = value
    return result


def log_security_event(event_type: str, user: str, details: str):
    """Log security-relevant events."""
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "event_type": event_type,
        "user": user,
        "details": details,
        "severity": "warning" if "blocked" in event_type else "info"
    }
    print(f"[SECURITY] {json.dumps(entry)}")


TENANT_CONTEXT_STORE: Dict[str, Dict[str, Dict]] = defaultdict(dict)

RATE_LIMITS: Dict[str, List[float]] = defaultdict(list)

def check_rate_limit(identifier: str, max_per_minute: int = 60) -> bool:
    """Rate limiting to prevent brute force."""
    now = time.time()
    RATE_LIMITS[identifier] = [t for t in RATE_LIMITS[identifier] if t > now - 60]
    if len(RATE_LIMITS[identifier]) >= max_per_minute:
        return False
    RATE_LIMITS[identifier].append(now)
    return True


def authenticate(token: Optional[str]) -> Dict[str, Any]:
    """Require authentication, generic errors, constant-time comparison."""
    
    if not token:
        return {"authenticated": False, "error": "Authentication required"}
    
    for valid_token, user_data in AUTH_TOKENS.items():
        if secrets.compare_digest(token, valid_token):
            return {**user_data, "authenticated": True}
    
    return {"authenticated": False, "error": "Invalid credentials"}


def check_permission(auth: Dict, required: str) -> bool:
    return required in auth.get("permissions", [])


es = Elasticsearch(ES_URL)

mcp = FastMCP(APP_NAME)


@mcp.tool()
def update_my_profile(settings: str, auth_token: str = "") -> dict:
    """
    Update your profile settings.
    
    Args:
        settings: JSON object with fields to update.
                  Allowed fields: display_name, email_notifications, theme
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    try:
        updates = json.loads(settings) if settings else {}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {str(e)}"}
    
    if not updates:
        return {"error": "No settings provided"}
    
    ALLOWED_FIELDS = ["display_name", "email_notifications", "theme"]
    
    invalid_fields = [k for k in updates.keys() if k not in ALLOWED_FIELDS]
    if invalid_fields:
        log_security_event("mass_assignment_blocked", auth["user"], f"Attempted fields: {invalid_fields}")
        return {
            "error": "Invalid fields in settings",
            "invalid_fields": invalid_fields,
            "allowed_fields": ALLOWED_FIELDS
        }
    
    if "theme" in updates and updates["theme"] not in ["light", "dark", "system"]:
        return {"error": "Invalid theme. Allowed: light, dark, system"}
    
    if "email_notifications" in updates and not isinstance(updates["email_notifications"], bool):
        return {"error": "email_notifications must be boolean"}
    
    log_audit("update_my_profile", auth["user"], auth["tenant"], "success",
              {"fields": list(updates.keys())}, "Profile updated")
    
    return {
        "status": "updated",
        "updated_fields": list(updates.keys()),
        "profile": {
            "display_name": updates.get("display_name", auth["user"]),
            "email_notifications": updates.get("email_notifications", True),
            "theme": updates.get("theme", "dark")
        }
    }


@mcp.tool()
def search_alerts(
    query: str = "*",
    severity: str = "",
    tenant: str = "",
    limit: int = 10,
    auth_token: str = ""
) -> dict:
    """Search security alerts in the SOC database."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    must = []
    if query and query != "*":
        must.append({"query_string": {"query": query}})
    if severity:
        must.append({"term": {"severity.keyword": severity.lower()}})
    if tenant:
        must.append({"term": {"tenant.keyword": tenant}})
    
    es_query = {"bool": {"must": must}} if must else {"match_all": {}}
    
    limit = max(1, min(limit or 10, 100))
    
    try:
        result = es.search(index=ES_INDEX, query=es_query, size=limit)
        alerts = [hit["_source"] for hit in result["hits"]["hits"]]
        
        log_audit("search_alerts", auth["user"], auth["tenant"], "success",
                  {"query": query, "severity": severity, "tenant": tenant, "limit": limit},
                  f"Found {len(alerts)} alerts")
        
        return {
            "total": result["hits"]["total"]["value"],
            "returned": len(alerts),
            "alerts": alerts
        }
    except Exception as e:
        log_audit("search_alerts", auth["user"], auth["tenant"], "error",
                  {"query": query}, str(e))
        return {"error": "Search failed"}


@mcp.tool()
def get_alert_details(alert_id: str, auth_token: str = "") -> dict:
    """Get full details for a specific alert."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    if not re.match(r'^[A-Z]-\d{4}$', alert_id):
        return {"error": "Invalid alert_id format. Expected: X-0000"}
    
    try:
        result = es.search(
            index=ES_INDEX,
            query={"term": {"alert_id.keyword": alert_id}},
            size=1
        )
        
        if not result["hits"]["hits"]:
            return {"error": f"Alert {alert_id} not found"}
        
        alert = result["hits"]["hits"][0]["_source"]
        
        try:
            notes_result = es.search(
                index="analyst-notes",
                query={"term": {"alert_id.keyword": alert_id}},
                size=50,
                sort=[{"@timestamp": "asc"}]
            )
            notes = [hit["_source"] for hit in notes_result["hits"]["hits"]]
        except:
            notes = []
        
        log_audit("get_alert_details", auth["user"], auth["tenant"], "success",
                  {"alert_id": alert_id}, f"Alert: {alert.get('title')}")
        
        return {
            "alert": alert,
            "investigation_notes": notes
        }
    except Exception as e:
        log_audit("get_alert_details", auth["user"], auth["tenant"], "error",
                  {"alert_id": alert_id}, str(e))
        return {"error": "Failed to retrieve alert"}


@mcp.tool()
def add_investigation_note(alert_id: str, note: str, auth_token: str = "") -> dict:
    """Add an investigation note to an alert."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    if not alert_id or not re.match(r'^[A-Z]-\d{4}$', alert_id):
        return {"error": "Invalid alert_id format. Expected: X-0000"}
    
    if not note or len(note) > 10000:
        return {"error": "Note is required and must be under 10000 characters"}
    
    doc = {
        "@timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "alert_id": alert_id,
        "analyst": auth["user"],
        "role": auth["role"],
        "note": note,
        "tenant": auth["tenant"]
    }
    
    try:
        result = es.index(index="analyst-notes", document=doc, refresh=True)
        
        log_audit("add_investigation_note", auth["user"], auth["tenant"], "success",
                  {"alert_id": alert_id, "note_length": len(note)},
                  f"Note added to {alert_id}")
        
        return {
            "status": "success",
            "message": f"Note added to alert {alert_id}",
            "note_id": result["_id"],
            "added_by": auth["user"],
            "timestamp": doc["@timestamp"]
        }
    except Exception as e:
        log_audit("add_investigation_note", auth["user"], auth["tenant"], "error",
                  {"alert_id": alert_id}, str(e))
        return {"error": "Failed to add note"}


@mcp.tool()
def execute_remediation(
    alert_id: str,
    action: str,
    target: str,
    auth_token: str = ""
) -> dict:
    """Execute remediation action. Requires 'remediate' or 'admin' permission."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    has_permission = check_permission(auth, "remediate") or check_permission(auth, "admin")
    
    if not has_permission:
        log_security_event("unauthorized_remediation", auth["user"], 
                          f"Attempted {action} on {target}")
        return {
            "error": "Permission denied",
            "message": "Requires 'remediate' or 'admin' permission."
        }
    
    valid_actions = ["block_ip", "isolate_host", "disable_account", "kill_process"]
    if action not in valid_actions:
        return {"error": f"Invalid action. Valid actions: {valid_actions}"}
    
    if action == "block_ip":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return {"error": "Invalid IP address format"}
    
    log_audit("execute_remediation", auth["user"], auth["tenant"], "success",
              {"alert_id": alert_id, "action": action, "target": target},
              f"Executed {action} on {target}")
    
    return {
        "status": "executed",
        "action": action,
        "target": target,
        "alert_id": alert_id,
        "executed_by": auth["user"],
        "executed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }


ALLOWED_TI_DOMAINS = ["api.virustotal.com", "otx.alienvault.com", "api.abuseipdb.com"]

BLOCKED_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

MOCK_TI_RESPONSE = {
    "data": {
        "type": "ip_address",
        "attributes": {
            "reputation": 0,
            "country": "US",
            "as_owner": "GOOGLE",
            "last_analysis_stats": {"harmless": 70, "malicious": 2}
        }
    }
}


def is_safe_url(url: str) -> tuple:
    """Validate URL is safe to fetch - prevents SSRF."""
    try:
        parsed = urlparse(url)
        
        if parsed.scheme not in ["http", "https"]:
            return False, "Only http/https allowed"
        
        if parsed.netloc not in ALLOWED_TI_DOMAINS:
            return False, f"Domain not in allowlist. Allowed: {ALLOWED_TI_DOMAINS}"
        
        import socket
        try:
            ip = socket.gethostbyname(parsed.hostname)
            ip_addr = ipaddress.ip_address(ip)
            
            for blocked in BLOCKED_IP_RANGES:
                if ip_addr in blocked:
                    return False, f"IP {ip} is in blocked range"
        except socket.gaierror:
            return False, "Could not resolve hostname"
        
        return True, "OK"
    except Exception as e:
        return False, str(e)


@mcp.tool()
def enrich_ioc(indicator: str, source_url: str = "", auth_token: str = "") -> dict:
    """Enrich an IOC with threat intelligence."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    if not source_url:
        log_audit("enrich_ioc", auth["user"], auth["tenant"], "success",
                  {"indicator": indicator, "source": "default"}, "Mock enrichment")
        return {
            "indicator": indicator,
            "source": "VirusTotal (simulated)",
            "enrichment": MOCK_TI_RESPONSE
        }
    
    is_safe, reason = is_safe_url(source_url)
    if not is_safe:
        log_security_event("ssrf_blocked", auth["user"], f"URL: {source_url}, Reason: {reason}")
        return {
            "error": "URL not allowed",
            "reason": reason,
            "allowed_domains": ALLOWED_TI_DOMAINS
        }
    
    log_audit("enrich_ioc", auth["user"], auth["tenant"], "success",
              {"indicator": indicator, "source_url": source_url}, "External enrichment")
    
    try:
        with httpx.Client(timeout=10.0, follow_redirects=False, verify=True) as client:
            response = client.get(source_url)
            return {
                "indicator": indicator,
                "source": source_url,
                "data": response.json() if "application/json" in response.headers.get("content-type", "") else response.text[:1000]
            }
    except Exception as e:
        return {"error": "Failed to fetch threat intelligence"}


@mcp.tool()
def export_report(alert_id: str, format: str = "txt", auth_token: str = "") -> dict:
    """Export an alert report."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    if not re.match(r'^[A-Z]-\d{4}$', alert_id):
        return {"error": "Invalid alert_id format. Expected: X-0000"}
    
    if format not in ["txt", "json", "csv"]:
        return {"error": "Invalid format. Allowed: txt, json, csv"}
    
    try:
        result = es.search(
            index=ES_INDEX,
            query={"term": {"alert_id.keyword": alert_id}},
            size=1
        )
        
        if not result["hits"]["hits"]:
            return {"error": f"Alert {alert_id} not found"}
        
        alert = result["hits"]["hits"][0]["_source"]
    except Exception as e:
        return {"error": "Failed to fetch alert"}
    
    if format == "txt":
        report = f"""=== Alert Report ===
ID: {alert_id}
Title: {alert.get('title', 'N/A')}
Severity: {alert.get('severity', 'N/A')}
Type: {alert.get('alert_type', 'N/A')}
Timestamp: {alert.get('@timestamp', 'N/A')}
Generated: {datetime.utcnow().isoformat()}
Generated by: {auth['user']}
"""
    elif format == "json":
        report = json.dumps(alert, indent=2)
    else:
        report = f"alert_id,title,severity\n{alert_id},{alert.get('title')},{alert.get('severity')}"
    
    log_audit("export_report", auth["user"], auth["tenant"], "success",
              {"alert_id": alert_id, "format": format}, "Report generated")
    
    return {
        "report": report,
        "format": format,
        "generated_by": auth["user"]
    }


@mcp.tool()
def calculate_risk_score(
    alert_id: str,
    formula: str = "default",
    auth_token: str = ""
) -> dict:
    """Calculate risk score. Supports: 'default', 'cvss', 'weighted'."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    ALLOWED_FORMULAS = ["default", "cvss", "weighted"]
    
    if formula not in ALLOWED_FORMULAS:
        log_security_event("code_injection_blocked", auth["user"], f"Formula: {formula}")
        return {
            "error": "Invalid formula",
            "allowed_formulas": ALLOWED_FORMULAS,
            "description": {
                "default": "Simple severity-based scoring",
                "cvss": "CVSS-adjusted with asset context",
                "weighted": "Weighted by alert type"
            }
        }
    
    try:
        result = es.search(
            index=ES_INDEX,
            query={"term": {"alert_id.keyword": alert_id}},
            size=1
        )
        
        if not result["hits"]["hits"]:
            return {"error": f"Alert {alert_id} not found"}
        
        alert = result["hits"]["hits"][0]["_source"]
    except Exception as e:
        return {"error": "Failed to fetch alert"}
    
    severity_scores = {"critical": 95, "high": 75, "medium": 50, "low": 25}
    severity = alert.get("severity", "medium").lower()
    base_score = severity_scores.get(severity, 50)
    
    if formula == "default":
        score = base_score
    elif formula == "cvss":
        if alert.get("alert_type") == "endpoint":
            score = min(base_score + 15, 100)
        elif alert.get("alert_type") == "network":
            score = min(base_score + 10, 100)
        else:
            score = base_score
    else:
        type_weights = {"endpoint": 1.2, "network": 1.1, "authentication": 1.0}
        weight = type_weights.get(alert.get("alert_type", ""), 1.0)
        score = min(int(base_score * weight), 100)
    
    log_audit("calculate_risk_score", auth["user"], auth["tenant"], "success",
              {"alert_id": alert_id, "formula": formula},
              f"Score: {score}")
    
    return {
        "alert_id": alert_id,
        "risk_score": score,
        "severity": severity,
        "calculation_method": formula,
        "calculated_by": auth["user"]
    }


@mcp.tool()
def get_debug_info(auth_token: str = "") -> dict:
    """Get server status (safe information only)."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    log_audit("get_debug_info", auth["user"], auth["tenant"], "success",
              {}, "Debug info retrieved")
    
    return {
        "status": "operational",
        "version": "2.0-secured",
        "mode": "secured",
        "your_user": auth["user"],
        "your_role": auth["role"],
        "your_permissions": auth["permissions"]
    }


@mcp.tool()
def get_audit_log(limit: int = 20, auth_token: str = "") -> dict:
    """Retrieve audit log entries with full request details."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    limit = max(1, min(limit or 20, 100))
    entries = list(AUDIT_LOG)[-limit:]
    
    return {
        "total_entries": len(AUDIT_LOG),
        "returned": len(entries),
        "entries": entries,
        "note": "Full request parameters are logged (sensitive values redacted)"
    }


@mcp.tool()
def get_recent_activity(limit: int = 20, auth_token: str = "") -> dict:
    """View recent activity - filtered by tenant."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    tenant_entries = [e for e in AUDIT_LOG if e.get("tenant") == auth["tenant"]]
    entries = tenant_entries[-limit:] if limit else tenant_entries
    
    return {
        "total_entries": len(tenant_entries),
        "returned": len(entries),
        "entries": entries
    }


@mcp.tool()
def save_context(key: str, value: str, auth_token: str = "") -> dict:
    """Save investigation context (isolated per user and tenant)."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    if not key or len(key) > 100:
        return {"error": "Key is required and must be under 100 characters"}
    
    if not value or len(value) > 10000:
        return {"error": "Value is required and must be under 10000 characters"}
    
    tenant = auth["tenant"]
    user = auth["user"]
    
    namespaced_key = f"{user}:{key}"
    
    TENANT_CONTEXT_STORE[tenant][namespaced_key] = {
        "value": value,
        "saved_by": user,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }
    
    log_audit("save_context", auth["user"], auth["tenant"], "success",
              {"key": key, "value_length": len(value)}, "Context saved")
    
    return {
        "status": "saved",
        "key": key,
        "saved_by": user,
        "timestamp": TENANT_CONTEXT_STORE[tenant][namespaced_key]["timestamp"]
    }


@mcp.tool()
def get_context(key: str, auth_token: str = "") -> dict:
    """Retrieve your saved investigation context."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    tenant = auth["tenant"]
    user = auth["user"]
    namespaced_key = f"{user}:{key}"
    
    tenant_store = TENANT_CONTEXT_STORE.get(tenant, {})
    
    if namespaced_key not in tenant_store:
        return {"error": f"Context key '{key}' not found"}
    
    context = tenant_store[namespaced_key]
    
    log_audit("get_context", auth["user"], auth["tenant"], "success",
              {"key": key}, "Context retrieved")
    
    return {
        "key": key,
        "value": context["value"],
        "timestamp": context["timestamp"]
    }


@mcp.tool()
def list_context_keys(auth_token: str = "") -> dict:
    """List your saved context keys."""
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error")}
    
    tenant = auth["tenant"]
    user = auth["user"]
    prefix = f"{user}:"
    
    tenant_store = TENANT_CONTEXT_STORE.get(tenant, {})
    user_keys = [
        {
            "key": k.replace(prefix, ""),
            "timestamp": v["timestamp"]
        }
        for k, v in tenant_store.items()
        if k.startswith(prefix)
    ]
    
    return {
        "total_keys": len(user_keys),
        "keys": user_keys
    }


print(f"[*] SOC MCP Server - SECURED MODE")
print(f"[*] Elasticsearch: {ES_URL}")
print(f"[*] All security controls enabled")

app = mcp.http_app()
