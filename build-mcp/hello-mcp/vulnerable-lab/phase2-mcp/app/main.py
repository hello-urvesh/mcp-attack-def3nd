"""
Nullcon MCP Security Lab - Vulnerable MCP Server
"""

import os
import re
import json
import subprocess
import hashlib
import traceback
from typing import Any, Dict, Optional, List
from datetime import datetime
from collections import deque

import httpx
from elasticsearch import Elasticsearch
from fastmcp import FastMCP

APP_NAME = "soc-alerts-mcp"
MODE = os.getenv("MCP_MODE", "vuln").lower()
ES_URL = os.getenv("ES_URL", "http://elk-es:9200")
ES_INDEX = os.getenv("ES_INDEX", "soc-alerts-*")

TOKEN_SECRET = "mcp-nullcon-2025-secret"

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

DEFAULT_SERVICE_ACCOUNT = {
    "user": "svc-mcp-dev", "role": "analyst", "permissions": ["read"],
    "team": "service", "tenant": "acme-corp"
}

ALL_TENANTS = ["acme-corp", "globex-inc", "wayne-ent"]

AUDIT_LOG: List[Dict] = []
MAX_AUDIT_ENTRIES = 100

def log_audit(tool: str, user: str, status: str, summary: str):
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "tool": tool,
        "user": user,
        "status": status,
        "summary": summary,
    }
    AUDIT_LOG.append(entry)
    if len(AUDIT_LOG) > MAX_AUDIT_ENTRIES:
        AUDIT_LOG.pop(0)

SHARED_QUERY_HISTORY: deque = deque(maxlen=50)

def log_query(user: str, tenant: str, tool: str, query_details: str, result_summary: str):
    entry = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "user": user,
        "tenant": tenant,
        "tool": tool,
        "query": query_details,
        "result_preview": result_summary,
    }
    SHARED_QUERY_HISTORY.append(entry)


def authenticate(token: Optional[str]) -> Dict[str, Any]:
    if not token:
        if MODE == "vuln":
            return {
                **DEFAULT_SERVICE_ACCOUNT,
                "authenticated": True,
                "_auth_method": "default_fallback"
            }
        return {"authenticated": False, "error": "Authentication required"}
    
    if token in AUTH_TOKENS:
        return {**AUTH_TOKENS[token], "authenticated": True, "_auth_method": "token"}
    
    if MODE == "vuln":
        return {
            "authenticated": False,
            "error": "Invalid token",
            "_debug": {
                "token_format": "sk-{role}-{hash}",
                "hash_algorithm": "MD5(username:secret)[:12]",
                "secret_hint": TOKEN_SECRET[:12] + "...",
                "valid_roles": ["analyst", "senior", "admin"],
                "sample_users": ["jsmith", "mwilson", "agarcia", "admin", "bsmith"]
            }
        }
    return {"authenticated": False, "error": "Invalid token"}


def check_permission(auth: Dict, required: str) -> bool:
    return required in auth.get("permissions", [])


def get_user_token(username: str) -> Optional[str]:
    """Find the token for a given username."""
    for token, user_data in AUTH_TOKENS.items():
        if user_data["user"] == username:
            return token
    return None


es = Elasticsearch(ES_URL)

mcp = FastMCP(APP_NAME)


@mcp.tool()
def update_my_profile(settings: str, auth_token: str = "") -> dict:
    """
    Update your profile settings.
    
    Args:
        settings: JSON object with fields to update.
                  Supported: display_name, email_notifications, theme
                  Example: {"display_name": "John Smith", "theme": "dark"}
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    try:
        updates = json.loads(settings) if settings else {}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {str(e)}"}
    
    if not updates:
        return {"error": "No settings provided"}
    
    user_token = get_user_token(auth["user"])
    if not user_token:
        return {"error": "User not found"}
    
    ALLOWED_FIELDS = ["display_name", "email_notifications", "theme"]
    
    if MODE == "hardened":
        invalid_fields = [k for k in updates.keys() if k not in ALLOWED_FIELDS]
        if invalid_fields:
            return {
                "error": "Invalid fields in settings",
                "invalid_fields": invalid_fields,
                "allowed_fields": ALLOWED_FIELDS
            }
    
    updated_fields = []
    
    for field, value in updates.items():
        if MODE == "vuln" or field in ALLOWED_FIELDS:
            AUTH_TOKENS[user_token][field] = value
            updated_fields.append(field)
    
    log_audit("update_my_profile", auth["user"], "success", f"Updated profile fields: {updated_fields}")
    
    current = AUTH_TOKENS[user_token]
    return {
        "status": "updated",
        "updated_fields": updated_fields,
        "profile": {
            "user": current.get("user"),
            "display_name": current.get("display_name", current.get("user")),
            "email_notifications": current.get("email_notifications", True),
            "theme": current.get("theme", "dark"),
            "role": current.get("role"),
            "permissions": current.get("permissions"),
            "tenant": current.get("tenant"),
            "team": current.get("team")
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
    """
    Search security alerts in the SOC database.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    must = []
    if query and query != "*":
        must.append({"query_string": {"query": query}})
    if severity:
        must.append({"term": {"severity.keyword": severity.lower()}})
    if tenant:
        must.append({"term": {"tenant.keyword": tenant}})
    
    es_query = {"bool": {"must": must}} if must else {"match_all": {}}
    
    if limit is None or limit < 1:
        limit = 10
    limit = min(limit, 100)
    
    try:
        result = es.search(index=ES_INDEX, query=es_query, size=limit)
        alerts = [hit["_source"] for hit in result["hits"]["hits"]]
        
        log_audit("search_alerts", auth["user"], "success", f"Searched alerts, returned {len(alerts)} results")
        
        alert_ids = [a.get("alert_id", "unknown") for a in alerts[:3]]
        log_query(
            auth["user"], 
            auth["tenant"], 
            "search_alerts",
            f"query={query}, severity={severity}, tenant={tenant}",
            f"Found {len(alerts)} alerts: {', '.join(alert_ids)}..."
        )
        
        response = {
            "total": result["hits"]["total"]["value"],
            "returned": len(alerts),
            "alerts": alerts,
            "_context": {
                "user": auth["user"],
                "role": auth["role"],
                "tenant": auth["tenant"],
                "permissions": auth["permissions"],
                "auth_method": auth.get("_auth_method")
            }
        }
        
        if MODE == "vuln":
            response["_internal"] = {
                "all_tenants": ALL_TENANTS,
                "es_url": ES_URL
            }
        
        return response
    except Exception as e:
        log_audit("search_alerts", auth["user"], "error", "Search failed")
        return {"error": str(e)}


@mcp.tool()
def get_alert_details(alert_id: str, auth_token: str = "") -> dict:
    """
    Get full details for a specific alert including all investigation notes.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
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
        
        log_audit("get_alert_details", auth["user"], "success", f"Retrieved alert details")
        
        log_query(
            auth["user"],
            auth["tenant"],
            "get_alert_details", 
            f"alert_id={alert_id}",
            f"Alert: {alert.get('title', 'unknown')}, Severity: {alert.get('severity', 'unknown')}"
        )
        
        response = {
            "alert": alert,
            "investigation_notes": notes,
            "_context": {
                "user": auth["user"],
                "role": auth["role"],
                "tenant": auth["tenant"],
                "permissions": auth["permissions"]
            }
        }
        
        if MODE == "vuln":
            response["_internal_config"] = {
                "token_generation": {
                    "algorithm": "MD5",
                    "secret": TOKEN_SECRET,
                    "format": "sk-{role}-{md5(username:secret)[:12]}"
                },
                "all_tenants": ALL_TENANTS,
                "api_keys": {
                    "virustotal": "vt_api_key_a1b2c3d4e5f6",
                    "shodan": "shodan_key_x9y8z7w6",
                    "slack_webhook": "https://hooks.slack.com/services/T00/B00/xxx"
                },
                "internal_services": {
                    "elasticsearch": ES_URL,
                    "siem": "http://siem.internal:8080",
                    "ticketing": "http://jira.internal:8080"
                }
            }
        
        return response
    except Exception as e:
        log_audit("get_alert_details", auth["user"], "error", "Failed to retrieve alert")
        return {"error": str(e), "_trace": traceback.format_exc() if MODE == "vuln" else None}


@mcp.tool()
def add_investigation_note(alert_id: str, note: str, auth_token: str = "") -> dict:
    """
    Add an investigation note to an alert.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    if not alert_id or not note:
        return {"error": "Both alert_id and note are required"}
    
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
        
        log_audit("add_investigation_note", auth["user"], "success", f"Added note to {alert_id}")
        
        log_query(
            auth["user"],
            auth["tenant"],
            "add_investigation_note",
            f"alert_id={alert_id}",
            f"Note added: {note[:50]}..."
        )
        
        return {
            "status": "success",
            "message": f"Note added to alert {alert_id}",
            "note_id": result["_id"],
            "added_by": auth["user"],
            "timestamp": doc["@timestamp"],
            "note_preview": note[:100] + "..." if len(note) > 100 else note
        }
    except Exception as e:
        log_audit("add_investigation_note", auth["user"], "error", "Failed to add note")
        return {"error": str(e)}


@mcp.tool()
def execute_remediation(
    alert_id: str,
    action: str,
    target: str,
    auth_token: str = ""
) -> dict:
    """
    Execute remediation action for an alert. Requires 'remediate' or 'admin' permission.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    valid_actions = ["block_ip", "isolate_host", "disable_account", "kill_process"]
    if action not in valid_actions:
        return {"error": f"Invalid action. Valid actions: {valid_actions}"}
    
    has_permission = check_permission(auth, "remediate") or check_permission(auth, "admin")
    
    if not has_permission:
        return {
            "error": "Permission denied",
            "message": f"Executing '{action}' requires 'remediate' or 'admin' permission.",
            "your_permissions": auth["permissions"],
            "required_permission": "remediate",
            "hint": "Contact your administrator to request elevated permissions."
        }
    
    log_audit("execute_remediation", auth["user"], "executed", f"Executed {action}")
    
    log_query(
        auth["user"],
        auth["tenant"],
        "execute_remediation",
        f"action={action}, target={target}",
        f"Remediation executed on {target}"
    )
    
    return {
        "status": "executed",
        "action": action,
        "target": target,
        "alert_id": alert_id,
        "executed_by": auth["user"],
        "executed_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "user_role": auth["role"],
        "user_permissions": auth["permissions"]
    }


MOCK_TI_RESPONSES = {
    "virustotal": {
        "data": {
            "type": "ip_address",
            "id": "8.8.8.8",
            "attributes": {
                "reputation": 0,
                "country": "US",
                "as_owner": "GOOGLE",
                "last_analysis_stats": {
                    "harmless": 70,
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 12
                }
            }
        },
        "source": "VirusTotal API"
    },
    "alienvault": {
        "indicator": "8.8.8.8",
        "type": "IPv4",
        "pulse_info": {
            "count": 3,
            "pulses": [
                {"name": "Known DNS Resolvers", "tags": ["dns", "resolver"]},
                {"name": "Google Infrastructure", "tags": ["google", "cloud"]}
            ]
        },
        "source": "AlienVault OTX"
    }
}


@mcp.tool()
def enrich_ioc(indicator: str, source_url: str = "", auth_token: str = "") -> dict:
    """
    Enrich an IOC (Indicator of Compromise) with external threat intelligence.
    
    Args:
        indicator: The IOC to enrich (IP, domain, hash)
        source_url: Optional custom threat intel source URL. 
                    If not provided, uses VirusTotal by default.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    allowed_domains = ["api.virustotal.com", "otx.alienvault.com"]
    
    if not source_url:
        log_audit("enrich_ioc", auth["user"], "success", f"Enriched IOC {indicator} via VirusTotal")
        return {
            "indicator": indicator,
            "source": "https://api.virustotal.com/api/v3/ip_addresses/" + indicator,
            "enrichment": MOCK_TI_RESPONSES["virustotal"],
            "_fetched_by": auth["user"]
        }
    
    if MODE == "hardened":
        from urllib.parse import urlparse
        parsed = urlparse(source_url)
        if parsed.netloc not in allowed_domains:
            return {"error": "URL not in allowlist", "allowed": allowed_domains}
    
    log_audit("enrich_ioc", auth["user"], "success", f"Enriched IOC {indicator}")
    
    log_query(
        auth["user"],
        auth["tenant"],
        "enrich_ioc",
        f"indicator={indicator}, source={source_url}",
        f"Fetched from {source_url[:50]}"
    )
    
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(source_url)
            try:
                data = response.json()
            except:
                data = response.text[:2000]
            
            return {
                "indicator": indicator,
                "source": source_url,
                "status_code": response.status_code,
                "data": data,
                "_fetched_by": auth["user"]
            }
    except Exception as e:
        return {"error": str(e), "source": source_url}


@mcp.tool()
def export_report(alert_id: str, format: str = "txt", auth_token: str = "") -> dict:
    """
    Export an alert report.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    if MODE == "hardened":
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', alert_id)
        return {"report": f"Alert Report: {safe_id}", "format": format}
    
    log_audit("export_report", auth["user"], "success", "Generated report")
    
    cmd = f'echo === Alert Report === && echo ID: {alert_id} && echo Format: {format} && date'
    
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10)
        return {
            "report": output.decode(),
            "format": format,
            "generated_by": auth["user"]
        }
    except subprocess.CalledProcessError as e:
        return {
            "error": "Generation failed",
            "output": e.output.decode() if e.output else ""
        }
    except Exception as e:
        return {"error": f"Report generation failed: {str(e)}"}


@mcp.tool()
def calculate_risk_score(
    alert_id: str,
    formula: str = "default",
    auth_token: str = ""
) -> dict:
    """
    Calculate risk score for an alert using configurable formula.
    Supports: 'default', 'cvss', or custom expressions.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
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
        return {"error": f"Failed to fetch alert: {str(e)}"}
    
    severity_scores = {
        "critical": 95,
        "high": 75,
        "medium": 50,
        "low": 25
    }
    
    severity = alert.get("severity", "medium").lower()
    
    if formula not in ["default", "cvss"]:
        log_audit("calculate_risk_score", auth["user"], "success", 
                  f"Calculated risk for {alert_id} using custom_formula")
    else:
        log_audit("calculate_risk_score", auth["user"], "success",
                  f"Calculated risk for {alert_id} using {formula}")
    
    if formula == "default":
        score = severity_scores.get(severity, 50)
        method = "default_severity_mapping"
        
    elif formula == "cvss":
        base_score = severity_scores.get(severity, 50)
        if alert.get("alert_type") == "endpoint":
            score = min(base_score + 15, 100)
        elif alert.get("alert_type") == "network":
            score = min(base_score + 10, 100)
        else:
            score = base_score
        method = "cvss_adjusted"
        
    else:
        if MODE == "hardened":
            return {
                "error": "Custom formulas are disabled",
                "allowed_formulas": ["default", "cvss"]
            }
        
        try:
            context = {
                "severity": severity,
                "severity_score": severity_scores.get(severity, 50),
                "alert_type": alert.get("alert_type", "unknown"),
                "alert": alert,
            }
            
            score = eval(formula, {"__builtins__": __builtins__}, context)
            method = f"custom_formula"
            
        except Exception as e:
            return {
                "error": f"Formula evaluation failed: {str(e)}",
                "formula": formula,
                "available_variables": ["severity", "severity_score", "alert_type", "alert"]
            }
    
    return {
        "alert_id": alert_id,
        "risk_score": score,
        "severity": severity,
        "calculation_method": method,
        "calculated_by": auth["user"],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }


@mcp.tool()
def get_debug_info(auth_token: str = "") -> dict:
    """
    Get server status and configuration info.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    log_audit("get_debug_info", auth["user"], "success", "Retrieved debug info")
    
    if MODE == "hardened":
        return {
            "status": "operational",
            "version": "2.0",
            "your_user": auth["user"],
            "your_role": auth["role"]
        }
    
    return {
        "status": "operational",
        "version": "2.0",
        "authentication_config": {
            "token_algorithm": "MD5",
            "token_format": "sk-{role}-{md5(username:secret)[:12]}",
            "token_secret": TOKEN_SECRET,
            "example_token": f"sk-admin-{hashlib.md5(f'admin:{TOKEN_SECRET}'.encode()).hexdigest()[:12]}"
        },
        "registered_users": list(set(v["user"] for v in AUTH_TOKENS.values())),
        "available_roles": ["analyst", "senior", "admin"],
        "tenants": ALL_TENANTS,
        "your_context": {
            "user": auth["user"],
            "role": auth["role"],
            "permissions": auth["permissions"],
            "tenant": auth["tenant"]
        }
    }


@mcp.tool()
def get_audit_log(limit: int = 20, auth_token: str = "") -> dict:
    """
    Retrieve audit log entries for security review.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    log_audit("get_audit_log", auth["user"], "success", "Retrieved audit log")
    
    entries = list(AUDIT_LOG)[-limit:] if limit else list(AUDIT_LOG)
    
    return {
        "total_entries": len(AUDIT_LOG),
        "returned": len(entries),
        "entries": entries
    }


@mcp.tool()
def get_recent_activity(limit: int = 20, auth_token: str = "") -> dict:
    """
    View recent system activity and queries for situational awareness.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    log_audit("get_recent_activity", auth["user"], "success", "Retrieved activity log")
    
    entries = list(SHARED_QUERY_HISTORY)[-limit:] if limit else list(SHARED_QUERY_HISTORY)
    
    return {
        "total_entries": len(SHARED_QUERY_HISTORY),
        "returned": len(entries),
        "entries": entries
    }


SHARED_CONTEXT_STORE: Dict[str, Dict] = {}

@mcp.tool()
def save_context(key: str, value: str, auth_token: str = "") -> dict:
    """
    Save investigation context for later retrieval. Useful for storing findings,
    hypotheses, or intermediate results during long-running investigations.
    Context is preserved across sessions for continuity.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    SHARED_CONTEXT_STORE[key] = {
        "value": value,
        "saved_by": auth["user"],
        "tenant": auth["tenant"],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }
    
    log_audit("save_context", auth["user"], "success", f"Saved context key: {key}")
    
    return {
        "status": "saved",
        "key": key,
        "saved_by": auth["user"],
        "timestamp": SHARED_CONTEXT_STORE[key]["timestamp"]
    }


@mcp.tool()
def get_context(key: str, auth_token: str = "") -> dict:
    """
    Retrieve previously saved investigation context by key.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    if key not in SHARED_CONTEXT_STORE:
        return {"error": f"Context key '{key}' not found"}
    
    context = SHARED_CONTEXT_STORE[key]
    log_audit("get_context", auth["user"], "success", f"Retrieved context key: {key}")
    
    return {
        "key": key,
        "value": context["value"],
        "saved_by": context["saved_by"],
        "tenant": context["tenant"],
        "timestamp": context["timestamp"],
        "retrieved_by": auth["user"]
    }


@mcp.tool()
def list_context_keys(auth_token: str = "") -> dict:
    """
    List all available context keys for investigation reference.
    """
    auth = authenticate(auth_token)
    if not auth.get("authenticated"):
        return {"error": auth.get("error"), "_debug": auth.get("_debug")}
    
    keys_info = []
    for key, data in SHARED_CONTEXT_STORE.items():
        keys_info.append({
            "key": key,
            "saved_by": data["saved_by"],
            "tenant": data["tenant"],
            "timestamp": data["timestamp"]
        })
    
    log_audit("list_context_keys", auth["user"], "success", "Listed context keys")
    
    return {
        "total_keys": len(keys_info),
        "keys": keys_info
    }


print(f"[*] SOC MCP Server - Mode: {MODE.upper()}")
print(f"[*] Elasticsearch: {ES_URL}")

app = mcp.http_app()
