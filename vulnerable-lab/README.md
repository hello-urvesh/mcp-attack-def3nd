# Nullcon MCP Security Lab - Attack Guide

## Prerequisites

1. Docker Desktop running
2. Ollama running with llama3.2 model: `ollama run llama3.2`
3. Lab started: `start-lab.bat`

## Access Points

| Interface | URL |
|-----------|-----|
| SOC AI Assistant (LLM) | http://localhost:8080 |
| MCP Server (Direct) | http://localhost:7000 |
| Elasticsearch | http://localhost:9200 |
| Kibana | http://localhost:5601 |

---

## User Tokens Reference

| User | Role | Permissions | Token |
|------|------|-------------|-------|
| jsmith | analyst | **read** | `sk-analyst-ffa91ecfede2` |
| mwilson | analyst | **read** | `sk-analyst-e3dbb80cddbf` |
| agarcia | senior_analyst | read, **write** | `sk-senior-b7a7505267f6` |
| admin | admin | read, write, admin, **remediate** | `sk-admin-5c94a1b623c1` |
| bsmith | analyst | **read** | `sk-analyst-500d720525d2` |

**Key Point:** Only `admin` has the `remediate` permission required for remediation actions.

---

FULL INSTRUCTIONS: https://hellourvesh.notion.site/NullCon-MCP-Workshop-307e60ac546480f9b930fee79a2db1ad?pvs=74 
