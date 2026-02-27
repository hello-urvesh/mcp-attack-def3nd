"""
Elasticsearch MCP Server - Connect AI to security logs

This is what you TYPE LIVE during the workshop!
Just 2 simple tools: search_logs and get_alerts

Usage:
  HTTP testing:     python es_mcp_server.py
  Claude Desktop:   python es_mcp_server.py --stdio
"""
import sys
import httpx
from fastmcp import FastMCP

# Elasticsearch URL
ES_URL = "http://localhost:9201"

# Create MCP Server
mcp = FastMCP("elasticsearch")


@mcp.tool()
def search_logs(query: str = "*") -> dict:
    """
    Search security logs in Elasticsearch.
    
    Args:
        query: Search term (default: * for all logs)
    
    Examples:
        search_logs("admin")
        search_logs("login_failed")
    """
    response = httpx.post(
        f"{ES_URL}/security-logs/_search",
        json={"query": {"query_string": {"query": query}}, "size": 10}
    )
    data = response.json()
    logs = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    return {"total": data["hits"]["total"]["value"], "logs": logs}


@mcp.tool()  
def get_alerts() -> dict:
    """
    Get all security alerts from the logs.
    
    Returns events marked as alerts or failed logins.
    """
    response = httpx.post(
        f"{ES_URL}/security-logs/_search",
        json={
            "query": {
                "bool": {
                    "should": [
                        {"match": {"event": "alert"}},
                        {"match": {"event": "login_failed"}}
                    ]
                }
            },
            "size": 20
        }
    )
    data = response.json()
    logs = [hit["_source"] for hit in data.get("hits", {}).get("hits", [])]
    return {"alert_count": len(logs), "alerts": logs}


# Entry point
if __name__ == "__main__":
    if "--stdio" in sys.argv:
        mcp.run()
    else:
        import uvicorn
        print("=" * 50)
        print("Elasticsearch MCP Server")
        print("=" * 50)
        print(f"ES: {ES_URL}")
        print(f"MCP: http://localhost:8001/mcp")
        print("Tools: search_logs, get_alerts")
        print("=" * 50)
        uvicorn.run(mcp.http_app(), host="0.0.0.0", port=8001)
