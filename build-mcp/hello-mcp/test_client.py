"""Test client for Hello World MCP Server"""
import httpx

MCP_URL = "http://localhost:8000/mcp"

def call_tool(tool_name: str, args: dict):
    """Call an MCP tool via HTTP"""
    response = httpx.post(
        MCP_URL,
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": args},
            "id": 1
        },
        timeout=30
    )
    return response.json()

def list_tools():
    """List available tools"""
    response = httpx.post(
        MCP_URL,
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        timeout=30
    )
    return response.json()

if __name__ == "__main__":
    print("=" * 50)
    print("Testing Hello World MCP Server")
    print("=" * 50)
    
    print("\n1. Listing tools...")
    result = list_tools()
    if "result" in result:
        for tool in result["result"].get("tools", []):
            print(f"   - {tool['name']}: {tool.get('description', '')[:50]}")
    
    print("\n2. Testing greet('NullCon')...")
    result = call_tool("greet", {"name": "NullCon"})
    print(f"   Result: {result}")
    
    print("\n3. Testing add(40, 2)...")
    result = call_tool("add", {"a": 40, "b": 2})
    print(f"   Result: {result}")
    
    print("\n4. Testing reverse('MCP rocks')...")
    result = call_tool("reverse", {"text": "MCP rocks"})
    print(f"   Result: {result}")
    
    print("\n" + "=" * 50)
    print("Done!")
