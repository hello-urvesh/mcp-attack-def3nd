"""
Hello World MCP Server - The simplest MCP server

Usage:
  HTTP testing:     python server.py
  Claude Desktop:   python server.py --stdio
"""
import sys
from fastmcp import FastMCP

mcp = FastMCP("hello-world")


@mcp.tool()
def greet(name: str) -> str:
    """Say hello to someone. Example: greet("World")"""
    return f"Hello, {name}! Welcome to MCP."


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers. Example: add(2, 3)"""
    return a + b


@mcp.tool()
def reverse(text: str) -> str:
    """Reverse any text. Example: reverse("hello")"""
    return text[::-1]


if __name__ == "__main__":
    if "--stdio" in sys.argv:
        # Stdio mode for Claude Desktop
        mcp.run()
    else:
        # HTTP mode for testing
        import uvicorn
        print("=" * 50)
        print("Hello World MCP Server")
        print("=" * 50)
        print("HTTP: http://localhost:8000/mcp")
        print("SSE:  http://localhost:8000/sse")
        print("Tools: greet, add, reverse")
        print("")
        print("For Claude Desktop, run with --stdio flag")
        print("=" * 50)
        uvicorn.run(mcp.http_app(), host="0.0.0.0", port=8000)
