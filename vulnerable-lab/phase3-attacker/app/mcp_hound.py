#!/usr/bin/env python3
"""
MCP Hound - Simple MCP Client for Pentesting
=============================================

A lightweight tool to interact with MCP servers for security testing.
Use this to manually explore and test MCP vulnerabilities.

Usage:
  python mcp_hound.py discover                              # List available tools
  python mcp_hound.py call <tool> -a key=value -a key=val   # Call with key=value args
  python mcp_hound.py call <tool> -j '{"key": "value"}'     # Call with JSON (bash/zsh)
  echo '{"key":"val"}' | python mcp_hound.py call <tool> --stdin  # Pipe JSON via stdin
"""

import sys
import json
import asyncio
from typing import Optional, List

import typer
from rich import print
from rich.pretty import Pretty
from rich.console import Console
from rich.table import Table

from fastmcp.client.client import Client

app = typer.Typer(
    name="mcp-hound",
    help="Simple MCP Client for Security Testing",
    add_completion=False,
)
console = Console()

DEFAULT_MCP_URL = "http://mcp-ref:7000/mcp"


def _parse_json(s: str) -> dict:
    """Parse JSON string to dict."""
    if not s or s == "{}":
        return {}
    try:
        obj = json.loads(s)
        if not isinstance(obj, dict):
            raise typer.BadParameter("JSON must be an object")
        return obj
    except json.JSONDecodeError as e:
        raise typer.BadParameter(f"Invalid JSON: {e}")


def _build_args(
    json_args: str,
    arg_list: Optional[List[str]],
    use_stdin: bool,
) -> dict:
    """Build tool arguments from the various input methods."""
    # Priority: --stdin > -a/--arg > -j/--json
    if use_stdin:
        raw = sys.stdin.read().strip()
        if not raw:
            return {}
        return _parse_json(raw)

    if arg_list:
        args = {}
        for kv in arg_list:
            if "=" not in kv:
                raise typer.BadParameter(
                    f"Invalid arg format '{kv}'. Use KEY=VALUE"
                )
            key, _, val = kv.partition("=")
            key = key.strip()
            val = val.strip()
            # Try to interpret as JSON value (number, bool, etc.)
            # Fall back to plain string
            try:
                args[key] = json.loads(val)
            except (json.JSONDecodeError, ValueError):
                args[key] = val
        return args

    if json_args:
        return _parse_json(json_args)

    return {}


@app.command("discover")
def discover(
    mcp_url: str = typer.Option(DEFAULT_MCP_URL, "--url", "-u", help="MCP server URL"),
):
    """
    Discover and list all tools exposed by the MCP server.

    This is typically the first step in MCP reconnaissance.
    """
    async def _run():
        async with Client(mcp_url) as c:
            tools = await c.list_tools()

            console.print(f"\n[bold cyan]MCP Server:[/bold cyan] {mcp_url}\n")

            table = Table(title="Available Tools", show_lines=True)
            table.add_column("Tool Name", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Parameters", style="yellow")

            for t in tools:
                params = []
                if hasattr(t, 'inputSchema') and t.inputSchema:
                    schema = t.inputSchema
                    if 'properties' in schema:
                        for pname, pinfo in schema['properties'].items():
                            ptype = pinfo.get('type', 'any')
                            required = pname in schema.get('required', [])
                            req_mark = "*" if required else ""
                            params.append(f"{pname}{req_mark}: {ptype}")

                params_str = "\n".join(params) if params else "(none)"
                desc = (t.description or "No description")[:100]
                table.add_row(t.name, desc, params_str)

            console.print(table)
            console.print("\n[dim]* = required parameter[/dim]\n")

    asyncio.run(_run())


@app.command("call")
def call_tool(
    tool: str = typer.Argument(..., help="Tool name to call"),
    mcp_url: str = typer.Option(DEFAULT_MCP_URL, "--url", "-u", help="MCP server URL"),
    json_args: str = typer.Option("", "--json", "-j", help="Tool arguments as JSON string"),
    arg: Optional[List[str]] = typer.Option(None, "--arg", "-a", help="Tool argument as KEY=VALUE (repeatable)"),
    use_stdin: bool = typer.Option(False, "--stdin", help="Read JSON arguments from stdin"),
    raw: bool = typer.Option(False, "--raw", "-r", help="Output raw JSON"),
):
    """
    Call an MCP tool with the specified arguments.

    Three ways to pass arguments:

      1. Key=Value (recommended, works in all shells including PowerShell):
         mcp_hound.py call search_alerts -a severity=critical -a limit=5
         mcp_hound.py call get_alert_details -a alert_id=A-0001
         mcp_hound.py call enrich_ioc -a indicator=test -a source_url=http://elk-es:9200

      2. JSON string (bash/zsh only):
         mcp_hound.py call search_alerts -j '{"severity": "critical"}'

      3. Piped stdin (all shells):
         echo '{"alert_id":"A-0001"}' | mcp_hound.py call get_alert_details --stdin
    """
    args = _build_args(json_args, arg, use_stdin)

    async def _run():
        try:
            async with Client(mcp_url) as c:
                result = await c.call_tool(tool, args)

                if raw:
                    print(json.dumps(result, indent=2, default=str))
                else:
                    console.print(f"\n[bold cyan]Tool:[/bold cyan] {tool}")
                    console.print(f"[bold cyan]Args:[/bold cyan] {args}\n")
                    console.print(Pretty(result, expand_all=True))
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")

    asyncio.run(_run())


@app.command("schema")
def get_schema(
    tool: str = typer.Argument(..., help="Tool name to get schema for"),
    mcp_url: str = typer.Option(DEFAULT_MCP_URL, "--url", "-u", help="MCP server URL"),
):
    """
    Get the full schema for a specific tool.

    Useful for understanding required parameters and types.
    """
    async def _run():
        async with Client(mcp_url) as c:
            tools = await c.list_tools()

            for t in tools:
                if t.name == tool:
                    console.print(f"\n[bold cyan]Tool:[/bold cyan] {t.name}")
                    console.print(f"[bold cyan]Description:[/bold cyan] {t.description}\n")

                    if hasattr(t, 'inputSchema') and t.inputSchema:
                        console.print("[bold]Input Schema:[/bold]")
                        console.print(Pretty(t.inputSchema, expand_all=True))
                    else:
                        console.print("[dim]No schema available[/dim]")
                    return

            console.print(f"[red]Tool '{tool}' not found[/red]")

    asyncio.run(_run())


@app.command("probe")
def probe(
    mcp_url: str = typer.Option(DEFAULT_MCP_URL, "--url", "-u", help="MCP server URL"),
):
    """
    Quick probe to check if MCP server is reachable.
    """
    async def _run():
        try:
            async with Client(mcp_url) as c:
                tools = await c.list_tools()
                console.print(f"[green]✓[/green] MCP server reachable at {mcp_url}")
                console.print(f"[green]✓[/green] Found {len(tools)} tools")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to connect: {e}")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
