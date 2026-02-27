<<<<<<< HEAD
# MCP Security Lab - Attack & Defense - Building & Breaking MCP Servers


---

## 📁 Repository Structure

```
├── vulnerable-lab/     # 🔴 Intentionally vulnerable MCP server
│   ├── README.md       # Attack guide with exploit commands
│   └── ...             # Full lab with all vulnerabilities
│
└── secured-lab/        # 🟢 Hardened MCP server with fixes
    ├── README.md       # Defense guide with CLI + LLM examples
    ├── SECURING.md     # Detailed code comparisons (vuln vs secure)
    └── ...             # Full lab with all fixes applied
```

---

## 🔴 Vulnerable Lab

The vulnerable lab demonstrates **8 OWASP MCP Top 10 vulnerabilities**:

| ID | Vulnerability | Impact |
|----|---------------|--------|
| MCP01 | Credential Leakage | Token secrets exposed in responses |
| MCP02 | Mass Assignment | Analyst → Admin privilege escalation |
| MCP05 | Code Injection | RCE via eval() and shell injection |
| MCP06 | Prompt Injection | LLM manipulation via poisoned data |
| MCP07 | Auth Bypass | No token = free access (fail-open) |
| MCP08 | Insufficient Audit | Attack payloads not logged |
| MCP09 | SSRF | Access internal services via IOC enrichment |
| MCP10 | Context Sharing | Cross-tenant data leakage |

### Quick Start (Vulnerable)

```bash
cd vulnerable-lab
start-lab.bat
# Open http://localhost:8080 for LLM UI
# Open http://localhost:5601 for Kibana
```

---

## 🟢 Secured Lab

The secured lab implements **proper security controls**:

| Control | Implementation |
|---------|----------------|
| No credential leakage | Secrets never in responses |
| Field allowlists | Only safe fields accepted |
| Predefined formulas | No eval(), no shell |
| Prompt injection defense | Data treated as untrusted |
| Fail-closed auth | No token = denied |
| Comprehensive audit | Full request params logged |
| URL allowlists | SSRF blocked |
| Tenant isolation | Per-user, per-tenant storage |

### Quick Start (Secured)

```bash
cd secured-lab
start-lab.bat
# Open http://localhost:8080 for LLM UI
```

---

## 🛠️ Prerequisites

1. **Docker Desktop** - Running
2. **Ollama** - With llama3.2 model
   ```bash
   ollama pull llama3.2
   ollama run llama3.2
   ```

---

## 📚 Learning Path

1. **Start with vulnerable lab** → Run attacks, understand the vulnerabilities
2. **Read SECURING.md** → See vulnerable vs secure code side-by-side
3. **Test secured lab** → Verify attacks are blocked
4. **Compare audit logs** → See the difference in forensic capability

---

## 🔗 Resources

- [OWASP MCP Top 10](https://genai.owasp.org)
- [MCP Protocol Specification](https://modelcontextprotocol.io)
- [FastMCP Library](https://github.com/jlowin/fastmcp)

---

## ⚠️ Disclaimer

This lab is for **educational purposes only**. The vulnerable server contains intentional security flaws. Do not deploy in production.

---

## 📝 License

MIT License - Use freely for learning and training.

---

## 👤 Author

<<<<<<< HEAD
**Urvesh Chandra** - Nullcon 2025
=======
**Urvesh Thakkar** - # MCP Security Lab - Attack & Defense

A hands-on security lab demonstrating **OWASP MCP Top 10** vulnerabilities and their fixes.

Built for **Nullcon 2026** workshop on MCP (Model Context Protocol) security.

---

## 📁 Repository Structure

```
├── vulnerable-lab/     # 🔴 Intentionally vulnerable MCP server
│   ├── README.md       # Attack guide with exploit commands
│   └── ...             # Full lab with all vulnerabilities
│
└── secured-lab/        # 🟢 Hardened MCP server with fixes
    ├── README.md       # Defense guide with CLI + LLM examples
    ├── SECURING.md     # Detailed code comparisons (vuln vs secure)
    └── ...             # Full lab with all fixes applied
```

---

## 🔴 Vulnerable Lab

The vulnerable lab demonstrates **8 OWASP MCP Top 10 vulnerabilities**:

| ID | Vulnerability | Impact |
|----|---------------|--------|
| MCP01 | Credential Leakage | Token secrets exposed in responses |
| MCP02 | Mass Assignment | Analyst → Admin privilege escalation |
| MCP05 | Code Injection | RCE via eval() and shell injection |
| MCP06 | Prompt Injection | LLM manipulation via poisoned data |
| MCP07 | Auth Bypass | No token = free access (fail-open) |
| MCP08 | Insufficient Audit | Attack payloads not logged |
| MCP09 | SSRF | Access internal services via IOC enrichment |
| MCP10 | Context Sharing | Cross-tenant data leakage |

### Quick Start (Vulnerable)

```bash
cd vulnerable-lab
start-lab.bat
# Open http://localhost:8080 for LLM UI
# Open http://localhost:5601 for Kibana
```

---

## 🟢 Secured Lab

The secured lab implements **proper security controls**:

| Control | Implementation |
|---------|----------------|
| No credential leakage | Secrets never in responses |
| Field allowlists | Only safe fields accepted |
| Predefined formulas | No eval(), no shell |
| Prompt injection defense | Data treated as untrusted |
| Fail-closed auth | No token = denied |
| Comprehensive audit | Full request params logged |
| URL allowlists | SSRF blocked |
| Tenant isolation | Per-user, per-tenant storage |

### Quick Start (Secured)

```bash
cd secured-lab
start-lab.bat
# Open http://localhost:8080 for LLM UI
```

---

## 🛠️ Prerequisites

1. **Docker Desktop** - Running
2. **Ollama** - With llama3.2 model
   ```bash
   ollama pull llama3.2
   ollama run llama3.2
   ```

---

## 📚 Learning Path

1. **Start with vulnerable lab** → Run attacks, understand the vulnerabilities
2. **Read SECURING.md** → See vulnerable vs secure code side-by-side
3. **Test secured lab** → Verify attacks are blocked
4. **Compare audit logs** → See the difference in forensic capability

---

## 🔗 Resources

- [OWASP MCP Top 10](https://genai.owasp.org)
- [MCP Protocol Specification](https://modelcontextprotocol.io)
- [FastMCP Library](https://github.com/jlowin/fastmcp)

---

## ⚠️ Disclaimer

This lab is for **educational purposes only**. The vulnerable server contains intentional security flaws. Do not deploy in production.

---

## 📝 License

MIT License - Use freely for learning and training.

---

## 👤 Author

**Urvesh Chandra** - https://www.linkedin.com/in/urvesh-thakkar/ 
>>>>>>> 7b8ff1d5cf36b857b105c4e160b1a4dd7dd606f3
=======
# Demo 2: Hello World MCP Server

The simplest MCP server - 20 lines of code, 3 tools.

## Install Dependencies

```bash
pip install fastmcp uvicorn httpx
```

## Run (HTTP Mode - For Testing)

```bash
python server.py
```

Server runs at `http://localhost:8000`

## Test

```bash
python test_client.py
```

Or test manually with curl:
```bash
curl -X POST http://localhost:8000/mcp -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}"
```

## Tools

| Tool | Description | Example |
|------|-------------|---------|
| `greet(name)` | Say hello | "Hello, NullCon!" |
| `add(a, b)` | Add numbers | 42 |
| `reverse(text)` | Reverse text | "olleh" |

---

## Connect to Claude Desktop

Claude Desktop connects to MCP servers via **stdio** (standard input/output), not HTTP URLs. You configure it by specifying the Python command to run.

### Step 1: Find Claude Config File

Open this file (create if doesn't exist):
```
%APPDATA%\Claude\claude_desktop_config.json
```

On Windows, this is typically:
```
C:\Users\YourUsername\AppData\Roaming\Claude\claude_desktop_config.json
```

### Step 2: Add MCP Server Config

```json
{
  "mcpServers": {
    "hello-world": {
      "command": "python",
      "args": [
        "C:\\Users\\Urvesh\\Documents\\nullcon-mcp-lab\\build-mcp\\02-hello-mcp\\server.py",
        "--stdio"
      ]
    }
  }
}
```

**Important:**
- Use double backslashes `\\` in Windows paths
- The `--stdio` flag tells the server to use stdio mode (required for Claude Desktop)
- `command` is the executable (python)
- `args` is the list of arguments

### Step 3: Restart Claude Desktop

Completely close and reopen Claude Desktop.

### Step 4: Verify Connection

In Claude Desktop, you should see a 🔌 icon or tools indicator showing MCP is connected.

### Step 5: Test It!

Ask Claude:
- *"Use the greet tool to say hello to NullCon"*
- *"Add 42 and 58"*
- *"Reverse the text 'security workshop'"*

Claude will recognize it has MCP tools and use them!

---

## How It Works

```
┌─────────────────┐       stdio        ┌─────────────────┐
│  Claude Desktop │ ←───────────────→  │   server.py     │
│                 │   (JSON-RPC)       │   (MCP Server)  │
└─────────────────┘                    └─────────────────┘

1. Claude Desktop spawns: python server.py --stdio
2. Communication happens via stdin/stdout
3. Claude sends JSON-RPC requests
4. Server responds with tool results
```

This is different from HTTP mode (used for N8N/testing) where the server runs as a web service.
>>>>>>> a7005a3 (Hello MCP - Simple MCP Server Example)
