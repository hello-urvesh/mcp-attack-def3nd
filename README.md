# MCP Security Lab - Attack & Defense

A hands-on security lab demonstrating **OWASP MCP Top 10** vulnerabilities and their fixes.

Built for **Nullcon 2025** workshop on MCP (Model Context Protocol) security.

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

**Urvesh Chandra** - Nullcon 2025
