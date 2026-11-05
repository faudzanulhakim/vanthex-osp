"""
MCPAudit v1 — MCP & AI Agent Security Auditor untuk VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — read-only.

Audit server MCP / AI-agent target yang terbuka dari jaringan:
- listing tools tanpa auth → tool berbahaya ter-expose (exec/write)
- tool description terlalu luas (scope excessive)
- kredensial/token menempel di listing
"""
import json as _json

from exploitkit import _F

DANGEROUS_TOOL_PAT = ("exec", "shell", "command", "write", "delete",
                      "eval", "sudo", "rm ", "file_write", "db_query")


def c_mcp_audit(ctx, add):
    """Endpoint MCP yang tidak diautentikasi + mengekspos tool
    destruktif = confusion deputy. Kontrol /safe/mcp/tools 403."""
    r = None
    try:
        r = ctx.client.get("/mcp/tools")
    except Exception:
        return
    if r is None or r.status != 200:
        return
    try:
        data = _json.loads(r.body or "")
    except Exception:
        return
    tools = data.get("tools") if isinstance(data, dict) else data
    if not isinstance(tools, list) or not tools:
        return
    dangerous = []
    leaked = []
    for t in tools[:40]:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name", "")).lower()
        desc = str(t.get("description", "")).lower()
        blob = name + " " + desc
        if any(p in blob for p in DANGEROUS_TOOL_PAT):
            dangerous.append(str(t.get("name", "?")))
        if t.get("token") or t.get("api_key") or t.get("credential"):
            leaked.append(str(t.get("name", "?")))
    if not dangerous and not leaked:
        return
    rs = None
    try:
        rs = ctx.client.get("/safe/mcp/tools")
    except Exception:
        pass
    if rs is None or rs.status not in (401, 403):
        return
    det = (f"destructive tools: {dangerous[:5]}" if dangerous else "") + \
          (f"; credentials in listing: {leaked[:3]}" if leaked else "")
    sev = "CRITICAL" if dangerous else "HIGH"
    add(_F(sev,
           "MCP Server Open Without Authentication — Internal Tools Exposed",
           f"MCP/agent server serves a tool listing WITHOUT auth ({det}) — "
           "an agent or external attacker can call destructive tools "
           "(confused deputy, OWASP Agentic Top-10: "
           "excessive agency).",
           evidence=f"GET /mcp/tools -> 200 ({len(tools)} tools); {det}; "
                    "/safe=401/403",
           cwe="CWE-306", owasp="A01:2021 Broken Access Control",
           cvss=9.1 if dangerous else 7.5,
           location="/mcp/tools", param="tools",
           remed="Require auth on the MCP server, audit tool scope "
                 "least-privilege, never place tokens in tool "
                 "metadata, human-in-the-loop for destructive tools.",
           confidence="confirmed"))
