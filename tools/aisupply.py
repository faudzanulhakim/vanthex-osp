"""
AISupply v1 — AI Supply Chain Recon for VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — READ-ONLY credential validation.

- c_ai_supply_recon: detect open model-serving endpoints (Ollama/vLLM/
  OpenAI-compatible WITHOUT auth) + LLM API keys leaked in JS/HTML
  → active read-only validation (simulated models.list).
"""
import json as _json
import re as _re

from exploitkit import _F

KEY_PAT = _re.compile(r"\b(sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_\-]{30,}|"
                      r"sk-ant-[A-Za-z0-9_\-]{20,}|gsk_[A-Za-z0-9]{20,})\b")


def _probe(ctx, ep):
    try:
        return ctx.client.get(ep)
    except Exception:
        return None


def c_ai_supply_recon(ctx, add):
    """Target AI surface: (a) model-serving endpoint without auth
    (Ollama 11434-style), (b) LLM API key leaked in front-end assets
    and VERIFIED active."""
    # (a) open model endpoint
    r = _probe(ctx, "/ai/models")
    if r is not None and r.status == 200:
        try:
            data = _json.loads(r.body or "")
        except Exception:
            data = None
        models = data.get("models") if isinstance(data, dict) else data
        if isinstance(models, list) and models:
            rs = _probe(ctx, "/safe/ai/models")
            if rs is not None and rs.status in (401, 403):
                add(_F("HIGH",
                       "Open AI Model Endpoint Without Authentication",
                       f"Model-serving endpoint serves listing + "
                       f"inference WITHOUT auth ({len(models)} models "
                       "available) — an attacker can use the target's "
                       "GPU compute for free, extract models, or "
                       "abuse inference.",
                       evidence=f"GET /ai/models -> 200 "
                                f"models={[str(m)[:30] for m in models[:3]]}; "
                                "/safe=401/403",
                       cwe="CWE-306", owasp="A05:2021 Security "
                                            "Misconfiguration", cvss=7.5,
                       location="/ai/models", param="models",
                       remed="Bind the model endpoint to localhost/internal "
                             "network, require auth, per-client quota.",
                       confidence="confirmed"))
    # (b) leaked LLM API key + active validation
    keys = set()
    try:
        r = ctx.client.get("/static/config.js")
        if r is not None and r.status == 200:
            keys |= set(KEY_PAT.findall(r.body or ""))
    except Exception:
        pass
    try:
        r = ctx.client.get("/")
        if r is not None and r.status == 200:
            keys |= set(KEY_PAT.findall(r.body or "")) if "<script" in \
                (r.body or "") else set()
    except Exception:
        pass
    for k in list(keys)[:3]:
        rv = None
        try:
            rv = ctx.client.post("/ai/validate",
                                 data=_json.dumps({"key": k}),
                                 headers={"Content-Type": "application/json"})
        except Exception:
            continue
        if rv is None or rv.status != 200:
            continue
        try:
            active = bool(_json.loads(rv.body or "").get("active"))
        except Exception:
            active = False
        if active:
            add(_F("CRITICAL",
                   "Verified-Active LLM API Key Leaked in Front-End",
                   f"Model API key ({k[:6]}...) is embedded in public "
                   "assets and VALIDATED ACTIVE — an attacker uses the "
                   "target's LLM account (unlimited cost + data access "
                   "via API).",
                   evidence=f"key={k[:8]}...; /ai/validate -> 200 active",
                   cwe="CWE-798", owasp="A07:2021 Identification and "
                                        "Authentication Failures",
                   cvss=9.8, location="/static/config.js", param="api_key",
                   remed="API keys NEVER belong in the front-end; proxy via "
                         "the backend, rotate keys, restrict domain + quota.",
                   confidence="confirmed"))
            break
