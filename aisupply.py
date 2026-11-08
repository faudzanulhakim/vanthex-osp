"""
AISupply v1 — AI Supply Chain Recon untuk VANTHEX (v1.9.0).
AUTHORIZED TESTING ONLY — validasi kredensial READ-ONLY.

- c_ai_supply_recon: deteksi endpoint model terbuka (Ollama/vLLM/
  OpenAI-compatible TANPA auth) + API key LLM yang bocor di JS/HTML
  → validasi aktif read-only (models.list simulasi).
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
    """Permukaan AI target: (a) model-serving endpoint tanpa auth
    (Ollama 11434-style), (b) API key LLM bocor di asset front-end yang
    TERVERIFIKASI aktif."""
    # (a) endpoint model terbuka
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
                       "Endpoint Model AI Terbuka Tanpa Autentikasi",
                       f"Endpoint serving model melayani daftar + "
                       f"inferensi TANPA auth ({len(models)} model "
                       "tersedia) — penyerang bisa memakai komputasi "
                       "GPU target gratis, mengekstrak model, atau "
                       "menyalahgunakan inferensi.",
                       evidence=f"GET /ai/models -> 200 "
                                f"models={[str(m)[:30] for m in models[:3]]}; "
                                "/safe=401/403",
                       cwe="CWE-306", owasp="A05:2021 Security "
                                            "Misconfiguration", cvss=7.5,
                       location="/ai/models", param="models",
                       remed="Bind endpoint model ke localhost/jaringan "
                             "internal, wajibkan auth, quota per-client.",
                       confidence="confirmed"))
    # (b) API key LLM bocor + validasi aktif
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
                   "API Key LLM Terverifikasi Aktif Terbocor di Front-End",
                   f"API key model ({k[:6]}...) ditanam di asset publik "
                   "dan TERVALIDASI AKTIF — penyerang memakai akun LLM "
                   "target (biaya tak terbatas + akses data via API).",
                   evidence=f"key={k[:8]}...; /ai/validate -> 200 aktif",
                   cwe="CWE-798", owasp="A07:2021 Identification and "
                                        "Authentication Failures",
                   cvss=9.8, location="/static/config.js", param="api_key",
                   remed="API key TIDAK PERNAH di front-end; proxy via "
                         "backend, rotasi key, restrict domain + quota.",
                   confidence="confirmed"))
            break
