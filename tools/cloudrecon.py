"""
CloudRecon v1 — Cloud & Container Recon for VANTHEX (v1.8.0).
AUTHORIZED TESTING ONLY — READ-ONLY credential validation.

- c_cloud_container_recon(): single pass detecting:
  (a) open IMDSv1 metadata (instance credentials) → active validation
  (b) exposed Docker API (daemon 2375-style) → container & port info
  (c) unauthenticated Kubernetes API → pod/secret listings readable
  All validation is GET/status only — resources are never modified.
"""
import json as _json

from exploitkit import _F


def _probe(ctx, ep, headers=None):
    try:
        return ctx.client.get(ep, headers=headers or {})
    except Exception:
        return None


def _safe_ep(ctx, ep):
    r = _probe(ctx, "/safe" + ep)
    return r is not None and r.status in (401, 403)


def c_cloud_container_recon(ctx, add):
    """Audit the cloud/container surface that is often forgotten in deploys:
    IMDSv1 metadata service, Docker API, unauthenticated K8s API. Credential
    findings MUST be actively validated (read-only) before being reported
    confirmed."""
    # (a) IMDSv1 — token header NOT sent (that is the gap)
    r = _probe(ctx, "/cloud/metadata")
    if r is not None and r.status == 200:
        try:
            data = _json.loads(r.body or "")
        except Exception:
            data = None
        if isinstance(data, dict) and (data.get("AccessKeyId")
                                       or data.get("access_key")):
            key = str(data.get("AccessKeyId") or data.get("access_key"))
            # active validation (read-only)
            rv = None
            try:
                rv = ctx.client.post("/cloud/validate",
                                     data=_json.dumps({"key": key}),
                                     headers={"Content-Type": "application/json"})
            except Exception:
                pass
            active = False
            if rv is not None and rv.status == 200:
                try:
                    active = bool(_json.loads(rv.body or "").get("active"))
                except Exception:
                    active = False
            if active and _safe_ep(ctx, "/cloud/metadata"):
                add(_F("CRITICAL",
                       "IMDSv1 Open — Cloud Instance Credentials Actively Validated",
                       "Metadata service serves credentials WITHOUT IMDSv2 "
                       "token and those credentials are VALIDATED ACTIVE "
                       "(read-only) — an attacker with a single SSRF can "
                       "walk the role credentials out of the instance.",
                       evidence=f"AccessKeyId={key[:6]}...; /cloud/validate="
                                "200 active; /safe=401/403",
                       cwe="CWE-1390", owasp="A07:2021 Identification and "
                                            "Authentication Failures",
                       cvss=9.3, location="/cloud/metadata",
                       remed="Require IMDSv2 (hop limit 1); restrict instance "
                             "role permissions; deny egress to 169.254.169.254.",
                       confidence="confirmed"))
    # (b) Docker API exposed
    r = _probe(ctx, "/docker/api")
    if r is not None and r.status == 200:
        try:
            data = _json.loads(r.body or "")
        except Exception:
            data = None
        if isinstance(data, dict) and ("Containers" in data or "Version" in data):
            n = len(data.get("Containers") or [])
            ports = []
            for c in (data.get("Containers") or [])[:4]:
                ports += [p for p in (c.get("Ports") or [])][:2]
            if _safe_ep(ctx, "/docker/api"):
                add(_F("CRITICAL",
                       "Docker API Open Without Auth (Remote Code Execution)",
                       "Docker daemon exposes its API without TLS/auth — "
                       "this API is root-equivalent on the host: anyone can spawn "
                       f"containers ({n} active containers seen, ports "
                       f"{ports or 'n/a'}) and mount the host filesystem.",
                       evidence=f"GET /docker/api -> 200 JSON "
                                f"Version={data.get('Version', '?')}; "
                                f"/safe=401/403",
                       cwe="CWE-306", owasp="A05:2021 Security Misconfiguration",
                       cvss=9.8, location="/docker/api",
                       remed="Bind docker.sock via unix socket only; TLS "
                             "client-cert for remote; firewall 2375/2376.",
                       confidence="confirmed"))
    # (c) Kubernetes API unauthenticated
    r = _probe(ctx, "/k8s/api")
    if r is not None and r.status == 200:
        body = r.body or ""
        ok = ("items" in body or "pods" in body.lower()) and \
            ("metadata" in body or "kind" in body)
        try:
            data = _json.loads(body)
            ok = ok or isinstance(data.get("items"), list)
        except Exception:
            pass
        if ok and _safe_ep(ctx, "/k8s/api"):
            add(_F("HIGH",
                   "Kubernetes API Accessible Without Authentication",
                   "API server serves resource listings (pod/secret "
                   "references) without credentials — the cluster's first "
                   "wall is missing; enumeration & intra-cluster pivot open.",
                   evidence=f"GET /k8s/api -> 200 JSON resource listing "
                            f"({len(body)}B); /safe=401/403",
                   cwe="CWE-306", owasp="A05:2021 Security Misconfiguration",
                   cvss=8.6, location="/k8s/api",
                   remed="Always require authn/authz (RBAC); anonymous access "
                         "disabled; audit logging active.",
                   confidence="confirmed"))
