"""Notification dispatcher for VANTHEX scan results.

AUTHORIZED TESTING ONLY. Sends a compact summary of scan findings to
configured channels when the scan produced at least one P1 finding (or
PTK_NOTIFY_ALWAYS=1). Never raises: every send is wrapped, timeout 8s,
retried once, and failures are only logged.

Channels (env or cfg dict):
    PTK_NOTIFY_TELEGRAM_BOT_TOKEN + PTK_NOTIFY_TELEGRAM_CHAT_ID
        -> POST https://api.telegram.org/bot<token>/sendMessage
    PTK_NOTIFY_SLACK_WEBHOOK  -> POST {"text": ...}
    PTK_NOTIFY_WEBHOOK_URL    -> POST {"text": ..., "summary": {...}}

PTK_NOTIFY=0 disables dispatch entirely.
"""
import json
import os
import urllib.request

_TIMEOUT_S = 8
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _cfg(cfg):
    if isinstance(cfg, dict):
        env = dict(os.environ)
        env.update({k: str(v) for k, v in cfg.items()})
        return env
    return os.environ


def build_summary(findings):
    """Compact text summary: counts by severity/priority + top 5 titles."""
    findings = findings if isinstance(findings, list) else []
    sev_counts = {}
    prio_counts = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        prio = str(f.get("priority") or "")
        if prio.startswith("P"):
            prio_counts[prio] = prio_counts.get(prio, 0) + 1
    top = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "").upper()
        if sev in ("CRITICAL", "HIGH") or str(f.get("priority") or "") == "P1":
            top.append(f)
    top = top[:5]
    lines = ["VANTHEX scan summary",
             "Severity: " + (", ".join(f"{s}={sev_counts[s]}" for s in _SEV_ORDER
                                       if sev_counts.get(s)) or "none"),
             "Priority: " + (", ".join(f"{p}={prio_counts[p]}"
                                       for p in sorted(prio_counts)) or "n/a"),
             f"Total: {len(findings)}"]
    if top:
        lines.append("Top findings:")
        for f in top:
            lines.append(f"- [{f.get('severity')}] {str(f.get('title'))[:120]}")
    return "\n".join(lines)


def _post(url, payload, headers=None):
    """One POST attempt with timeout; returns True on 2xx."""
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers=headers or
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception:
        return False


def _send_with_retry(fn, text):
    """Retry once on failure; never raise."""
    for _attempt in range(2):
        try:
            if fn(text):
                return True
        except Exception:
            pass
    return False


def _channels(env):
    """[(name, callable(text)->bool)] for each fully configured channel."""
    chans = []
    tok = env.get("PTK_NOTIFY_TELEGRAM_BOT_TOKEN")
    chat = env.get("PTK_NOTIFY_TELEGRAM_CHAT_ID")
    if tok and chat:
        def tg(text, _url=f"https://api.telegram.org/bot{tok}/sendMessage",
               _chat=chat):
            return _post(_url, {"chat_id": _chat, "text": text})
        chans.append(("telegram", tg))
    slack = env.get("PTK_NOTIFY_SLACK_WEBHOOK")
    if slack:
        def sl(text, _url=slack):
            return _post(_url, {"text": text})
        chans.append(("slack", sl))
    hook = env.get("PTK_NOTIFY_WEBHOOK_URL")
    if hook:
        def wh(text, _url=hook):
            return _post(_url, {"text": text, "summary": text})
        chans.append(("webhook", wh))
    return chans


def has_p1(findings):
    for f in findings or []:
        if isinstance(f, dict) and (
                str(f.get("priority") or "") == "P1"
                or str(f.get("severity") or "").upper() == "CRITICAL"):
            return True
    return False


def notify(findings, cfg=None, log=None):
    """Dispatch the summary. Returns list of channel names sent to.

    Sends only when a P1/CRITICAL finding exists (or PTK_NOTIFY_ALWAYS=1).
    Never raises; failures are retried once then swallowed.
    """
    env = _cfg(cfg)
    if env.get("PTK_NOTIFY") == "0":
        return []
    chans = _channels(env)
    if not chans:
        return []
    if not has_p1(findings) and env.get("PTK_NOTIFY_ALWAYS") != "1":
        if log:
            try:
                log("[notify] no P1 findings — silent skip")
            except Exception:
                pass
        return []
    text = build_summary(findings)
    sent = []
    for name, fn in chans:
        if _send_with_retry(fn, text):
            sent.append(name)
        elif log:
            try:
                log(f"[notify] failed to send via {name}")
            except Exception:
                pass
    if log:
        try:
            if sent:
                log(f"[notify] sent via {len(sent)} channel(s): {', '.join(sent)}")
            else:
                log("[notify] no channel delivery succeeded")
        except Exception:
            pass
    return sent


def channels_configured(cfg=None):
    """True when at least one notification channel is configured."""
    return bool(_channels(_cfg(cfg)))
