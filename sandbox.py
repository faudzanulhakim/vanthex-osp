"""Sandbox runner (Fase 3): menjalankan analisis paket tak-tepercaya di
subprocess terisolasi dengan batas waktu keras di sisi parent (worker
memasang rlimit CPU/RAM sendiri). Timeout/crash/OOM dilaporkan sebagai
SandboxError — TIDAK ada fallback diam-diam ke analisis in-process.
"""
import json
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(_HERE, "sandbox_worker.py")


class SandboxError(Exception):
    pass


def run_worker(script, args, timeout):
    """Jalankan script worker, kembalikan envelope JSON-nya.
    Melempar SandboxError pada timeout / envelope tidak valid."""
    proc = subprocess.Popen([sys.executable, script] + list(args),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.communicate(timeout=5)
        except Exception:
            pass
        raise SandboxError(
            f"sandbox worker exceeded {timeout}s and was killed")
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    if not lines:
        raise SandboxError(
            f"sandbox worker produced no result (rc={proc.returncode}): "
            f"{(err or '')[-300:]}")
    try:
        return json.loads(lines[-1])
    except Exception:
        raise SandboxError(
            f"sandbox worker output was not valid JSON "
            f"(rc={proc.returncode}): {(err or '')[-300:]}")


def analyze_package_sandboxed(fpath, fname, timeout=None, log=None):
    """Analisis APK/IPA lewat subprocess sandbox. Mengembalikan result
    dict yang sama seperti mobile.analyze_package, ditambah metadata
    sandbox di result['meta']['sandbox']."""
    timeout = timeout or int(os.environ.get("PTK_SANDBOX_TIMEOUT", "180"))
    env_obj = run_worker(WORKER, [fpath, fname], timeout)
    if log is not None:
        log.extend(env_obj.get("log", []))
    if not env_obj.get("ok"):
        raise SandboxError(env_obj.get("error", "sandbox worker failed"))
    result = env_obj["result"]
    meta = result.setdefault("meta", {})
    meta["sandbox"] = {"enabled": True, "timeout_s": timeout,
                       "mem_mb": int(os.environ.get(
                           "PTK_SANDBOX_MEM_MB", "1536")),
                       "cpu_s": int(os.environ.get(
                           "PTK_SANDBOX_CPU_S", "150"))}
    return result
