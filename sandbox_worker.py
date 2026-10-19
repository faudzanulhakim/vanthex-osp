"""Worker sandbox analisis paket (Fase 3) — dijalankan sebagai subprocess.

Urutan penting: rlimit dipasang SEBELUM mengimpor analyzer/androguard,
supaya file jahat (zip bomb, DEX pathological) tidak bisa menghabiskan
CPU/RAM proses service utama. Hasil dikirim sebagai SATU baris JSON di
stdout; selama analisis stdout dialihkan ke devnull agar print liar dari
library tidak merusak envelope.
"""
import json
import os
try:
    import resource
except ImportError:
    resource = None
import sys

MEM_MB = int(os.environ.get("PTK_SANDBOX_MEM_MB", "1536"))
CPU_S = int(os.environ.get("PTK_SANDBOX_CPU_S", "150"))


def _apply_limits():
    if not resource:
        return
    resource.setrlimit(resource.RLIMIT_AS,
                       (MEM_MB * 1024 * 1024, MEM_MB * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_S, CPU_S + 5))
    resource.setrlimit(resource.RLIMIT_FSIZE,
                       (64 * 1024 * 1024, 64 * 1024 * 1024))


def main():
    _apply_limits()
    fpath, fname = sys.argv[1], sys.argv[2]
    real_stdout = sys.stdout
    log = []
    try:
        sys.stdout = open(os.devnull, "w")
        try:
            import mobile
            result = mobile.analyze_package(fpath, fname, log=log)
        finally:
            sys.stdout.close()
            sys.stdout = real_stdout
        print(json.dumps({"ok": True, "result": result, "log": log}),
              flush=True)
        return 0
    except Exception as e:
        try:
            sys.stdout = real_stdout
        except Exception:
            pass
        print(json.dumps({"ok": False,
                          "error": f"{type(e).__name__}: {e}"[:300],
                          "log": log}), flush=True)
        return 3


if __name__ == "__main__":
    sys.exit(main())
