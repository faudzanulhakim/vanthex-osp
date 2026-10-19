#!/usr/bin/env bash
# OPSIONAL (Fase 3): pasang unit systemd untuk Pentest Toolkit.
# Skrip ini HANYA menyalin unit + daemon-reload. Ia TIDAK menghentikan
# supervisor Bash (run.sh) dan TIDAK mengaktifkan unit — dua supervisor
# tidak boleh jalan bersamaan (berebut port 5000).
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
cp "$SRC/pentest-toolkit.service" /etc/systemd/system/pentest-toolkit.service
systemctl daemon-reload
echo "Unit terpasang (belum aktif). Untuk beralih dari supervisor Bash:"
echo "  1) hentikan run.sh (stop.sh di folder service) dan pastikan watchdog"
echo "     restore-all.sh TIDAK lagi menyalakan run.sh (seksi 9) — ganti isinya"
echo "     menjadi 'systemctl start pentest-toolkit' agar tidak bentrok."
echo "  2) systemctl enable --now pentest-toolkit"
echo "  3) verifikasi: systemctl status pentest-toolkit && curl -s localhost:5000/login"
