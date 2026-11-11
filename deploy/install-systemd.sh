#!/usr/bin/env bash
# OPTIONAL (Phase 3): install the systemd unit for the Pentest Toolkit.
# This script ONLY copies the unit + daemon-reload. It does NOT stop the
# Bash supervisor (run.sh) and does NOT enable the unit — two supervisors
# must never run at the same time (they fight over port 5000).
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
cp "$SRC/vanthex.service" /etc/systemd/system/vanthex.service
systemctl daemon-reload
echo "Unit installed (not active yet). To switch from the Bash supervisor:"
echo "  1) stop run.sh (stop.sh in the service folder) and make sure the watchdog"
echo "     restore-all.sh no longer starts run.sh (section 9) — replace its contents"
echo "     with 'systemctl start vanthex' to avoid a clash."
echo "  2) systemctl enable --now pentest-toolkit"
echo "  3) verify: systemctl status pentest-toolkit && curl -s localhost:5000/login"
