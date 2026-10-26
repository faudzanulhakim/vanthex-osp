#!/bin/sh
# VANTHEX container entrypoint: link persistent state from the /data
# volume into the app directory (the engine resolves toolkit.db and
# secrets.key next to its code), optionally start the globe fetch
# daemon for direct-egress containers, then hand over to the app.
set -e

mkdir -p /data

for f in toolkit.db secrets.key; do
    if [ ! -e "/app/$f" ]; then
        ln -s "/data/$f" "/app/$f"
    fi
done

# Container fetch daemon (opt-in, direct egress only): when
# VANTHEX_CONTAINER_FETCH_DAEMON=1, run globe_fetch_daemon.py in the
# background on a container-local socket so globe_feeds tier-1
# delegation resolves inside the container (the VM default socket
# path ../pentest-toolkit-service/globe-fetch.sock does not exist
# at /app). The daemon fetches direct (no Muse proxy creds exist
# here) and never self-exits on 407 in this mode: there is no
# watchdog to relaunch it, so exiting would kill windgrid until
# container restart. If the daemon fails to start, the container
# still starts and the service still serves (wind_particles stays
# offline rather than crashing the container); if the daemon dies
# later, globe_feeds falls through to direct fetch as today.
if [ "${VANTHEX_CONTAINER_FETCH_DAEMON:-}" = "1" ]; then
    export VANTHEX_GLOBE_FETCH_SOCK="${VANTHEX_GLOBE_FETCH_SOCK:-/tmp/globe-fetch.sock}"
    export VANTHEX_FETCH_DAEMON_DIRECT=1
    (python /app/globe_fetch_daemon.py 2>&1 || true) &
fi

exec "$@"
