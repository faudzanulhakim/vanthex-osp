#!/bin/sh
# VANTHEX container entrypoint: link persistent state from the /data
# volume into the app directory (the engine resolves toolkit.db and
# secrets.key next to its code), then hand over to the app.
set -e

mkdir -p /data

for f in toolkit.db secrets.key; do
    [ -e "/data/$f" ] || : > "/data/$f"
    ln -sfn "/data/$f" "/app/$f"
done

exec "$@"
