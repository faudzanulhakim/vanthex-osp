"""v1.2.1 container fetch daemon (daemon-in-container).

The docker container has no fetch daemon: globe_feeds' default socket
path (../pentest-toolkit-service/globe-fetch.sock) does not resolve
at /app, so windgrid (GFS GRIB2) falls through to direct fetch and
WIND PARTICLES stays OFFLINE. The container daemon fixes the
delegation, not the data: when VANTHEX_CONTAINER_FETCH_DAEMON=1,
docker-entrypoint.sh starts globe_fetch_daemon.py on a
container-local socket (/tmp/globe-fetch.sock) in direct-egress
mode (VANTHEX_FETCH_DAEMON_DIRECT=1, never self-exits on 407: no
proxy to rotate, no watchdog to relaunch), and the service connects
to that same socket via the existing VANTHEX_GLOBE_FETCH_SOCK
override. If the daemon fails or dies, the container still starts
and serves, and globe_feeds falls through to direct fetch as today
(wind_particles stays offline rather than crashing anything).

This file is hermetic: no live service, no network, no DB, no
creds, no daemon process started. It pins:
- direct mode is strict opt-in (only the exact value "1");
- 407 is fatal by VM default, never fatal in direct mode;
- the daemon socket path honors VANTHEX_GLOBE_FETCH_SOCK and
  defaults to the VM path when unset;
- a service-to-daemon socket round-trip works, and a missing
  socket falls through to None (fail-open);
- the entrypoint keeps DB/key symlinks + exec "$@" and launches
  the daemon only under the opt-in guard, backgrounded and
  failure-proofed;
- the deploy compose passes the opt-in flag through with an empty
  default (off unless ADE sets it);
- .env.example documents the flag commented-out (never active by
  copying);
- globe_feeds still reads the same socket override (rendezvous var
  intact, no reroute of any other family).
"""

import contextlib
import importlib
import os
import threading

import globe_fetch_daemon as daemon
import globe_feeds

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MISSING = object()


@contextlib.contextmanager
def _daemon_env(overrides):
    """Reload globe_fetch_daemon with controlled env, restore after.

    The module computes _DIRECT and SOCK_PATH at import, so the env
    must be set before reload. The finally block restores both vars
    and reloads again, so no test leaks env or module state into the
    next test. Reloading this module is side-effect-free: it defines
    functions/classes only (threads start in main(), never called).
    """
    saved = {}
    for key in ("VANTHEX_FETCH_DAEMON_DIRECT", "VANTHEX_GLOBE_FETCH_SOCK"):
        saved[key] = os.environ.get(key, _MISSING)
        if key in overrides:
            if overrides[key] is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = overrides[key]
    importlib.reload(daemon)
    try:
        yield daemon
    finally:
        for key, val in saved.items():
            if val is _MISSING:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        importlib.reload(daemon)


def _read_tree(rel):
    with open(os.path.join(TREE, rel), "r", encoding="utf-8") as f:
        return f.read()


def test_direct_flag_default_off():
    with _daemon_env({"VANTHEX_FETCH_DAEMON_DIRECT": None}) as d:
        assert d._DIRECT is False


def test_direct_flag_strict_1():
    for value, want in (("1", True), ("0", False), ("yes", False),
                        ("", False)):
        with _daemon_env({"VANTHEX_FETCH_DAEMON_DIRECT": value}) as d:
            assert d._DIRECT is want


def test_probe_failure_fatal_by_default():
    with _daemon_env({"VANTHEX_FETCH_DAEMON_DIRECT": None}) as d:
        assert d._probe_failure_is_fatal(
            Exception("407 Proxy Authentication Required")) is True
        assert d._probe_failure_is_fatal(Exception("HTTP 407")) is True
        assert d._probe_failure_is_fatal(Exception("boom")) is False


def test_probe_failure_never_fatal_in_direct():
    with _daemon_env({"VANTHEX_FETCH_DAEMON_DIRECT": "1"}) as d:
        assert d._probe_failure_is_fatal(
            Exception("407 Proxy Authentication Required")) is False
        assert d._probe_failure_is_fatal(Exception("boom")) is False


def test_daemon_socket_path_default():
    with _daemon_env({"VANTHEX_GLOBE_FETCH_SOCK": None}) as d:
        expected = os.path.normpath(os.path.join(
            d._HERE, "..", "pentest-toolkit-service", "globe-fetch.sock"))
        assert d.SOCK_PATH == expected


def test_daemon_socket_path_env_override():
    with _daemon_env(
            {"VANTHEX_GLOBE_FETCH_SOCK": "/tmp/test-globe-fetch.sock"}) as d:
        assert d.SOCK_PATH == "/tmp/test-globe-fetch.sock"


def test_daemon_fetch_roundtrip_via_socket(monkeypatch, tmp_path):
    class _FakeHelper:
        @staticmethod
        def execute(req):
            assert req["op"] == "binary"
            return ({"status": 200, "headers": {}, "cut": False,
                     "error": "", "error_type": ""}, b"GRIB-fake")

    sock_path = str(tmp_path / "globe-fetch.sock")
    monkeypatch.setattr(daemon, "helper", _FakeHelper)
    srv = daemon._Server(sock_path, daemon._Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        monkeypatch.setattr(globe_feeds, "_FETCH_SOCK_PATH", sock_path)
        meta = globe_feeds._daemon_fetch(
            "binary", {"url": "https://example.invalid/x"}, 30.0)
    finally:
        srv.shutdown()
        srv.server_close()
    assert meta is not None
    assert meta["status"] == 200
    assert meta["body"] == b"GRIB-fake"


def test_daemon_fetch_none_when_socket_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(globe_feeds, "_FETCH_SOCK_PATH",
                        str(tmp_path / "no-such.sock"))
    assert globe_feeds._daemon_fetch(
        "binary", {"url": "https://example.invalid/x"}, 30.0) is None


def test_entrypoint_container_daemon_block():
    text = _read_tree("docker-entrypoint.sh")
    assert ('if [ "${VANTHEX_CONTAINER_FETCH_DAEMON:-}" = "1" ]; then'
            in text)
    assert ('VANTHEX_GLOBE_FETCH_SOCK='
            '"${VANTHEX_GLOBE_FETCH_SOCK:-/tmp/globe-fetch.sock}"'
            in text)
    assert "VANTHEX_FETCH_DAEMON_DIRECT=1" in text
    assert "globe_fetch_daemon.py" in text
    assert ") &" in text
    assert "|| true" in text
    # Preserved behavior: fail-open container, DB/key links, handover.
    assert "set -e" in text
    assert "for f in toolkit.db secrets.key" in text
    assert 'ln -s "/data/$f" "/app/$f"' in text
    assert 'exec "$@"' in text


def test_compose_daemon_passthrough_opt_in():
    text = _read_tree("docker-compose.deploy.yml")
    assert ("VANTHEX_CONTAINER_FETCH_DAEMON: "
            "${VANTHEX_CONTAINER_FETCH_DAEMON:-}" in text)
    assert ("VANTHEX_CONTAINER_FETCH_DAEMON: "
            "${VANTHEX_CONTAINER_FETCH_DAEMON:-1}" not in text)


def test_env_example_documents_daemon_flag_commented():
    text = _read_tree(".env.example")
    assert "VANTHEX_CONTAINER_FETCH_DAEMON" in text
    assert "#VANTHEX_CONTAINER_FETCH_DAEMON=1" in text
    for line in text.splitlines():
        s = line.strip()
        assert not s.startswith("VANTHEX_CONTAINER_FETCH_DAEMON="), (
            "flag must stay commented-out, found active: %r" % line)


def test_feeds_socket_override_still_present():
    text = _read_tree("globe_feeds.py")
    assert '"VANTHEX_GLOBE_FETCH_SOCK"' in text
