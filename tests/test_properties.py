"""Property-based test (hypothesis, v3.3): fungsi murni engine tidak boleh
crash pada input acak apa pun dan invariant keamanan harus selalu berlaku."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from hypothesis import given, settings, strategies as st

import mobile
import scanners as S
from crawler import params_of

_PORT = st.integers(min_value=1, max_value=65535)


@given(st.binary(max_size=80), _PORT)
@settings(max_examples=60)
def test_banner_signature_total(data, port):
    r = S._match_banner_signature(port, data)
    assert r is None or isinstance(r, str)


@given(st.binary(max_size=80), _PORT)
@settings(max_examples=60)
def test_probe_response_total(data, port):
    r = S._match_probe_response(port, data)
    assert r is None or isinstance(r, str)


@given(st.lists(st.tuples(_PORT, st.text(max_size=40), st.booleans()), max_size=12))
@settings(max_examples=40)
def test_detect_interception_typed(rows):
    ports = [{"port": p, "banner": b, "verified": v} for p, b, v in rows]
    ok, reason, sample = S.detect_interception(ports)
    assert isinstance(ok, bool) and isinstance(reason, str)


def test_muse_banner_always_detected():
    ports = [{"port": p, "verified": False,
              "banner": "muse: Other TCP connections is turned off for this assistant."}
             for p in (23, 443, 5900)]
    assert S.detect_interception(ports)[0] is True


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
               min_size=9, max_size=80))
@settings(max_examples=60)
def test_mask_never_reveals_middle(s):
    m = mobile._mask(s)
    assert "***" in m and m != s and len(m) <= 9
    if len(s) > 10:
        assert s[4:-2] not in m


@given(st.text(alphabet="ab12=&%", max_size=40))
@settings(max_examples=40)
def test_params_of_robust(qs):
    base, names = params_of("/x?" + qs)
    assert base == "/x" and isinstance(names, list)
    assert all(isinstance(n, str) for n in names)
