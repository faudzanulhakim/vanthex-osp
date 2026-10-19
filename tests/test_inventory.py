"""Test Inventory Integrasi v1.1: profil multi-evidence + confidence,
signature Deployment/DevOps & Admin Tool, parser probe komponen, mesin
CVE rentang versi, dan kontrol negatif jebakan teks biasa."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import techdb


def test_jenkins_multi_evidence_confirmed():
    r = techdb.profile([("X-Jenkins", "2.319.1")],
                       "<html><title>Sign in [Jenkins]</title></html>", [])
    j = [t for t in r if t["name"] == "Jenkins"]
    assert j and j[0]["version"] == "2.319.1"
    assert j[0]["confidence"] == "confirmed"  # 2 sumber independen
    assert j[0]["category"] == "Deployment/DevOps"
    assert len(j[0]["evidence_list"]) >= 2 and j[0]["detail"]


def test_gitlab_dan_phpmyadmin_signatures():
    r = techdb.profile([], "<p>GitLab Community Edition</p>", [])
    assert any(t["name"] == "GitLab" for t in r)
    r = techdb.profile([("Set-Cookie", "phpMyAdmin=abc; path=/")], "", [])
    assert any(t["name"] == "phpMyAdmin" for t in r)


def test_jebakan_teks_biasa_tidak_terdeteksi():
    # Nama produk sebagai teks artikel biasa (pola jebakan battery) TIDAK
    # boleh menjadi deteksi — hanya signature khas produk yang sah.
    prose = ("<html><title>Artikel</title>Tim kami memakai Jenkins, GitLab, "
             "Docker, Kubernetes, Portainer, dan phpMyAdmin untuk proyek "
             "mereka. MySQL dan PostgreSQL juga disebut.</html>")
    names = {t["name"] for t in techdb.profile([], prose, [])}
    for banned in ("Jenkins", "GitLab", "Docker Registry", "Kubernetes API",
                   "Portainer", "phpMyAdmin", "MySQL", "PostgreSQL"):
        assert banned not in names, banned


def test_probe_parsers():
    assert techdb._p_docker_registry(
        [("Docker-Distribution-API-Version", "registry/2.8.3")], "{}") == \
        (True, "2.8.3")
    assert techdb._p_docker_registry([], "{}") == (False, "")
    assert techdb._p_kubernetes([], '{"gitVersion":"v1.28.2"}') == \
        (True, "1.28.2")
    assert techdb._p_kubernetes([], '{"status":"UP"}') == (False, "")
    assert techdb._p_portainer(
        [], '{"Version":"2.19.4","InstanceID":"x"}') == (True, "2.19.4")
    assert techdb._p_argocd([], '{"Version":"v2.9.3"}') == (True, "2.9.3")
    assert techdb._p_openapi(
        [], '{"openapi":"3.1.0","info":{"version":"1.4.0"}}') == (True, "1.4.0")
    assert techdb._p_openapi([], '{"status":"UP"}') == (False, "")
    assert techdb._p_graphql([], '{"data":{"__typename":"Query"}}') == \
        (True, "")
    assert techdb._p_graphql([], '{"data":{"__typename":"Mutation"}}') == \
        (False, "")
    assert techdb._p_gitlab_health([], "GitLab OK") == (True, "")
    assert techdb._p_jenkins([("X-Jenkins", "2.319.1")], "") == \
        (True, "2.319.1")
    assert techdb._p_jenkins([], "<html>login biasa</html>") == (False, "")


def test_spec_match_rentang():
    import vulnscan2
    m = vulnscan2._spec_match
    assert m("2.4.49", "==2.4.49") and not m("2.4.51", "==2.4.49")
    assert m("1.11.1", "<3.0.0") and m("2.2.4", "<3.0.0")
    assert not m("3.0.0", "<3.0.0") and not m("5.8.3", "<5.8.3")
    assert m("5.8", "<5.8.3") and m("5.8.2", "<5.8.3")
    assert m("1.20.0", ">=0.6.18,<=1.20.0")
    assert not m("1.20.1", ">=0.6.18,<=1.20.0")
    assert m("13.8.5", ">=11.9,<13.10.3")
    assert not m("bukan-versi", "<3.0.0")  # tidak terparse -> tidak menebak
    assert not m("1.0", "spec-rusak")


def test_attach_cves_builtin():
    import vulnscan2
    techs = [{"name": "jQuery", "version": "1.11.1", "evidence": "ev"},
             {"name": "WordPress", "version": "5.8", "evidence": "ev"},
             {"name": "Apache", "version": "2.4.49", "evidence": "ev"},
             {"name": "nginx", "version": "1.25.4", "evidence": "ev"}]
    hits = vulnscan2._attach_cves(None, techs)
    by_name = {t["name"]: [c["id"] for c in t["cves"]] for t in techs}
    assert "CVE-2015-9251" in by_name["jQuery"]
    assert "CVE-2019-11358" in by_name["jQuery"]
    assert "CVE-2022-21661" in by_name["WordPress"]
    assert "CVE-2021-41773" in by_name["Apache"]
    assert by_name["nginx"] == []  # 1.25.4 di luar rentang CVE-2021-23017
    assert hits  # ada temuan bawaan tabel untuk dijadikan finding


def test_keycloak_oidc_dan_qdrant_parsers():
    r = techdb.profile(
        [], '<a href="https://idp.example/auth/realms/main/protocol/'
            'openid-connect/auth">login</a>', [])
    assert any(t["name"] == "Keycloak" for t in r)
    assert techdb._p_qdrant(
        [], '{"title":"qdrant - vector search engine","version":"1.11.3"}') \
        == (True, "1.11.3")
    assert techdb._p_qdrant([], '{"title":"Blog"}') == (False, "")
    assert techdb._p_oidc(
        [], '{"issuer":"https://x/realms/m","authorization_endpoint":"https://x/a"}') \
        == (True, "")
    assert techdb._p_oidc([], '{"issuer":"https://x"}') == (False, "")
