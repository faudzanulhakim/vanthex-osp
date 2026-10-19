"""Test profiler teknologi & integrasi (techdb, v3.5): deteksi berbasis
artefak dengan evidence; petunjuk lemah TIDAK boleh menjadi klaim."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import techdb


def names(res):
    return {t["name"]: t for t in res}


def test_server_dan_versi_dari_header():
    r = names(techdb.profile([("Server", "Apache/2.4.49 (Unix)")], ""))
    assert r["Apache"]["version"] == "2.4.49"
    assert r["Apache"]["category"] == "Web Server"


def test_runtime_dari_nama_cookie():
    r = names(techdb.profile(
        [("Set-Cookie", "JSESSIONID=AB12; Path=/"), ("Set-Cookie", "AUTH_SESSION_ID=XY; Path=/")], ""))
    assert "Java (Servlet)" in r and "Keycloak" in r


def test_genexus_butuh_sinyal_asli_bukan_token_hex():
    # Token hex acak bergaya GeneXus SAJA tidak cukup (kasus FP F5 2026-10-16).
    trap = '<div data-key="38ff6460ffff59ffff06ff6bffff3644"></div>'
    assert "GeneXus" not in names(techdb.profile([("Server", "nginx")], trap))
    # JSON gx asli di body aplikasi GeneXus = sinyal sah.
    real = '<script>var g = {"gx ajax_key":"38ff64","gx_ajax_iv":"8722"}</script>'
    assert "GeneXus" in names(techdb.profile([], real))


def test_wordpress_versi_dan_jquery_dari_script():
    body = ('<meta name="generator" content="WordPress 5.8">'
            '<script src="/static/jquery-1.11.1.min.js"></script>')
    r = names(techdb.profile([], body, ["/static/jquery-1.11.1.min.js"]))
    assert r["WordPress"]["version"] == "5.8"
    assert r["jQuery"]["version"] == "1.11.1"


def test_integrasi_pihak_ketiga():
    srcs = ["https://www.googletagmanager.com/gtag/js?id=G-ABC123",
            "https://js.stripe.com/v3",
            "https://app.midtrans.com/snap/snap.js",
            "https://www.google.com/recaptcha/api.js"]
    body = "".join(f'<script src="{s}"></script>' for s in srcs)
    r = names(techdb.profile([], body, srcs))
    for n in ("Google Analytics", "Stripe", "Midtrans", "Google reCAPTCHA"):
        assert n in r, f"{n} tidak terdeteksi"
    assert r["Google Analytics"]["version"] == "G-ABC123"
    assert r["Midtrans"]["category"] == "Payment"


def test_nextjs_dan_angular_version():
    r = names(techdb.profile([], '<script id="__NEXT_DATA__" type="application/json">{}</script>'))
    assert "Next.js" in r
    r2 = names(techdb.profile([], '<app-root ng-version="15.2.0"></app-root>'))
    assert r2["Angular"]["version"] == "15.2.0"


ERR_MYSQL = ("Warning: mysqli_query(): You have an error in your SQL syntax; "
             "check the manual that corresponds to your MySQL server version "
             "for the right syntax to use near '' at line 1 in "
             "/var/www/html/index.php on line 42")


def test_database_dari_error_bukan_dari_teks_biasa():
    # Nama DB di teks biasa TIDAK boleh terdeteksi (aturan anti-tebakan).
    res = techdb.profile([], "<html>blog tentang mysql, oracle, mongodb, postgresql</html>", [])
    assert not [t for t in res if t["category"] == "Database"]
    # Frasa error khas di halaman error WAJIB terdeteksi + OS dari jalurnya.
    res = techdb.profile([], "<html>home</html>", [], error_body=ERR_MYSQL)
    names = {(t["name"], t["category"]) for t in res}
    assert ("MySQL", "Database") in names
    assert ("Linux (from error path)", "Operating System") in names
    ev = [t["evidence"] for t in res if t["name"] == "MySQL"][0]
    assert ev.startswith("error:")


def test_verify_spring_dan_fastapi():
    assert techdb.parse_verify("Spring Boot", '{"status":"UP"}') == (True, None)
    assert techdb.parse_verify("Spring Boot", '{"status":"DOWN"}') == (False, None)
    assert techdb.parse_verify("FastAPI", '{"openapi":"3.1.0","info":{}}') == (True, None)
    assert techdb.parse_verify("FastAPI", "<html>docs</html>") == (False, None)
