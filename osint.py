"""
osint.py — Deep OSINT scan type (VANTHEX v1.3.0; universal query v1.3.1;
archive & hygiene pack v1.5.0; People OSINT Deep v1.6.0; OSINT
alignment pack v1.11.0 — sanctions/wallet/phone/Telegram, see the
v1.11.0 section below).

Public lookups only — no attack traffic. Every claim carries its
source; every external-source failure becomes a warning, never a
finding and never a silent "clean".

UNIVERSAL QUERY: one free-text query may be a person name, an
institution/company name, a domain, an email address, a username /
handle, or an IP address. The engine detects the identifier type and
pivots across every relevant direction:

- domain  -> the original deep domain OSINT (A1-A5 below).
- IP      -> RDAP ownership, reverse DNS (PTR via DoH), other names
             proven to share the IP (candidates), then the full domain
             flow on the PTR domain.
- email   -> domain part runs the full domain flow with the local part
             as the username handle (A3); light email checks (P3:
             format / DoH resolution / MX / disposable signals) run
             on the address; a Gravatar public profile is
             only claimed when the service really returns one; breach
             exposure (A5) can also run by email on opt-in.
- handle  -> A3 username OSINT plus code exposure for that handle
             (GitHub/GitLab public profiles and repositories, READMEs
             scanned by the Secrets Engine).
- name phrase (person and/or institution — the engine does not pretend
  it can tell the two apart, so BOTH pivots run):
  * person: username candidates are derived from the name (labelled
    name-derived) and checked through the control-gated A3 machinery.
    An identity is NEVER claimed from a single signal: an account only
    rises to `probable` when >= 2 independent corroborating signals
    agree (e.g. the profile displays the full name AND mentions a
    query context term, or the name search and the profile agree).
    Everything else stays `candidate`, explicitly labelled
    "name-derived candidate, identity NOT verified".
  * institution: official-domain candidates are generated from the
    normalized name and validated with DoH (a name that resolves is a
    strong candidate and runs the full domain flow; guesses that do
    not resolve are reported as failed candidates, never silently
    dropped). GitHub organization search and a Certificate
    Transparency identity search run alongside.

Modules (domain flow):
- A1 Infrastructure intelligence: ASN / prefix / owner via RDAP for the
  DoH-resolved IPs; nameserver & mail provider fingerprints taken from
  the record hostnames themselves (never bare substring guessing).
- A2 Domain intelligence: Certificate Transparency deep parse (names
  from expired certificates that no longer resolve = candidate shadow
  subdomains) and the Wayback Machine CDX index (historical attack
  surface; archived JS/config snapshots are fed to the Secrets Engine).
- A3 Username OSINT: a curated platform set where EVERY platform must
  first pass a junk-handle control probe. A platform that claims a
  random handle exists is catch-all: its results are downgraded to
  candidate ("unverified presence signal") or discarded. `probable`
  requires a clean control AND a profile-content marker match.
- A4 Code-exposure OSINT: GitHub/GitLab public search APIs (rate
  limits respected). Public files that are fetched (READMEs of matched
  repositories) are scanned by the Secrets Engine, not just named.
  When an API refuses (e.g. GitHub code search needs authentication),
  the module reports "not evaluated" instead of zero.
- A5 Breach exposure: BUILT BUT OFF BY DEFAULT (decision K3). It only
  runs on explicit opt-in; an API key, when used, arrives via the
  secrets vault (secretsmgr/store) and is never logged. Findings are
  always `candidate` and source-labelled.
- v1.5.0 hygiene & history pack (passive; DNS only via DoH):
  * P1 Wayback CDX history: historical hosts become candidate graph
    nodes (SEEN_IN_ARCHIVE, capture-range evidence; live hosts are
    enriched, never duplicated) and exposure-shaped archived paths
    become explicitly HISTORICAL candidate findings. Snapshot content
    is NOT fetched (K4).
  * P2a PassiveDNS: HackerTarget hostsearch as a named SINGLE source;
    pairs stay `candidate` unless corroborated by a current DoH A
    record (K1).
  * P2b Typosquatting: deterministic typo candidates (cap 300) whose
    existence is checked ONLY via DoH A/NS/MX; registered variants
    become candidate nodes (TYPOSQUAT_OF) with a mail-capable flag
    when MX answers — a risk signal, not an accusation (K2). No
    homoglyph/IDN generation.
  * P2c DNSBL reputation for domains and IPs via DoH: a listing is a
    `probable` finding carrying the zone's own TXT reason; zone
    blocked-resolver error codes (e.g. Spamhaus 127.255.255.x) are
    "not evaluated", never a listing; "not listed in the zones
    checked" is meta only, never a clean bill.
  * P3 email checks (in the email pivot): signal-based only —
    strict format, DoH domain resolution, MX hosts, and a curated
    in-repo disposable-provider list (non-exhaustive, dated). NO
    SMTP probing of any kind.
- v1.6.0 People OSINT Deep (module tag A6) — public-coverage
  maximalism WITHOUT loosening the evidence standard:
  * WS-C: the A3 dataset grows to 175 platforms; an entry only
    counts ACTIVE after the dataset self-check passes it.
  * WS-A Web Mentions: the subject is searched on keyless web
    search engines (DuckDuckGo html/lite, Bing); results are
    classified (profile / document / mention) and graphed as
    candidates — a failed engine is "not evaluated", never zero.
  * WS-B entity extraction (SpiderFoot-style) over fetched public
    pages and gate-passed profile bodies: emails, social handles,
    internationally-formatted phone numbers PUBLISHED on the page
    (candidate, source-labelled, never enriched — K2), outbound
    URLs, and subject-matching @handles.
  * WS-F: dedicated profile extractors for metadata/JSON-rich
    public platforms plus JSON-LD `sameAs` in the generic fallback
    (typed cross-platform identifiers = the cross-link signal).
  * WS-D email permutator: common patterns over corroborated
    domains, scored with the P3 signals only (no SMTP); a candidate
    rises to probable only with an independent signal.
  * WS-E avatar matching: aHash (16x16, implemented in-module on
    Pillow) with a STRICT Hamming threshold (K4); a (near-)identical
    avatar is the `same-avatar` corroboration class.
  * Corroboration classes are now explicit (profile-name-match,
    context-mention, handle-exact, search-match, cross-link,
    website-match, email-match, same-avatar); an identity still
    needs >= 2 DIFFERENT classes, and each graph node carries its
    `signals` class list. meta["coverage"] states measurably what
    was searched (and what was not evaluated) instead of any claim
    of completeness.

Secrets found by this module are never validated against their
provider (decision D5/K1) and never shown in full (masked evidence).

INVESTIGATION GRAPH: every run also returns meta["graph"] —
{nodes, edges} built ONLY from relations the pivots actually proved
(DoH resolution, RDAP/CT data, control-gated platform results,
explicit profile fields). Name-derived / inferred relations are
always `candidate` edges. Nodes deduplicate by (type, normalized
label); meta["graph_stats"] summarizes the graph and
meta["graph_truncated"] is set explicitly when the 400-node cap
truncates it. Second-degree pivots are bounded: live CT names are
followed to IP/ASN (max 3 names), an institution's validated domain
runs the full domain flow, and a domain written explicitly in a
GitHub profile (blog) is followed to its IPs/ASN.
"""
import hashlib
import html as html_mod
import io
import ipaddress
import json
import os
import re
import secrets as pysecrets
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import (parse_qs, parse_qsl, quote, quote_plus,
                          unquote, urlencode, urlparse)

import netclient
import passive as passive_mod
import scanners
from vulnscan2 import F, risk_score, _scan_secrets_in

_NS_PROVIDERS = (
    ("ns.cloudflare.com", "Cloudflare DNS"),
    ("googledomains.com", "Google Domains DNS"),
    ("domaincontrol.com", "GoDaddy DNS"),
    ("awsdns", "Amazon Route 53"),
    ("azure-dns", "Microsoft Azure DNS"),
    ("digitalocean.com", "DigitalOcean DNS"),
    ("nsone.net", "NS1"),
    ("dynect.net", "Oracle Dyn DNS"),
    ("ultradns", "UltraDNS"),
    ("registrar-servers.com", "Namecheap DNS"),
    ("dnsimple.com", "DNSimple"),
    ("cloudns.net", "ClouDNS"),
    ("hetzner.com", "Hetzner DNS"),
    ("ovh.net", "OVH DNS"),
    ("gandi.net", "Gandi DNS"),
    ("dreamhost.com", "DreamHost DNS"),
    ("bluehost.com", "Bluehost DNS"),
    ("hostgator.com", "HostGator DNS"),
    ("secureserver.net", "GoDaddy DNS"),
    ("worldnic.com", "Network Solutions DNS"),
)
_MX_PROVIDERS = (
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("zoho.com", "Zoho Mail"),
    ("zohomail", "Zoho Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("mxroute.com", "MXroute"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonaws.com", "Amazon SES"),
    ("registrar-servers.com", "Namecheap mail hosting"),
    ("secureserver.net", "GoDaddy mail hosting"),
    ("yandex", "Yandex Mail"),
    ("mail.ru", "VK WorkMail"),
    ("qq.com", "Tencent mail"),
    ("spamhero.com", "SpamHero"),
    ("mxlogic.net", "McAfee/MXLogic (legacy)"),
    ("iphmx.com", "Cisco IronPort"),
    ("messagelabs.com", "Symantec MessageLabs (legacy)"),
    ("fireeyecloud.com", "FireEye Email Security"),
)


def _provider_of(hostname, table):
    h = (hostname or "").lower().rstrip(".")
    labels = h.split(".")
    for suffix, name in table:
        if (h == suffix or h.endswith("." + suffix)
                or any(lab == suffix or lab.startswith(suffix)
                       for lab in labels)):
            return name
    return None


def _doh_ips(name):
    try:
        vals = scanners.doh_query(name, "A")
    except Exception:
        vals = None
    return sorted({v for v in (vals or []) if not scanners.is_synthetic_ip(v)})


def _rdap_ip(ip, fetch):
    st, _h, raw = fetch(f"https://rdap.org/ip/{ip}", verify=True, timeout=12)
    if st != 200 or not raw:
        return None
    try:
        d = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return None
    owner = ""
    for ent in d.get("entities") or []:
        roles = ent.get("roles") or []
        if not any(r in roles for r in ("registrant", "administrative", "abuse")):
            continue
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                owner = str(item[3])[:80]
                break
        if owner:
            break
    prefix = ""
    cidrs = d.get("cidr0_cidrs") or []
    if cidrs and isinstance(cidrs[0], dict):
        c0 = cidrs[0]
        if c0.get("v4prefix"):
            prefix = f"{c0['v4prefix']}/{c0.get('length', '')}"
        elif c0.get("v6prefix"):
            prefix = f"{c0['v6prefix']}/{c0.get('length', '')}"
    if not prefix and d.get("startAddress"):
        prefix = f"{d.get('startAddress')} - {d.get('endAddress')}"
    asn = ""
    m = re.search(r"\bAS(\d{2,7})\b", json.dumps(d)[:20000])
    if m:
        asn = "AS" + m.group(1)
    return {"ip": ip, "network": str(d.get("name", ""))[:60],
            "owner": owner, "country": str(d.get("country", ""))[:4],
            "prefix": prefix, "asn": asn}


# ------------------------------------------------------------- A3 platforms
# WS4 (v1.4.0): the platform set is a STRUCTURED DATASET (maigret-site
# schema). _PLATFORM_DEFS keeps the exact legacy (name, url template,
# body marker template) triples — {h} = handle — and PLATFORM_SCHEMA
# derives the full records from them, so verdicts on previously tested
# cases are unchanged by construction. claimed_handle/unclaimed_handle
# are MANDATORY per platform: they are the fixtures of the offline
# self-check (see self_check_platforms). check_type "message" is the
# VANTHEX control-gated existence semantics: the profile URL must
# answer 200 with a presence marker AND the per-scan junk control must
# NOT claim a random handle (that gate is retained unchanged).
# Claimed handles are the platforms' well-known official accounts;
# the self-check report is their audit surface — a wrong entry shows
# up there as FAIL, and disabling persists to a JSON sidecar, never
# into this dataset.
_PLATFORM_DEFS = [
    ("GitHub", "https://api.github.com/users/{h}", '"login"'),
    ("GitLab", "https://gitlab.com/api/v4/users?username={h}", '"username"'),
    ("Bitbucket", "https://api.bitbucket.org/2.0/users/{h}", '"display_name"'),
    ("Docker Hub", "https://hub.docker.com/v2/users/{h}/", '"username"'),
    ("Chess.com", "https://api.chess.com/pub/player/{h}", '"username"'),
    ("Lichess", "https://lichess.org/api/user/{h}", '"id"'),
    ("HackerNews", "https://news.ycombinator.com/user?id={h}", '{h}'),
    ("Keybase", "https://keybase.io/{h}", '{h}'),
    ("Dev.to", "https://dev.to/{h}", '{h}'),
    ("Hashnode", "https://hashnode.com/@{h}", '{h}'),
    ("Medium", "https://medium.com/@{h}", '{h}'),
    ("Substack", "https://{h}.substack.com/", '{h}'),
    ("Reddit", "https://www.reddit.com/user/{h}", '{h}'),
    ("X (Twitter)", "https://x.com/{h}", '{h}'),
    ("Instagram", "https://www.instagram.com/{h}", '{h}'),
    ("Facebook", "https://www.facebook.com/{h}", '{h}'),
    ("LinkedIn", "https://www.linkedin.com/in/{h}", '{h}'),
    ("TikTok", "https://www.tiktok.com/@{h}", '{h}'),
    ("YouTube", "https://www.youtube.com/@{h}", '{h}'),
    ("Twitch", "https://www.twitch.tv/{h}", '{h}'),
    ("Pinterest", "https://www.pinterest.com/{h}", '{h}'),
    ("Snapchat", "https://www.snapchat.com/add/{h}", '{h}'),
    ("Telegram", "https://t.me/{h}", '{h}'),
    ("Mastodon", "https://mastodon.social/@{h}", '{h}'),
    ("Bluesky", "https://bsky.app/profile/{h}", '{h}'),
    ("npm", "https://www.npmjs.com/~{h}", '{h}'),
    ("PyPI", "https://pypi.org/user/{h}/", '{h}'),
    ("Hugging Face", "https://huggingface.co/{h}", '{h}'),
    ("Kaggle", "https://www.kaggle.com/{h}", '{h}'),
    ("LeetCode", "https://leetcode.com/u/{h}/", '{h}'),
    ("HackerRank", "https://www.hackerrank.com/profile/{h}", '{h}'),
    ("Codeforces", "https://codeforces.com/profile/{h}", '{h}'),
    ("Product Hunt", "https://www.producthunt.com/@{h}", '{h}'),
    ("Dribbble", "https://dribbble.com/{h}", '{h}'),
    ("Behance", "https://www.behance.net/{h}", '{h}'),
    ("Unsplash", "https://unsplash.com/@{h}", '{h}'),
    ("SoundCloud", "https://soundcloud.com/{h}", '{h}'),
    ("Spotify", "https://open.spotify.com/user/{h}", '{h}'),
    ("Steam", "https://steamcommunity.com/id/{h}", '{h}'),
    ("Patreon", "https://www.patreon.com/{h}", '{h}'),
    ("Gravatar", "https://gravatar.com/{h}", '{h}'),
    ("About.me", "https://about.me/{h}", '{h}'),
    ("Vimeo", "https://vimeo.com/{h}", '{h}'),
    ("Flickr", "https://www.flickr.com/people/{h}", '{h}'),
    ("TryHackMe", "https://tryhackme.com/p/{h}", '{h}'),
    # ---- v1.6.0 expansion (WS-C): social / creator / professional /
    # dev / gaming / community / regional platforms. Every entry
    # carries a researched claimed_handle (official account) in
    # _PLATFORM_CLAIMED below; an entry only counts as ACTIVE after
    # the dataset self-check passes it — failures are disabled
    # persistently by the self-check, never forced live.
    ("Threads", "https://www.threads.net/@{h}", '{h}'),
    ("VK", "https://vk.com/{h}", '{h}'),
    ("Gab", "https://gab.com/{h}", '{h}'),
    ("Minds", "https://www.minds.com/{h}", '{h}'),
    ("Truth Social", "https://truthsocial.com/@{h}", '{h}'),
    ("Odysee", "https://odysee.com/@{h}", '{h}'),
    ("Kick", "https://kick.com/{h}", '{h}'),
    ("Trovo", "https://trovo.live/s/{h}", '{h}'),
    ("Mixcloud", "https://www.mixcloud.com/{h}/", '{h}'),
    ("Audius", "https://audius.co/{h}", '{h}'),
    ("Last.fm", "https://www.last.fm/user/{h}", '{h}'),
    ("Genius", "https://genius.com/{h}", '{h}'),
    ("Wattpad", "https://www.wattpad.com/user/{h}", '{h}'),
    ("DeviantArt", "https://www.deviantart.com/{h}", '{h}'),
    ("ArtStation", "https://www.artstation.com/{h}", '{h}'),
    ("Newgrounds", "https://{h}.newgrounds.com/", '{h}'),
    ("Itch.io", "https://{h}.itch.io/", '{h}'),
    ("Bandcamp", "https://{h}.bandcamp.com/", '{h}'),
    ("Tumblr", "https://{h}.tumblr.com/", '{h}'),
    ("Misskey", "https://misskey.io/@{h}", '{h}'),
    ("Game Jolt", "https://gamejolt.com/@{h}", '{h}'),
    ("FACEIT", "https://www.faceit.com/en/players/{h}", '{h}'),
    ("Speedrun.com", "https://www.speedrun.com/user/{h}", '{h}'),
    ("Codeberg", "https://codeberg.org/api/v1/users/{h}", '"login"'),
    ("SourceHut", "https://sr.ht/~{h}", '{h}'),
    ("CodePen", "https://codepen.io/{h}", '{h}'),
    ("JSFiddle", "https://jsfiddle.net/user/{h}/", '{h}'),
    ("Replit", "https://replit.com/@{h}", '{h}'),
    ("Glitch", "https://glitch.com/@{h}", '{h}'),
    ("Observable", "https://observablehq.com/@{h}", '{h}'),
    ("CodeChef", "https://www.codechef.com/users/{h}", '{h}'),
    ("AtCoder", "https://atcoder.jp/users/{h}", '{h}'),
    ("Exercism", "https://exercism.org/profiles/{h}", '{h}'),
    ("Spoj", "https://www.spoj.com/users/{h}/", '{h}'),
    ("SourceForge", "https://sourceforge.net/u/{h}/profile", '{h}'),
    ("Launchpad", "https://launchpad.net/~{h}", '{h}'),
    ("RubyGems", "https://rubygems.org/profiles/{h}", '{h}'),
    ("NuGet", "https://www.nuget.org/profiles/{h}", '{h}'),
    ("Anaconda", "https://anaconda.org/{h}", '{h}'),
    ("HackerOne", "https://hackerone.com/{h}", '{h}'),
    ("Bugcrowd", "https://bugcrowd.com/{h}", '{h}'),
    ("freeCodeCamp", "https://www.freecodecamp.org/{h}", '{h}'),
    ("Codecademy", "https://www.codecademy.com/profiles/{h}", '{h}'),
    ("Frontend Mentor", "https://www.frontendmentor.io/profile/{h}", '{h}'),
    ("Fiverr", "https://www.fiverr.com/{h}", '{h}'),
    ("Freelancer", "https://www.freelancer.com/u/{h}", '{h}'),
    ("Contra", "https://contra.com/{h}", '{h}'),
    ("VSCO", "https://vsco.co/{h}", '{h}'),
    ("500px", "https://500px.com/p/{h}", '{h}'),
    ("Write.as", "https://write.as/{h}", '{h}'),
    ("Carrd", "https://{h}.carrd.co/", '{h}'),
    ("Linktree", "https://linktr.ee/{h}", '{h}'),
    ("Beacons", "https://beacons.ai/{h}", '{h}'),
    ("Lobsters", "https://lobste.rs/u/{h}", '{h}'),
    ("Slashdot", "https://slashdot.org/~{h}", '{h}'),
    ("BoardGameGeek", "https://boardgamegeek.com/user/{h}", '{h}'),
    ("MyAnimeList", "https://myanimelist.net/profile/{h}", '{h}'),
    ("AniList", "https://anilist.co/user/{h}", '{h}'),
    ("Letterboxd", "https://letterboxd.com/{h}", '{h}'),
    ("Trakt", "https://trakt.tv/users/{h}", '{h}'),
    ("StoryGraph", "https://app.thestorygraph.com/profile/{h}", '{h}'),
    ("Discogs", "https://www.discogs.com/user/{h}", '{h}'),
    ("MusicBrainz", "https://musicbrainz.org/user/{h}", '{h}'),
    ("CurseForge", "https://www.curseforge.com/members/{h}", '{h}'),
    ("ModDB", "https://www.moddb.com/members/{h}", '{h}'),
    ("MyFitnessPal", "https://www.myfitnesspal.com/profile/{h}", '{h}'),
    ("OpenSea", "https://opensea.io/{h}", '{h}'),
    ("TradingView", "https://www.tradingview.com/u/{h}/", '{h}'),
    ("StockTwits", "https://stocktwits.com/{h}", '{h}'),
    ("eToro", "https://www.etoro.com/people/{h}", '{h}'),
    ("Plurk", "https://www.plurk.com/{h}", '{h}'),
    ("Pixelfed", "https://pixelfed.social/{h}", '{h}'),
    ("Dailymotion", "https://www.dailymotion.com/{h}", '{h}'),
    ("BitChute", "https://www.bitchute.com/channel/{h}/", '{h}'),
    ("Audiomack", "https://audiomack.com/{h}", '{h}'),
    ("Pexels", "https://www.pexels.com/@{h}", '{h}'),
    ("Pixabay", "https://pixabay.com/users/{h}", '{h}'),
    ("Imgur", "https://imgur.com/user/{h}", '{h}'),
    ("Polywork", "https://www.polywork.com/{h}", '{h}'),
    ("Peerlist", "https://peerlist.io/{h}", '{h}'),
    ("Read.cv", "https://read.cv/{h}", '{h}'),
    ("Duolingo", "https://www.duolingo.com/profile/{h}", '{h}'),
    ("Quizlet", "https://quizlet.com/{h}", '{h}'),
    ("Ko-fi", "https://ko-fi.com/{h}", '{h}'),
    ("Buy Me a Coffee", "https://www.buymeacoffee.com/{h}", '{h}'),
    ("Gumroad", "https://gumroad.com/{h}", '{h}'),
    ("Liberapay", "https://liberapay.com/{h}", '{h}'),
    ("Open Collective", "https://opencollective.com/{h}", '{h}'),
    ("Trakteer", "https://trakteer.id/{h}", '{h}'),
    ("Sociabuzz", "https://sociabuzz.com/{h}", '{h}'),
    ("Kompasiana", "https://www.kompasiana.com/{h}", '{h}'),
    ("Gitee", "https://gitee.com/{h}", '{h}'),
    ("CodeSandbox", "https://codesandbox.io/u/{h}", '{h}'),
    ("StackBlitz", "https://stackblitz.com/@{h}", '{h}'),
    ("Replicate", "https://replicate.com/{h}", '{h}'),
    ("Civitai", "https://civitai.com/user/{h}", '{h}'),
    ("Poe", "https://poe.com/{h}", '{h}'),
    ("Mirror", "https://mirror.xyz/{h}", '{h}'),
    ("Warpcast", "https://warpcast.com/{h}", '{h}'),
    ("Zora", "https://zora.co/@{h}", '{h}'),
    ("Anchor", "https://anchor.fm/{h}", '{h}'),
    ("Trello", "https://trello.com/{h}", '{h}'),
    ("Figma", "https://www.figma.com/@{h}", '{h}'),
    ("Flipboard", "https://flipboard.com/@{h}", '{h}'),
    ("Steemit", "https://steemit.com/@{h}", '{h}'),
    ("Publish0x", "https://www.publish0x.com/@{h}", '{h}'),
    ("Read.cash", "https://read.cash/@{h}", '{h}'),
    ("iNaturalist", "https://www.inaturalist.org/people/{h}", '{h}'),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{h}", '{h}'),
    ("Foursquare", "https://foursquare.com/{h}", '{h}'),
    ("Untappd", "https://untappd.com/user/{h}", '{h}'),
    ("Kitsu", "https://kitsu.app/users/{h}", '{h}'),
    ("Grouvee", "https://www.grouvee.com/user/{h}/", '{h}'),
    ("Backloggd", "https://backloggd.com/u/{h}", '{h}'),
    ("HowLongToBeat", "https://howlongtobeat.com/user/{h}", '{h}'),
    ("TrueAchievements", "https://www.trueachievements.com/gamer/{h}", '{h}'),
    ("PSNProfiles", "https://psnprofiles.com/{h}", '{h}'),
    ("Exophase", "https://www.exophase.com/user/{h}/", '{h}'),
    ("RetroAchievements", "https://retroachievements.org/user/{h}", '{h}'),
    ("Scratch", "https://scratch.mit.edu/users/{h}", '{h}'),
    ("Zotero", "https://www.zotero.org/{h}", '{h}'),
    ("Sketchfab", "https://sketchfab.com/{h}", '{h}'),
    ("CGTrader", "https://www.cgtrader.com/{h}", '{h}'),
    ("Fur Affinity", "https://www.furaffinity.net/user/{h}", '{h}'),
    ("Weasyl", "https://www.weasyl.com/~{h}", '{h}'),
    ("Toyhouse", "https://toyhou.se/{h}", '{h}'),
    ("ArtFight", "https://artfight.net/~{h}", '{h}'),
    ("Cara", "https://cara.app/{h}", '{h}'),
    ("Pillowfort", "https://www.pillowfort.social/{h}", '{h}'),
    ("Spoutible", "https://spoutible.com/{h}", '{h}'),
    # v1.11.0 F5: +128 researched platforms (URL patterns + claimed handles from public
    # pattern research; every entry still passes the control gate + self-check)
    ("Codewars", "https://www.codewars.com/users/{h}", '{h}'),
    ("GeeksforGeeks", "https://auth.geeksforgeeks.org/user/{h}", '{h}'),
    ("HackerEarth", "https://hackerearth.com/@{h}", '{h}'),
    ("Topcoder", "https://profiles.topcoder.com/{h}/", '{h}'),
    ("CodersRank", "https://profile.codersrank.io/user/{h}/", '{h}'),
    ("Coderwall", "https://coderwall.com/{h}", '{h}'),
    ("CryptoHack", "https://cryptohack.org/user/{h}/", '{h}'),
    ("HackTheBox", "https://forum.hackthebox.com/u/{h}", '{h}'),
    ("PentesterLab", "https://pentesterlab.com/profile/{h}", '{h}'),
    ("CyberDefenders", "https://cyberdefenders.org/p/{h}", '{h}'),
    ("HackenProof", "https://hackenproof.com/hackers/{h}", '{h}'),
    ("DMOJ", "https://dmoj.ca/user/{h}", '{h}'),
    ("CSSBattle", "https://cssbattle.dev/player/{h}", '{h}'),
    ("Codolio", "https://codolio.com/profile/{h}", '{h}'),
    ("Pastebin", "https://pastebin.com/u/{h}", '{h}'),
    ("GitBook", "https://{h}.gitbook.io/", '{h}'),
    ("Gitea", "https://gitea.com/{h}", '{h}'),
    ("Packagist", "https://packagist.org/packages/{h}/", '{h}'),
    ("Wakatime", "https://wakatime.com/@{h}", '{h}'),
    ("VirusTotal", "https://www.virustotal.com/gui/user/{h}", '{h}'),
    ("devRant", "https://devrant.com/users/{h}", '{h}'),
    ("Hackster", "https://www.hackster.io/{h}", '{h}'),
    ("Vjudge", "https://VJudge.net/user/{h}", '{h}'),
    ("Asciinema", "https://asciinema.org/~{h}", '{h}'),
    ("Pychess", "https://www.pychess.org/@/{h}", '{h}'),
    ("Blitz Tactics", "https://blitztactics.com/{h}", '{h}'),
    ("FortniteTracker", "https://fortnitetracker.com/profile/all/{h}", '{h}'),
    ("GameFAQs", "https://gamefaqs.gamespot.com/community/{h}", '{h}'),
    ("Gamespot", "https://www.gamespot.com/profile/{h}/", '{h}'),
    ("Giant Bomb", "https://www.giantbomb.com/profile/{h}/", '{h}'),
    ("Kongregate", "https://www.kongregate.com/accounts/{h}", '{h}'),
    ("Minecraft", "https://api.mojang.com/users/profiles/minecraft/{h}", '{h}'),
    ("Ninja Kiwi", "https://ninjakiwi.com/profile/{h}", '{h}'),
    ("NintendoLife", "https://www.nintendolife.com/users/{h}", '{h}'),
    ("Pokemon Showdown", "https://pokemonshowdown.com/users/{h}", '{h}'),
    ("Realmeye", "https://www.realmeye.com/player/{h}", '{h}'),
    ("RuneScape", "https://apps.runescape.com/runemetrics/app/overview/player/{h}", '{h}'),
    ("TETR.IO", "https://ch.tetr.io/u/{h}", '{h}'),
    ("Terraria Forums", "https://forums.terraria.org/index.php?search/42798315/&c[users]={h}&o=relevance", '{h}'),
    ("osu!", "https://osu.ppy.sh/users/{h}", '{h}'),
    ("Typeracer", "https://data.typeracer.com/pit/profile?user={h}", '{h}'),
    ("Monkeytype", "https://monkeytype.com/profile/{h}", '{h}'),
    ("NitroType", "https://www.nitrotype.com/racer/{h}", '{h}'),
    ("Wowhead", "https://wowhead.com/user={h}", '{h}'),
    ("Carbonmade", "https://{h}.carbonmade.com", '{h}'),
    ("ColourLovers", "https://www.colourlovers.com/lover/{h}", '{h}'),
    ("Coroflot", "https://www.coroflot.com/{h}", '{h}'),
    ("Crevado", "https://{h}.crevado.com", '{h}'),
    ("Cults3D", "https://cults3d.com/en/users/{h}/creations", '{h}'),
    ("MyMiniFactory", "https://www.myminifactory.com/users/{h}", '{h}'),
    ("OpenGameArt", "https://opengameart.org/users/{h}", '{h}'),
    ("EyeEm", "https://www.eyeem.com/u/{h}", '{h}'),
    ("SmugMug", "https://{h}.smugmug.com", '{h}'),
    ("Blipfoto", "https://www.blipfoto.com/{h}", '{h}'),
    ("LottieFiles", "https://lottiefiles.com/{h}", '{h}'),
    ("Freesound", "https://freesound.org/people/{h}/", '{h}'),
    ("MuseScore", "https://musescore.com/{h}", '{h}'),
    ("Instructables", "https://www.instructables.com/member/{h}", '{h}'),
    ("Airbit", "https://airbit.com/{h}", '{h}'),
    ("ReverbNation", "https://www.reverbnation.com/{h}", '{h}'),
    ("PromoDJ", "http://promodj.com/{h}", '{h}'),
    ("TRAKTRAIN", "https://traktrain.com/{h}", '{h}'),
    ("Smule", "https://www.smule.com/{h}", '{h}'),
    ("Splice", "https://splice.com/{h}", '{h}'),
    ("YandexMusic", "https://music.yandex/users/{h}/playlists", '{h}'),
    ("Rumble", "https://rumble.com/user/{h}", '{h}'),
    ("Clapper", "https://clapperapp.com/{h}", '{h}'),
    ("Itemfix", "https://www.itemfix.com/c/{h}", '{h}'),
    ("Giphy", "https://giphy.com/{h}", '{h}'),
    ("Tenor", "https://tenor.com/users/{h}", '{h}'),
    ("YouPic", "https://youpic.com/photographer/{h}/", '{h}'),
    ("SpaceHey", "https://spacehey.com/{h}", '{h}'),
    ("Myspace", "https://myspace.com/{h}", '{h}'),
    ("LiveJournal", "https://{h}.livejournal.com", '{h}'),
    ("Clubhouse", "https://www.clubhouse.com/@{h}", '{h}'),
    ("AllMyLinks", "https://allmylinks.com/{h}", '{h}'),
    ("Listed", "https://listed.to/@{h}", '{h}'),
    ("Hubski", "https://hubski.com/user/{h}", '{h}'),
    ("LessWrong", "https://www.lesswrong.com/users/{h}", '{h}'),
    ("SoylentNews", "https://soylentnews.org/~{h}", '{h}'),
    ("Fandom", "https://www.fandom.com/u/{h}", '{h}'),
    ("Fanpop", "https://www.fanpop.com/fans/{h}", '{h}'),
    ("GaiaOnline", "https://www.gaiaonline.com/profiles/{h}", '{h}'),
    ("Kaskus", "https://www.kaskus.co.id/@{h}", '{h}'),
    ("Pikabu", "https://pikabu.ru/@{h}", '{h}'),
    ("Interpals", "https://www.interpals.net/{h}", '{h}'),
    ("Couchsurfing", "https://www.couchsurfing.com/people/{h}", '{h}'),
    ("Archive of Our Own (AO3)", "https://archiveofourown.org/users/{h}", '{h}'),
    ("Blogger", "https://{h}.blogspot.com", '{h}'),
    ("HubPages", "https://hubpages.com/@{h}", '{h}'),
    ("Scribd", "https://www.scribd.com/{h}", '{h}'),
    ("SlideShare", "https://slideshare.net/{h}", '{h}'),
    ("SpeakerDeck", "https://speakerdeck.com/{h}", '{h}'),
    ("ResearchGate", "https://www.researchgate.net/profile/{h}", '{h}'),
    ("Academia.edu", "https://independent.academia.edu/{h}", '{h}'),
    ("LibraryThing", "https://www.librarything.com/profile/{h}", '{h}'),
    ("Mydramalist", "https://www.mydramalist.com/profile/{h}", '{h}'),
    ("Rate Your Music", "https://rateyourmusic.com/~{h}", '{h}'),
    ("Wikipedia", "https://en.wikipedia.org/wiki/Special:CentralAuth/{h}?uselang=qqx", '{h}'),
    ("Credly", "https://www.credly.com/users/{h}", '{h}'),
    ("Memrise", "https://www.memrise.com/user/{h}/", '{h}'),
    ("Clozemaster", "https://www.clozemaster.com/players/{h}", '{h}'),
    ("Platzi", "https://platzi.com/p/{h}/", '{h}'),
    ("BuyMeACoffee", "https://buymeacoff.ee/{h}", '{h}'),
    ("Contently", "https://{h}.contently.com/", '{h}'),
    ("Houzz", "https://houzz.com/user/{h}", '{h}'),
    ("BiggerPockets", "https://www.biggerpockets.com/users/{h}", '{h}'),
    ("Sessionize", "https://sessionize.com/{h}", '{h}'),
    ("Arduino Forum", "https://forum.arduino.cc/u/{h}/summary", '{h}'),
    ("Naver", "https://blog.naver.com/{h}", '{h}'),
    ("Linux.org.ru", "https://www.linux.org.ru/people/{h}/profile", '{h}'),
    ("LinuxFR.org", "https://linuxfr.org/users/{h}", '{h}'),
    ("Habr", "https://habr.com/ru/users/{h}", '{h}'),
    ("Habr Career", "https://career.habr.com/{h}", '{h}'),
    ("Tistory", "https://{h}.tistory.com/", '{h}'),
    ("Velog", "https://velog.io/@{h}/posts", '{h}'),
    ("note.com", "https://note.com/{h}", '{h}'),
    ("DCinside", "https://gallog.dcinside.com/{h}", '{h}'),
    ("Jeuxvideo", "https://www.jeuxvideo.com/profil/{h}", '{h}'),
    ("Wykop", "https://www.wykop.pl/ludzie/{h}", '{h}'),
    ("Pr0gramm", "https://pr0gramm.com/user/{h}", '{h}'),
    ("Ultimate-Guitar", "https://ultimate-guitar.com/u/{h}", '{h}'),
    ("Geocaching", "https://www.geocaching.com/p/default.aspx?u={h}", '{h}'),
    ("Venmo", "https://account.venmo.com/u/{h}", '{h}'),
    ("Vero", "https://vero.co/{h}", '{h}'),
    ("SOOP", "https://www.sooplive.co.kr/station/{h}", '{h}'),
    ("Tellonym", "https://tellonym.me/{h}", '{h}'),
    ("Archive.org", "https://archive.org/details/@{h}", '{h}'),
]

_UNCLAIMED_HANDLE = "ptk-unclaimed-7f3a9c1e55"
_PLATFORM_CLAIMED = {
    "GitHub": "github", "GitLab": "gitlab", "Bitbucket": "bitbucket",
    "Docker Hub": "docker", "Chess.com": "hikaru", "Lichess": "lichess",
    "HackerNews": "pg", "Keybase": "keybase", "Dev.to": "devteam",
    "Hashnode": "hashnode", "Medium": "medium", "Substack": "platformer",
    "Reddit": "reddit", "X (Twitter)": "x", "Instagram": "instagram",
    "Facebook": "facebook", "LinkedIn": "reidhoffman",
    "TikTok": "tiktok", "YouTube": "YouTube", "Twitch": "twitch",
    "Pinterest": "pinterest", "Snapchat": "snapchat",
    "Telegram": "telegram", "Mastodon": "mastodon",
    "Bluesky": "bsky.app", "npm": "npm", "PyPI": "django",
    "Hugging Face": "huggingface", "Kaggle": "kaggle",
    "LeetCode": "leetcode", "HackerRank": "hackerrank",
    "Codeforces": "tourist", "Product Hunt": "producthunt",
    "Dribbble": "dribbble", "Behance": "behance",
    "Unsplash": "unsplash", "SoundCloud": "soundcloud",
    "Spotify": "spotify", "Steam": "gaben", "Patreon": "patreon",
    "Gravatar": "gravatar", "About.me": "aboutme", "Vimeo": "vimeo",
    "Flickr": "flickr", "TryHackMe": "tryhackme",
    "Threads": "threads", "VK": "vk", "Gab": "gab", "Minds": "minds",
    "Truth Social": "realdonaldtrump", "Odysee": "odysee",
    "Kick": "kick", "Trovo": "trovo", "Mixcloud": "mixcloud",
    "Audius": "audius", "Last.fm": "lastfm", "Genius": "Genius",
    "Wattpad": "wattpad", "DeviantArt": "deviantart",
    "ArtStation": "artstation", "Newgrounds": "tomfulp",
    "Itch.io": "itchio", "Bandcamp": "bandcamp", "Tumblr": "staff",
    "Misskey": "syuilo", "Game Jolt": "gamejolt", "FACEIT": "faceit",
    "Speedrun.com": "speedrun", "Codeberg": "codeberg",
    "SourceHut": "sircmpwn", "CodePen": "codepen",
    "JSFiddle": "jsfiddle", "Replit": "replit", "Glitch": "glitch",
    "Observable": "observable", "CodeChef": "codechef",
    "AtCoder": "atcoder", "Exercism": "exercism", "Spoj": "spoj",
    "SourceForge": "sourceforge", "Launchpad": "launchpad",
    "RubyGems": "rubygems", "NuGet": "nuget", "Anaconda": "anaconda",
    "HackerOne": "hackerone", "Bugcrowd": "bugcrowd",
    "freeCodeCamp": "freecodecamp", "Codecademy": "codecademy",
    "Frontend Mentor": "frontendmentor", "Fiverr": "fiverr",
    "Freelancer": "freelancer", "Contra": "contra", "VSCO": "vsco",
    "500px": "500px", "Write.as": "matt", "Carrd": "carrd",
    "Linktree": "linktree", "Beacons": "beacons",
    "Lobsters": "lobsters", "Slashdot": "slashdot",
    "BoardGameGeek": "boardgamegeek", "MyAnimeList": "myanimelist",
    "AniList": "anilist", "Letterboxd": "letterboxd",
    "Trakt": "trakt", "StoryGraph": "thestorygraph",
    "Discogs": "discogs", "MusicBrainz": "musicbrainz",
    "CurseForge": "curseforge", "ModDB": "moddb",
    "MyFitnessPal": "myfitnesspal", "OpenSea": "opensea",
    "TradingView": "TradingView", "StockTwits": "stocktwits",
    "eToro": "etoro", "Plurk": "plurk", "Pixelfed": "pixelfed",
    "Dailymotion": "dailymotion", "BitChute": "bitchute",
    "Audiomack": "audiomack", "Pexels": "pexels",
    "Pixabay": "pixabay", "Imgur": "imgur", "Polywork": "polywork",
    "Peerlist": "peerlist", "Read.cv": "readcv",
    "Duolingo": "duolingo", "Quizlet": "quizlet", "Ko-fi": "kofi",
    "Buy Me a Coffee": "buymeacoffee", "Gumroad": "gumroad",
    "Liberapay": "liberapay", "Open Collective": "opencollective",
    "Trakteer": "trakteer", "Sociabuzz": "sociabuzz",
    "Kompasiana": "kompasiana", "Gitee": "gitee",
    "CodeSandbox": "codesandbox", "StackBlitz": "stackblitz",
    "Replicate": "replicate", "Civitai": "civitai", "Poe": "poe",
    "Mirror": "mirror", "Warpcast": "warpcast", "Zora": "zora",
    "Anchor": "anchor", "Trello": "trello", "Figma": "figma",
    "Flipboard": "flipboard", "Steemit": "steemit",
    "Publish0x": "publish0x", "Read.cash": "readcash",
    "iNaturalist": "inaturalist", "OpenStreetMap": "openstreetmap",
    "Foursquare": "foursquare", "Untappd": "untappd",
    "Kitsu": "kitsu", "Grouvee": "grouvee",
    "Backloggd": "backloggd", "HowLongToBeat": "howlongtobeat",
    "TrueAchievements": "trueachievements",
    "PSNProfiles": "psnprofiles", "Exophase": "exophase",
    "RetroAchievements": "retroachievements",
    "Scratch": "scratchteam", "Zotero": "zotero",
    "Sketchfab": "sketchfab", "CGTrader": "cgtrader",
    "Fur Affinity": "furaffinity", "Weasyl": "weasyl",
    "Toyhouse": "toyhouse", "ArtFight": "artfight", "Cara": "cara",
    "Pillowfort": "pillowfort", "Spoutible": "spoutible",
    "Codewars": "example", "GeeksforGeeks": "adam", "HackerEarth": "naveennamani877", "Topcoder": "USER", "CodersRank": "rootkit7628", "Coderwall": "hacker", "CryptoHack": "blue", "HackTheBox": "angar", "PentesterLab": "0day", "CyberDefenders": "mlohn", "HackenProof": "blazezaria", "DMOJ": "junferno", "CSSBattle": "beo", "Codolio": "testuser", "Pastebin": "blue", "GitBook": "gitbook", "Gitea": "xorm", "Packagist": "psr", "Wakatime": "blue", "VirusTotal": "blue", "devRant": "blue", "Hackster": "blue", "Vjudge": "tokitsukaze", "Asciinema": "red", "Pychess": "gbtami", "Blitz Tactics": "Lance5500", "FortniteTracker": "blue", "GameFAQs": "blue", "Gamespot": "blue", "Giant Bomb": "bob", "Kongregate": "blue", "Minecraft": "blue", "Ninja Kiwi": "Kyruko", "NintendoLife": "goku", "Pokemon Showdown": "blue", "Realmeye": "rotmg", "RuneScape": "L33", "TETR.IO": "osk", "Terraria Forums": "blue", "osu!": "blue", "Typeracer": "blue", "Monkeytype": "Lost_Arrow", "NitroType": "jianclash", "Wowhead": "blue", "Carbonmade": "jenny", "ColourLovers": "blue", "Coroflot": "blue", "Crevado": "blue", "Cults3D": "brown", "MyMiniFactory": "blue", "OpenGameArt": "ski", "EyeEm": "blue", "SmugMug": "winchester", "Blipfoto": "blue", "LottieFiles": "lottiefiles", "Freesound": "blue", "MuseScore": "arrangeme", "Instructables": "blue", "Airbit": "airbit", "ReverbNation": "blue", "PromoDJ": "blue", "TRAKTRAIN": "traktrain", "Smule": "blue", "Splice": "splice", "YandexMusic": "ya.playlist", "Rumble": "John", "Clapper": "blue", "Itemfix": "blue", "Giphy": "red", "Tenor": "red", "YouPic": "blue", "SpaceHey": "blue", "Myspace": "blue", "LiveJournal": "blue", "Clubhouse": "waniathar", "AllMyLinks": "blue", "Listed": "listed", "Hubski": "blue", "LessWrong": "habryka", "SoylentNews": "adam", "Fandom": "Jungypoo", "Fanpop": "blue", "GaiaOnline": "adam", "Kaskus": "l0mbart", "Pikabu": "blue", "Interpals": "blue", "Couchsurfing": "blue", "Archive of Our Own (AO3)": "test", "Blogger": "blue", "HubPages": "blue", "Scribd": "blue", "SlideShare": "blue", "SpeakerDeck": "pylapp", "ResearchGate": "John_Smith", "Academia.edu": "blue", "LibraryThing": "blue", "Mydramalist": "elhadidy12398", "Rate Your Music": "blue", "Wikipedia": "Hoadlck", "Credly": "credly", "Memrise": "blue", "Clozemaster": "green", "Platzi": "freddier", "BuyMeACoffee": "red", "Contently": "jordanteicher", "Houzz": "blue", "BiggerPockets": "blue", "Sessionize": "jason-mayes", "Arduino Forum": "system", "Naver": "blue", "Linux.org.ru": "red", "LinuxFR.org": "pylapp", "Habr": "blue", "Habr Career": "blue", "Tistory": "notice", "Velog": "qlgks1", "note.com": "blue", "DCinside": "anrbrb", "Jeuxvideo": "adam", "Wykop": "blue", "Pr0gramm": "cha0s", "Ultimate-Guitar": "blue", "Geocaching": "blue", "Venmo": "jenny", "Vero": "blue", "SOOP": "udkn", "Tellonym": "blue", "Archive.org": "blue",
}
_PLATFORM_EXTRACT = {"GitHub": "github", "GitLab": "gitlab",
                     "Docker Hub": "dockerhub", "Chess.com": "chesscom",
                     "Lichess": "lichess", "Keybase": "keybase",
                     "YouTube": "youtube", "TikTok": "tiktok",
                     "X (Twitter)": "twitter", "Medium": "medium",
                     "Substack": "substack", "Instagram": "instagram",
                     "Linktree": "linktree", "About.me": "aboutme"}
PLATFORM_SCHEMA = [{
    "name": _n, "url_pattern": _u, "url_probe": _u,
    "check_type": "message", "presence_strs": [_m], "absence_strs": [],
    "marker": _m, "error_strs": ["404", "not found", "page not found"],
    "claimed_handle": _PLATFORM_CLAIMED.get(_n, ""),
    "unclaimed_handle": _UNCLAIMED_HANDLE,
    "regex_check": None, "ignore_403": False, "engine": "vanthex-a3",
    "tags": [], "disabled": False,
    "extract": _PLATFORM_EXTRACT.get(_n),
} for _n, _u, _m in _PLATFORM_DEFS]
# Legacy tuple view, derived — the engine and older callers keep
# working on exactly the same (name, template, marker) triples.
PLATFORMS = [(d["name"], d["url_pattern"], d["marker"])
             for d in PLATFORM_SCHEMA]
_PLATFORM_BY_NAME = {d["name"]: d for d in PLATFORM_SCHEMA}

# Persistent self-check state (platforms disabled by the offline
# self-check). Sidecar JSON; overridable via env for tests/ops.
_PLATFORM_STATE_PATH = os.environ.get(
    "PTK_OSINT_PLATFORM_STATE") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "osint_platform_state.json")


def _load_platform_state(path=None):
    try:
        with open(path or _PLATFORM_STATE_PATH, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _save_platform_state(state, path=None):
    with open(path or _PLATFORM_STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1)


def disabled_platform_names(path=None):
    st = _load_platform_state(path)
    return {n for n, v in (st.get("disabled") or {}).items() if v}


def active_platforms(platforms=None, state_path=None):
    """Platform tuples minus disabled entries (schema flag OR a
    persisted self-check disable). Unknown (test-supplied) platforms
    are never filtered out."""
    srcp = platforms if platforms is not None else PLATFORMS
    dis = disabled_platform_names(state_path)
    out = []
    for name, tpl, marker in srcp:
        d = _PLATFORM_BY_NAME.get(name) or {}
        if d.get("disabled") or name in dis:
            continue
        out.append((name, tpl, marker))
    return out

# Identity-relevant subset used for name-derived candidates: a person
# search fans out over several generated handles, so each candidate is
# probed on the platforms where a real identity is most meaningful
# instead of the full 45-platform set (documented fan-out bound).
NAME_PLATFORM_NAMES = (
    "GitHub", "GitLab", "Bitbucket", "Keybase", "X (Twitter)",
    "Instagram", "Facebook", "LinkedIn", "Reddit", "YouTube",
    "TikTok", "Medium", "Dev.to", "HackerNews", "Threads", "Linktree",
)


def _profile_exists(status, body_text, marker):
    return status == 200 and bool(body_text) and marker in body_text


def _check_platform_full(fetch, name, template, marker_t, handle, junk):
    """One platform, control-gated. Returns (verdict, url, body) where
    verdict is 'probable' | 'candidate' | 'absent' | 'unevaluated' and
    body is the profile response text (for corroboration signals)."""
    url = template.replace("{h}", quote(handle, safe=""))
    junk_url = template.replace("{h}", quote(junk, safe=""))
    cst, _ch, craw = fetch(junk_url, timeout=7, cap=512 * 1024)
    if cst == 0:
        return "unevaluated", url, ""
    cbody = craw.decode("utf-8", "replace") if craw else ""
    junk_marker = marker_t.replace("{h}", junk)
    control_claims = _profile_exists(cst, cbody, junk_marker)
    tst, _th, traw = fetch(url, timeout=7, cap=512 * 1024)
    if tst == 0:
        return "unevaluated", url, ""
    tbody = traw.decode("utf-8", "replace") if traw else ""
    marker = marker_t.replace("{h}", handle)
    exists = _profile_exists(tst, tbody, marker)
    if not exists:
        return "absent", url, tbody
    if control_claims:
        return "candidate", url, tbody
    return "probable", url, tbody


def _check_platform(fetch, name, template, marker_t, handle, junk):
    """One platform, control-gated. Returns (verdict, url) where verdict
    is 'probable' | 'candidate' | 'absent' | 'unevaluated'."""
    verdict, url, _body = _check_platform_full(
        fetch, name, template, marker_t, handle, junk)
    return verdict, url


def _probe_workers():
    try:
        return max(1, min(32, int(os.environ.get(
            "PTK_OSINT_PROBE_WORKERS", "12"))))
    except Exception:
        return 12


def _username_probe(fetch, handle, platforms, stats=None, cancelled=None):
    """Control-gated probe of one handle over a platform set.
    Returns {platform_name: (verdict, url, body)}.

    v1.6.1: probes run in parallel (12 workers by default), but
    results are assembled strictly in platform order (ex.map
    preserves input order), so findings/graph output is identical
    to a sequential sweep. When `cancelled` fires, queued probes
    return the 'skipped' verdict with no network traffic and
    in-flight probes end within one fetch timeout (<=7s), so the
    sweep drains in seconds. Only platforms actually probed are
    counted in stats['platforms_checked']."""
    junk = "ptk" + pysecrets.token_hex(5) + "zz9"
    results = {}

    def _one(p):
        if cancelled is not None:
            try:
                if cancelled():
                    return p[0], ("skipped", p[1].replace(
                        "{h}", quote(handle, safe="")), "")
            except Exception:
                pass
        if stats is not None:
            stats["platforms_checked"].add(p[0])
        return p[0], _check_platform_full(fetch, p[0], p[1], p[2],
                                          handle, junk)

    with ThreadPoolExecutor(max_workers=_probe_workers()) as ex:
        for name, res in ex.map(_one, platforms):
            results[name] = res
    return results



# ------------------------------------------- profile extraction (WS4)
# Structured extraction from GATE-PASSED (probable) profile responses
# only. API/JSON platforms have dedicated parsers; everything else
# falls back to conservative page-metadata (og:/title/canonical).
# Extracted cross-platform identifiers are TYPED ({type, platform,
# value, field}) — they feed the recursive graph pivots and count as
# independent corroboration in the person pivot.

def _profile_dict(**kw):
    return {k: v for k, v in kw.items()
            if v not in (None, "", [], {})}


def _extract_github(body, handle):
    d = json.loads(body)
    if not isinstance(d, dict) or "login" not in d:
        return {}
    ids = []
    tw = str(d.get("twitter_username") or "").strip().lstrip("@")
    if tw:
        ids.append({"type": "username", "platform": "X (Twitter)",
                    "value": tw, "field": "twitter_username"})
    blog = str(d.get("blog") or "").strip()
    if blog:
        host = urlparse(blog if "://" in blog else "https://" + blog).hostname
        if host:
            ids.append({"type": "domain", "platform": "",
                        "value": host.lower(), "field": "blog"})
    links = [d.get("html_url") or ""]
    return _profile_dict(
        fullname=str(d.get("name") or "")[:120],
        bio=str(d.get("bio") or "")[:300],
        avatar_url=str(d.get("avatar_url") or ""),
        location=str(d.get("location") or "")[:120],
        website=blog, company=str(d.get("company") or "")[:120],
        created_at=str(d.get("created_at") or ""),
        followers=d.get("followers"), following=d.get("following"),
        public_repos=d.get("public_repos"),
        links=[u for u in links if u], identifiers=ids)


def _extract_gitlab(body, handle):
    d = json.loads(body)
    if isinstance(d, dict):
        d = [d]
    if not isinstance(d, list) or not d or not isinstance(d[0], dict):
        return {}
    u = d[0]
    return _profile_dict(
        fullname=str(u.get("name") or "")[:120],
        avatar_url=str(u.get("avatar_url") or ""),
        website=str(u.get("website") or u.get("web_url") or ""),
        links=[u.get("web_url") or ""])


def _extract_dockerhub(body, handle):
    d = json.loads(body)
    if not isinstance(d, dict):
        return {}
    return _profile_dict(
        fullname=str(d.get("full_name") or "")[:120],
        location=str(d.get("location") or "")[:120],
        company=str(d.get("company") or "")[:120],
        created_at=str(d.get("date_joined") or ""),
        links=[f"https://hub.docker.com/u/{handle}"])


def _extract_chesscom(body, handle):
    d = json.loads(body)
    if not isinstance(d, dict):
        return {}
    return _profile_dict(
        fullname=str(d.get("name") or "")[:120],
        avatar_url=str(d.get("avatar_url") or ""),
        location=str(d.get("location") or "")[:120],
        followers=d.get("followers"),
        links=[str(d.get("url") or "")])


def _extract_lichess(body, handle):
    d = json.loads(body)
    if not isinstance(d, dict):
        return {}
    prof = d.get("profile") or {}
    links_d = prof.get("links") or {}
    links = [v for v in (links_d.values() if isinstance(links_d, dict)
                         else []) if v]
    return _profile_dict(
        fullname=str(prof.get("name") or prof.get("firstName") or "")[:120],
        bio=str(prof.get("bio") or "")[:300],
        location=str(prof.get("location") or "")[:120],
        links=links[:4])


_EXTRACTORS = {"github": _extract_github, "gitlab": _extract_gitlab,
               "dockerhub": _extract_dockerhub, "chesscom": _extract_chesscom,
               "lichess": _extract_lichess}


_SOCIAL_URL_PATTERNS = [
    (r"(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,30})", "X (Twitter)"),
    (r"instagram\.com/([A-Za-z0-9_.]{1,30})", "Instagram"),
    (r"facebook\.com/([A-Za-z0-9_.]{3,60})", "Facebook"),
    (r"github\.com/([A-Za-z0-9\-]{1,39})", "GitHub"),
    (r"gitlab\.com/([A-Za-z0-9_.\-]{1,60})", "GitLab"),
    (r"linkedin\.com/in/([A-Za-z0-9\-]{3,100})", "LinkedIn"),
    (r"tiktok\.com/@([A-Za-z0-9_.]{2,30})", "TikTok"),
    (r"youtube\.com/@([A-Za-z0-9_.\-]{3,40})", "YouTube"),
    (r"t\.me/([A-Za-z0-9_]{5,32})", "Telegram"),
    (r"reddit\.com/user/([A-Za-z0-9_\-]{3,20})", "Reddit"),
    (r"medium\.com/@([A-Za-z0-9_.\-]{1,60})", "Medium"),
    (r"twitch\.tv/([A-Za-z0-9_]{4,25})", "Twitch"),
    (r"keybase\.io/([A-Za-z0-9_]{2,30})", "Keybase"),
    (r"mastodon\.social/@([A-Za-z0-9_]{1,30})", "Mastodon"),
    (r"bsky\.app/profile/([A-Za-z0-9_.\-]{3,60})", "Bluesky"),
]
_SOCIAL_BAD_HANDLES = {
    "intent", "share", "sharer", "home", "search", "explore", "login",
    "signup", "about", "help", "privacy", "terms", "settings",
    "notifications", "messages", "watch", "hashtag", "dialog",
    "plugins", "reel", "reels", "stories", "music", "gaming", "p",
    "tr", "in", "user", "users", "channel", "c", "profile",
}


def _social_ids_from_text(text, field="profile link"):
    """Typed username identifiers from social-profile URLs appearing
    in a page body (hrefs or plain text). Conservative: platform URL
    shapes only, generic path segments rejected."""
    out, seen = [], set()
    for pat, platform in _SOCIAL_URL_PATTERNS:
        for m in re.finditer(pat, text or "", re.I):
            val = m.group(1)
            if val.lower() in _SOCIAL_BAD_HANDLES:
                continue
            # a segment immediately followed by a file extension is
            # an asset path (e.g. keybase.io/ava.png), not a handle
            tail = (text or "")[m.end():m.end() + 5].lower()
            if tail.startswith(".") and any(
                    tail[1:].startswith(e) for e in
                    ("png", "jpg", "jpeg", "gif", "svg", "webp",
                     "css", "js", "ico")):
                continue
            key = (platform, val.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": "username", "platform": platform,
                        "value": val, "field": field})
    return out[:12]


def _jsonld_sameas(body):
    """sameAs URLs from JSON-LD blocks — a site's own declared
    cross-platform identity links (high-value corroboration)."""
    urls = []
    for m in re.finditer(
            r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>'
            r'(.*?)</script>', body or "", re.S | re.I):
        try:
            data = json.loads(m.group(1))
        except Exception:
            continue
        stack = [data]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                sa = x.get("sameAs")
                if isinstance(sa, str):
                    urls.append(sa)
                elif isinstance(sa, list):
                    urls += [u for u in sa if isinstance(u, str)]
                stack.extend(x.values())
            elif isinstance(x, list):
                stack.extend(x)
    out = []
    for u in urls:
        if u and u not in out:
            out.append(u)
    return out[:12]


def _extract_generic_meta(body, handle):
    """Conservative fallback: OpenGraph / title / canonical only.
    Plain text mentioning a name is NOT extraction — it stays a raw
    body signal for the caller, never a structured profile."""
    if not body or "<" not in body:
        return {}
    def _meta(prop):
        m = re.search(
            r'<meta[^>]+(?:property|name)=["\']' + re.escape(prop) +
            r'["\'][^>]+content=["\']([^"\']{1,300})["\']', body, re.I)
        return m.group(1).strip() if m else ""
    out = _profile_dict(
        fullname=_meta("og:title")[:120],
        bio=_meta("og:description")[:300],
        avatar_url=_meta("og:image"))
    m = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+'
                  r'href=["\']([^"\']+)["\']', body, re.I)
    if m:
        out["website"] = m.group(1)[:200]
    # v1.6.0 (WS-F): JSON-LD sameAs — declared cross-platform links.
    sameas = _jsonld_sameas(body)
    if sameas:
        ids = _social_ids_from_text(" ".join(sameas),
                                    field="JSON-LD sameAs")
        social_hosts = ("twitter.com", "x.com", "instagram.com",
                        "facebook.com", "github.com", "gitlab.com",
                        "linkedin.com", "tiktok.com", "youtube.com",
                        "t.me", "reddit.com", "medium.com",
                        "twitch.tv", "keybase.io", "mastodon.social",
                        "bsky.app")
        for u in sameas:
            host = (urlparse(u).hostname or "").lower()
            if host and not any(host == h or host.endswith("." + h)
                                 for h in social_hosts):
                ids.append({"type": "domain", "platform": "",
                            "value": host,
                            "field": "JSON-LD sameAs"})
        out["identifiers"] = ids[:12]
        links = list(out.get("links") or [])
        for u in sameas:
            if u not in links:
                links.append(u)
        out["links"] = links[:8]
    if out.get("fullname", "").lower() == handle.lower():
        out.pop("fullname", None)  # title == handle teaches nothing
    return out


def extract_profile(platform_name, body, handle):
    """Structured profile for one gate-passed response ({} when the
    platform yields nothing structured). Never raises."""
    kind = (_PLATFORM_BY_NAME.get(platform_name) or {}).get("extract")
    fn = _EXTRACTORS.get(kind) if kind else None
    prof = {}
    if fn is not None:
        try:
            prof = fn(body, handle) or {}
        except Exception:
            prof = {}
    if not prof:
        try:
            prof = _extract_generic_meta(body, handle)
        except Exception:
            prof = {}
    return prof


def compact_profile(prof):
    """The small attribute set carried on graph nodes."""
    if not prof:
        return {}
    out = {}
    for k in ("fullname", "location", "website", "company"):
        if prof.get(k):
            out[k] = str(prof[k])[:120]
    if prof.get("bio"):
        out["bio"] = str(prof["bio"])[:140]
    if prof.get("avatar_url"):
        out["avatar"] = str(prof["avatar_url"])[:200]
    if prof.get("followers") is not None:
        out["followers"] = prof["followers"]
    return out


# ------------------------------------------------- A3 self-check (WS4)

def self_check_platforms(fetch=None, platforms=None, apply_disable=False,
                         state_path=None):
    """Offline dataset self-check (maigret discipline): every platform
    is probed with its claimed_handle (must be confirmed 'probable'
    through the same control-gated engine) and its unclaimed_handle
    (must NOT be claimed). A platform that fails either side is
    reported FAIL; a platform that cannot be evaluated is UNKNOWN and
    UNKNOWN NEVER DISABLES (a refused/unreachable check is not
    evidence). With apply_disable=True, FAIL platforms are persisted
    to the platform state file and excluded from future probes."""
    fetch = fetch or passive_mod._fetch_bytes
    srcp = platforms if platforms is not None else PLATFORMS
    report = []
    for name, template, marker_t in srcp:
        d = _PLATFORM_BY_NAME.get(name) or {}
        claimed = d.get("claimed_handle") or ""
        unclaimed = d.get("unclaimed_handle") or _UNCLAIMED_HANDLE
        entry = {"platform": name, "claimed_handle": claimed,
                 "unclaimed_handle": unclaimed, "action": "none"}
        if not claimed:
            entry.update(status="unknown",
                         reason="dataset entry has no claimed_handle fixture")
            report.append(entry)
            continue
        junk = "ptk" + pysecrets.token_hex(5) + "zz9"
        v_claim, _u, _b = _check_platform_full(
            fetch, name, template, marker_t, claimed, junk)
        junk2 = "ptk" + pysecrets.token_hex(5) + "zz9"
        v_uncl, _u2, _b2 = _check_platform_full(
            fetch, name, template, marker_t, unclaimed, junk2)
        entry["claimed_verdict"] = v_claim
        entry["unclaimed_verdict"] = v_uncl
        if v_claim == "unevaluated" or v_uncl == "unevaluated":
            entry.update(status="unknown",
                         reason="platform unreachable/unevaluated from this host")
        elif v_claim != "probable":
            entry.update(status="fail",
                         reason=f"claimed handle '{claimed}' not confirmed "
                                f"(verdict: {v_claim})")
        elif v_uncl in ("probable", "candidate"):
            entry.update(status="fail",
                         reason=f"unclaimed handle was claimed "
                                f"(verdict: {v_uncl}) — catch-all behavior")
        else:
            entry.update(status="pass", reason="")
        report.append(entry)
    if apply_disable:
        state = _load_platform_state(state_path)
        dis = dict(state.get("disabled") or {})
        for e in report:
            if e["status"] == "fail":
                dis[e["platform"]] = {
                    "reason": e["reason"],
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                e["action"] = "disabled (persisted)"
        state["disabled"] = dis
        _save_platform_state(state, state_path)
    return report


def permuted_username_candidates(name):
    """Maigret-permutator-style enrichment of the base candidates:
    name parts joined with separators "", "_", "-", "." plus
    underscore-wrapped variants and initial-forms with the same
    separators. Base candidates keep their priority order; the result
    is deduplicated and capped at 10. Candidates still pass through
    the control gate + the >=2 corroboration rule — permutation only
    widens the guess set, never the claim standard."""
    base = generate_username_candidates(name)
    words = [w for w in re.findall(r"[a-z0-9]+", (name or "").lower())
             if w not in _NAME_STOPWORDS and len(w) > 1]
    out = list(base)
    if len(words) >= 2:
        full = words[:3]
        for sep in ("", "_", "-", "."):
            out.append(sep.join(full))
        joined = "".join(full)
        out += ["_" + joined, joined + "_"]
        for sep in ("", "_", "-", "."):
            out.append(full[0][0] + sep + full[-1])
            out.append(full[0] + sep + full[-1][0])
    seen, res = set(), []
    for c in out:
        if c and c not in seen and len(c) >= 2:
            seen.add(c)
            res.append(c)
    return res[:10]


def _pivot_extracted_handles(ctx, source_handle, profiles, depth, seen):
    """Recursive graph pivot over TYPED username identifiers extracted
    from gate-passed profiles (WS4). Depth cap 2; the shared 400-node
    graph cap and its truncation flag bound the fan-out; a domain
    identifier is recorded as a graph edge only (a full domain pivot
    from a profile field already exists in the code-exposure flow)."""
    if depth > 2:
        ctx.meta["recursion_depth_capped"] = True
        return
    if ctx.stop_requested():
        return
    for pname, prof in (profiles or {}).items():
        for ident in (prof or {}).get("identifiers") or []:
            value = str(ident.get("value") or "").strip().lstrip("@")[:80]
            if not value:
                continue
            if ident.get("type") == "domain":
                src_id = ctx.graph.node("username", source_handle,
                                        "candidate", "A3")
                dom_id = ctx.graph.node("domain", value.lower(),
                                        "candidate", "A3")
                if src_id and dom_id:
                    ctx.graph.edge(src_id, dom_id, "LINKS_TO", "candidate",
                                   f"profile on {pname} lists this domain "
                                   f"(field: {ident.get('field', '')})")
                continue
            if ident.get("type") != "username":
                continue
            if value.lower() in {s.lower() for s in seen}:
                continue
            if ctx.graph.truncated:
                ctx.meta["recursion_truncated"] = True
                return
            seen.add(value)
            src_id = ctx.graph.node("username", source_handle,
                                    "candidate", "A3")
            dst_id = ctx.graph.node("username", value, "candidate", "A3")
            if src_id and dst_id:
                ctx.graph.edge(src_id, dst_id, "LINKED_TO", "probable",
                               f"profile on {pname} lists this handle "
                               f"(extracted field: {ident.get('field', '')})")
            if ctx.stop_requested():
                return
            ctx.L(f"[osint] recursive pivot (depth {depth}): handle "
                  f"'{value}' extracted from {source_handle}'s {pname} profile")
            ufinds, umeta = _username_osint(
                ctx.fetch, value, ctx.L, ctx.warnings,
                platforms=ctx.platforms, graph=ctx.graph,
                stats=ctx.stats, cancelled=ctx.stop_requested)
            for f in ufinds:
                ctx.add(f)
            ctx.meta.setdefault("recursion", []).append(
                {"handle": value, "depth": depth, "from": source_handle,
                 "via_platform": pname,
                 "probable": umeta.get("probable", [])})
            _pivot_extracted_handles(ctx, value,
                                     umeta.get("profiles") or {},
                                     depth + 1, seen)


def _username_osint(fetch, handle, L, warnings, platforms=None, graph=None,
                    stats=None, entity_hook=None, cancelled=None):
    """Returns (findings, meta). Control gate is mandatory per platform."""
    findings = []
    platforms = platforms if platforms is not None else active_platforms()
    probed = _username_probe(fetch, handle, platforms, stats=stats,
                             cancelled=cancelled)
    results = {name: res[0] for name, res in probed.items()}
    # WS4: structured extraction from gate-passed (probable) results.
    profiles = {}
    for name, (verdict, url, body) in probed.items():
        if verdict == "probable" and body:
            prof = extract_profile(name, body, handle)
            if prof:
                profiles[name] = prof
    user_id = None
    site_ids = {}
    if graph is not None:
        user_id = graph.node("username", handle, "candidate", "A3")
    for name, (verdict, url, _body) in probed.items():
        if verdict in ("probable", "candidate") and graph is not None:
            site_id = graph.node("website", name, "info", "A3")
            site_ids[name] = site_id
            graph.edge(user_id, site_id, "FOUND_ON", verdict,
                       f"{url} (control check "
                       f"{'passed' if verdict == 'probable' else 'FAILED — catch-all platform'})")
            if verdict == "probable":
                graph.node("username", handle, "probable", "A3")
            if name in profiles:
                graph.node_attr(site_id, profile=compact_profile(
                    profiles[name]))
    if entity_hook is not None:
        # WS-B (v1.6.0): entity extraction over gate-passed bodies.
        for name, (verdict, url, body) in probed.items():
            if verdict == "probable" and body:
                try:
                    entity_hook(name, url, body, site_ids.get(name))
                except Exception:
                    pass
    for name, (verdict, url, _body) in probed.items():
        if verdict == "probable":
            findings.append(F(
                "INFO", f"Username '{handle}' found on {name}",
                f"A public profile for handle '{handle}' exists on {name}. The platform passed the junk-handle control check (a random handle was correctly reported absent) and the profile page carries the expected content marker.",
                evidence=f"{url} (control check passed)",
                cwe="", owasp="", cvss=0.0,
                remed="Confirm this account is official; unofficial or impersonating accounts under an organization's handle are a phishing risk.",
                confidence="probable", location=url, origin="passive"))
        elif verdict == "candidate":
            findings.append(F(
                "INFO", f"Possible username '{handle}' on {name} (unverified)",
                f"A profile-like response for '{handle}' was returned by {name}, BUT the platform also claims a random junk handle exists — it answers catch-all style, so this presence signal is UNVERIFIED.",
                evidence=f"{url} (control check FAILED — catch-all platform)",
                cwe="", owasp="", cvss=0.0,
                remed="Manually open the profile before treating this account as real.",
                confidence="candidate", location=url, origin="passive"))
    meta = {"handle": handle,
            "probable": sorted(n for n, v in results.items() if v == "probable"),
            "candidate": sorted(n for n, v in results.items() if v == "candidate"),
            "unevaluated": sorted(n for n, v in results.items() if v == "unevaluated"),
            "skipped": sorted(n for n, v in results.items() if v == "skipped"),
            "profiles": profiles}
    L(f"[osint] username '{handle}': {len(meta['probable'])} probable, "
      f"{len(meta['candidate'])} candidate (catch-all platforms), "
      f"{len(meta['unevaluated'])} unevaluated")
    return findings, meta


# ------------------------------------------------- universal query layer

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_HANDLE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,39}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?$")
_KNOWN_TLDS = {
    "com", "net", "org", "io", "co", "dev", "app", "ai", "me", "tv",
    "gg", "xyz", "info", "biz", "edu", "gov", "mil", "int", "pro",
    "id", "us", "uk", "de", "fr", "jp", "kr", "cn", "au", "ca", "nl",
    "se", "no", "es", "it", "my", "sg", "vn", "th", "ph", "in", "br",
    "mx", "za", "nz", "ie", "ch", "at", "be", "dk", "fi", "pl", "tr",
    "test", "local",
}
_NAME_STOPWORDS = {
    "the", "and", "of", "for", "pt", "cv", "ud", "tbk", "inc", "llc",
    "llp", "ltd", "limited", "corp", "corporation", "company", "co",
    "group", "holdings", "holding",
}


def _looks_like_domain(host):
    if not host or " " in host or "." not in host:
        return False
    labels = host.lower().rstrip(".").split(".")
    if any(not _LABEL_RE.match(lab) for lab in labels):
        return False
    tld = labels[-1]
    if tld in _KNOWN_TLDS:
        return True
    # ccTLD with a well-known second level (example.co.id, .com.au ...)
    return (len(labels) >= 3 and len(tld) == 2
            and labels[-2] in ("co", "com", "ac", "go", "or", "net", "web"))


def _query_host(query):
    """Host part of a domain-ish query (scheme/path/port stripped)."""
    q = (query or "").strip()
    if "://" in q:
        return (urlparse(q).hostname or "").lower()
    return q.split("/")[0].split(":")[0].lower().rstrip(".")


def detect_query_type(query):
    """Classify a free-text OSINT query:
    'email' | 'ip' | 'domain' | 'handle' | 'name' | 'empty'.
    A phrase with spaces that is none of the structured types is a
    'name' (person or institution — deliberately not distinguished)."""
    q = (query or "").strip()
    if not q:
        return "empty"
    if _EMAIL_RE.match(q):
        return "email"
    try:
        ipaddress.ip_address(q)
        return "ip"
    except ValueError:
        pass
    if "://" in q:
        host = urlparse(q).hostname or ""
        if host:
            try:
                ipaddress.ip_address(host)
                return "ip"
            except ValueError:
                return "domain"
    if _looks_like_domain(_query_host(q)):
        return "domain"
    # v1.11.0: structurally-validated wallet addresses and
    # international phone numbers are identifier types of their own
    # (checksum/shape gates live in wallet_info / parse_phone — a
    # handle-shaped string never promotes on shape alone).
    if wallet_info(q):
        return "wallet"
    if parse_phone(q):
        return "phone"
    if q.startswith("@") and _HANDLE_TOKEN_RE.match(q[1:]):
        return "handle"
    if " " not in q and _HANDLE_TOKEN_RE.match(q):
        return "handle"
    return "name"


def query_subject_host(query):
    """The host the domain allowlist should be evaluated against for a
    universal query: the domain itself, an email's domain part, or an
    IP. Name and handle queries carry no host -> '' (never blocked by
    the domain allowlist)."""
    t = detect_query_type(query)
    if t == "email":
        return query.strip().split("@")[-1].lower()
    if t == "ip":
        return _query_host(query) or query.strip()
    if t == "domain":
        return _query_host(query)
    return ""


def _name_words(name):
    return [w for w in re.split(r"[^a-z0-9]+", (name or "").lower()) if w]


def generate_username_candidates(name):
    """Username candidates derived from a person's name. Every result
    is a name-derived guess (callers must label it as such)."""
    words = _name_words(name)
    words = [w for w in words if w not in _NAME_STOPWORDS] or words
    if not words:
        return []
    if len(words) == 1:
        return [words[0]]
    first, last = words[0], words[1]
    cands = [first + last, f"{first}.{last}", first[0] + last,
             f"{first}_{last}", first + last[0], last + first]
    out = []
    for c in cands:
        if c not in out:
            out.append(c)
    return out[:6]


_LEGAL_SUFFIXES = _NAME_STOPWORDS | {
    "global", "international", "intl", "gmbh", "pte", "sdn", "bhd",
    "plc", "sarl", "bv", "ag", "sa", "kk", "foundation", "institute",
}


def _institution_domain_guesses(name):
    words = [w for w in _name_words(name) if w not in _LEGAL_SUFFIXES]
    if not words:
        return []
    joined = "".join(words)
    bases = [joined]
    if len(words) > 1 and words[0] != joined:
        bases.append(words[0])
    tlds = ["com", "co.id", "net", "org", "io", "id"]
    out = []
    for b in bases:
        for t in tlds:
            g = f"{b}.{t}"
            if g not in out:
                out.append(g)
    return out[:10]


# ============================================================ v1.11.0
# OSINT alignment pack (design file
# vanthex-osint-osiris-alignment-design.md; ADE decisions K1 full
# F1-F6, K2 wallet limited, K4 version 1.11.0). New identifier types
# (wallet, phone), OpenSanctions screening against a dated LOCAL
# snapshot, a second breach source, and Telegram public-preview
# metadata. Rules that do not bend: structural/local validation only
# (D5 — never log in anywhere), no carrier/owner enrichment for phone
# numbers, no transaction tracing for wallets, no Telegram content
# scraping, and "not evaluated" is a first-class result — absence of
# data is reported, never dressed up as a clean bill.

# ------------------------------------------------------- F1: sanctions
# OpenSanctions consolidated sanctions dataset, snapshotted locally
# at release time (CC-BY 4.0). Matching gates (design F1): an exact
# normalized name/alias match ALONE is `candidate` and is always
# labelled "NAME MATCH ONLY — NOT AN IDENTIFICATION"; `probable`
# requires name + a hard attribute (DOB / nationality / official ID)
# matching the SAME entry, or an exact crypto-address match. Fuzzy
# matching is deliberately NOT performed (deferred by design).

_SANCTIONS_MAX_AGE_DAYS = 30
_sanctions_cache = {"state": None}


def _sanctions_norm(name):
    """NFKD, strip diacritics + punctuation, lowercase, collapse
    whitespace — applied identically to snapshot entries and queries."""
    s = unicodedata.normalize("NFKD", str(name or ""))
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^\w\s]", " ", s.lower())
    return re.sub(r"\s+", " ", s).strip()


def _days_from_civil(y, m, d):
    """Days since 1970-01-01 (Hinnant's algorithm) — date-age math
    without depending on the host clock's timezone."""
    y -= 1 if m <= 2 else 0
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m - 3 if m > 2 else m + 9) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _sanctions_load():
    """Load + index the local snapshot once per process. Returns
    (state, snapshot_date, reason): state is 'ok' or 'not evaluated'
    (missing / unreadable / stale snapshot — screening then honestly
    reports not evaluated; data is never fabricated)."""
    if _sanctions_cache["state"] is not None:
        return (_sanctions_cache["state"], _sanctions_cache.get("date"),
                _sanctions_cache.get("reason"))
    state, date_s, reason = "not evaluated", None, ""
    path = os.environ.get("PTK_OSINT_SANCTIONS_SNAPSHOT") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "sanctions_snapshot.json")
    try:
        with open(path, encoding="utf-8") as fh:
            snap = json.load(fh)
        entries_raw = snap["entries"]
        crypto_raw = snap["crypto"]
        date_s = str(snap.get("snapshot_date") or "")
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", date_s)
        if not m:
            raise ValueError("snapshot has no usable snapshot_date")
        snap_days = _days_from_civil(int(m.group(1)), int(m.group(2)),
                                     int(m.group(3)))
        now = time.gmtime()
        age = (_days_from_civil(now.tm_year, now.tm_mon, now.tm_mday)
               - snap_days)
        if age > _SANCTIONS_MAX_AGE_DAYS:
            reason = (f"snapshot dated {date_s} is {age} days old "
                      f"(limit {_SANCTIONS_MAX_AGE_DAYS})")
            raise ValueError(reason)
        names, crypto = {}, {}
        for row in entries_raw:
            e = {"name": row[0], "schema": row[1], "dob": row[2],
                 "nat": row[3], "ids": row[4], "aliases": row[5]}
            for key in {e["name"]} | set(e["aliases"]):
                nk = _sanctions_norm(key)
                if nk:
                    names.setdefault(nk, []).append(e)
        for addr, holder in crypto_raw:
            crypto[str(addr)] = holder
            if str(addr).startswith("0x"):
                crypto[str(addr).lower()] = holder
        _sanctions_cache["index"] = {"names": names, "crypto": crypto}
        state, reason = "ok", ""
    except Exception as exc:
        if not reason:
            reason = ("snapshot missing or unreadable "
                      f"({type(exc).__name__})")
        state = "not evaluated"
    _sanctions_cache.update(state=state, date=date_s, reason=reason)
    return state, date_s, reason


def _sanctions_meta(ctx):
    m = ctx.meta.get("sanctions")
    if not isinstance(m, dict):
        state, date_s, reason = _sanctions_load()
        m = {"status": state, "snapshot_date": date_s, "checks": [],
             "matches": [], "address_matches": []}
        if reason:
            m["reason"] = reason
        ctx.meta["sanctions"] = m
    return m


def _sanctions_attr_match(entry, attrs):
    """Which hard attribute in attrs matches this entry, if any:
    'date of birth' | 'nationality' | 'official ID' | None."""
    if not attrs:
        return None
    dobs = {str(x).strip() for x in attrs.get("dob") or []
            if str(x).strip()}
    for want in dobs:
        for have in entry["dob"]:
            have = str(have).strip()
            if want == have:
                return "date of birth"
            if (len(want) >= 4 and len(have) >= 4
                    and want[:4].isdigit() and have[:4].isdigit()
                    and want[:4] == have[:4]
                    and (len(want) == 4 or len(have) == 4)):
                return "date of birth (year)"
    nats = {str(x).strip().lower() for x in attrs.get("nationality") or []
            if str(x).strip()}
    if nats & {str(x).strip().lower() for x in entry["nat"]}:
        return "nationality"
    ids = {re.sub(r"\s+", "", str(x)).lower()
           for x in attrs.get("id") or [] if str(x).strip()}
    have_ids = {re.sub(r"\s+", "", str(x)).lower() for x in entry["ids"]}
    if ids & have_ids:
        return "official ID"
    return None


def sanctions_match_name(name, attrs=None):
    """Exact normalized name/alias matches from the local snapshot.
    [] both for 'no match' and for 'not evaluated' — callers separate
    the two via _sanctions_load's state."""
    state, _d, _r = _sanctions_load()
    if state != "ok":
        return []
    idx = _sanctions_cache["index"]["names"]
    out, seen = [], set()
    for e in idx.get(_sanctions_norm(name), []):
        if id(e) in seen:
            continue
        seen.add(id(e))
        attr = _sanctions_attr_match(e, attrs)
        out.append({"entry": e,
                    "tier": "probable" if attr else "candidate",
                    "attribute": attr})
    return out


def sanctions_match_address(address):
    """Exact crypto-address match -> {'address','holder'} or None."""
    state, _d, _r = _sanctions_load()
    if state != "ok":
        return None
    crypto = _sanctions_cache["index"]["crypto"]
    addr = str(address or "").strip()
    holder = crypto.get(addr)
    if holder is None and addr.startswith("0x"):
        holder = crypto.get(addr.lower())
    if holder is None:
        return None
    return {"address": addr, "holder": holder}


def _sanctions_check_name(ctx, name, source_desc, subject_node_id=None,
                          attrs=None):
    """F1 screening of ONE name string (a query name, an RDAP owner).
    The check is recorded in meta['sanctions'] either way; a match
    makes a `sanction` node + a gated finding."""
    L, add, g = ctx.L, ctx.add, ctx.graph
    smeta = _sanctions_meta(ctx)
    name = (name or "").strip()
    if not name:
        return []
    if smeta["status"] != "ok":
        if not smeta.get("warned"):
            smeta["warned"] = True
            ctx.warn("F1 sanctions screening not evaluated — "
                     + (smeta.get("reason") or "snapshot unavailable"))
            L("[osint] F1 sanctions: not evaluated ("
              + (smeta.get("reason") or "snapshot unavailable") + ")")
        smeta["checks"].append({"name": name, "source": source_desc,
                                "matches": 0, "status": "not evaluated"})
        return []
    hits = sanctions_match_name(name, attrs)
    smeta["checks"].append({"name": name, "source": source_desc,
                            "matches": len(hits)})
    base = subject_node_id or ctx.root_id
    for hit in hits[:3]:
        e = hit["entry"]
        tier = hit["tier"]
        flag = "sanctions_attr" if tier == "probable" else "sanctions_name"
        nid = g.node("sanction", e["name"], tier, "F1")
        if nid is None:
            continue
        g.node_attr(nid, flag=flag,
                    snapshot_date=smeta["snapshot_date"])
        if base:
            g.edge(base, nid, "SANCTIONS_MATCH", tier,
                   f"exact name match in OpenSanctions snapshot "
                   f"{smeta['snapshot_date']}"
                   + (f"; corroborated by {hit['attribute']}"
                      if hit["attribute"] else
                      " — NAME MATCH ONLY, NOT AN IDENTIFICATION"))
        smeta["matches"].append(
            {"checked_name": name, "entry": e["name"],
             "schema": e["schema"], "tier": tier,
             "attribute": hit["attribute"], "source": source_desc})
        if tier == "probable":
            add(F("LOW", "Sanctions-list match (name + attribute)",
                  "The checked name matches a sanctions-list entry AND "
                  "a hard attribute (date of birth / nationality / "
                  "official ID) published for that entry agrees. This "
                  "is a probable match, not a confirmed identification "
                  "— verify with the official list before acting.",
                  evidence=(f"entry: {e['name']} ({e['schema']}) | "
                            f"checked name: {name} ({source_desc}) | "
                            f"corroborating attribute: {hit['attribute']}"
                            f" | source: OpenSanctions consolidated "
                            f"sanctions snapshot "
                            f"{smeta['snapshot_date']} (CC-BY 4.0)"),
                  cwe="", owasp="", cvss=3.1,
                  remed="Verify against the official sanctions list; "
                        "if confirmed, follow your sanctions-compliance "
                        "procedure.",
                  confidence="probable", location=name, origin="passive"))
        else:
            add(F("INFO",
                  "Possible sanctions-list name match — NOT an "
                  "identification",
                  "A name in the public data examined here exactly "
                  "matches a name or alias on the consolidated "
                  "sanctions list. A name match alone does NOT "
                  "identify the subject as the listed person or "
                  "entity — many people and companies share names. "
                  "NAME MATCH ONLY — NOT AN IDENTIFICATION. "
                  "Corroborate with date of birth, nationality or an "
                  "official ID from a reliable source before drawing "
                  "any conclusion.",
                  evidence=(f"entry: {e['name']} ({e['schema']}) | "
                            f"checked name: {name} ({source_desc}) | "
                            f"match basis: exact name/alias only, no "
                            f"attribute corroboration | source: "
                            f"OpenSanctions consolidated sanctions "
                            f"snapshot {smeta['snapshot_date']} "
                            f"(CC-BY 4.0)"),
                  cwe="", owasp="", cvss=0.0,
                  remed="Do not act on a name match alone; corroborate "
                        "with hard identifiers via official sources.",
                  confidence="candidate", location=name,
                  origin="passive"))
    if hits:
        L(f"[osint] F1 sanctions: {len(hits)} match(es) for '{name}' "
          f"({source_desc})")
    return hits


def _sanctions_flag_address(ctx, address, node_id, where_desc):
    """Exact-address sanctions flag for a wallet node (F1/F2 shared).
    Returns the hit dict or None; records into meta['sanctions']."""
    smeta = _sanctions_meta(ctx)
    if smeta["status"] != "ok":
        return None
    hit = sanctions_match_address(address)
    if not hit:
        return None
    if node_id:
        ctx.graph.node_attr(node_id, flag="sanctioned_address")
    smeta["address_matches"].append(
        {"address": address, "holder": hit["holder"], "seen": where_desc})
    ctx.add(F("LOW", "Sanctioned crypto address (exact match)",
              "This exact wallet address appears on the consolidated "
              "sanctions list. An address match is exact (unlike a "
              "name match), but it still identifies the ADDRESS, not "
              "the person operating it.",
              evidence=(f"address: {address} | list entry holder: "
                        f"{hit['holder'] or '—'} | seen: {where_desc} "
                        f"| source: OpenSanctions consolidated "
                        f"sanctions snapshot {smeta['snapshot_date']} "
                        f"(CC-BY 4.0)"),
              cwe="", owasp="", cvss=3.1,
              remed="Treat flows involving this address per your "
                    "sanctions-compliance procedure; verify on the "
                    "official list.",
              confidence="probable", location=address,
              origin="passive"))
    ctx.L(f"[osint] F1 sanctions: exact address match for {address}")
    return hit


# --------------------------------------------------------- F3: phone
# Structural parse ONLY (design F3 + the standing K2 rule): country
# from a curated calling-code table, national-length validation.
# Carrier, line type and owner enrichment are NOT performed — no
# HLR/carrier/reverse-phone source is consulted, ever.

_PHONE_CC = {
    "1": ("United States / Canada (NANP)", {10}),
    "7": ("Russia / Kazakhstan", {10}),
    "20": ("Egypt", {9, 10}), "27": ("South Africa", {9}),
    "30": ("Greece", {10}), "31": ("Netherlands", {9}),
    "32": ("Belgium", {8, 9}), "33": ("France", {9}),
    "34": ("Spain", {9}), "36": ("Hungary", {8, 9}),
    "39": ("Italy", {9, 10}), "40": ("Romania", {9}),
    "41": ("Switzerland", {9}), "43": ("Austria", {9, 10}),
    "44": ("United Kingdom", {10}), "45": ("Denmark", {8}),
    "46": ("Sweden", {7, 8, 9}), "47": ("Norway", {8}),
    "48": ("Poland", {9}), "49": ("Germany", {10, 11}),
    "51": ("Peru", {9}), "52": ("Mexico", {10}), "53": ("Cuba", {8}),
    "54": ("Argentina", {10}), "55": ("Brazil", {10, 11}),
    "56": ("Chile", {9}), "57": ("Colombia", {10}),
    "58": ("Venezuela", {10}), "60": ("Malaysia", {9, 10}),
    "61": ("Australia", {9}), "62": ("Indonesia", {9, 10, 11, 12}),
    "63": ("Philippines", {10}), "64": ("New Zealand", {8, 9, 10}),
    "65": ("Singapore", {8}), "66": ("Thailand", {9}),
    "81": ("Japan", {10}), "82": ("South Korea", {9, 10}),
    "84": ("Vietnam", {9}), "86": ("China", {11}),
    "90": ("Turkey", {10}), "91": ("India", {10}),
    "92": ("Pakistan", {10}), "93": ("Afghanistan", {9}),
    "94": ("Sri Lanka", {9}), "95": ("Myanmar", {8, 9, 10}),
    "98": ("Iran", {10}), "212": ("Morocco", {9}),
    "234": ("Nigeria", {10}), "254": ("Kenya", {9}),
    "351": ("Portugal", {9}), "352": ("Luxembourg", {6, 7, 8, 9}),
    "353": ("Ireland", {9}), "358": ("Finland", {9, 10}),
    "380": ("Ukraine", {9}), "420": ("Czechia", {9}),
    "852": ("Hong Kong", {8}), "855": ("Cambodia", {8, 9}),
    "856": ("Laos", {10}), "880": ("Bangladesh", {10}),
    "886": ("Taiwan", {9}), "966": ("Saudi Arabia", {9}),
    "971": ("United Arab Emirates", {9}), "972": ("Israel", {9}),
    "974": ("Qatar", {8}), "977": ("Nepal", {10}),
}


def parse_phone(raw):
    """Parse an international-format number ('+'-prefixed, spaces /
    dashes / parentheses tolerated) into structural facts, or None
    when the shape is not a plausible number in the curated table —
    unknown country codes and wrong national lengths are rejected,
    never guessed."""
    s = re.sub(r"[\s().\-]", "", (raw or "").strip())
    if not re.fullmatch(r"\+\d{8,15}", s):
        return None
    digits = s[1:]
    for ln in (3, 2, 1):
        cc = digits[:ln]
        if cc in _PHONE_CC:
            region, lens = _PHONE_CC[cc]
            national = digits[ln:]
            if len(national) not in lens:
                return None
            return {"e164": "+" + digits, "country_code": cc,
                    "region": region, "national": national,
                    "national_length": len(national), "digits": digits}
    return None


# -------------------------------------------------------- F2: wallet
# Structural validation is hand-rolled, stdlib only (design F2a):
# BTC Base58Check (double-SHA256 checksum) + Bech32/Bech32m SegWit
# (BIP-173/350 polymod), ETH EIP-55 (pure-Python Keccak-256 —
# hashlib.sha3_256 is FIPS SHA-3, a DIFFERENT padding), SOL base58
# decoding to exactly 32 bytes. Summaries are limited (design K2):
# balance / tx count / first+last seen where the public source
# actually exposes them. No transaction tracing.

_B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_REV = {c: i for i, c in enumerate(_B58_CHARS)}
_BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_REV = {c: i for i, c in enumerate(_BECH32_CHARS)}
_MASK64 = (1 << 64) - 1
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_KECCAK_R = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2],
             [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
             [27, 20, 39, 8, 14]]
_BTC_LEGACY_RE = re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}\Z")
_BTC_BECH32_RE = re.compile(r"bc1[ac-hj-np-z02-9]{11,71}\Z", re.I)
_ETH_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_SOL_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}\Z")
_ENTITY_WALLET_RE = re.compile(
    r"\b(?:0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    r"|[bB][cC]1[ac-hj-np-z02-9]{11,71}"
    r"|[1-9A-HJ-NP-Za-km-z]{32,44})\b")


def _b58_decode(s):
    try:
        n = 0
        for c in s:
            n = n * 58 + _B58_REV[c]
    except KeyError:
        return None
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def _b58check_ok(s):
    raw = _b58_decode(s)
    if raw is None or len(raw) != 25:
        return False
    if raw[0] not in (0x00, 0x05, 0x6f, 0xc2):
        return False
    digest = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()
    return digest[:4] == raw[21:]


def _bech32_polymod(values):
    chk = 1
    gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _segwit_decode(addr):
    """BIP-173/350 decode -> (hrp, witness_version, program) or None."""
    if (not addr or len(addr) > 90
            or (addr != addr.lower() and addr != addr.upper())):
        return None
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a):
        return None
    hrp, data_part = a[:pos], a[pos + 1:]
    if any(c not in _BECH32_REV for c in data_part):
        return None
    data = [_BECH32_REV[c] for c in data_part]
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = _bech32_polymod(expand + data)
    witver = data[0]
    if witver == 0 and pm != 1:
        return None
    if witver != 0 and pm != 0x2BC830A3:
        return None
    acc, bits, prog = 0, 0, bytearray()
    for v in data[1:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xFF)
    if bits >= 5:
        return None
    if bits and (acc & ((1 << bits) - 1)):
        return None
    if not (2 <= len(prog) <= 40):
        return None
    if witver == 0 and len(prog) not in (20, 32):
        return None
    if witver == 1 and len(prog) != 32:
        return None
    return hrp, witver, bytes(prog)


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK64 if n else x


def _keccak_f1600(st):
    for rc in _KECCAK_RC:
        c = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1)
             for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    st[x + 5 * y], _KECCAK_R[x][y])
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] = (b[x + 5 * y]
                                 ^ ((~b[(x + 1) % 5 + 5 * y] & _MASK64)
                                    & b[(x + 2) % 5 + 5 * y]))
        st[0] ^= rc


def _keccak256(data):
    """Keccak-256 (original Keccak pad10*1 with the 0x01 domain —
    NOT FIPS SHA3-256; this is Ethereum's hash). Pure Python."""
    rate = 136
    st = [0] * 25
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % rate:
        buf.append(0x00)
    buf[-1] |= 0x80
    for off in range(0, len(buf), rate):
        block = buf[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f1600(st)
    return b"".join(st[i].to_bytes(8, "little") for i in range(4))[:32]


def _eip55_checksum_ok(addr):
    """'valid' (mixed case + checksum correct), 'plain' (single-case
    — no checksum embedded), 'invalid' (mixed case, checksum wrong)."""
    hexpart = addr[2:]
    if hexpart == hexpart.lower() or hexpart == hexpart.upper():
        return "plain"
    low = hexpart.lower()
    digest = _keccak256(low.encode("ascii")).hex()
    expect = "".join(
        c.upper() if c in "abcdef" and int(digest[i], 16) >= 8 else c
        for i, c in enumerate(low))
    return "valid" if expect == hexpart else "invalid"


def wallet_info(query):
    """Structural wallet-address recognition (design F2a). Returns
    {'chain': 'BTC'|'ETH'|'SOL', 'checksum': str} or None. BTC legacy
    requires a valid Base58Check checksum and SegWit a valid
    Bech32/Bech32m checksum — a handle-shaped string is never
    promoted to 'wallet' on shape alone. Mixed-case ETH must pass
    EIP-55. Solana has no checksum: base58 to exactly 32 bytes."""
    s = (query or "").strip()
    if not s or " " in s:
        return None
    if _ETH_RE.match(s):
        st = _eip55_checksum_ok(s)
        if st == "invalid":
            return None
        return {"chain": "ETH", "checksum": (
            "EIP-55 checksum valid" if st == "valid" else
            "not checksummed (single-case hex)")}
    if _BTC_LEGACY_RE.match(s) and _b58check_ok(s):
        return {"chain": "BTC", "checksum": "Base58Check checksum valid"}
    if _BTC_BECH32_RE.match(s):
        dec = _segwit_decode(s)
        if dec and dec[0] == "bc":
            return {"chain": "BTC",
                    "checksum": "Bech32 SegWit checksum valid"}
    if _SOL_RE.match(s):
        raw = _b58_decode(s)
        if raw is not None and len(raw) == 32:
            return {"chain": "SOL", "checksum":
                    "n/a — Solana addresses carry no checksum "
                    "(base58, 32 bytes)"}
    return None


def _wallet_pivot(ctx, subject):
    L, add, g = ctx.L, ctx.add, ctx.graph
    addr = subject.strip()
    info = wallet_info(addr) or {"chain": "?", "checksum": ""}
    chain = info["chain"]
    ctx.pivots.append(f"wallet:{chain}")
    wid = g.node("wallet", addr, "probable", "F2")
    g.edge(ctx.root_id, wid, "LINKED_TO", "probable",
           f"query detected as a {chain} wallet address "
           f"({info['checksum']})")
    wmeta = {"address": addr, "chain": chain,
             "checksum": info["checksum"], "sanctioned": None,
             "summary": "not evaluated", "source": None}
    ctx.meta["wallet"] = wmeta
    smeta = _sanctions_meta(ctx)
    if smeta["status"] == "ok":
        hit = _sanctions_flag_address(ctx, addr, wid, "the query itself")
        wmeta["sanctioned"] = {"holder": hit["holder"]} if hit else False
    else:
        wmeta["sanctioned"] = "not evaluated"
    if ctx.stop_requested():
        return
    if chain == "BTC":
        wmeta["source"] = "blockstream.info"
        st, _h, raw = ctx.fetch(
            f"https://blockstream.info/api/address/{addr}",
            timeout=20, verify=True)
        data = None
        if st == 200 and raw:
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                data = None
        cs = (data or {}).get("chain_stats") or {}
        if cs:
            funded = int(cs.get("funded_txo_sum") or 0)
            spent = int(cs.get("spent_txo_sum") or 0)
            tx_count = int(cs.get("tx_count") or 0)
            summ = {"balance_btc": round((funded - spent) / 1e8, 8),
                    "total_received_btc": round(funded / 1e8, 8),
                    "tx_count": tx_count,
                    "first_seen": "not evaluated",
                    "last_seen": "not evaluated"}
            if tx_count:
                st2, _h2, raw2 = ctx.fetch(
                    f"https://blockstream.info/api/address/{addr}/txs",
                    timeout=20, verify=True)
                txs = None
                if st2 == 200 and raw2:
                    try:
                        txs = json.loads(raw2.decode("utf-8", "replace"))
                    except Exception:
                        txs = None
                times = sorted(
                    t["status"]["block_time"] for t in (txs or [])
                    if isinstance(t, dict)
                    and (t.get("status") or {}).get("block_time"))
                if times:
                    summ["last_seen"] = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(times[-1]))
                    if len(txs) >= tx_count:
                        summ["first_seen"] = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(times[0]))
            wmeta["summary"] = summ
            add(F("INFO", "Wallet summary (BTC, public ledger)",
                  "Public summary for this Bitcoin address from a "
                  "public ledger API. Summary only — individual "
                  "transactions are not traced (design K2).",
                  evidence=(f"address {addr} | balance "
                            f"{summ['balance_btc']} BTC | received "
                            f"{summ['total_received_btc']} BTC | "
                            f"transactions {tx_count} | first seen "
                            f"{summ['first_seen']} | last seen "
                            f"{summ['last_seen']} | source: "
                            f"blockstream.info"),
                  cwe="", owasp="", cvss=0.0,
                  remed="Informational; no action required.",
                  confidence="probable", location=addr,
                  origin="passive"))
        else:
            ctx.warn(f"F2: blockstream.info lookup failed (HTTP {st}) "
                     "— BTC wallet summary not evaluated")
    elif chain == "ETH":
        wmeta["source"] = "Blockscout (eth.blockscout.com)"
        st, _h, raw = ctx.fetch(
            f"https://eth.blockscout.com/api/v2/addresses/{addr}",
            timeout=20, verify=True)
        data = None
        if st == 200 and raw:
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                data = None
        if isinstance(data, dict) and data.get("coin_balance") is not None:
            wei = int(data["coin_balance"])
            summ = {"balance_eth": round(wei / 1e18, 8),
                    "tx_count": "not evaluated",
                    "first_seen": "not evaluated",
                    "last_seen": "not evaluated"}
            st2, _h2, raw2 = ctx.fetch(
                f"https://eth.blockscout.com/api/v2/addresses/"
                f"{addr}/counters", timeout=20, verify=True)
            if st2 == 200 and raw2:
                try:
                    cnt = json.loads(raw2.decode("utf-8", "replace"))
                    summ["tx_count"] = int(cnt.get("transactions_count"))
                except Exception:
                    pass
            wmeta["summary"] = summ
            add(F("INFO", "Wallet summary (ETH, public ledger)",
                  "Public summary for this Ethereum address from a "
                  "public ledger API. Summary only — individual "
                  "transactions and token flows are not traced "
                  "(design K2). First/last activity are not exposed "
                  "by this source and are reported as not evaluated.",
                  evidence=(f"address {addr} | balance "
                            f"{summ['balance_eth']} ETH | transactions "
                            f"{summ['tx_count']} | source: Blockscout "
                            f"(eth.blockscout.com)"),
                  cwe="", owasp="", cvss=0.0,
                  remed="Informational; no action required.",
                  confidence="probable", location=addr,
                  origin="passive"))
        else:
            ctx.warn(f"F2: Blockscout lookup failed (HTTP {st}) — ETH "
                     "wallet summary not evaluated")
    else:  # SOL — detection + sanctions flag only (design F2/K2)
        L("[osint] F2: Solana address — detection + sanctions flag "
          "only; on-chain summary not evaluated in v1.11.0 (design K2)")
    L(f"[osint] F2 wallet pivot: {chain} {addr}")


def _phone_pivot(ctx, subject):
    L, add, g = ctx.L, ctx.add, ctx.graph
    parsed = parse_phone(subject)
    if not parsed:
        ctx.warn("F3: phone-shaped query failed structural validation "
                 "— no phone pivot run")
        return
    e164 = parsed["e164"]
    ctx.pivots.append(f"phone:{e164}")
    pmeta = {"input": subject.strip(), "e164": e164,
             "country_code": parsed["country_code"],
             "region": parsed["region"],
             "national": parsed["national"],
             "national_length": parsed["national_length"],
             "carrier": "not evaluated", "line_type": "not evaluated",
             "owner": "not evaluated", "published_matches": 0,
             "signals": []}
    ctx.meta["phone"] = pmeta
    pid = g.node("phone", e164, "probable", "F3")
    g.edge(ctx.root_id, pid, "LINKED_TO", "probable",
           "query detected as an international phone number")
    add(F("INFO", "Phone number structure (structural parse only)",
          "Country and shape were determined by a local structural "
          "parse against a curated calling-code table. Carrier, line "
          "type and owner were NOT looked up — VANTHEX performs no "
          "carrier/HLR/reverse-phone enrichment (design F3/K2).",
          evidence=(f"{e164} | country +{parsed['country_code']} "
                    f"({parsed['region']}) | national number "
                    f"{parsed['national']} ({parsed['national_length']} "
                    f"digits) | source: local structural parse — "
                    f"carrier/line-type/owner not evaluated"),
          cwe="", owasp="", cvss=0.0,
          remed="Informational; no action required.",
          confidence="probable", location=e164, origin="passive"))
    L(f"[osint] F3 phone pivot: {e164} ({parsed['region']}) — "
      "structural facts only")
    if ctx.stop_requested():
        return
    _web_mentions(ctx, e164, pid, kind="phone")
    # Correlation: the same digits published on a fetched public page
    # (pages extracted by WS-B during the mentions pivot) — one
    # corroboration signal class ('phone-published'), never an
    # identity claim on its own (design F3d).
    digits = parsed["digits"]
    graph_nodes, _stats = g.build()
    for node in graph_nodes["nodes"]:
        if node["type"] != "phone" or node["id"] == pid:
            continue
        if re.sub(r"\D", "", node["label"]) == digits:
            g.edge(pid, node["id"], "SAME_NUMBER", "probable",
                   "same digits as a phone number published on a "
                   "fetched public page")
            pmeta["published_matches"] += 1
    if pmeta["published_matches"]:
        pmeta["signals"] = ["phone-published"]
        L(f"[osint] F3: number also published on "
          f"{pmeta['published_matches']} extracted node(s) "
          "(signal class: phone-published)")


# ------------------------------------------------------ F6: Telegram
# Public-preview metadata ONLY (t.me/s/<channel>): title, subscriber
# count, public description. Message content is never fetched or
# scraped (design F6). A channel without a public preview (private /
# nonexistent) is simply not evaluated, never an error finding.

_TG_TITLE_RE = re.compile(
    r'tgme_channel_info_header_title"[^>]*>\s*<span[^>]*>(.*?)</span>',
    re.S)
_TG_COUNTER_RE = re.compile(
    r'tgme_channel_info_counter_value">([^<]+)</span>\s*'
    r'<span class="tgme_channel_info_counter_label">([^<]+)</span>')
_TG_DESC_RE = re.compile(
    r'tgme_channel_info_description"[^>]*>(.*?)</div>', re.S)


def _tg_clean(fragment):
    txt = re.sub(r"<br\s*/?>", " ", fragment or "")
    txt = re.sub(r"<[^>]+>", "", txt)
    return re.sub(r"\s+", " ", html_mod.unescape(txt)).strip()


def _telegram_channel_meta(ctx, channel):
    """Public preview metadata for one Telegram channel, or None
    when no public preview exists (private/nonexistent channel)."""
    st, _h, raw = ctx.fetch(
        f"https://t.me/s/{quote(channel, safe='')}",
        timeout=12, verify=True)
    if st != 200 or not raw:
        return None
    body = raw.decode("utf-8", "replace")
    m = _TG_TITLE_RE.search(body)
    if not m:
        return None
    subs = None
    for val, label in _TG_COUNTER_RE.findall(body):
        if label.strip().lower().startswith("subscriber"):
            subs = val.strip()
            break
    dm = _TG_DESC_RE.search(body)
    return {"channel": channel, "title": _tg_clean(m.group(1)),
            "subscribers": subs,
            "description": _tg_clean(dm.group(1))[:240] if dm else "",
            "url": f"https://t.me/{channel}"}


# ------------------------------------------------- F4: XposedOrNot
# Second A5 breach source (design F4), under the SAME explicit
# opt-in as HudsonRock. Results stay `candidate` (third-party claim);
# when both sources report the same address, the finding text says
# so — the tier does not rise. XposedOrNot offers no domain lookup
# endpoint (verified at build time: /v1/check-domain does not
# exist), so the domain flow marks this source 'not evaluated'
# instead of calling a dead endpoint.

def _xposedornot_email(ctx, email):
    """-> {'status': 'reported'|'not_reported'|'not evaluated', ...}"""
    st, _h, raw = ctx.fetch(
        "https://api.xposedornot.com/v1/breach-analytics?email="
        + quote(email), timeout=20, verify=True)
    if st != 200 or not raw:
        return {"status": "not evaluated"}
    try:
        d = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"status": "not evaluated"}
    site = ""
    if isinstance(d, dict):
        site = (d.get("BreachesSummary") or {}).get("site") or ""
    names = [s.strip() for s in str(site).split(";") if s.strip()]
    return {"status": "reported" if names else "not_reported",
            "breaches": names[:50], "count": len(names)}



# ------------------------------------------------------------- run context

_GRAPH_CONF_RANK = {"info": 0, "candidate": 1, "probable": 2, "confirmed": 3}


class _Graph:
    """Investigation graph built ONLY from relations a pivot actually
    proved (DoH resolution, RDAP/CT data, control-gated platform
    results, explicit profile fields). Name-derived or inferred
    relations are always `candidate` edges. Nodes are deduplicated by
    (type, normalized label); the node cap is explicit — hitting it
    sets `truncated` instead of silently dropping entities."""

    MAX_NODES = 400

    def __init__(self):
        self._nodes = {}
        self._by_id = {}
        self.edges = []
        self._edge_keys = set()
        self.truncated = False

    def node(self, ntype, label, confidence="info", module=""):
        label = str(label or "").strip()
        if not label:
            return None
        key = (ntype, label.lower())
        existing = self._nodes.get(key)
        if existing:
            if (_GRAPH_CONF_RANK.get(confidence, 0)
                    > _GRAPH_CONF_RANK.get(existing["confidence"], 0)):
                existing["confidence"] = confidence
            return existing["id"]
        if len(self._nodes) >= self.MAX_NODES:
            self.truncated = True
            return None
        nid = f"{ntype}:{label.lower()}"
        node = {"id": nid, "type": ntype, "label": label,
                "confidence": confidence, "module": module}
        self._nodes[key] = node
        self._by_id[nid] = node
        return nid

    def edge(self, source, target, relation, confidence, evidence):
        if not source or not target or source == target:
            return
        if source not in self._by_id or target not in self._by_id:
            return
        key = (source, target, relation)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({"source": source, "target": target,
                           "relation": relation,
                           "confidence": confidence,
                           "evidence": str(evidence)[:160]})

    def node_attr(self, nid, **attrs):
        """Merge extra attributes into an existing node (WS4: compact
        extracted-profile attributes ride on graph nodes)."""
        node = self._by_id.get(nid or "")
        if node is None:
            return
        for k, v in attrs.items():
            if v is not None:
                node[k] = v

    def build(self):
        nodes = list(self._nodes.values())
        by_type = {}
        for n in nodes:
            by_type[n["type"]] = by_type.get(n["type"], 0) + 1
        return ({"nodes": nodes, "edges": self.edges},
                {"nodes": len(nodes), "edges": len(self.edges),
                 "by_type": by_type})


class _Ctx:
    """Shared state for one universal OSINT run."""

    def __init__(self, fetch, L, opts, platforms, cancelled=None,
                 deadline=None, budget_s=None):
        self.fetch = fetch
        self.L = L
        self.opts = opts or {}
        # v1.6.1: cooperative stop — an operator cancel callback plus
        # a soft wall-clock deadline. Every pivot polls stop_requested()
        # at phase/probe boundaries; when it fires, the run returns the
        # partial results gathered so far (never fabricated, never
        # discarded) and the coverage statement records why it stopped.
        self._cancel_cb = cancelled
        self.deadline = deadline
        self.budget_s = budget_s
        self.stop_reason = None
        # WS4: platforms disabled by the offline self-check (or the
        # schema flag) are excluded from every probe in this run.
        self.platforms = (active_platforms(platforms)
                          if platforms is not None else None)
        self.findings = []
        self.warnings = []
        self.meta = {}
        self.pivots = []
        self.graph = _Graph()
        self.root_id = None
        self.domain_node = None
        # v1.6.0 coverage accounting + A6 budgets/state.
        self.stats = {"platforms_checked": set(), "pages_fetched": 0,
                      "entities_extracted": 0}
        self.a6_nodes = 0
        self.extracted_emails = set()
        self.mentions_done = set()

    def add(self, f):
        key = (f["title"], f.get("location", ""), f.get("param", ""))
        if not any((x["title"], x.get("location", ""), x.get("param", "")) == key
                   for x in self.findings):
            self.findings.append(f)

    def warn(self, w):
        self.warnings.append(w)

    def is_cancelled(self):
        cb = self._cancel_cb
        if cb is None:
            return False
        try:
            return bool(cb())
        except Exception:
            return False

    def budget_hit(self):
        return self.deadline is not None and time.time() >= self.deadline

    def stop_requested(self):
        """True once the operator cancelled or the soft time budget
        ran out; the reason is latched in self.stop_reason
        ('cancelled' | 'time_budget') for the coverage statement."""
        if self.stop_reason:
            return True
        if self.is_cancelled():
            self.stop_reason = "cancelled"
        elif self.budget_hit():
            self.stop_reason = "time_budget"
        return bool(self.stop_reason)


def _ct_rows(fetch, domain):
    """crt.sh rows for a domain -> (rows|None|'parse_error', http_status)."""
    st, _h, raw = fetch(f"https://crt.sh/?q=%25.{domain}&output=json",
                        timeout=20, verify=True)
    if st != 200 or not raw:
        return None, st
    try:
        rows = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return "parse_error", st
    return (rows if isinstance(rows, list) else []), st


def _ct_parse_rows(rows):
    """Split CT rows into (live-cert names, expired-only names)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    live_names, expired_names = set(), set()
    for row in rows or []:
        names = [n.strip().lower().lstrip("*.")
                 for n in str(row.get("name_value", "")).splitlines()
                 if n.strip()]
        expired = False
        na = str(row.get("not_after", ""))
        try:
            parsed_na = datetime.fromisoformat(na.replace("Z", "+00:00"))
            if parsed_na.tzinfo is None:
                parsed_na = parsed_na.replace(tzinfo=timezone.utc)
            expired = parsed_na < now
        except Exception:
            expired = False
        for n in names:
            (expired_names if expired else live_names).add(n)
    return live_names, expired_names


def _scan_readmes(ctx, repo_items, url_of, branch_of, cap_repos=3):
    """Fetch README files of public repos and scan them with the
    Secrets Engine. repo_items: list of API item dicts."""
    sec_state = {"seen": set(), "count": 0, "cap": 6}
    for it in repo_items[:cap_repos]:
        readme_url = url_of(it, branch_of(it))
        if not readme_url:
            continue
        s2, _h2, raw2 = ctx.fetch(readme_url, timeout=12, verify=True,
                                   cap=512 * 1024)
        if s2 == 200 and raw2:
            _scan_secrets_in(ctx.add, raw2.decode("utf-8", "replace"),
                             readme_url, sec_state, config_style=True)
    return sec_state["count"]


# --------------------------------- v1.5.0: archive & hygiene (P1-P3)
# Passive gap-closers from the OSINT Framework mapping. Every source
# is third-party data ABOUT the target; every DNS answer comes ONLY
# from scanners.doh_query (DoH ground truth — the system resolver is
# never used as evidence). Every failure becomes an explicit
# "not evaluated" meta state, never a silent empty result and never
# a finding.

_PASSIVEDNS_CAP = 100


def _doh_query(name, rrtype):
    """The only DNS channel for the v1.5.0 modules: scanners.doh_query
    (DNS-over-HTTPS). Returns the answer-data list ([] = the name has
    no such record) or None when the DoH transport itself failed —
    callers must treat None as 'not evaluated', never as 'no record'."""
    try:
        return scanners.doh_query(name, rrtype)
    except Exception:
        return None


def _find_node_by_label(g, label):
    """Id of an existing graph node with this label (any type), else
    None. Used so historical/passive names enrich the node the live
    pivots already created instead of duplicating the entity under a
    second type."""
    ll = (label or "").lower()
    for node in g._by_id.values():
        if node["label"].lower() == ll:
            return node["id"]
    return None


# ------------------------------------------------------------------ P1

_ARCHIVE_HOST_CAP = 100
_ARCHIVE_PATH_CAP = 50
_ARCHIVE_PATH_RE = re.compile(
    r"/\.git(/|$|\?)|\.env(\.|/|$|\?)"
    r"|\.(bak|zip|sql|old|tar|tgz|gz)(/|$|\?)"
    r"|/admin(/|$|\?)|/config(\.|/|$|\?)|swagger|api-docs", re.I)


def _cdx_date(ts):
    """Wayback timestamp '20180511123045' -> '2018-05-11' ('' if bad)."""
    ts = str(ts or "")
    if len(ts) >= 8 and ts[:8].isdigit():
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return ""


def _archive_history(ctx, dom_id, domain):
    """P1: Wayback CDX historical hosts + exposure-shaped paths.

    HISTORICAL only: an archived URL proves the host/path was public
    at capture time; it says nothing about the present, and no
    snapshot content is fetched (K4). Hosts become candidate graph
    nodes (SEEN_IN_ARCHIVE) with capture-range evidence; a host the
    live pivots already found is enriched with archive attributes,
    never duplicated."""
    fetch, add, L = ctx.fetch, ctx.add, ctx.L
    g = ctx.graph
    meta = {"status": "not evaluated", "hosts": 0, "hosts_seen": 0,
            "hostnames": [], "paths": 0, "interesting_paths": [],
            "captures_total": 0, "earliest": None, "latest": None}
    ctx.meta["archive"] = meta
    url = ("https://web.archive.org/cdx/search/cdx?url="
           + quote(domain, safe="")
           + "&matchType=domain&output=json"
             "&fl=timestamp,original,statuscode,mimetype"
             "&collapse=urlkey&limit=5000")
    st, _h, raw = fetch(url, timeout=25, verify=True)
    rows = None
    if st == 200 and raw:
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            parsed = None
        if isinstance(parsed, list):
            rows = parsed
    if rows is None:
        ctx.warn(f"A1 archive: Wayback CDX unavailable (HTTP {st}) — "
                 "archive history not evaluated")
        meta["note"] = "Wayback CDX lookup failed — not evaluated"
        L("[osint] A1 archive: not evaluated (Wayback CDX unavailable)")
        return
    hosts = {}   # host -> [url_count, first_ts, last_ts]
    paths = {}   # url -> latest capture ts
    total = 0
    for row in rows:
        if not isinstance(row, list) or len(row) < 2:
            continue  # malformed row — skipped, never guessed at
        if str(row[0]).strip().lower() == "timestamp":
            continue  # header row
        ts, orig = str(row[0]).strip(), str(row[1]).strip()
        if not ts[:8].isdigit() or not orig:
            continue
        total += 1
        host = (urlparse(orig).hostname or "").lower()
        if host:
            ent = hosts.setdefault(host, [0, ts, ts])
            ent[0] += 1
            ent[1] = min(ent[1], ts)
            ent[2] = max(ent[2], ts)
        if _ARCHIVE_PATH_RE.search(orig):
            if orig not in paths or ts > paths[orig]:
                paths[orig] = ts
    meta["status"] = "evaluated"
    meta["captures_total"] = total
    all_ts = [t for ent in hosts.values() for t in (ent[1], ent[2])]
    if all_ts:
        meta["earliest"] = _cdx_date(min(all_ts))
        meta["latest"] = _cdx_date(max(all_ts))
    hostnames = sorted(hosts)
    meta["hosts_seen"] = len(hostnames)
    capped = hostnames[:_ARCHIVE_HOST_CAP]
    meta["hosts"] = len(capped)
    meta["hostnames"] = capped
    if len(hostnames) > len(capped):
        meta["note"] = (f"{len(hostnames)} historical hosts seen; "
                        f"listing capped at {_ARCHIVE_HOST_CAP}")
    for host in capped:
        count, first, last = hosts[host]
        ev = (f"Wayback Machine archive: {count} archived URL(s), "
              f"captured {_cdx_date(first)} … {_cdx_date(last)}")
        existing = dom_id if host == domain else _find_node_by_label(
            g, host)
        if existing:
            g.node_attr(existing, archived=True, archive_captures=count,
                        archive_first=_cdx_date(first),
                        archive_last=_cdx_date(last))
            if existing != dom_id:
                g.edge(dom_id, existing, "SEEN_IN_ARCHIVE",
                       "candidate", ev)
        else:
            nid = g.node("subdomain", host, "candidate", "A1")
            if nid:
                g.node_attr(nid, archived=True, archive_captures=count,
                            archive_first=_cdx_date(first),
                            archive_last=_cdx_date(last))
                g.edge(dom_id, nid, "SEEN_IN_ARCHIVE", "candidate", ev)
    plist = sorted(paths.items(), key=lambda kv: kv[1], reverse=True)
    meta["paths"] = len(plist)
    meta["interesting_paths"] = [
        {"url": u, "captured": _cdx_date(ts)}
        for u, ts in plist[:_ARCHIVE_PATH_CAP]]
    if plist:
        ev = "; ".join(
            f"{p['url']} (captured {p['captured']})"
            for p in meta["interesting_paths"][:15])
        add(F("LOW",
              "Historically public exposure-shaped paths (Wayback Machine)",
              "These URLs were publicly captured by the Wayback Machine in the past and match exposure-shaped patterns (.git, .env, backup archives, admin/config, API docs). This is a HISTORICAL observation: it proves the paths were public at capture time and says nothing about their current state — OSINT does not assess the present; verify current exposure with a vulnscan.",
              evidence=ev + " | source: Wayback Machine CDX index",
              cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
              cvss=3.1,
              remed="Check whether these paths are still exposed today; if archived snapshots contain secrets or sensitive files, rotate them and request Wayback exclusions.",
              confidence="candidate", location=domain,
              origin="passive"))
    L(f"[osint] A1 archive: {total} archived URL(s), "
      f"{len(hostnames)} host(s), {len(plist)} exposure-shaped path(s)")


# ----------------------------------------------------------------- P2a

def _passivedns(ctx, dom_id, domain):
    """P2a: PassiveDNS via HackerTarget hostsearch — a SINGLE named
    source (K1). Pairs stay `candidate`; a pair is corroborated (and
    its graph edge rises to `probable`) only when the pair's IP still
    matches a current DoH A record for the host. The source is named
    in every evidence string — never presented as multi-source fact."""
    fetch, add, L = ctx.fetch, ctx.add, ctx.L
    g = ctx.graph
    meta = {"status": "not evaluated", "source": "hackertarget",
            "pairs": 0, "corroborated": 0}
    ctx.meta["passivedns"] = meta
    st, _h, raw = fetch(
        "https://api.hackertarget.com/hostsearch/?q="
        + quote(domain, safe=""), timeout=15, verify=True)
    text = raw.decode("utf-8", "replace") if raw else ""
    first = text.strip().splitlines()[0].lower() if text.strip() else ""
    if st != 200 or not text.strip() or first.startswith("error"):
        ctx.warn(f"A1 passivedns: HackerTarget hostsearch unavailable "
                 f"(HTTP {st}) — passive DNS not evaluated")
        meta["note"] = "HackerTarget lookup failed — not evaluated"
        L("[osint] A1 passivedns: not evaluated (HackerTarget unavailable)")
        return
    pairs, seen = [], set()
    for line in text.splitlines():
        host, sep, ip = line.partition(",")
        host, ip = host.strip().lower(), ip.strip().strip()
        if not sep or not host or not ip or (host, ip) in seen:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        seen.add((host, ip))
        pairs.append((host, ip))
        if len(pairs) >= _PASSIVEDNS_CAP:
            break
    meta["status"] = "evaluated"
    meta["pairs"] = len(pairs)
    if not pairs:
        L("[osint] A1 passivedns: 0 pairs (HackerTarget)")
        return
    by_host = {}
    for host, ip in pairs:
        by_host.setdefault(host, []).append(ip)
    corroborate = len(by_host) <= 40
    if not corroborate:
        meta["note"] = ("corroboration skipped: more than 40 distinct "
                        "hosts in the passive result")
    corroborated_pairs = 0
    for host in sorted(by_host):
        ips = by_host[host]
        current = set(_doh_ips(host)) if corroborate else set()
        corr = [ip for ip in ips if ip in current]
        corroborated_pairs += len(corr)
        tier = "probable" if corr else "candidate"
        ev = (f"HackerTarget hostsearch (single source): "
              f"{host} -> {', '.join(ips[:3])}"
              + (" | corroborated by current DoH A record" if corr
                 else ""))
        nid = _find_node_by_label(g, host)
        if not nid:
            nid = g.node("subdomain", host, tier, "A1")
        if nid:
            g.edge(dom_id, nid, "PASSIVE_DNS", tier, ev)
    meta["corroborated"] = corroborated_pairs
    ev_pairs = "; ".join(f"{h} -> {i}" for h, i in pairs[:10])
    add(F("INFO", "Passive DNS records (single source: HackerTarget)",
          "Passive DNS pairs reported by ONE third-party source (HackerTarget hostsearch). Treat uncorroborated pairs as leads, not facts: only pairs whose IP still matches a current DoH A record were corroborated during this run.",
          evidence=(ev_pairs
                    + f" | {corroborated_pairs}/{len(pairs)} pair(s) "
                      "corroborated by current DoH A records"
                    + " | source: HackerTarget hostsearch (single source)"),
          cwe="", owasp="", cvss=0.0,
          remed="No action required; informational. Verify important pairs against your DNS change history.",
          confidence="candidate", location=domain, origin="passive"))
    L(f"[osint] A1 passivedns: {len(pairs)} pair(s), "
      f"{corroborated_pairs} corroborated")


# ----------------------------------------------------------------- P2b

_TYPOSQUAT_CAP = 300
_TYPO_TLDS = ("com", "net", "org", "io", "co")
_TWO_LEVEL_SUFFIX = {"co", "com", "net", "org", "ac", "go", "or",
                     "ne", "re"}
_KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")


def _build_keyboard_neighbors():
    pos = {}
    for r, row in enumerate(_KEYBOARD_ROWS):
        for c, k in enumerate(row):
            pos[k] = (r, c)
    out = {}
    for k, (r0, c0) in pos.items():
        out[k] = sorted(k2 for k2, (r, c) in pos.items()
                        if k2 != k and abs(r - r0) <= 1
                        and abs(c - c0) <= 1)
    return out


_KEYBOARD_NEIGHBORS = _build_keyboard_neighbors()


def _typosquat_candidates(domain):
    """Deterministic typo variants of the registrable domain:
    omission, duplication, adjacent transposition, keyboard-neighbour
    substitution, hyphen insertion/removal, and TLD swaps from a small
    list. Homoglyph/IDN variants are intentionally NOT generated
    (decision K2). Generation order is fixed, so the capped working
    set is deterministic too."""
    domain = (domain or "").lower().rstrip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    if (len(parts) >= 3 and len(parts[-1]) == 2
            and parts[-2] in _TWO_LEVEL_SUFFIX):
        name_labels, suffix = parts[:-2], parts[-2:]
    else:
        name_labels, suffix = parts[:-1], parts[-1:]
    sld = name_labels[-1]
    prefix = name_labels[:-1]
    out, seen = [], set()

    def emit(new_sld, new_suffix=None):
        if not new_sld:
            return
        cand = ".".join(prefix + [new_sld] + (new_suffix or suffix))
        if cand != domain and cand not in seen:
            seen.add(cand)
            out.append(cand)

    for i in range(len(sld)):                       # omission
        emit(sld[:i] + sld[i + 1:])
    for i in range(len(sld)):                       # duplication
        emit(sld[:i] + sld[i] + sld[i:])
    for i in range(len(sld) - 1):                   # transposition
        if sld[i] != sld[i + 1]:
            emit(sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:])
    for i, ch in enumerate(sld):                    # substitution
        for nb in _KEYBOARD_NEIGHBORS.get(ch, []):
            emit(sld[:i] + nb + sld[i + 1:])
    for i in range(1, len(sld)):                    # hyphen insertion
        emit(sld[:i] + "-" + sld[i:])
    if "-" in sld:                                  # hyphen removal
        emit(sld.replace("-", ""))
    for tld in _TYPO_TLDS:                          # TLD swaps
        if suffix != [tld]:
            emit(sld, [tld])
    return out


def _typosquat_probe(cand):
    """Existence of ONE candidate, via DoH only (A -> NS -> MX, first
    answer wins); the candidate domain itself is never contacted.
    Returns (record_type|None, all_queries_failed)."""
    failed = 0
    for rt in ("A", "NS", "MX"):
        vals = _doh_query(cand, rt)
        if vals is None:
            failed += 1
            continue
        if [v for v in vals if str(v).strip()]:
            return rt, False
    return None, failed == 3


def _typosquatting(ctx, dom_id, domain):
    add, L = ctx.add, ctx.L
    g = ctx.graph
    cands = _typosquat_candidates(domain)
    meta = {"status": "evaluated", "generated": len(cands), "checked": 0,
            "registered": 0, "mail_capable": 0, "check_errors": 0,
            "candidate_cap": _TYPOSQUAT_CAP}
    ctx.meta["typosquat"] = meta
    todo = cands[:_TYPOSQUAT_CAP]
    if not todo:
        meta["status"] = "not evaluated"
        meta["note"] = "no typo candidates could be generated"
        return
    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(_typosquat_probe, todo))
    meta["checked"] = len(todo)
    registered = []
    for cand, (rtype, all_failed) in zip(todo, results):
        if rtype:
            registered.append((cand, rtype))
        elif all_failed:
            meta["check_errors"] += 1
    if meta["check_errors"] == meta["checked"]:
        meta["status"] = "not evaluated"
        meta["note"] = ("DoH lookups failed for every candidate — "
                        "typosquat existence not evaluated")
        ctx.warn("A1 typosquat: DoH unavailable — typosquat check "
                 "not evaluated")
        L("[osint] A1 typosquat: not evaluated (DoH unavailable)")
        return
    mail_flags = {}
    for cand, rtype in registered:
        mail = rtype == "MX"
        if not mail:
            mx = _doh_query(cand, "MX")
            mail = bool(mx and [v for v in mx if str(v).strip()])
        mail_flags[cand] = mail
        nid = g.node("domain", cand, "candidate", "A1")
        if nid:
            g.edge(dom_id, nid, "TYPOSQUAT_OF", "candidate",
                   f"typo variant of {domain}; registered "
                   f"(DoH {rtype} record present)"
                   + ("; MX present — mail-capable "
                      "(phishing-risk signal)" if mail else ""))
    meta["registered"] = len(registered)
    meta["mail_capable"] = sum(1 for v in mail_flags.values() if v)
    meta["graph_truncated"] = bool(g.truncated)
    if registered:
        ev = "; ".join(
            f"{c} (via {rt}" + (", mail-capable" if mail_flags[c]
                                else "") + ")"
            for c, rt in registered[:15])
        add(F("LOW", "Registered typosquat-candidate domains",
              "Typo permutations of this domain that are REGISTERED (they answer DNS-over-HTTPS queries). They may be defensive registrations or parked pages, but lookalike domains are a classic phishing / credential-harvesting vehicle — the mail-capable flag means the domain answers MX queries and can receive mail, which raises the phishing risk. The flag is a risk signal, not an accusation against the registrant.",
              evidence=(ev + f" | {len(registered)} registered of "
                        f"{meta['checked']} candidates checked "
                        "| source: DoH (A/NS/MX)"),
              cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
              cvss=3.1,
              remed="Review each lookalike: if it is not yours, monitor it, report phishing use to the registrar/host, and consider defensive registration of the remaining variants.",
              confidence="candidate", location=domain,
              origin="passive"))
    L(f"[osint] A1 typosquat: {meta['generated']} generated, "
      f"{meta['checked']} checked, {len(registered)} registered")


# ----------------------------------------------------------------- P2c

_DNSBL_DOMAIN_ZONES = ("multi.surbl.org", "dbl.spamhaus.org",
                       "multi.uribl.com")
_DNSBL_IP_ZONES = ("zen.spamhaus.org", "bl.spamcop.net",
                   "b.barracudacentral.org")
# Zone convention: 127.255.255.x answers mean the ZONE refused the
# query (e.g. Spamhaus blocking public resolvers) — an error, never
# a listing.
_DNSBL_ERROR_IP_RE = re.compile(r"^127\.255\.255\.\d{1,3}$")


def _dnsbl_lookup(qname):
    """One DNSBL zone query via DoH. Returns (state, reason_txt) with
    state 'listed' | 'not_listed' | 'error'."""
    a = _doh_query(qname, "A")
    if a is None:
        return "error", ""
    hits = [str(x).strip().strip('"') for x in a if str(x).strip()]
    if not hits:
        return "not_listed", ""
    real = [h for h in hits if not _DNSBL_ERROR_IP_RE.match(h)]
    if not real:
        return "error", ""
    txt = ""
    t = _doh_query(qname, "TXT")
    if t:
        txt = " ".join(str(x).strip().strip('"') for x in t)[:200]
    return "listed", txt


def _dnsbl_reputation(ctx, subject, kind):
    """P2c: DNSBL reputation for a domain or an IP (zones queried via
    DoH only). A listing is a `probable` finding carrying the zone's
    own TXT reason. Not-listed is meta only — never a 'clean'
    finding."""
    add, L = ctx.add, ctx.L
    zones = (_DNSBL_DOMAIN_ZONES if kind == "domain"
             else _DNSBL_IP_ZONES)
    rep = {"subject": subject, "kind": kind, "zones_checked": 0,
           "listed": [], "status": "not evaluated", "note": ""}
    if kind == "ip":
        try:
            is6 = ipaddress.ip_address(subject).version == 6
        except ValueError:
            is6 = False
        if is6:
            rep["note"] = ("the DNSBL zones checked here are IPv4/domain "
                           "zones — IPv6 reputation not evaluated")
            return rep
        qname = ".".join(reversed(subject.split(".")))
    else:
        qname = subject
    errors = 0
    for z in zones:
        state, txt = _dnsbl_lookup(f"{qname}.{z}")
        if state == "error":
            errors += 1
            continue
        rep["zones_checked"] += 1
        if state == "listed":
            rep["listed"].append({"zone": z, "reason": txt})
            add(F("LOW", f"{subject} is listed in the {z} DNS blocklist",
                  f"A DNS blocklist query (via DNS-over-HTTPS) returned a listing record for this {kind} in {z}. A listing is third-party reputation data maintained by the zone operator — verify it on the operator's lookup page before acting; listings can be stale or disputed.",
                  evidence=(f"DoH A query {qname}.{z} returned a "
                            "listing record"
                            + (f" | zone reason: {txt}" if txt else "")
                            + " | source: DoH DNSBL"),
                  cwe="", owasp="", cvss=0.0,
                  remed="Confirm the listing with the zone operator; if the cause is fixed or the listing is erroneous, follow the operator's delisting process.",
                  confidence="probable", location=subject,
                  origin="passive"))
    if errors:
        rep["zones_error"] = errors
    if rep["zones_checked"]:
        rep["status"] = "evaluated"
        if not rep["listed"]:
            rep["note"] = "not listed in the zones checked"
    else:
        rep["note"] = ("blocklist zones could not be evaluated "
                        "(queries blocked or unreachable)")
    L(f"[osint] A1 reputation: {subject} ({kind}) — "
      f"{len(rep['listed'])} listing(s), "
      f"{rep['zones_checked']} zone(s) checked")
    return rep


# ------------------------------------------------------------------ P3

# Curated snapshot of well-known disposable / throwaway email
# providers (K3) — compiled 2026-10-21. NON-EXHAUSTIVE by design:
# absence from this list says nothing about a provider. Kept in-repo
# (no third-party dataset import) so the list is auditable.
_DISPOSABLE_EMAIL_DOMAINS = frozenset("""
10minemail.com 10minutemail.co.uk 10minutemail.com 10minutemail.de
10minutemail.info 10minutemail.net 10minutemail.org 10minutemail.us
10minutesmail.com 10mail.org 123-m.com 0-mail.com 0clickemail.com
0window.com 20email.eu 20email.it 20mail.in 20mail.it 20minute.email
20minutemail.com 2prong.com 30minutemail.com 4warding.com
4warding.net 4warding.org 60minutemail.com 675hosting.com
675hosting.net 675hosting.org add3000.pp.ua alltempmail.com
anonbox.net anonymail.dk anonymbox.com antispam.de antispam24.de
anyalias.com armyspy.com asdasd.ru binkmail.com bobmail.info
chammy.info cool.fr.nf courriel.fr.nf cuvox.de dayrep.com
deadaddress.com devnullmail.com discard.email discardmail.com
discardmail.de disposable.info disposableemailaddresses.com
disposableinbox.com disposablemail.com disposeamail.com
dispostable.com einrot.com email-fake.com emailfake.com
emailondeck.com fake-mail.net fakeinbox.com fakemail.net
fakemailgenerator.com fleckens.hu generator.email germans.in
getairmail.com getnada.com grr.la guerrillamail.biz
guerrillamail.com guerrillamail.de guerrillamail.net
guerrillamail.org guerrillamailblock.com gustr.com
harakirimail.com incognitomail.com incognitomail.org inboxalias.com
inboxkitten.com jetable.com jetable.fr.nf jetable.net jetable.org
jourrapide.com kasmail.com kurzepost.de letthemeatspam.com
mail-temp.com mail1a.de mail21.cc mail2rss.org mail2world.com
mail3plus.net mail4trash.com mail4u.info mail666.ru mail7.io
mailabconline.com mailas.com mailasdkr.com mailavalanche.com
mailcatch.com mailcatch.xyz maildrop.cc maildrop.xyz
mailfaker.com mailforspam.com mailfreeonline.com mailimate.com
mailin8r.com mailinater.com mailinator.com mailinator.net
mailinator.org mailinator2.com mailme.lv mailme24.com
mailnesia.com mailnull.com mailnull.net mailproxsy.com
mailrock.biz mailsucker.net mailtemp.cc mailtemp.info
mailtemporaire.com mailtemporaire.fr mailthrowaway.com
mailto.space mailtrash.net mailzilla.com mailzilla.org
mega.zik.dj meltmail.com mierdamail.com mintemail.com moakt.com
mohmal.com mohmal.im moncourrier.fr.nf monemail.fr.nf
monmail.fr.nf muellmail.com mytemp.email mytrashmail.com
nada.email nada.ltd no-spam.ws nomail.xl.cx nospam.ze.tc
objectmail.com one-time.email pokemail.net poubelle.org
reconmail.com recursor.net safetymail.info selfdestructingmail.com
selfdestructingmail.org sendspamhere.com sharklasers.com
smashmail.de sofort-mail.de sogetthis.com spam4.me spamavert.com
spambox.info spambox.us spamcorptastic.com spamex.com
spamfree24.de spamfree24.eu spamfree24.org spamgoes.in
spamgourmet.com spamgourmet.net spamgourmet.org spamherelots.com
spamhereplease.com spamhole.com spam.la spaml.com
spaml.de spammotel.com spamstack.net spamthisplease.com
spam.su streetwisemail.com suremail.info teleworm.us
temp-mail.com temp-mail.info temp-mail.io temp-mail.net
temp-mail.org tempail.com tempemail.biz tempemail.co
tempemail.com tempemail.net tempemail.org tempinbox.co.uk
tempinbox.com tempmail.com tempmail.de tempmail.fr tempmail.info
tempmail.io tempmail.lol tempmail.net tempmail.org tempmail.plus
tempmailaddress.com tempmailer.com tempmailer.de tempmailin.com
tempmailo.com thisisnotmyrealemail.com throwaway.email
throwawaymail.com throwawaymail.io tmpmail.net tmpmail.org
tradermail.info trash-mail.com trash2009.com trashdevil.com
trashemail.de trashinbox.com trashmail.app trashmail.at
trashmail.com trashmail.de trashmail.io trashmail.net
trashmail.org trashmail.ws trashmail.xyz trashmailer.com
trashymail.com veryrealemail.com viditag.com viewcastmedia.com
viewcastmedia.net viewcastmedia.org webm4il.info wegwerf-email.de
wegwerfadresse.de wegwerfemail.de wegwerfmail.de wegwerfmail.net
wegwerfmail.org wetrainbayarea.com wetrainbayarea.org whatiaas.com
whatsaduck.com whopy.com wilemail.com willselfdestruct.com
winemaven.info wronghead.com wuzupmail.net xagloo.com xemaps.com
xents.com xmaily.com xoxy.net yep.it yogamaven.com yopmail.com
yopmail.fr yopmail.info yopmail.net yopmail.org yuurok.com
zehnminutenmail.de zetmail.com zippymail.info zoemail.net zomg.info
""".split())

_EMAIL_FMT_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")


def _email_format_ok(email):
    """Strict-ish format gate: overall length, single @, local-part
    dot rules, label hyphen rules, and the conservative regex. This
    judges SYNTAX only — never deliverability."""
    if not email or len(email) > 254 or email.count("@") != 1:
        return False
    local, dom = email.split("@")
    if not local or len(local) > 64:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    if not _EMAIL_FMT_RE.match(email):
        return False
    for lab in dom.split("."):
        if not lab or lab.startswith("-") or lab.endswith("-"):
            return False
    return True


def _email_checks(ctx, email, dom):
    """P3: light email verification — SIGNALS ONLY, no SMTP probing
    of any kind (explicit non-goal). The assessment is a tiered
    signal label, never a valid/invalid verdict: strict format, DoH
    domain resolution, DoH MX hosts (preference order; a null-MX
    '.' answer means the domain declares no mail service and counts
    as no MX), and the curated disposable-provider list."""
    add, L = ctx.add, ctx.L
    out = {"status": "evaluated", "format_ok": False,
           "domain_resolves": False, "mx_hosts": [],
           "disposable": False, "assessment": ""}
    fmt_ok = _email_format_ok(email)
    out["format_ok"] = fmt_ok
    registrable = passive_mod._registrable(dom)
    out["disposable"] = (dom in _DISPOSABLE_EMAIL_DOMAINS
                         or registrable in _DISPOSABLE_EMAIL_DOMAINS)
    if not fmt_ok:
        out["assessment"] = "invalid format"
        L("[osint] email checks: invalid format")
        return out
    out["domain_resolves"] = bool(_doh_ips(dom))
    mx_raw = _doh_query(dom, "MX")
    hosts = []
    for rec in (mx_raw or []):
        parts = str(rec).strip().split()
        if not parts:
            continue
        host = parts[-1].rstrip(".")
        if not host or host == ".":
            continue  # null MX: the domain declares no mail service
        try:
            pref = int(parts[0]) if len(parts) > 1 else 0
        except ValueError:
            pref = 0
        hosts.append((pref, host))
    out["mx_hosts"] = [h for _p, h in sorted(hosts)]
    if out["disposable"]:
        out["assessment"] = "disposable provider"
        add(F("INFO",
              f"Email domain {dom} is a known disposable-mail provider",
              "The address's domain appears in VANTHEX's curated disposable-provider list (compiled 2026-10-21, non-exhaustive). Disposable addresses are throwaway by design — a credibility signal for the contact, not proof of bad faith.",
              evidence=(f"{dom} matches the curated disposable-provider "
                        "list (non-exhaustive) | source: in-repo list "
                        "+ DoH"),
              cwe="", owasp="", cvss=0.0,
              remed="Treat the address as ephemeral; ask for a durable contact address for anything important.",
              confidence="candidate", location=dom, origin="passive"))
    elif mx_raw is None:
        out["status"] = "not evaluated"
        out["assessment"] = "not evaluated (MX lookup via DoH unavailable)"
        ctx.warn("email checks: MX lookup via DoH unavailable — "
                 "email signals not evaluated")
    elif not out["domain_resolves"] and not out["mx_hosts"]:
        out["assessment"] = "domain does not resolve"
        add(F("INFO",
              f"Email domain {dom} does not resolve — address likely undeliverable",
              "Signal-based assessment (no SMTP probing was performed): the address is well-formed, but its domain returns no A records and no MX records via DNS-over-HTTPS, so mail to it very likely cannot be delivered.",
              evidence=(f"DoH A {dom}: no records | DoH MX {dom}: "
                        "no records | source: DoH"),
              cwe="", owasp="", cvss=0.0,
              remed="Verify the address through another channel; it is probably mistyped or retired.",
              confidence="candidate", location=dom, origin="passive"))
    elif not out["mx_hosts"]:
        out["assessment"] = "no MX — mail likely undeliverable"
        add(F("INFO",
              f"Email domain {dom} has no MX records — mail likely undeliverable",
              "Signal-based assessment (no SMTP probing was performed): the domain resolves, but publishes no MX records (or only a null MX), so it very likely cannot receive mail at this address.",
              evidence=(f"DoH MX {dom}: no usable MX hosts | "
                        f"domain resolves: {out['domain_resolves']} "
                        "| source: DoH"),
              cwe="", owasp="", cvss=0.0,
              remed="Verify the address through another channel before relying on it.",
              confidence="candidate", location=dom, origin="passive"))
    else:
        out["assessment"] = "plausible (MX present)"
    L(f"[osint] email checks: {out['assessment']}")
    return out


# --------------------------------- v1.6.0: People OSINT Deep (A6)
# WS-F extractors, WS-B entity extraction, WS-A web mentions,
# WS-D email permutator, WS-E avatar matching. Everything here is
# passive and public-only; every new source degrades to an explicit
# "not evaluated" instead of a silent zero, and nothing in this
# section loosens a confidence tier: A6 output starts `candidate`
# and rises only through the corroboration machinery.

def _og_map(body):
    out = {}
    for m in re.finditer(
            r'<meta[^>]+(?:property|name)=["\']((?:og|twitter):[a-z_:]+)'
            r'["\'][^>]+content=["\']([^"\']*)["\']', body or "", re.I):
        out.setdefault(m.group(1).lower(), m.group(2).strip())
    return out


def _unescape_js(s):
    try:
        return json.loads('"' + (s or "").replace('"', '\\"') + '"')
    except Exception:
        return s or ""


def _extract_keybase(body, handle):
    og = _og_map(body)
    name = ""
    m = re.search(r'"full_name"\s*:\s*"([^"]{1,120})"', body or "")
    if m:
        name = _unescape_js(m.group(1))
    if not name:
        t = og.get("og:title", "")
        t = re.sub(r"\s*\|\s*Keybase\s*$", "", t).strip()
        mm = re.match(r"^[^()]+\((.*?)\)\s*$", t)
        name = mm.group(1) if mm else t
    if name.lower() == handle.lower():
        name = ""
    ids = [i for i in _social_ids_from_text(body or "",
                                            field="keybase proof")
           if not (i["platform"] == "Keybase"
                   and i["value"].lower() == handle.lower())]
    return _profile_dict(
        fullname=name[:120], bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""), identifiers=ids)


def _extract_youtube(body, handle):
    og = _og_map(body)
    name = re.sub(r"\s*-\s*YouTube\s*$", "",
                  og.get("og:title", "")).strip()
    fol = ""
    m = re.search(r"([0-9][0-9.,]*\s*[KMB]?)\s+subscribers",
                  body or "", re.I)
    if m:
        fol = m.group(1).strip()
    ids = [i for i in _social_ids_from_text(body or "",
                                            field="channel link")
           if i["platform"] != "YouTube"]
    return _profile_dict(
        fullname=name[:120] if name.lower() != handle.lower() else "",
        bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""), followers=fol or None,
        identifiers=ids)


def _extract_tiktok(body, handle):
    body = body or ""
    og = _og_map(body)

    def _js_str(key):
        m = re.search(r'"' + key + r'":"((?:[^"\\]|\\.)*)"', body)
        return _unescape_js(m.group(1)) if m else ""

    name = _js_str("nickname")
    fol = None
    m = re.search(r'"followerCount":(\d+)', body)
    if m:
        fol = int(m.group(1))
    return _profile_dict(
        fullname=name[:120] if name and name.lower() != handle.lower()
        else "",
        bio=(_js_str("signature") or og.get("og:description", ""))[:300],
        avatar_url=_js_str("avatarLarger") or og.get("og:image", ""),
        website=_js_str("bioLink") or None, followers=fol)


def _extract_twitter(body, handle):
    og = _og_map(body)
    title = og.get("og:title", "")
    m = re.match(r"^(.*?)\s*\(@", title)
    name = m.group(1).strip() if m else title
    if name.lower() == handle.lower():
        name = ""
    ids = [i for i in _social_ids_from_text(body or "",
                                            field="profile link")
           if i["platform"] != "X (Twitter)"]
    return _profile_dict(
        fullname=name[:120], bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""), identifiers=ids)


def _extract_medium(body, handle):
    og = _og_map(body)
    name = re.sub(r"\s*[–\-|]\s*Medium\s*$", "",
                  og.get("og:title", "")).strip()
    if name.lower() == handle.lower():
        name = ""
    return _profile_dict(
        fullname=name[:120], bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""))


def _extract_substack(body, handle):
    og = _og_map(body)
    name = og.get("og:title", "").strip()
    if name.lower() == handle.lower():
        name = ""
    ids = _social_ids_from_text(body or "", field="publication link")
    return _profile_dict(
        fullname=name[:120], bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""), identifiers=ids)


def _extract_instagram(body, handle):
    og = _og_map(body)
    name = og.get("og:title", "").split("•")[0].strip()
    name = re.sub(r"\s*\(@[^)]*\)\s*$", "", name).strip()
    if name.lower() == handle.lower():
        name = ""
    desc = og.get("og:description", "")
    fol, bio = "", desc
    m = re.match(r"\s*([0-9][0-9.,]*\s*[KMB]?) Followers,"
                 r"\s*[0-9][0-9.,]*\s*[KMB]? Following,"
                 r"\s*[0-9][0-9.,]*\s*[KMB]? Posts\s*-\s*(.*)",
                 desc, re.S)
    if m:
        fol, bio = m.group(1).strip(), m.group(2)
    return _profile_dict(
        fullname=name[:120], bio=bio[:300],
        avatar_url=og.get("og:image", ""), followers=fol or None)


def _extract_linktree(body, handle):
    og = _og_map(body)
    links = []
    m = re.search(r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
                  body or "", re.S)
    if m:
        try:
            blob = json.dumps(json.loads(m.group(1)))
        except Exception:
            blob = ""
        for um in re.finditer(r'https?://[^\s"\'\\]+', blob):
            u = um.group(0)
            host = urlparse(u).hostname or ""
            if ("linktr.ee" in host or "linktree" in host
                    or any(u.lower().endswith(e) for e in
                           (".js", ".css", ".png", ".svg", ".ico"))):
                continue
            if u not in links:
                links.append(u)
    ids = _social_ids_from_text(" ".join(links), field="linktree link")
    name = re.sub(r"\s*\|\s*Linktree\s*$", "",
                  og.get("og:title", "")).strip()
    if name.lower() == handle.lower():
        name = ""
    return _profile_dict(
        fullname=name[:120], bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""), links=links[:10],
        identifiers=ids)


def _extract_aboutme(body, handle):
    og = _og_map(body)
    name = og.get("og:title", "").strip()
    if name.lower() == handle.lower():
        name = ""
    ids = _social_ids_from_text(body or "", field="about.me link")
    return _profile_dict(
        fullname=name[:120], bio=og.get("og:description", "")[:300],
        avatar_url=og.get("og:image", ""), identifiers=ids)


def _extract_codeberg(body, handle):
    d = json.loads(body)
    if not isinstance(d, dict) or "login" not in d:
        return {}
    return _profile_dict(
        fullname=str(d.get("full_name") or "")[:120],
        bio=str(d.get("description") or "")[:300],
        avatar_url=str(d.get("avatar_url") or ""),
        website=str(d.get("website") or ""),
        created_at=str(d.get("created") or ""),
        links=[str(d.get("html_url") or "")])


_EXTRACTORS.update({
    "keybase": _extract_keybase, "youtube": _extract_youtube,
    "tiktok": _extract_tiktok, "twitter": _extract_twitter,
    "medium": _extract_medium, "substack": _extract_substack,
    "instagram": _extract_instagram, "linktree": _extract_linktree,
    "aboutme": _extract_aboutme, "codeberg": _extract_codeberg,
})
if "Codeberg" in _PLATFORM_BY_NAME:
    _PLATFORM_BY_NAME["Codeberg"]["extract"] = "codeberg"


# ------------------------------------------------------------- A6 core

_A6_NODE_CAP = 120
_PAGE_FETCH_CAP = 15


def _a6_node(ctx, ntype, label, confidence="candidate"):
    """Graph node under the A6 sub-budget (the shared 400-node cap
    still applies on top)."""
    if ctx.a6_nodes >= _A6_NODE_CAP:
        ctx.meta["a6_node_budget_exhausted"] = True
        return None
    before = len(ctx.graph._nodes)
    nid = ctx.graph.node(ntype, label, confidence, "A6")
    if nid is not None and len(ctx.graph._nodes) > before:
        ctx.a6_nodes += 1
    return nid


def _looks_binary(raw):
    if not raw:
        return False
    if raw[:8].startswith((b"%PDF", b"\x89PNG", b"PK\x03\x04",
                           b"\xff\xd8\xff", b"GIF8")):
        return True
    return b"\x00" in raw[:1024]


def _visible_text(html_text):
    t = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html_text or "",
               flags=re.S | re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return html_mod.unescape(t)


def _ctx_line(text, needle, width=55):
    i = (text or "").lower().find(needle.lower())
    if i < 0:
        return ""
    s = max(0, i - width)
    e = min(len(text), i + len(needle) + width)
    return re.sub(r"\s+", " ", text[s:e]).strip()[:140]


# ------------------------------------------------------------- WS-B

_ENTITY_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
_ENTITY_PHONE_RE = re.compile(r"\+\d(?:[\s().\-]*\d){8,15}")
_ENTITY_HREF_RE = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.I)
_FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js",
              "ico", "woff", "woff2", "mp4", "zip", "xml"}
_PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net",
                        "domain.com", "email.com"}


def _extract_entities(ctx, text, source_url, source_node_id,
                      subject_handles=()):
    """WS-B: SpiderFoot-style entity extraction from ONE fetched
    public page. Entities become candidate A6 graph nodes with a
    FOUND_ON edge to the page node; the evidence always names the
    source page. Phone numbers are recorded exactly as published on
    the page — never enriched (K2). Returns what was found."""
    found = {"emails": set(), "phones": set(), "handles": {},
             "urls": [], "wallets": set(), "telegram": []}
    if not text:
        return found
    subj = {str(h).lower() for h in subject_handles}
    cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text,
                     flags=re.S | re.I)
    visible = html_mod.unescape(re.sub(r"<[^>]+>", " ", cleaned))

    def _register(ntype, label, evidence):
        nid = _a6_node(ctx, ntype, label)
        if nid is None:
            return None
        if source_node_id:
            ctx.graph.edge(nid, source_node_id, "FOUND_ON", "candidate",
                           evidence[:150])
        ctx.stats["entities_extracted"] += 1
        return nid

    # emails (raw text incl. mailto: hrefs; format-gated)
    for m in _ENTITY_EMAIL_RE.finditer(cleaned):
        addr = m.group(0).lower().strip("._-")
        if addr in found["emails"] or not _email_format_ok(addr):
            continue
        dom = addr.split("@")[-1]
        if (dom.rsplit(".", 1)[-1] in _FILE_TLDS
                or dom in _PLACEHOLDER_DOMAINS):
            continue
        found["emails"].add(addr)
        ctx.extracted_emails.add(addr)
        _register("email", addr,
                  f"published on {source_url} — "
                  f"…{_ctx_line(visible, addr) or addr}…")
    # phone numbers as published (visible text, international format)
    for m in _ENTITY_PHONE_RE.finditer(visible):
        num = re.sub(r"\s+", " ", m.group(0)).strip()
        digits = re.sub(r"\D", "", num)
        if not (9 <= len(digits) <= 15) or digits.startswith("0"):
            continue
        if digits in {re.sub(r"\D", "", p) for p in found["phones"]}:
            continue
        found["phones"].add(num)
        _register("phone", num,
                  f"phone number published on {source_url} "
                  f"(as printed; no carrier/lookup enrichment)")
    # social handles declared by the page's own links
    for ident in _social_ids_from_text(cleaned, field="page link"):
        val = ident["value"]
        if ident["platform"] in found["handles"]:
            continue
        found["handles"][ident["platform"]] = val
        uid = _register("username", val,
                        f"{ident['platform']} profile linked from "
                        f"{source_url}")
        # F6 (v1.11.0): a linked Telegram channel gets public
        # preview metadata (title/subscribers) — message content is
        # never read. Bounded to 2 preview fetches per scan.
        if (ident["platform"] == "Telegram"
                and getattr(ctx, "_tg_meta_calls", 0) < 2):
            ctx._tg_meta_calls = getattr(ctx, "_tg_meta_calls", 0) + 1
            tg = _telegram_channel_meta(ctx, val)
            if tg:
                cnid = _register(
                    "telegram_channel", val,
                    f"Telegram channel linked from {source_url} "
                    f"(public preview: {tg['title']})")
                if cnid:
                    ctx.graph.node_attr(
                        cnid, title=tg["title"],
                        subscribers=tg["subscribers"])
                    if uid:
                        ctx.graph.edge(cnid, uid, "LINKED_TO",
                                       "candidate",
                                       "channel preview for the "
                                       "linked Telegram handle")
                ctx.meta.setdefault("telegram", {"channels": []})[
                    "channels"].append(tg)
                found["telegram"].append(tg)
    # F2(e) (v1.11.0): wallet addresses published on the page —
    # structurally validated by wallet_info (BTC/ETH checksums, SOL
    # 32-byte base58); exact sanctions hits are flagged on the node.
    for m in _ENTITY_WALLET_RE.finditer(cleaned):
        tok = m.group(0)
        if tok in found["wallets"]:
            continue
        winfo = wallet_info(tok)
        if not winfo:
            continue
        found["wallets"].add(tok)
        wid = _register("wallet", tok,
                        f"{winfo['chain']} wallet address published "
                        f"on {source_url}")
        if wid:
            _sanctions_flag_address(ctx, tok, wid,
                                    f"published on {source_url}")
        if len(found["wallets"]) >= 4:
            break
    # @handles in visible text, only when they match the subject's
    # own candidate handles (conservative context rule)
    if subj:
        for m in re.finditer(r"(?<![\w.])@([A-Za-z0-9_.]{2,30})",
                             visible):
            val = m.group(1)
            if val.lower() not in subj:
                continue
            if val.lower() in {v.lower()
                               for v in found["handles"].values()}:
                continue
            found["handles"].setdefault("@mention", val)
            _register("username", val,
                      f"mentioned as @{val} on {source_url}")
    # outbound URLs (cross-domain, non-asset, capped)
    src_host = (urlparse(source_url).hostname or "").lower()
    seen_urls = set()
    for m in _ENTITY_HREF_RE.finditer(cleaned):
        u = m.group(1)
        host = (urlparse(u).hostname or "").lower()
        if not host or host == src_host or u in seen_urls:
            continue
        if any(urlparse(u).path.lower().endswith("." + e)
               for e in _FILE_TLDS):
            continue
        if _social_ids_from_text(u):
            continue  # already registered as a handle above
        seen_urls.add(u)
        if len(found["urls"]) >= 5:
            break
        found["urls"].append(u)
        nid = _a6_node(ctx, "website", u[:160])
        if nid is not None and source_node_id:
            ctx.graph.edge(source_node_id, nid, "LINKS_TO", "candidate",
                           f"outbound link published on {source_url}")
            ctx.stats["entities_extracted"] += 1
    return found


# ------------------------------------------------------------- WS-A

def _norm_url(u):
    try:
        p = urlparse(u or "")
    except Exception:
        return ""
    if p.scheme not in ("http", "https") or not p.hostname:
        return ""
    host = p.hostname.lower()
    path = re.sub(r"/+$", "", p.path or "")
    q = [(k, v) for k, v in parse_qsl(p.query)
         if not k.lower().startswith("utm_")]
    out = f"{p.scheme}://{host}{path}"
    if q:
        out += "?" + urlencode(q)
    return out[:300]


def _ddg_target(href):
    href = html_mod.unescape((href or "").strip())
    if href.startswith("//"):
        href = "https:" + href
    if "duckduckgo.com/l/" in href:
        qs = parse_qs(urlparse(href).query)
        if qs.get("uddg"):
            return unquote(qs["uddg"][0])
    return href


def _clean_html_text(s):
    return html_mod.unescape(re.sub(r"<[^>]+>", " ", s or "")).strip()


def _parse_ddg_html(text):
    out = []
    for m in re.finditer(
            r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"'
            r'[^>]*>(.*?)</a>', text or "", re.S):
        url = _ddg_target(m.group(1))
        snip = ""
        sm = re.search(r'result__snippet[^>]*>(.*?)</a>',
                       text[m.end():m.end() + 2500], re.S)
        if sm:
            snip = _clean_html_text(sm.group(1))
        out.append((url, _clean_html_text(m.group(2)), snip))
    return out


def _parse_ddg_lite(text):
    out = []
    for m in re.finditer(
            r"<a[^>]+class=['\"]result-link['\"][^>]+href=['\"]([^'\"]+)"
            r"['\"][^>]*>(.*?)</a>", text or "", re.S):
        url = _ddg_target(m.group(1))
        snip = ""
        sm = re.search(r"class=['\"]result-snippet['\"][^>]*>(.*?)</td>",
                       text[m.end():m.end() + 2000], re.S)
        if sm:
            snip = _clean_html_text(sm.group(1))
        out.append((url, _clean_html_text(m.group(2)), snip))
    return out


def _bing_target(href):
    """Bing wraps result links in a /ck/a redirector whose `u`
    parameter carries the real URL (base64, 'a1' prefixed). Unwrap
    it like the DuckDuckGo redirector; anything else passes
    through unchanged."""
    href = html_mod.unescape((href or "").strip())
    if "bing.com/ck/a" not in href:
        return href
    try:
        import base64
        qs = parse_qs(urlparse(href).query)
        u = (qs.get("u") or [""])[0]
        if u.startswith("a1"):
            u = u[2:]
        pad = "=" * (-len(u) % 4)
        real = base64.urlsafe_b64decode(u + pad).decode(
            "utf-8", "replace")
        if real.startswith(("http://", "https://")):
            return real
    except Exception:
        pass
    return href


def _parse_bing(text):
    out = []
    for m in re.finditer(
            r'<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
            text or "", re.S):
        snip = ""
        sm = re.search(r"<p[^>]*>(.*?)</p>",
                       text[m.end():m.end() + 1500], re.S)
        if sm:
            snip = _clean_html_text(sm.group(1))
        out.append((_bing_target(m.group(1)),
                    _clean_html_text(m.group(2)), snip))
    return out


_DOC_EXTS = (".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx",
             ".odt", ".rtf")
_PROFILE_PATH_RE = re.compile(
    r"/(@|user|users|profile|profiles|people|member|members|channel"
    r"|u|in)/", re.I)
_PLATFORM_HOSTS_CACHE = None


def _platform_host_set():
    global _PLATFORM_HOSTS_CACHE
    if _PLATFORM_HOSTS_CACHE is None:
        hosts = set()
        for d in PLATFORM_SCHEMA:
            h = (urlparse(d["url_pattern"]).hostname or "").lower()
            h = h.replace("{h}.", "").replace("{h}", "")
            if h:
                hosts.add(h)
                # profile pages live on the web host even when the
                # probe pattern uses an API host (api.github.com)
                hosts.add(passive_mod._registrable(h))
        hosts |= {"x.com", "twitter.com", "linktr.ee", "about.me",
                  "keybase.io"}
        _PLATFORM_HOSTS_CACHE = hosts
    return _PLATFORM_HOSTS_CACHE


def _classify_mention(url):
    p = urlparse(url)
    path = (p.path or "").lower()
    if any(path.endswith(e) for e in _DOC_EXTS):
        return "document"
    host = (p.hostname or "").lower()
    if (host in _platform_host_set() or "/@" in p.path
            or _PROFILE_PATH_RE.search(p.path or "")):
        return "profile"
    return "mention"


def _run_search_engine(ctx, endpoints, formulations, results):
    """One engine, keyless HTML endpoints with fallback. Returns
    'ok' when any endpoint answered HTTP 200 for any formulation,
    else 'not evaluated' — an unreachable engine is never a zero."""
    for base, parser, extra in endpoints:
        any_ok = False
        for q in formulations:
            if ctx.stop_requested():
                return "ok" if any_ok else "not evaluated"
            st, _h, raw = ctx.fetch(base + quote_plus(q) + extra,
                                    timeout=12, cap=1024 * 1024)
            if st != 200 or not raw:
                continue
            any_ok = True
            text = raw.decode("utf-8", "replace")
            for url, title, snip in parser(text):
                nu = _norm_url(url)
                if not nu or nu in results:
                    continue
                results[nu] = {"url": nu, "title": title[:160],
                               "snippet": snip[:240],
                               "class": _classify_mention(nu)}
                if len(results) >= 200:
                    break
        if any_ok:
            return "ok"
    return "not evaluated"


def _a6_formulations(subject, context_terms=(), kind="name"):
    """A6 query formulations. Base set: the exact phrase, the plain
    subject, and the subject plus context terms the engine has
    ALREADY discovered (never guesses). WS6 (v1.8.0) adds OPERATOR
    DORKING variants — site: / filetype: / inurl: / intitle: queries
    that narrow the same public search index. These are ordinary
    search-engine queries; no Shodan/Censys or other scan-index
    service is queried or claimed. Returns (formulations, dorks)."""
    forms, dorks = [], []

    def _addf(f, lst, cap):
        if f and f not in lst and len(forms) < cap:
            forms.append(f)
            lst.append(f)

    base = []
    _addf(f'"{subject}"', base, 6)
    _addf(subject, base, 6)
    for t in (context_terms or [])[:3]:
        t = str(t).strip()
        if t and t.lower() not in subject.lower():
            _addf(f"{subject} {t}", base, 6)
    if kind == "domain":
        cand = [f"site:{subject}", f'"{subject}" filetype:pdf',
                f"inurl:login {subject}"]
    elif kind == "email":
        cand = [f'"{subject}" filetype:pdf']
    else:
        cand = [f'intitle:"{subject}"', f'"{subject}" filetype:pdf',
                f'"{subject}" inurl:profile']
    for d in cand:
        _addf(d, dorks, 9)
    return forms, dorks


def _web_mentions(ctx, subject, subject_node_id, context_terms=(),
                  kind="name", subject_handles=()):
    """WS-A: web mentions search (module A6). Formulations are the
    exact phrase, the plain subject, and subject + context terms the
    engine has ALREADY discovered (never guesses). Results are
    candidates; engines that fail are reported per engine."""
    L = ctx.L
    subject = (subject or "").strip()
    if not subject:
        return None
    key = subject.lower()
    if key in ctx.mentions_done:
        return ctx.meta.get("mentions")
    ctx.mentions_done.add(key)
    formulations, dork_queries = _a6_formulations(subject,
                                                  context_terms, kind)
    results = {}
    engines = {}
    engines["duckduckgo"] = _run_search_engine(ctx, [
        ("https://html.duckduckgo.com/html/?q=", _parse_ddg_html, ""),
        ("https://lite.duckduckgo.com/lite/?q=", _parse_ddg_lite, ""),
    ], formulations, results)
    engines["bing"] = _run_search_engine(ctx, [
        ("https://www.bing.com/search?q=", _parse_bing, "&count=20"),
    ], formulations, results)
    items = list(results.values())
    profs = [i for i in items if i["class"] == "profile"]
    docs = [i for i in items if i["class"] == "document"]
    plain = [i for i in items if i["class"] == "mention"]
    evaluated = any(v == "ok" for v in engines.values())
    meta_m = {"subject": subject,
              "status": "evaluated" if evaluated else "not evaluated",
              "engines": engines, "queries": formulations,
              "dork_queries": dork_queries,
              "results": items[:60], "total": len(items),
              "profiles": len(profs), "documents": len(docs),
              "pages_fetched": 0, "pages_skipped_binary": 0}
    ctx.meta["mentions"] = meta_m
    if not evaluated:
        ctx.warn(f"A6: web search engines not evaluated from this "
                 f"host — web mentions unknown for '{subject}'")
        L(f"[osint] A6 web mentions for '{subject}': not evaluated "
          f"(engines unreachable)")
        return meta_m
    ctx.pivots.append(f"mentions:{subject}")
    page_nodes = {}
    for it in profs + docs + plain:
        nid = _a6_node(ctx, "website", it["url"][:160])
        if nid is None:
            continue
        page_nodes[it["url"]] = nid
        if subject_node_id:
            rel = ("MENTIONED_AS_PROFILE" if it["class"] == "profile"
                   else "MENTIONS")
            ctx.graph.edge(subject_node_id, nid, rel, "candidate",
                           (it["snippet"] or it["title"]
                            or "web search result")[:150])
    if items:
        top = "; ".join(i["url"] for i in items[:3])
        ctx.add(F(
            "INFO", f"Web mentions for '{subject}': {len(items)} "
                    f"public page(s) found",
            f"Keyless web search (DuckDuckGo/Bing) returned "
            f"{len(items)} public page(s) mentioning '{subject}': "
            f"{len(profs)} profile-shaped, {len(docs)} document(s), "
            f"{len(plain)} other mention(s). Search results are "
            f"candidates — a mention proves the page exists and "
            f"carries the text, not that it is about the subject.",
            evidence=f"{top} | engines: "
                     + ", ".join(f"{k}={v}" for k, v in engines.items()),
            cwe="", owasp="", cvss=0.0,
            remed="Review the profile-shaped results first; confirm "
                  "identity via the corroborated platform accounts.",
            confidence="candidate", location=subject,
            origin="passive"))
    # Page-fetch pipeline (WS-B extraction + WS-F profile extraction):
    # profiles first, then plain mentions; documents are binary in
    # practice and only text documents are fetched.
    fetch_order = (profs + [d for d in docs
                            if d["url"].lower().endswith(".txt")]
                   + plain)
    fetched = 0
    # v1.6.1: result pages are fetched in parallel waves (network
    # only, 8 at a time); ALL processing below still runs strictly
    # in fetch_order, so nodes/findings stay identical to the old
    # sequential pipeline. A stop request drains the current wave
    # within one fetch timeout and ends the pipeline.
    _WAVE = 8
    _idx = 0
    while _idx < len(fetch_order):
        if fetched >= _PAGE_FETCH_CAP or ctx.stop_requested():
            break
        wave = fetch_order[_idx:_idx + _WAVE]
        _idx += len(wave)

        def _get(it):
            if ctx.stop_requested():
                return it, 0, b""
            try:
                st, _h, raw = ctx.fetch(it["url"], timeout=10,
                                        cap=1024 * 1024)
            except Exception:
                return it, 0, b""
            return it, st, raw

        with ThreadPoolExecutor(max_workers=_WAVE) as ex:
            wave_res = list(ex.map(_get, wave))
        for it, st, raw in wave_res:
            if fetched >= _PAGE_FETCH_CAP or ctx.stop_requested():
                break
            if st != 200 or not raw:
                continue
            if _looks_binary(raw):
                meta_m["pages_skipped_binary"] += 1
                continue
            text = raw.decode("utf-8", "replace")
            fetched += 1
            ctx.stats["pages_fetched"] += 1
            page_node = page_nodes.get(it["url"])
            if it["class"] == "profile":
                prof = extract_profile("", text, subject)
                if prof:
                    it["profile"] = compact_profile(prof)
                    for ident in prof.get("identifiers") or []:
                        if ident.get("type") == "username":
                            iid = _a6_node(ctx, "username",
                                           ident["value"])
                            if iid and page_node:
                                ctx.graph.edge(
                                    page_node, iid, "LINKED_TO",
                                    "candidate",
                                    f"profile page declares this "
                                    f"handle ({ident.get('field', 'profile')})")
            _extract_entities(ctx, text, it["url"], page_node,
                              subject_handles=subject_handles)
    meta_m["pages_fetched"] = fetched
    L(f"[osint] A6 web mentions for '{subject}': {len(items)} "
      f"result(s) ({len(profs)} profile, {len(docs)} document, "
      f"{len(plain)} mention), engines {engines}, "
      f"{fetched} page(s) fetched")
    return meta_m


# ------------------------------------------------------------- WS-D

def _mx_hosts_of(dom):
    """MX hosts via DoH in preference order; None = lookup failed
    (not evaluated), [] = the domain publishes no usable MX."""
    raw = _doh_query(dom, "MX")
    if raw is None:
        return None
    hosts = []
    for rec in raw:
        parts = str(rec).strip().split()
        if not parts:
            continue
        host = parts[-1].rstrip(".")
        if not host or host == ".":
            continue
        try:
            pref = int(parts[0]) if len(parts) > 1 else 0
        except ValueError:
            pref = 0
        hosts.append((pref, host))
    return [h for _p, h in sorted(hosts)]


def _email_signal_lite(email):
    """P3 signals for a permuted candidate — assessment ONLY, no
    findings and no SMTP probing of any kind."""
    dom = email.split("@")[-1].lower()
    if not _email_format_ok(email):
        return {"format_ok": False, "domain_resolves": False,
                "mx_hosts": [], "disposable": False,
                "assessment": "invalid format"}
    mx = _mx_hosts_of(dom)
    registrable = passive_mod._registrable(dom)
    disp = (dom in _DISPOSABLE_EMAIL_DOMAINS
            or registrable in _DISPOSABLE_EMAIL_DOMAINS)
    resolves = bool(_doh_ips(dom))
    if mx is None:
        assessment = "not evaluated (MX lookup unavailable)"
    elif disp:
        assessment = "disposable provider"
    elif not resolves and not mx:
        assessment = "domain does not resolve"
    elif not mx:
        assessment = "no MX — mail likely undeliverable"
    else:
        assessment = "plausible (MX present)"
    return {"format_ok": True, "domain_resolves": resolves,
            "mx_hosts": mx or [], "mx_evaluated": mx is not None,
            "disposable": disp, "assessment": assessment}


def _email_permutator(ctx, name):
    """WS-D: common email patterns over domains BOUND to the subject
    by corroborated evidence (a confirmed institution domain, or a
    website on a corroborated profile). Signals only — an address is
    a candidate until an independent signal (the address appearing
    verbatim on a fetched public page, or its local part matching a
    corroborated handle while the domain publishes MX) lifts it."""
    meta_e = {"status": "not evaluated", "domains": [],
              "candidates": [], "probable": []}
    ctx.meta["email_candidates"] = meta_e
    domains = []
    inst = ctx.meta.get("institution") or {}
    if inst.get("confirmed_domain"):
        domains.append(passive_mod._registrable(
            inst["confirmed_domain"]))
    ident = ctx.meta.get("identity") or {}
    for acct in ident.get("accounts") or []:
        w = (acct.get("profile") or {}).get("website") or ""
        if w:
            h = _query_host(w if "://" in w else "https://" + w)
            if h:
                domains.append(passive_mod._registrable(h))
    seen_dom, doms = set(), []
    for d in domains:
        if d and d not in seen_dom:
            seen_dom.add(d)
            doms.append(d)
    domains = doms[:2]
    if not domains:
        meta_e["reason"] = ("no corroborated domain is bound to "
                            "the subject")
        ctx.L("[osint] A6 email permutator: not evaluated "
              "(no corroborated domain)")
        return meta_e
    words = ([w for w in _name_words(name) if w not in _NAME_STOPWORDS]
             or _name_words(name))
    if not words:
        return meta_e
    first = words[0]
    last = words[-1] if len(words) > 1 else ""
    locals_ = []
    if last and last != first:
        locals_ = [f"{first}.{last}", f"{first}{last}",
                   f"{first[0]}.{last}", f"{first}.{last[0]}",
                   f"{first}_{last}", f"{last}.{first}"]
    locals_.append(first)
    corroborated_handles = {c.lower()
                            for c in ident.get("corroborated") or []}
    entries = []
    for dom in domains:
        if ctx.stop_requested():
            break
        for loc in locals_:
            if len(entries) >= 14 or ctx.stop_requested():
                break
            addr = f"{loc}@{dom}"
            sig = _email_signal_lite(addr)
            conf, why = "candidate", []
            if addr in ctx.extracted_emails:
                conf = "probable"
                why.append("the address appears verbatim on a "
                           "fetched public page")
            elif (loc.lower() in corroborated_handles
                    and sig["mx_hosts"]):
                conf = "probable"
                why.append("local part matches a corroborated handle "
                           "and the domain publishes MX records")
            entries.append({"email": addr, "pattern": loc,
                            "domain": dom, "signals": sig,
                            "confidence": conf, "why": why})
    meta_e.update(status="evaluated", domains=domains,
                  candidates=entries,
                  probable=[e["email"] for e in entries
                            if e["confidence"] == "probable"])
    for e in entries:
        nid = ctx.graph.node("email", e["email"], e["confidence"],
                             "A6")
        if nid and ctx.root_id:
            ctx.graph.edge(
                ctx.root_id, nid, "POSSIBLE_EMAIL", e["confidence"],
                (f"name pattern over a corroborated domain; signals: "
                 f"{e['signals']['assessment']}"
                 + (f"; {e['why'][0]}" if e["why"] else ""))[:150])
    if entries:
        ctx.add(F(
            "INFO", f"Permuted email candidates for '{name}'",
            "Common email patterns generated from the name over "
            "domain(s) bound to the subject by corroborated evidence. "
            "Signal-based assessment only (format / DoH resolution / "
            "MX / disposable) — NO SMTP verification was performed, "
            "so a candidate address is a guess until independently "
            "corroborated.",
            evidence="; ".join(
                f"{e['email']} [{e['confidence']}; "
                f"{e['signals']['assessment']}]"
                for e in entries[:8]),
            cwe="", owasp="", cvss=0.0,
            remed="Verify any address through an official channel "
                  "before using it as a contact.",
            confidence="candidate", location=name, origin="passive"))
    if (meta_e["probable"] and ctx.opts.get("breach") is True
            and not ctx.stop_requested()):
        bres = {}
        for addr in meta_e["probable"][:3]:
            bres[addr] = _breach_email(ctx, addr)
        meta_e["breach"] = bres
        ctx.pivots.append("breach:permuted-email")
    ctx.L(f"[osint] A6 email permutator: {len(entries)} candidate(s) "
          f"over {domains}, {len(meta_e['probable'])} probable")
    return meta_e


# ------------------------------------------------------------- WS-E

_AHASH_MAX_DIST = 10  # of 256 bits — strict (K4)


def _ahash16(data):
    """Average hash, 16x16, implemented in-module on Pillow.
    Returns a 256-bit int, or None when the bytes are not a
    decodable image."""
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data))
        im = im.convert("L").resize((16, 16))
        px = list(im.getdata())
    except Exception:
        return None
    if len(px) != 256:
        return None
    avg = sum(px) / 256.0
    h = 0
    for i, p in enumerate(px):
        if p > avg:
            h |= (1 << i)
    return h


def _avatar_matching(ctx, items):
    """WS-E: pairwise avatar comparison over gate-passed profiles.
    items: [{handle, platform, avatar_url, node_id}]. A pair counts
    only at a STRICT Hamming distance (K4) — loose similarity is
    never a signal. Returns (meta, matched_pairs)."""
    meta = {"compared": 0, "matched": 0, "skipped": 0, "matches": []}
    pairs = []
    cache = {}
    usable = []
    for it in items[:20]:
        if ctx.stop_requested():
            meta["skipped"] += 1
            continue
        url = it.get("avatar_url") or ""
        if not url:
            meta["skipped"] += 1
            continue
        if url not in cache:
            st, _h, raw = ctx.fetch(url, timeout=8,
                                    cap=2 * 1024 * 1024)
            cache[url] = (_ahash16(raw) if (st == 200 and raw)
                          else None)
        h = cache[url]
        if h is None:
            meta["skipped"] += 1
            continue
        usable.append((it, h))
    for i in range(len(usable)):
        for j in range(i + 1, len(usable)):
            a, ha = usable[i]
            b, hb = usable[j]
            if (a["handle"].lower() == b["handle"].lower()
                    and a["platform"] == b["platform"]):
                continue
            meta["compared"] += 1
            dist = bin(ha ^ hb).count("1")
            if dist <= _AHASH_MAX_DIST:
                meta["matched"] += 1
                meta["matches"].append({
                    "a": f"{a['handle']} ({a['platform']})",
                    "b": f"{b['handle']} ({b['platform']})",
                    "distance": dist})
                pairs.append((a["handle"], a["platform"],
                              b["handle"], b["platform"]))
                if (a.get("node_id") and b.get("node_id")
                        and a["node_id"] != b["node_id"]):
                    ctx.graph.edge(
                        a["node_id"], b["node_id"], "SAME_AVATAR",
                        "probable",
                        f"profile avatars are (near-)identical "
                        f"(aHash distance {dist}/256, strict "
                        f"threshold {_AHASH_MAX_DIST})")
    return meta, pairs


# ------------------------------------------------------- domain flow (A1-A5)

def _domain_osint(ctx, host, domain, handle_override=None):
    """The original v1.3.0 deep domain OSINT: A1 infra, A2 CT/Wayback,
    A3 username, A4 code exposure, A5 breach (opt-in)."""
    fetch, L, warnings, meta = ctx.fetch, ctx.L, ctx.warnings, ctx.meta
    add, opts = ctx.add, ctx.opts
    g = ctx.graph
    meta["domain"] = domain
    meta["host"] = host
    dom_id = g.node("domain", domain, "info", "A1")
    ctx.domain_node = dom_id
    L(f"[osint] deep OSINT for {host} (domain {domain}) — public lookups only")

    # ---------------- A1: infrastructure intelligence
    ips = _doh_ips(host)
    if not ips:
        warnings.append(f"A1: no A records for {host} via DoH — infrastructure intel limited")
    nsrec, _f1, _n1 = passive_mod._dns_records(domain, ("NS", "MX"))
    ns_providers = sorted({p for h in nsrec.get("NS", [])
                           for p in [_provider_of(h, _NS_PROVIDERS)] if p})
    mx_providers = sorted({p for h in nsrec.get("MX", [])
                           for rec in [h.split()[-1] if h.split() else ""]
                           for p in [_provider_of(rec, _MX_PROVIDERS)] if p})
    rdap_ips = []
    for ip in ips[:3]:
        info = _rdap_ip(ip, fetch)
        if info:
            rdap_ips.append(info)
    if ips and not rdap_ips:
        warnings.append("A1: RDAP IP lookups unavailable — ASN/owner not evaluated")
    meta["infra"] = {"ips": ips, "rdap": rdap_ips,
                     "ns_providers": ns_providers, "mx_providers": mx_providers}
    if ips:
        g.node("domain", domain, "probable", "A1")
    for ip in ips[:3]:
        ip_id = g.node("ip", ip, "probable", "A1")
        g.edge(dom_id, ip_id, "RESOLVES_TO", "confirmed",
               f"DoH A record: {host} -> {ip}")
    for info in rdap_ips:
        ip_id = g.node("ip", info["ip"], "probable", "A1")
        if info["asn"]:
            asn_id = g.node("asn", info["asn"], "probable", "A1")
            g.edge(ip_id, asn_id, "BELONGS_TO_ASN", "probable",
                   f"RDAP network {info['network'] or info['prefix']}")
        if info["prefix"]:
            cidr_id = g.node("cidr", info["prefix"], "probable", "A1")
            g.edge(ip_id, cidr_id, "IN_CIDR", "probable",
                   f"RDAP prefix covering {info['ip']}")
    for info in rdap_ips:
        ev = (f"{host} -> {info['ip']}"
              + (f" | network {info['prefix']}" if info["prefix"] else "")
              + (f" | {info['asn']}" if info["asn"] else "")
              + (f" | owner {info['owner']}" if info["owner"] else "")
              + (f" | netname {info['network']}" if info["network"] else "")
              + (f" | country {info['country']}" if info["country"] else "")
              + " | source: RDAP")
        add(F("INFO", "Infrastructure: hosting network identified",
              "Public RDAP data for the IP address(es) this host resolves to. Useful for asset ownership verification and third-party risk context.",
              evidence=ev, cwe="", owasp="", cvss=0.0,
              remed="No action required; informational.",
              confidence="probable", location=host, origin="passive"))
    # F1 (v1.11.0): sanctions screening of the RDAP owner names.
    for _owner in sorted({i["owner"] for i in rdap_ips
                          if i.get("owner")}):
        _sanctions_check_name(ctx, _owner, f"RDAP owner for {domain}",
                              subject_node_id=dom_id)
    if ns_providers or mx_providers:
        add(F("INFO", "Infrastructure: DNS & mail providers",
              "Providers identified from the NS/MX record hostnames themselves (not from content guessing).",
              evidence=(f"NS: {', '.join(ns_providers) or '-'} | "
                        f"MX: {', '.join(mx_providers) or '-'} | source: DNS (DoH/dnspython)"),
              cwe="", owasp="", cvss=0.0,
              remed="No action required; informational.",
              confidence="probable", location=domain, origin="passive"))
    L(f"[osint] A1 infra: {len(ips)} IP(s), {len(rdap_ips)} RDAP record(s), "
      f"NS={ns_providers}, MX={mx_providers}")

    if ctx.stop_requested():
        return
    # ---------------- A2: CT deep parse + Wayback
    ct_meta = {"names": 0}
    rows, ct_st = _ct_rows(fetch, domain)
    if rows == "parse_error":
        warnings.append("A2: crt.sh response could not be parsed")
    elif rows is None:
        warnings.append(f"A2: crt.sh lookup unavailable (HTTP {ct_st}) — CT intel not evaluated")
    else:
        live_names, expired_names = _ct_parse_rows(rows)
        only_expired = sorted(n for n in expired_names - live_names
                              if n != domain)[:40]
        shadow = []
        for n in only_expired[:25]:
            if not _doh_ips(n):
                shadow.append(n)
        ct_meta = {"names": len(live_names | expired_names),
                   "expired_only_names": only_expired,
                   "shadow_candidates": shadow}
        for n in sorted(live_names)[:40]:
            if n == domain:
                continue
            sub_id = g.node("subdomain", n, "probable", "A2")
            g.edge(dom_id, sub_id, "HAS_SUBDOMAIN", "probable",
                   "certificate transparency (live certificate)")
        for n in shadow:
            sub_id = g.node("subdomain", n, "candidate", "A2")
            g.edge(dom_id, sub_id, "HAS_SUBDOMAIN", "candidate",
                   "expired-certificate name; no DoH resolution")
        # Second-degree pivot (bounded): live CT name -> IP -> ASN.
        extra_rdap = 0
        for n in sorted(live_names)[:3]:
            if n == domain:
                continue
            sub_id = g.node("subdomain", n, "probable", "A2")
            for ip2 in _doh_ips(n)[:2]:
                ip2_id = g.node("ip", ip2, "probable", "A1")
                g.edge(sub_id, ip2_id, "RESOLVES_TO", "confirmed",
                       f"DoH A record: {n} -> {ip2}")
                info2 = next((i for i in rdap_ips if i["ip"] == ip2), None)
                if info2 is None and extra_rdap < 2:
                    info2 = _rdap_ip(ip2, fetch)
                    extra_rdap += 1
                if info2:
                    if info2["asn"]:
                        asn2 = g.node("asn", info2["asn"], "probable", "A1")
                        g.edge(ip2_id, asn2, "BELONGS_TO_ASN", "probable",
                               f"RDAP network {info2['network'] or info2['prefix']}")
                    if info2["prefix"]:
                        cidr2 = g.node("cidr", info2["prefix"], "probable", "A1")
                        g.edge(ip2_id, cidr2, "IN_CIDR", "probable",
                               f"RDAP prefix covering {ip2}")
        if shadow:
            add(F("LOW", "Possible shadow subdomains (expired-certificate names)",
                  "These names appear only on expired certificates and no longer resolve via DoH. They may be forgotten assets: if the names are ever re-pointed or the services still exist internally, they become takeover/attack surface. This is a candidate list, not proof the services are alive.",
                  evidence="; ".join(shadow[:15]) + " | source: crt.sh CT logs + DoH",
                  cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
                  cvss=3.1,
                  remed="Inventory these names; remove stale DNS/certificates or formally retire the assets.",
                  confidence="candidate", location=domain,
                  origin="passive"))
        L(f"[osint] A2 CT: {ct_meta['names']} names, "
          f"{len(shadow)} shadow candidate(s)")
    meta["ct"] = ct_meta

    wb_meta = {"archived_urls": 0}
    cdx_url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
               f"&output=json&limit=400&collapse=urlkey")
    st, _h, raw = fetch(cdx_url, timeout=20, verify=True)
    if st == 200 and raw:
        try:
            rows = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            rows = None
        if rows and len(rows) > 1:
            header, data = rows[0], rows[1:]
            idx = {name: i for i, name in enumerate(header)}
            # v1.5.0 robustness: drop malformed CDX rows before the
            # indexed accesses below (a short/non-list row used to
            # crash the whole scan with IndexError).
            _need = max(idx.get("timestamp", 0), idx.get("original", 0))
            data = [r for r in data
                    if isinstance(r, list) and len(r) > _need]
            wb_meta["archived_urls"] = len(data)
            years = sorted({str(r[idx["timestamp"]])[:4] for r in data
                            if str(r[idx["timestamp"]])[:4].isdigit()})
            wb_meta["years"] = years
            interesting = [r for r in data
                           if re.search(r"\.(js|json|map)$|config|\.env|backup",
                                        str(r[idx["original"]]), re.I)][:6]
            if data:
                add(F("INFO", "Historical attack surface in the Wayback Machine",
                      f"{len(data)} archived URL(s) of this domain are publicly browsable in the Wayback Machine"
                      + (f" spanning {years[0]}-{years[-1]}" if years else "")
                      + ". Archived snapshots can expose removed endpoints, old parameters and historical files.",
                      evidence=f"web.archive.org CDX: {len(data)} URLs",
                      cwe="", owasp="", cvss=0.0,
                      remed="Review archived snapshots for content that should no longer be public; request exclusions where appropriate.",
                      confidence="probable", location=domain,
                      origin="passive"))
                wb_id = g.node("website", "web.archive.org", "info", "A2")
                g.edge(dom_id, wb_id, "ARCHIVED_AS", "probable",
                       f"{len(data)} archived URL(s) in the Wayback Machine")
            sec_state = {"seen": set(), "count": 0, "cap": 6}
            for r in interesting:
                ts = str(r[idx["timestamp"]])
                orig = str(r[idx["original"]])
                snap = f"https://web.archive.org/web/{ts}id_/{orig}"
                s2, _h2, raw2 = fetch(snap, timeout=15, verify=True,
                                      cap=512 * 1024)
                if s2 == 200 and raw2:
                    _scan_secrets_in(
                        add, raw2.decode("utf-8", "replace"),
                        f"wayback:{orig}", sec_state, config_style=True)
            if sec_state["count"]:
                L(f"[osint] A2 wayback: {sec_state['count']} secret finding(s) "
                  f"in archived snapshots")
            wb_meta["snapshots_scanned"] = len(interesting)
        elif rows is not None:
            wb_meta["archived_urls"] = 0
    else:
        warnings.append(f"A2: Wayback CDX unavailable (HTTP {st}) — archive intel not evaluated")
    meta["wayback"] = wb_meta
    L(f"[osint] A2 wayback: {wb_meta.get('archived_urls', 0)} archived URL(s)")

    if ctx.stop_requested():
        return
    # ---------------- v1.5.0: archive history + domain hygiene (P1/P2)
    _archive_history(ctx, dom_id, domain)
    _passivedns(ctx, dom_id, domain)
    _typosquatting(ctx, dom_id, domain)
    ctx.meta["reputation"] = _dnsbl_reputation(ctx, domain, "domain")

    # ---------------- A3: username OSINT (control-gated)
    handle = str(opts.get("handle") or "").strip()[:80]
    derived = False
    handle_source = "option" if handle else ""
    if not handle and handle_override:
        handle = handle_override
        handle_source = "pivot"
    if not handle:
        handle = domain.split(".")[0]
        derived = True
        handle_source = "domain"
    ufinds, umeta = _username_osint(fetch, handle, L, warnings,
                                    platforms=ctx.platforms, graph=g,
                                    stats=ctx.stats,
                                    cancelled=ctx.stop_requested)
    umeta["derived_from_domain"] = derived
    umeta["handle_source"] = handle_source
    for f in ufinds:
        add(f)
    meta["username"] = umeta
    _pivot_extracted_handles(ctx, handle, umeta.get("profiles") or {},
                             1, {handle})

    if ctx.stop_requested():
        return
    # ---------------- A4: code-exposure OSINT
    code_meta = {"github_repos": [], "gitlab_projects": [],
                 "github_code_search": "not evaluated"}
    q = quote(domain)
    st, _h, raw = fetch(f"https://api.github.com/search/repositories?q={q}&per_page=5",
                        timeout=15, verify=True,
                        headers={"Accept": "application/vnd.github+json"})
    if st == 200 and raw:
        try:
            items = (json.loads(raw.decode("utf-8", "replace"))
                     .get("items") or [])
        except Exception:
            items = []
        code_meta["github_repos"] = [it.get("full_name", "") for it in items]
        if items:
            for it in items[:5]:
                repo_id = g.node("repository", it.get("full_name", ""),
                                 "probable", "A4")
                g.edge(repo_id, dom_id, "MENTIONS", "probable",
                       "repository metadata references the domain (GitHub search)")
            add(F("INFO", "Public GitHub repositories referencing this domain",
                  "Public repositories whose metadata references the target domain. Review whether they are official, leaked, or impersonating projects.",
                  evidence="; ".join(
                      f"{it.get('full_name')} ({it.get('html_url')})"
                      for it in items[:5]) + " | source: GitHub search API",
                  cwe="", owasp="", cvss=0.0,
                  remed="Confirm each repository is authorized; report leaked or impersonating repositories to GitHub.",
                  confidence="probable", location=domain, origin="passive"))
            n = _scan_readmes(
                ctx, items,
                lambda it, br: (f"https://raw.githubusercontent.com/"
                                f"{it.get('full_name', '')}/{br}/README.md"),
                lambda it: it.get("default_branch", "main"))
            if n:
                L(f"[osint] A4: {n} secret finding(s) in public repo READMEs")
    elif st in (403, 429):
        warnings.append(f"A4: GitHub search rate-limited/refused (HTTP {st}) — repository search not evaluated")
    else:
        warnings.append(f"A4: GitHub search unavailable (HTTP {st}) — not evaluated")
    # GitHub code search requires authentication; report honestly.
    st, _h, raw = fetch(f"https://api.github.com/search/code?q={q}",
                        timeout=15, verify=True,
                        headers={"Accept": "application/vnd.github+json"})
    if st == 401 or st == 403:
        code_meta["github_code_search"] = ("not evaluated — GitHub code "
                                            "search requires authentication")
        L("[osint] A4 github code search: not evaluated (authentication required)")
    elif st == 200:
        code_meta["github_code_search"] = "evaluated"
    st, _h, raw = fetch(f"https://gitlab.com/api/v4/projects?search={q}&per_page=5",
                        timeout=15, verify=True)
    if st == 200 and raw:
        try:
            projs = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            projs = []
        if isinstance(projs, list) and projs:
            code_meta["gitlab_projects"] = [p.get("path_with_namespace", "")
                                             for p in projs]
            for p in projs[:5]:
                repo_id = g.node("repository",
                                 p.get("path_with_namespace", ""),
                                 "probable", "A4")
                g.edge(repo_id, dom_id, "MENTIONS", "probable",
                       "project matches the domain name (GitLab search)")
            add(F("INFO", "Public GitLab projects referencing this domain",
                  "Public GitLab projects matching the target domain name. Review whether they are official or leaked.",
                  evidence="; ".join(
                      f"{p.get('path_with_namespace')} ({p.get('web_url')})"
                      for p in projs[:5]) + " | source: GitLab API",
                  cwe="", owasp="", cvss=0.0,
                  remed="Confirm each project is authorized.",
                  confidence="probable", location=domain, origin="passive"))
    elif st in (403, 429):
        warnings.append(f"A4: GitLab search rate-limited/refused (HTTP {st}) — not evaluated")
    meta["code_exposure"] = code_meta

    if ctx.stop_requested():
        return
    # ---------------- A5: breach exposure (OFF by default, K3)
    breach_meta = {"enabled": False}
    if opts.get("breach") is True:
        breach_meta["enabled"] = True
        L("[osint] A5 breach exposure: ENABLED by explicit opt-in")
        st, _h, raw = fetch(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
            f"search-by-domain?domain={q}", timeout=20, verify=True)
        if st == 200 and raw:
            try:
                d = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                d = None
            total = None
            if isinstance(d, dict):
                data = d.get("data") or {}
                total = (data.get("total") if isinstance(data, dict)
                         else None) or d.get("total")
            if total:
                add(F("LOW", "Breach/stealer-log exposure reported for this domain",
                      "A third-party breach-intelligence source reports records associated with this domain. This is an unverified third-party claim (candidate): confirm with the provider before acting, and treat any named accounts as potentially compromised.",
                      evidence=f"HudsonRock Cavalier: total={total} for {domain} (third-party data, not independently verified)",
                      cwe="CWE-200", owasp="A07:2021 Identification & Authentication Failures",
                      cvss=3.1,
                      remed="Force password resets + MFA for affected accounts after verifying the records with the provider.",
                      confidence="candidate", location=domain,
                      origin="passive"))
                breach_meta["hudsonrock_total"] = total
            else:
                breach_meta["hudsonrock_total"] = 0
        else:
            warnings.append(f"A5: HudsonRock lookup unavailable (HTTP {st}) — breach exposure not evaluated")
        # F4 (v1.11.0): XposedOrNot has no domain lookup endpoint
        # (verified at build time) — the second source is honestly
        # not evaluated for domain queries instead of calling a
        # dead endpoint.
        breach_meta["xposedornot"] = (
            "not evaluated — XposedOrNot provides email lookups "
            "only; no domain endpoint exists")
        breach_meta["sources"] = {
            "hudsonrock": ("reported" if breach_meta.get("hudsonrock_total")
                           else "not_reported"
                           if "hudsonrock_total" in breach_meta
                           else "not evaluated"),
            "xposedornot": "not evaluated",
        }
        if opts.get("breach_api_key"):
            breach_meta["breachdirectory"] = (
                "key supplied via vault; BreachDirectory lookup channel "
                "reserved — key value never logged")
            L("[osint] A5 breachdirectory: API key present (value not logged); channel reserved")
    else:
        L("[osint] A5 breach exposure: disabled (default — opt-in required)")
    meta["breach"] = breach_meta

    # WS-A (v1.6.0): web mentions complementing the domain flow —
    # pages that talk about this domain outside its own infra.
    if not ctx.stop_requested():
        _web_mentions(ctx, domain, dom_id, kind="domain")


# ------------------------------------------------------------ pivot: IP

def _doh_ptr(ip):
    """Reverse-DNS hostnames for an IP via DoH PTR. [] = no PTR data."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if addr.version == 4:
        name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    else:
        nibbles = addr.exploded.replace(":", "")
        name = ".".join(reversed(nibbles)) + ".ip6.arpa"
    try:
        vals = scanners.doh_query(name, "PTR")
    except Exception:
        vals = None
    return sorted({str(v).rstrip(".").lower() for v in (vals or []) if v})


def _ip_pivot(ctx, ip):
    L, add = ctx.L, ctx.add
    g = ctx.graph
    ctx.pivots.append(f"ip:{ip}")
    ip_meta = {"ip": ip, "ptr": [], "same_ip_names": []}
    ip_id = g.node("ip", ip, "probable", "A1")
    g.edge(ctx.root_id, ip_id, "LINKED_TO", "probable",
           "query is this IP address")
    info = _rdap_ip(ip, ctx.fetch)
    if info:
        if info["asn"]:
            asn_id = g.node("asn", info["asn"], "probable", "A1")
            g.edge(ip_id, asn_id, "BELONGS_TO_ASN", "probable",
                   f"RDAP network {info['network'] or info['prefix']}")
        if info["prefix"]:
            cidr_id = g.node("cidr", info["prefix"], "probable", "A1")
            g.edge(ip_id, cidr_id, "IN_CIDR", "probable",
                   f"RDAP prefix covering {ip}")
    if info:
        ev = (f"{ip}"
              + (f" | network {info['prefix']}" if info["prefix"] else "")
              + (f" | {info['asn']}" if info["asn"] else "")
              + (f" | owner {info['owner']}" if info["owner"] else "")
              + (f" | netname {info['network']}" if info["network"] else "")
              + (f" | country {info['country']}" if info["country"] else "")
              + " | source: RDAP")
        add(F("INFO", "Infrastructure: IP network identified (RDAP)",
              "Public RDAP registration data for the queried IP address: network block, ASN and owner.",
              evidence=ev, cwe="", owasp="", cvss=0.0,
              remed="No action required; informational.",
              confidence="probable", location=ip, origin="passive"))
        ip_meta["rdap"] = info
        # F1 (v1.11.0): sanctions screening of the RDAP owner name.
        if info.get("owner"):
            _sanctions_check_name(
                ctx, info["owner"],
                f"RDAP owner of {ip}", subject_node_id=ip_id)
    else:
        ctx.warn(f"IP: RDAP lookup unavailable for {ip} — ownership not evaluated")
    if ctx.stop_requested():
        ctx.meta["ip"] = ip_meta
        return
    rep = _dnsbl_reputation(ctx, ip, "ip")
    ip_meta["reputation"] = rep
    if "reputation" not in ctx.meta:
        ctx.meta["reputation"] = rep
    ptrs = _doh_ptr(ip)
    ip_meta["ptr"] = ptrs
    if ptrs:
        ptr_id = g.node("subdomain", ptrs[0], "probable", "A1")
        g.edge(ip_id, ptr_id, "LINKED_TO", "probable",
               f"PTR record (DoH): {ip} -> {ptrs[0]}")
        add(F("INFO", f"Reverse DNS (PTR) for {ip}",
              "Public PTR records returned by DNS-over-HTTPS for this IP address.",
              evidence="; ".join(ptrs) + " | source: DoH PTR",
              cwe="", owasp="", cvss=0.0,
              remed="No action required; informational.",
              confidence="probable", location=ip, origin="passive"))
        host = ptrs[0]
        domain = passive_mod._registrable(host)
        rows, _st = _ct_rows(ctx.fetch, domain)
        if isinstance(rows, list) and rows:
            live_names, expired_names = _ct_parse_rows(rows)
            names = sorted(live_names | expired_names)
            same = [n for n in names[:12] if ip in _doh_ips(n)]
            ip_meta["same_ip_names"] = same
            for n in same:
                n_id = g.node("subdomain", n, "candidate", "A2")
                g.edge(ip_id, n_id, "LINKED_TO", "candidate",
                       f"{n} resolves to {ip} via DoH (CT name, co-hosted)")
            if same:
                add(F("INFO", f"Other names proven to resolve to {ip}",
                      "Certificate Transparency names for the PTR domain whose A records (via DoH) include this exact IP. Co-hosting is proven; common ownership is NOT — shared hosting puts unrelated tenants on one IP.",
                      evidence="; ".join(same) + " | source: crt.sh + DoH A",
                      cwe="", owasp="", cvss=0.0,
                      remed="No action required; informational.",
                      confidence="candidate", location=ip,
                      origin="passive"))
        ctx.meta["ip"] = ip_meta
        L(f"[osint] pivot: IP {ip} -> PTR domain {domain}")
        ctx.pivots.append(f"domain:{domain}")
        if not ctx.stop_requested():
            _domain_osint(ctx, host, domain)
        if ctx.domain_node and ptr_id:
            g.edge(ctx.domain_node, ptr_id, "HAS_SUBDOMAIN", "probable",
                   "PTR hostname belongs to this domain")
    else:
        ctx.warn(f"IP: no PTR record for {ip} via DoH — hostname pivot not available")
        ctx.meta["ip"] = ip_meta
    L(f"[osint] IP pivot: ptr={ptrs}, "
      f"same-ip names={len(ip_meta['same_ip_names'])}")


# ------------------------------------------------------------ pivot: email

def _gravatar(ctx, email):
    """Public Gravatar profile for an email — claimed ONLY when the
    service returns a real profile document for the address hash."""
    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
    st, _h, raw = ctx.fetch(f"https://gravatar.com/{digest}.json",
                            timeout=10, verify=True)
    gmeta = {"checked": True, "profile": None}
    if st == 200 and raw:
        try:
            d = json.loads(raw.decode("utf-8", "replace"))
            entry = (d.get("entry") or [{}])[0]
        except Exception:
            entry = {}
        if entry:
            gmeta["profile"] = {
                "display_name": str(entry.get("displayName", ""))[:80],
                "username": str(entry.get("preferredUsername", ""))[:80],
                "profile_url": str(entry.get("profileUrl", ""))[:200],
            }
            ev = gmeta["profile"]["profile_url"]
            if gmeta["profile"]["display_name"]:
                ev += f" | display name: {gmeta['profile']['display_name']}"
            if gmeta["profile"]["username"]:
                ev += f" | username: {gmeta['profile']['username']}"
            em_id = ctx.graph.node("email", email, "probable", "A3")
            site_id = ctx.graph.node("website", "Gravatar", "info", "A3")
            ctx.graph.edge(em_id, site_id, "LINKED_TO", "probable",
                           "public Gravatar profile returned for this address")
            ctx.add(F(
                "INFO", "Public Gravatar profile exists for this email address",
                "Gravatar returned a public profile document for the MD5 hash of this email address. The profile content is public data published by the account holder.",
                evidence=ev + " | source: Gravatar profile API",
                cwe="", owasp="", cvss=0.0,
                remed="No action required; informational. Review what the profile discloses.",
                confidence="probable", location=email, origin="passive"))
            ctx.L("[osint] email pivot: Gravatar profile found")
            return gmeta
        gmeta["checked"] = "unevaluated"
        ctx.warn("email: Gravatar returned an unparseable profile — not evaluated")
    elif st == 404:
        ctx.L("[osint] email pivot: no Gravatar profile for this address")
    else:
        gmeta["checked"] = "unevaluated"
        ctx.warn(f"email: Gravatar lookup unavailable (HTTP {st}) — not evaluated")
    return gmeta


def _breach_email(ctx, email):
    """A5 by email (only called on explicit opt-in)."""
    L, add = ctx.L, ctx.add
    st, _h, raw = ctx.fetch(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/"
        f"search-by-email?email={quote(email)}", timeout=20, verify=True)
    out = {}
    if st == 200 and raw:
        try:
            d = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            d = None
        total = None
        if isinstance(d, dict):
            data = d.get("data") or {}
            total = (data.get("total") if isinstance(data, dict)
                     else None) or d.get("total")
        if total:
            add(F("LOW", "Breach/stealer-log exposure reported for this email address",
                  "A third-party breach-intelligence source reports records associated with this exact email address. This is an unverified third-party claim (candidate): confirm with the provider before acting.",
                  evidence=f"HudsonRock Cavalier: total={total} for the queried email (address masked in stored evidence: {email.split('@')[0][:2]}***@{email.split('@')[-1]}) (third-party data, not independently verified)",
                  cwe="CWE-200", owasp="A07:2021 Identification & Authentication Failures",
                  cvss=3.1,
                  remed="Force a password reset + MFA for the account after verifying the records with the provider.",
                  confidence="candidate", location=email.split("@")[-1],
                  origin="passive"))
            out["hudsonrock_total"] = total
        else:
            out["hudsonrock_total"] = 0
    else:
        ctx.warn(f"A5: HudsonRock email lookup unavailable (HTTP {st}) — breach exposure for email not evaluated")
    # F4 (v1.11.0): XposedOrNot — second, independent A5 source,
    # same opt-in. A failure here never affects the HudsonRock
    # result, and agreement between the two sources is stated in
    # the evidence without raising the candidate tier.
    xon = _xposedornot_email(ctx, email)
    out["xposedornot"] = xon
    out["sources"] = {
        "hudsonrock": ("reported" if out.get("hudsonrock_total")
                       else "not_reported"
                       if "hudsonrock_total" in out
                       else "not evaluated"),
        "xposedornot": xon["status"],
    }
    if xon["status"] == "reported":
        both = (" Corroborated by a second independent source: "
                "HudsonRock also reports this address (tier "
                "unchanged — still an unverified third-party claim)."
                if out.get("hudsonrock_total") else "")
        shown = "; ".join(xon["breaches"][:8])
        add(F("LOW",
              "Breach exposure reported for this email address "
              "(XposedOrNot)",
              "A second third-party breach-intelligence source "
              "reports this exact email address in public breach "
              "corpora. This is an unverified third-party claim "
              "(candidate): confirm with the provider before acting."
              + both,
              evidence=(f"XposedOrNot breach-analytics: "
                        f"{xon['count']} breach(es) for the queried "
                        f"email (address masked in stored evidence: "
                        f"{email.split('@')[0][:2]}***@"
                        f"{email.split('@')[-1]}): {shown} "
                        f"(third-party data, not independently "
                        f"verified)"),
              cwe="CWE-200",
              owasp="A07:2021 Identification & Authentication Failures",
              cvss=3.1,
              remed="Force a password reset + MFA for the account "
                    "after verifying the records with the provider.",
              confidence="candidate", location=email.split("@")[-1],
              origin="passive"))
    elif xon["status"] == "not evaluated":
        ctx.warn("A5/F4: XposedOrNot lookup unavailable — second "
                 "breach source not evaluated for email")
    if ctx.opts.get("breach_api_key"):
        out["breachdirectory"] = ("key supplied via vault; BreachDirectory "
                                   "lookup channel reserved — key value "
                                   "never logged")
        L("[osint] A5 breachdirectory (email): API key present (value not logged); channel reserved")
    return out


def _email_pivot(ctx, email):
    email = email.strip()
    local, _at, dom = email.partition("@")
    dom = dom.lower()
    domain = passive_mod._registrable(dom)
    ctx.meta["email"] = {"local_part": local, "domain": dom}
    ctx.meta["email_checks"] = _email_checks(ctx, email, dom)
    ctx.pivots.append(f"email:{dom}")
    em_id = ctx.graph.node("email", email, "probable", "A3")
    ctx.graph.edge(ctx.root_id, em_id, "LINKED_TO", "probable",
                   "query detected as an email address")
    ctx.meta["gravatar"] = _gravatar(ctx, email)
    ctx.pivots.append(f"domain:{domain}")
    if not ctx.stop_requested():
        _domain_osint(ctx, dom, domain, handle_override=local)
    if ctx.domain_node:
        ctx.graph.edge(em_id, ctx.domain_node, "EMAIL_DOMAIN", "confirmed",
                       "domain part of the email address")
    if ctx.stop_requested():
        return
    if ctx.opts.get("breach") is True:
        ctx.pivots.append("breach:email")
        b = _breach_email(ctx, email)
        if isinstance(ctx.meta.get("breach"), dict):
            ctx.meta["breach"]["email"] = b


# ------------------------------------------------------------ pivot: handle

def _code_exposure_handle(ctx, handle):
    """A4 for a handle: GitHub/GitLab public profiles + repositories;
    repository READMEs are scanned by the Secrets Engine."""
    fetch, L, add = ctx.fetch, ctx.L, ctx.add
    g = ctx.graph
    uid = g.node("username", handle, "candidate", "A3")
    ce = {"handle": handle, "github_user": None, "github_repos": [],
          "gitlab_user": None, "gitlab_projects": [],
          "github_code_search": ("not evaluated — GitHub code search "
                                 "requires authentication")}
    q = quote(handle, safe="")
    st, _h, raw = fetch(f"https://api.github.com/users/{q}",
                        timeout=15, verify=True,
                        headers={"Accept": "application/vnd.github+json"})
    if st == 200 and raw:
        try:
            u = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            u = {}
        if u.get("login"):
            ce["github_user"] = u["login"]
            gh_site = g.node("website", "GitHub", "info", "A4")
            g.edge(uid, gh_site, "FOUND_ON", "probable",
                   "GitHub API returned a public profile for this handle")
            g.node("username", handle, "probable", "A3")
            blog = str(u.get("blog") or "").strip()
            if blog:
                bhost = _query_host(blog if "://" in blog
                                    else "https://" + blog)
                if bhost and _looks_like_domain(bhost):
                    bdom = passive_mod._registrable(bhost)
                    ce["blog_domain"] = bdom
                    bd_id = g.node("domain", bdom, "candidate", "A4")
                    g.edge(uid, bd_id, "MENTIONS", "probable",
                           f"blog URL written in the GitHub profile: {blog}")
                    # Bounded second-degree pivot: resolve + RDAP.
                    ctx.pivots.append(f"domain2:{bdom}")
                    for bip in _doh_ips(bdom)[:2]:
                        bip_id = g.node("ip", bip, "probable", "A1")
                        g.edge(bd_id, bip_id, "RESOLVES_TO", "confirmed",
                               f"DoH A record: {bdom} -> {bip}")
                        binfo = _rdap_ip(bip, fetch)
                        if binfo:
                            if binfo["asn"]:
                                basn = g.node("asn", binfo["asn"],
                                              "probable", "A1")
                                g.edge(bip_id, basn, "BELONGS_TO_ASN",
                                       "probable",
                                       f"RDAP network {binfo['network'] or binfo['prefix']}")
                            if binfo["prefix"]:
                                bcidr = g.node("cidr", binfo["prefix"],
                                               "probable", "A1")
                                g.edge(bip_id, bcidr, "IN_CIDR", "probable",
                                       f"RDAP prefix covering {bip}")
            ev = (f"{u.get('html_url', '')}"
                  + (f" | name: {u['name']}" if u.get("name") else "")
                  + (f" | company: {u['company']}" if u.get("company") else "")
                  + (f" | blog: {u['blog']}" if u.get("blog") else "")
                  + f" | public repos: {u.get('public_repos', 0)}"
                  + " | source: GitHub API")
            add(F("INFO", f"GitHub profile for handle '{handle}'",
                  "A public GitHub user profile exists for this exact handle (returned by the GitHub API).",
                  evidence=ev, cwe="", owasp="", cvss=0.0,
                  remed="Confirm this account is official; impersonation accounts are a phishing risk.",
                  confidence="probable",
                  location=u.get("html_url", ""), origin="passive"))
            s2, _h2, raw2 = fetch(
                f"https://api.github.com/users/{q}/repos?per_page=5&sort=updated",
                timeout=15, verify=True,
                headers={"Accept": "application/vnd.github+json"})
            repos = []
            if s2 == 200 and raw2:
                try:
                    repos = json.loads(raw2.decode("utf-8", "replace")) or []
                except Exception:
                    repos = []
            if isinstance(repos, list) and repos:
                ce["github_repos"] = [r.get("full_name", "") for r in repos]
                for r in repos[:5]:
                    repo_id = g.node("repository", r.get("full_name", ""),
                                     "probable", "A4")
                    g.edge(uid, repo_id, "LINKED_TO", "probable",
                           "public repository owned by this handle")
                add(F("INFO", f"Public GitHub repositories of '{handle}'",
                      "Public repositories owned by this GitHub handle. Their README files were scanned by the Secrets Engine.",
                      evidence="; ".join(
                          f"{r.get('full_name')} ({r.get('html_url')})"
                          for r in repos[:5]) + " | source: GitHub API",
                      cwe="", owasp="", cvss=0.0,
                      remed="Review public repositories for leaked credentials or internal references.",
                      confidence="probable", location="github.com/" + handle,
                      origin="passive"))
                n = _scan_readmes(
                    ctx, repos,
                    lambda it, br: (f"https://raw.githubusercontent.com/"
                                    f"{it.get('full_name', '')}/{br}/README.md"),
                    lambda it: it.get("default_branch", "main"))
                if n:
                    L(f"[osint] A4(handle): {n} secret finding(s) in repo READMEs")
    elif st in (403, 429):
        ctx.warn(f"A4: GitHub user lookup rate-limited/refused (HTTP {st}) — not evaluated")
    elif st != 404:
        ctx.warn(f"A4: GitHub user lookup unavailable (HTTP {st}) — not evaluated")

    if ctx.stop_requested():
        ctx.meta["code_exposure"] = ce
        return ce
    st, _h, raw = fetch(f"https://gitlab.com/api/v4/users?username={q}",
                        timeout=15, verify=True)
    if st == 200 and raw:
        try:
            users = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            users = []
        if isinstance(users, list) and users:
            gu = users[0]
            ce["gitlab_user"] = gu.get("username")
            gl_site = g.node("website", "GitLab", "info", "A4")
            g.edge(uid, gl_site, "FOUND_ON", "probable",
                   "GitLab API returned a public profile for this handle")
            g.node("username", handle, "probable", "A3")
            add(F("INFO", f"GitLab profile for handle '{handle}'",
                  "A public GitLab user profile exists for this exact handle (returned by the GitLab API).",
                  evidence=(f"{gu.get('web_url', '')}"
                            + (f" | name: {gu['name']}" if gu.get("name") else "")
                            + " | source: GitLab API"),
                  cwe="", owasp="", cvss=0.0,
                  remed="Confirm this account is official.",
                  confidence="probable",
                  location=gu.get("web_url", ""), origin="passive"))
            s2, _h2, raw2 = fetch(
                f"https://gitlab.com/api/v4/users/{gu.get('id')}/projects?per_page=5",
                timeout=15, verify=True)
            projs = []
            if s2 == 200 and raw2:
                try:
                    projs = json.loads(raw2.decode("utf-8", "replace")) or []
                except Exception:
                    projs = []
            if isinstance(projs, list) and projs:
                ce["gitlab_projects"] = [p.get("path_with_namespace", "")
                                          for p in projs]
                for p in projs[:5]:
                    repo_id = g.node("repository",
                                     p.get("path_with_namespace", ""),
                                     "probable", "A4")
                    g.edge(uid, repo_id, "LINKED_TO", "probable",
                           "public project owned by this handle")
                n = _scan_readmes(
                    ctx, projs,
                    lambda it, br: (f"{it.get('web_url', '')}/-/raw/"
                                    f"{br}/README.md"),
                    lambda it: it.get("default_branch", "main"),
                    cap_repos=2)
                if n:
                    L(f"[osint] A4(handle): {n} secret finding(s) in GitLab READMEs")
    elif st in (403, 429):
        ctx.warn(f"A4: GitLab user lookup rate-limited/refused (HTTP {st}) — not evaluated")
    ctx.meta["code_exposure"] = ce
    return ce


def _handle_pivot(ctx, handle):
    handle = handle.strip().lstrip("@")[:80]
    ctx.pivots.append(f"username:{handle}")
    uid = ctx.graph.node("username", handle, "candidate", "A3")
    ctx.graph.edge(ctx.root_id, uid, "LINKED_TO", "probable",
                   "query detected as a username/handle")

    def _entity_hook(pname, url, body, site_id):
        # WS-B (v1.6.0): entities published on gate-passed profiles.
        _extract_entities(ctx, body, url, site_id,
                          subject_handles={handle.lower()})

    ufinds, umeta = _username_osint(ctx.fetch, handle, ctx.L, ctx.warnings,
                                    platforms=ctx.platforms, graph=ctx.graph,
                                    stats=ctx.stats,
                                    entity_hook=_entity_hook,
                                    cancelled=ctx.stop_requested)
    umeta["derived_from_domain"] = False
    umeta["handle_source"] = "query"
    for f in ufinds:
        ctx.add(f)
    ctx.meta["username"] = umeta
    if ctx.stop_requested():
        return
    _pivot_extracted_handles(ctx, handle, umeta.get("profiles") or {},
                             1, {handle})
    if ctx.stop_requested():
        return
    ctx.pivots.append(f"code_exposure:{handle}")
    _code_exposure_handle(ctx, handle)

    # WS-A (v1.6.0): web mentions for the handle itself.
    if not ctx.stop_requested():
        _web_mentions(ctx, handle, uid, kind="handle",
                      subject_handles={handle.lower()})


# ------------------------------------------------------------ pivot: name

_SIGNAL_CLASS_ORDER = (
    "profile-name-match", "context-mention", "handle-exact",
    "search-match", "cross-link", "website-match", "email-match",
    "same-avatar",
)


def _person_pivot(ctx, name):
    """Person pivot: name-derived username candidates through the
    control-gated A3 machinery + a >=2 independent-signal
    corroboration rule before any identity may be called probable.

    v1.6.0: signals are tracked as explicit CLASSES (see
    _SIGNAL_CLASS_ORDER). The rule is unchanged — an identity needs
    >= 2 DIFFERENT classes — but the class set is wider
    (website-match, email-match and same-avatar join the v1.3
    classes), each username graph node carries its `signals` class
    list, and WS-B entity extraction runs over gate-passed profile
    bodies while WS-A web mentions close the pivot."""
    L, add = ctx.L, ctx.add
    words = _name_words(name)
    core_words = words[:2] if len(words) > 2 else words
    core_name = " ".join(core_words)
    context_terms = [w for w in words[2:]
                     if len(w) >= 3 and w not in _NAME_STOPWORDS]
    candidates = permuted_username_candidates(name)
    platforms = ctx.platforms
    if platforms is None:
        platforms = [p for p in active_platforms()
                     if p[0] in NAME_PLATFORM_NAMES]
    id_meta = {"name": name, "core_name": core_name,
               "context_terms": context_terms,
               "candidates": candidates, "accounts": [],
               "corroborated": [], "platforms_checked": len(platforms)}
    cand_profiles_all = {}
    ctx.pivots.append(f"person:{core_name}")
    per_id = ctx.graph.node("person", core_name or name, "info", "A3")
    ctx.graph.edge(ctx.root_id, per_id, "LINKED_TO", "candidate",
                   "query interpreted as a person name")

    # Independent discovery path: GitHub user search by name.
    gh_logins = []
    gh_status = "not evaluated"
    st, _h, raw = ctx.fetch(
        "https://api.github.com/search/users?q="
        + quote(core_name) + "&per_page=5",
        timeout=15, verify=True,
        headers={"Accept": "application/vnd.github+json"})
    if st == 200 and raw:
        gh_status = "ok"
        try:
            items = (json.loads(raw.decode("utf-8", "replace"))
                     .get("items") or [])
            gh_logins = [it.get("login", "") for it in items if it.get("login")]
        except Exception:
            gh_logins = []
    elif st in (403, 429):
        ctx.warn(f"person: GitHub user search rate-limited/refused (HTTP {st}) — name search not evaluated")
    id_meta["github_search_logins"] = gh_logins
    id_meta["github_search_status"] = gh_status

    # Institution-name domain guesses that actually resolve — the
    # reference set for the website-match signal class.
    guess_regs = set()
    for g in _institution_domain_guesses(name):
        if _doh_ips(g):
            guess_regs.add(passive_mod._registrable(g))

    subject_handles = {c.lower() for c in candidates}
    records = {}
    for cand in candidates:
        if ctx.stop_requested():
            break
        probed = _username_probe(ctx.fetch, cand, platforms,
                                 stats=ctx.stats,
                                 cancelled=ctx.stop_requested)
        found = {n: r for n, r in probed.items()
                 if r[0] in ("probable", "candidate")}
        if not found:
            continue
        bodies = "\n".join(r[2] for r in found.values()).lower()
        cand_profiles = {}
        for pname, (verdict, url, body) in found.items():
            if verdict == "probable" and body:
                prof = extract_profile(pname, body, cand)
                if prof:
                    cand_profiles[pname] = prof
        cand_profiles_all[cand] = cand_profiles
        uid = ctx.graph.node("username", cand, "candidate", "A3")
        ctx.graph.edge(per_id, uid, "DERIVED_FROM_NAME", "candidate",
                       f"handle generated from the name '{name}'")
        classes = {}
        if core_name and core_name in bodies:
            classes["profile-name-match"] = (
                "a found profile displays the full name")
        for term in context_terms:
            if term in bodies:
                classes["context-mention"] = (
                    f"a found profile mentions query context '{term}'")
                break
        if len(found) >= 3:
            classes["handle-exact"] = (
                f"consistent presence on {len(found)} platforms")
        if cand in gh_logins:
            classes["search-match"] = (
                "GitHub user search for the name returns this handle")
        linked_ids = [i for prof in cand_profiles.values()
                      for i in (prof.get("identifiers") or [])]
        if linked_ids:
            classes["cross-link"] = (
                "an extracted profile field links a typed "
                "cross-platform identifier ("
                + ", ".join(sorted({i.get("value", "")
                                     for i in linked_ids})) + ")")
        # WS-B: entity extraction over gate-passed profile bodies.
        cand_emails = set()
        for pname, (verdict, url, body) in found.items():
            if verdict == "probable" and body:
                site_id = ctx.graph.node("website", pname, "info",
                                         "A3")
                ent = _extract_entities(ctx, body, url, site_id,
                                        subject_handles=subject_handles)
                cand_emails |= ent["emails"]
        if any(e.split("@")[0] == cand.lower() for e in cand_emails):
            classes["email-match"] = (
                "an email address published on a found profile page "
                "uses this handle")
        websites = set()
        for prof in cand_profiles.values():
            w = str(prof.get("website") or "").strip()
            if w:
                h = _query_host(w if "://" in w else "https://" + w)
                if h:
                    websites.add(passive_mod._registrable(h))
        records[cand] = {"found": found, "profiles": cand_profiles,
                         "uid": uid, "classes": classes,
                         "websites": websites}

    # WS-E: avatar matching across all gate-passed profiles found.
    avatar_items = []
    for cand, rec in records.items():
        for pname, prof in rec["profiles"].items():
            if prof.get("avatar_url"):
                avatar_items.append({"handle": cand, "platform": pname,
                                     "avatar_url": prof["avatar_url"],
                                     "node_id": rec["uid"]})
    if ctx.stop_requested():
        av_meta = {"compared": 0, "matched": 0,
                   "skipped": len(avatar_items), "matches": [],
                   "status": "not evaluated — scan stopped"}
        av_pairs = []
    else:
        av_meta, av_pairs = _avatar_matching(ctx, avatar_items)
    ctx.meta["avatar_match"] = av_meta
    if av_pairs:
        for cand, rec in records.items():
            for ha, _pa, hb, _pb in av_pairs:
                if cand.lower() in (ha.lower(), hb.lower()):
                    rec["classes"]["same-avatar"] = (
                        "the same (near-)identical profile avatar "
                        "appears on another found profile")
                    break
    # website-match: a profile website equals a resolving
    # name-derived domain, or two candidates publish the same site.
    site_owners = {}
    for cand, rec in records.items():
        for d in rec["websites"]:
            site_owners.setdefault(d, set()).add(cand)
    for cand, rec in records.items():
        for d in sorted(rec["websites"]):
            if d in guess_regs or len(site_owners.get(d, ())) > 1:
                rec["classes"]["website-match"] = (
                    f"a found profile's website matches '{d}'")
                break
    # email-match from the run-wide extracted set (a page fetched
    # for one candidate can corroborate another).
    for cand, rec in records.items():
        if "email-match" not in rec["classes"]:
            if any(e.split("@")[0] == cand.lower()
                   for e in ctx.extracted_emails):
                rec["classes"]["email-match"] = (
                    "an email address extracted from a fetched "
                    "public page uses this handle")

    # Finalize: verdicts, findings, graph edges (unchanged texts).
    for cand in candidates:
        rec = records.get(cand)
        if not rec:
            continue
        found = rec["found"]
        cand_profiles = rec["profiles"]
        uid = rec["uid"]
        classes = rec["classes"]
        class_list = [k for k in _SIGNAL_CLASS_ORDER if k in classes]
        signals = [classes[k] for k in class_list]
        corroborated = len(class_list) >= 2
        if corroborated:
            id_meta["corroborated"].append(cand)
        ctx.graph.node_attr(uid, signals=class_list)
        if cand_profiles:
            ctx.graph.node_attr(uid, profiles={
                p: compact_profile(pr)
                for p, pr in cand_profiles.items()})
        for pname, (verdict, url, _body) in sorted(found.items()):
            site_id = ctx.graph.node("website", pname, "info", "A3")
            edge_conf = ("probable" if (corroborated and verdict == "probable")
                         else "candidate")
            ctx.graph.edge(uid, site_id, "FOUND_ON", edge_conf,
                           f"control-gated platform check; identity signals: {len(signals)}")
            if edge_conf == "probable":
                ctx.graph.node("username", cand, "probable", "A3")
            if corroborated and verdict == "probable":
                add(F("INFO", f"Name-derived account '{cand}' on {pname} (identity corroborated)",
                      f"This account was derived from the name '{name}' and its identity is corroborated by {len(signals)} independent signals ({', '.join(class_list)}): {'; '.join(signals)}. The platform also passed the junk-handle control check.",
                      evidence=f"{url} (control check passed; signals: {'; '.join(signals)})",
                      cwe="", owasp="", cvss=0.0,
                      remed="Confirm this account belongs to the person before relying on it.",
                      confidence="probable", location=url,
                      origin="passive"))
                conf = "probable"
            else:
                add(F("INFO", f"Name-derived candidate '{cand}' on {pname} — identity NOT verified",
                      f"Handle '{cand}' was generated from the name '{name}' (a guess, not a known account) and a profile-like response exists on {pname}. Identity corroboration signals found: {len(signals)} ({'; '.join(signals) if signals else 'none'}) — below the >=2 required to call this the person's account. Treat as an unverified candidate.",
                      evidence=f"{url} (name-derived candidate, identity NOT verified)",
                      cwe="", owasp="", cvss=0.0,
                      remed="Manually verify the profile before treating this account as belonging to the person.",
                      confidence="candidate", location=url,
                      origin="passive"))
                conf = "candidate"
            _entry = {"candidate": cand, "platform": pname,
                      "platform_verdict": verdict, "confidence": conf,
                      "signals": signals,
                      "signal_classes": class_list}
            if pname in cand_profiles:
                _entry["profile"] = compact_profile(cand_profiles[pname])
            id_meta["accounts"].append(_entry)
    for cand in id_meta["corroborated"]:
        if ctx.stop_requested():
            break
        _pivot_extracted_handles(ctx, cand,
                                 cand_profiles_all.get(cand) or {},
                                 1, {cand})
    ctx.meta["identity"] = id_meta
    L(f"[osint] person pivot: {len(candidates)} name-derived candidate(s), "
      f"{len(id_meta['accounts'])} account(s) found, "
      f"{len(id_meta['corroborated'])} corroborated (>=2 signals)")

    # WS-A: web mentions, contextualized ONLY by what the pivots
    # already discovered (companies / locations on found profiles,
    # plus the query's own extra name words).
    mctx = []
    for profs in cand_profiles_all.values():
        for p in profs.values():
            for k in ("company", "location"):
                v = str(p.get(k) or "").strip().split(",")[0].strip()
                if v and v not in mctx:
                    mctx.append(v)
    if not ctx.stop_requested():
        _web_mentions(ctx, core_name or name, per_id,
                      context_terms=(mctx[:2] + context_terms[:1]),
                      kind="name", subject_handles=subject_handles)


def _institution_pivot(ctx, name):
    """Institution pivot: DoH-validated official-domain guesses, GitHub
    organization search, and a CT identity search. Failed guesses are
    reported, never silently dropped."""
    L, add = ctx.L, ctx.add
    guesses = _institution_domain_guesses(name)
    inst_meta = {"name": name, "guesses": guesses, "resolved": [],
                 "failed_guesses": [], "confirmed_domain": None,
                 "github_orgs": [], "ct_domains": []}
    ctx.pivots.append(f"institution:{name}")
    org_id = ctx.graph.node("organization", name, "info", "A2")
    ctx.graph.edge(ctx.root_id, org_id, "LINKED_TO", "candidate",
                   "query interpreted as an institution name")
    for g in guesses:
        if _doh_ips(g):
            inst_meta["resolved"].append(g)
        else:
            inst_meta["failed_guesses"].append(g)
    if inst_meta["resolved"]:
        confirmed = inst_meta["resolved"][0]
        inst_meta["confirmed_domain"] = confirmed
        for other in inst_meta["resolved"][1:]:
            o_id = ctx.graph.node("domain", other, "candidate", "A2")
            ctx.graph.edge(org_id, o_id, "OWNS_DOMAIN", "candidate",
                           "name-derived domain guess; also resolves via DoH")
        add(F("INFO", f"Likely official domain for '{name}': {confirmed}",
              "This domain was generated from the institution name and validated with DNS-over-HTTPS (it really resolves). It is a strong candidate for the official domain — the full domain OSINT below treats it as the pivot target. Resolution alone does not prove ownership; corroborate with the RDAP/CT evidence in the domain results.",
              evidence=f"{confirmed} resolves via DoH (A records present) | losing guesses: {', '.join(inst_meta['failed_guesses']) or '-'}",
              cwe="", owasp="", cvss=0.0,
              remed="No action required; informational.",
              confidence="probable", location=confirmed, origin="passive"))
        if len(inst_meta["resolved"]) > 1:
            add(F("INFO", f"Other name-derived domains for '{name}' that also resolve",
                  "Additional domain guesses generated from the institution name that also resolve via DoH. They may be regional/secondary domains or unrelated registrants.",
                  evidence="; ".join(inst_meta["resolved"][1:]) + " | source: DoH A",
                  cwe="", owasp="", cvss=0.0,
                  remed="Verify which domains are really operated by the institution.",
                  confidence="candidate", location=confirmed,
                  origin="passive"))
    elif guesses:
        add(F("INFO", f"Institution domain could not be confirmed for '{name}'",
              "Domain guesses generated from the institution name were validated with DNS-over-HTTPS and NONE of them resolve. The institution may use a different name/domain pattern, or the guesses are simply wrong — they are reported here instead of being silently dropped.",
              evidence="failed guesses: " + ", ".join(guesses) + " | source: DoH A (no records)",
              cwe="", owasp="", cvss=0.0,
              remed="Provide the official domain directly for a full domain OSINT.",
              confidence="candidate", location=name, origin="passive"))
    L(f"[osint] institution pivot: {len(guesses)} guess(es), "
      f"resolved={inst_meta['resolved']}")

    # GitHub organization search
    st, _h, raw = ctx.fetch(
        "https://api.github.com/search/users?q="
        + quote(name) + "+type:org&per_page=5",
        timeout=15, verify=True,
        headers={"Accept": "application/vnd.github+json"})
    if st == 200 and raw:
        try:
            items = (json.loads(raw.decode("utf-8", "replace"))
                     .get("items") or [])
        except Exception:
            items = []
        inst_meta["github_orgs"] = [it.get("login", "") for it in items]
        if items:
            for it in items[:5]:
                o_id = ctx.graph.node("organization", it.get("login", ""),
                                      "candidate", "A4")
                ctx.graph.edge(org_id, o_id, "LINKED_TO", "candidate",
                               "GitHub organization search match for the name")
            add(F("INFO", f"GitHub organizations matching '{name}'",
                  "Public GitHub organizations returned by the GitHub user search for this institution name.",
                  evidence="; ".join(
                      f"{it.get('login')} ({it.get('html_url')})"
                      for it in items[:5]) + " | source: GitHub search API",
                  cwe="", owasp="", cvss=0.0,
                  remed="Confirm which organization is official; impersonation orgs are a phishing risk.",
                  confidence="probable", location=name, origin="passive"))
    elif st in (403, 429):
        ctx.warn(f"institution: GitHub organization search rate-limited/refused (HTTP {st}) — not evaluated")
    else:
        ctx.warn(f"institution: GitHub organization search unavailable (HTTP {st}) — not evaluated")

    # Certificate Transparency identity search (crt.sh identity query)
    st, _h, raw = ctx.fetch(
        f"https://crt.sh/?q={quote(name)}&output=json",
        timeout=20, verify=True)
    if st == 200 and raw:
        try:
            rows = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            rows = None
        if isinstance(rows, list):
            domains = set()
            for row in rows[:300]:
                for n in str(row.get("name_value", "")).splitlines():
                    n = n.strip().lower().lstrip("*.")
                    if n and "." in n:
                        domains.add(passive_mod._registrable(n))
            inst_meta["ct_domains"] = sorted(domains)[:10]
            if domains:
                for d in inst_meta["ct_domains"]:
                    d_id = ctx.graph.node("domain", d, "candidate", "A2")
                    ctx.graph.edge(org_id, d_id, "MENTIONS", "candidate",
                                   "certificate identity search (crt.sh) carries this name")
                add(F("INFO", f"Certificates mentioning '{name}' (CT identity search)",
                      "Registrable domains whose publicly logged certificates carry this institution name in their identity fields. A certificate mention does not prove the institution operates the domain.",
                      evidence="; ".join(inst_meta["ct_domains"]) + " | source: crt.sh identity search",
                      cwe="", owasp="", cvss=0.0,
                      remed="Cross-check these domains against the institution's official asset list.",
                      confidence="candidate", location=name,
                      origin="passive"))
        else:
            ctx.warn("institution: crt.sh identity response could not be parsed — not evaluated")
    else:
        ctx.warn(f"institution: crt.sh identity search unavailable (HTTP {st}) — not evaluated")
    ctx.meta["institution"] = inst_meta

    if inst_meta["confirmed_domain"] and not ctx.stop_requested():
        domain = passive_mod._registrable(inst_meta["confirmed_domain"])
        ctx.pivots.append(f"domain:{domain}")
        _domain_osint(ctx, inst_meta["confirmed_domain"], domain)
        if ctx.domain_node:
            ctx.graph.edge(org_id, ctx.domain_node, "OWNS_DOMAIN",
                           "candidate",
                           "name-derived domain guess validated by DoH resolution")

    # WS-A (v1.6.0): web mentions for the institution name itself.
    if ctx.stop_requested():
        return
    _web_mentions(ctx, name, org_id,
                  context_terms=([inst_meta["confirmed_domain"]]
                                 if inst_meta.get("confirmed_domain")
                                 else []),
                  kind="institution")


# ------------------------------------------------------------------- module

def run_osint_recon(target, log=None, opts=None, _fetch=None, _platforms=None,
                    cancelled=None):
    """Universal deep OSINT.

    The subject is `opts['query']` when present (free text: person
    name, institution, domain, email, handle, or IP); otherwise the
    legacy `target` is used (domain/URL -> the original domain flow;
    other identifier shapes are detected the same way). Legacy callers
    passing a domain target and opts like {'handle': ...} get exactly
    the previous behaviour.

    _fetch/_platforms exist for hermetic tests; in production _fetch is
    passive._fetch_bytes and platforms are live.

    v1.6.1: `cancelled` is an optional callable -> bool (operator
    stop). Every pivot polls it (together with the soft time budget:
    opts['time_budget_s'] or env PTK_OSINT_TIME_BUDGET_S, default
    900s; <= 0 disables). When either fires, the run stops within
    seconds and returns the partial results gathered so far, with
    meta['coverage']['status'] recording 'cancelled' or
    'time_budget_exceeded' — partial is stated, never hidden."""
    opts = opts or {}
    fetch = _fetch or passive_mod._fetch_bytes
    budget_s = opts.get("time_budget_s")
    if budget_s is None:
        try:
            budget_s = float(os.environ.get(
                "PTK_OSINT_TIME_BUDGET_S", "900"))
        except Exception:
            budget_s = 900.0
    try:
        budget_s = float(budget_s)
    except Exception:
        budget_s = 900.0
    if budget_s <= 0:
        budget_s = None

    def L(msg):
        if log is None:
            return
        if callable(log):
            log(msg)
        else:
            log.append(msg)

    subject = str(opts.get("query") or target or "").strip()
    if not subject:
        raise ValueError("OSINT query/target is empty")
    dtype = detect_query_type(subject)
    if dtype == "empty":
        raise ValueError("OSINT query/target is empty")
    started = time.time()
    ctx = _Ctx(fetch, L, opts, _platforms, cancelled=cancelled,
               deadline=(started + budget_s) if budget_s else None,
               budget_s=budget_s)
    meta = ctx.meta
    meta["query"] = subject
    meta["detected_type"] = dtype
    ctx.root_id = ctx.graph.node(
        "query", subject, "info",
        {"domain": "A1", "ip": "A1", "email": "A3",
         "handle": "A3", "name": "A3", "phone": "F3",
         "wallet": "F2"}.get(dtype, "A1"))
    L(f"[osint] universal OSINT query: {subject} — detected type: {dtype} "
      f"(public lookups only)")

    if dtype == "domain":
        host = _query_host(subject)
        if not host:
            raise ValueError("target has no hostname")
        domain = passive_mod._registrable(host)
        ctx.pivots.append(f"domain:{domain}")
        _domain_osint(ctx, host, domain)
        if ctx.domain_node:
            ctx.graph.edge(ctx.root_id, ctx.domain_node, "LINKED_TO",
                           "probable", "query detected as a domain")
    elif dtype == "ip":
        _ip_pivot(ctx, _query_host(subject) or subject)
    elif dtype == "email":
        _email_pivot(ctx, subject)
    elif dtype == "handle":
        _handle_pivot(ctx, subject)
    elif dtype == "wallet":
        _wallet_pivot(ctx, subject)
    elif dtype == "phone":
        _phone_pivot(ctx, subject)
    else:  # name phrase — person AND institution pivots both run
        _person_pivot(ctx, subject)
        if not ctx.stop_requested():
            _institution_pivot(ctx, subject)
        # WS-D (v1.6.0): email permutator over corroborated domains.
        if not ctx.stop_requested():
            _email_permutator(ctx, subject)
        # F1 (v1.11.0): sanctions screening of the query name itself
        # (name-only matches stay candidate + labelled, by design).
        if not ctx.stop_requested():
            _sanctions_check_name(ctx, subject, "the query name itself")

    findings, warnings = ctx.findings, ctx.warnings
    meta["pivots_run"] = ctx.pivots
    graph, graph_stats = ctx.graph.build()
    meta["graph"] = graph
    meta["graph_stats"] = graph_stats
    meta["graph_truncated"] = ctx.graph.truncated
    L(f"[osint] graph: {graph_stats['nodes']} nodes, "
      f"{graph_stats['edges']} edges"
      + (" (TRUNCATED at node cap)" if ctx.graph.truncated else ""))
    # v1.6.0 coverage statement: what was actually searched (and
    # what could not be evaluated) — the honest replacement for any
    # claim of completeness.
    engines_cov = {}
    if isinstance(meta.get("mentions"), dict):
        engines_cov = meta["mentions"].get("engines") or {}
    not_eval = []
    for eng, stt in sorted(engines_cov.items()):
        if stt != "ok":
            not_eval.append(f"web mentions ({eng})")
    if (meta.get("archive") or {}).get("status") == "not evaluated":
        not_eval.append("web archive history (Wayback CDX)")
    if (meta.get("passivedns") or {}).get("status") == "not evaluated":
        not_eval.append("passive DNS (HackerTarget)")
    if ((meta.get("identity") or {}).get("github_search_status")
            == "not evaluated"):
        not_eval.append("GitHub name search")
    _sanc_cov = meta.get("sanctions") or {}
    if _sanc_cov.get("status") == "not evaluated":
        not_eval.append("sanctions screening (OpenSanctions snapshot: "
                        + (_sanc_cov.get("reason") or "unavailable")
                        + ")")
    _wal_cov = meta.get("wallet") or {}
    if isinstance(_wal_cov.get("summary"), str):
        not_eval.append("wallet on-chain summary (public ledger API)")
    if meta.get("phone"):
        not_eval.append("phone carrier / line-type / owner enrichment "
                        "(not performed by design — structural parse "
                        "only)")
    if ctx.stop_reason == "time_budget":
        not_eval.append("remaining OSINT modules (soft time budget "
                        "exceeded — not evaluated)")
    meta["coverage"] = {
        "platforms_checked": len(ctx.stats["platforms_checked"]),
        "platforms_active": (len(ctx.platforms)
                             if ctx.platforms is not None
                             else len(active_platforms())),
        "search_engines": engines_cov,
        "pages_fetched": ctx.stats["pages_fetched"],
        "entities_extracted": ctx.stats["entities_extracted"],
        "modules_not_evaluated": not_eval,
    }
    # v1.6.1: run status — a stopped run says so, with its budget.
    meta["coverage"]["status"] = (
        "cancelled" if ctx.stop_reason == "cancelled"
        else "time_budget_exceeded" if ctx.stop_reason == "time_budget"
        else "complete")
    meta["coverage"]["time_budget_s"] = budget_s
    meta["stopped_reason"] = ctx.stop_reason
    if ctx.stop_reason:
        L(f"[osint] stopped early ({ctx.stop_reason}) — returning "
          f"partial results: {len(findings)} finding(s), "
          f"{len(ctx.stats['platforms_checked'])} platform(s) checked")
    if not findings:
        warnings.append(
            "coverage: this run produced no findings — see the "
            "coverage statement for what was actually searched; an "
            "empty result is NOT evidence that the subject has no "
            "public presence")
    meta["sections"] = {k: meta[k] for k in (
        "infra", "ct", "wayback", "username", "code_exposure", "breach",
        "ip", "email", "gravatar", "identity", "institution",
        "archive", "passivedns", "typosquat", "reputation",
        "email_checks", "mentions", "email_candidates",
        "avatar_match", "sanctions", "phone", "wallet", "telegram",
        "coverage")
        if k in meta}
    summary = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    risk = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                 if summary.get(s)), "CLEAN")
    score = risk_score(findings)
    meta["elapsed_s"] = round(time.time() - started, 1)
    for w in warnings:
        L(f"[osint] WARNING: {w}")
    L(f"[osint] done: {len(findings)} findings | risk {risk} | score {score}/100")
    return {"type": "osint", "target": target, "query": subject,
            "detected_type": dtype, "profile": "osint-deep",
            "method": "passive", "findings": findings, "summary": summary,
            "overall_risk": risk, "risk_score": score, "meta": meta,
            "endpoints": [], "warnings": warnings, "errors": []}
