import ast, re, os, subprocess
os.chdir('/home/hatch/workspace/vanthex')
MODS = ['osint', 'osintwatch', 'ctstream', 'predator', 'breachoracle', 'attackpath',
        'avatardeanon', 'asnorbit', 'mobilemirror', 'globe_feeds', 'globe_recon',
        'globe_warmer', 'globe_fetch_daemon', 'globe_fetch_helper']
files = ['tests/test_v1130.py','tests/test_v1131.py','tests/test_v1132.py','tests/test_v1133.py','tests/test_v1140.py','tests/test_v1150.py','tests/test_v1151.py','tests/test_v1152.py','tests/test_v1160.py','tests/test_v1170.py','tests/test_v1180.py','tests/test_v1190.py','tests/test_v1200.py','tests/test_v1210.py','tests/test_v1240.py','tests/test_v1250.py']
# restore originals from git before re-running alias-aware removal
subprocess.run(['git', 'checkout', '--'] + files, check=False)
for f in files:
    lines = open(f).read().splitlines(keepends=True)
    tree = ast.parse(''.join(lines))
    aliases = set(MODS)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split('.')[0] in MODS:
                    aliases.add(a.asname or a.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split('.')[0] in MODS:
            for a in node.names:
                aliases.add(a.asname or a.name)
    pat = re.compile(r'\b(?:%s)\b' % '|'.join(re.escape(a) for a in aliases), re.I)
    drop = set()
    removed, total = [], 0
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = min([d.lineno for d in node.decorator_list] + [node.lineno])
            seg = ''.join(lines[start-1:node.end_lineno])
            if isinstance(node, ast.ClassDef):
                # only drop class if named test or entire class matches
                pass
            if node.name.startswith('test') or isinstance(node, ast.ClassDef):
                total += node.name.startswith('test')
            if pat.search(seg):
                drop.update(range(start-1, node.end_lineno))
                if node.name.startswith('test'):
                    removed.append(node.name)
    src = ''.join(l for i, l in enumerate(lines) if i not in drop)
    for m in list(aliases):
        src = re.sub(r'^import %s[^\n]*\n' % re.escape(m), '', src, flags=re.M)
        src = re.sub(r'^from %s[^\n]*\n' % re.escape(m), '', src, flags=re.M)
    open(f, 'w').write(src)
    remaining = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test') and n.name not in removed]
    # check remaining tests still use aliases
    still = [n.name for n in remaining if pat.search(ast.get_source_segment(src, n) or '')]
    try:
        compile(src, f, 'exec'); ok = 'OK'
    except SyntaxError as e:
        ok = 'SYNTAX ERR line %s' % e.lineno
    print(f, 'removed %d/%d tests' % (len(removed), total), 'still-ref:', still[:5], ok)
