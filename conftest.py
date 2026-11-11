"""Pytest path bootstrap: make bare imports of moved modules work everywhere.

The source tree groups modules into subfolders (webapp/, engine/, tools/,
offensive/, scripts/) but keeps bare module names (`import vulnscan2`,
`import app2`). Insert the project root plus each folder at the FRONT of
sys.path so those imports resolve for pytest regardless of cwd.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
for _sub in ("", "webapp", "engine", "tools", "offensive", "scripts"):
    _p = os.path.join(_ROOT, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)
