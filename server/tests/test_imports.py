"""Build smoke: every LearnAI-fork server module imports cleanly.

Catches three classes of regression:

  * Missing dependency in requirements.txt (the `from x import y` blows
    up at import time).
  * Syntax errors slipped past the pre-commit AST parse.
  * A new module that forgets to expose something other code imports.

Pure-import only. No Postgres, no network, no LLM. Sub-second.
"""

from __future__ import annotations

import importlib
import os
import sys

# Make the server/ directory importable like the running container does.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Set the env vars referenced at import time so module-level code that
# reads them doesn't blow up under pytest. Real values aren't needed.
os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("HISTORY_DB_PATH", "/tmp/test-history.db")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("POSTGRES_PORT", "5432")
os.environ.setdefault("POSTGRES_DB", "test")
os.environ.setdefault("POSTGRES_USER", "test")
os.environ.setdefault("POSTGRES_PASSWORD", "test")


SERVER_MODULES = [
    "auth",
    "db",
    "errors",
    "models",
    "postgres_history",
    "rate_limit",
    "schemas",
    "server_state",
    "telemetry",
    # routers
    "routers.auth",
    "routers.api_keys",
    "routers.entities",
    "routers.requests",
    "routers.learnai_compat",
    "routers.google_auth",
    "routers.user_state",
]


def test_each_server_module_imports():
    failed = []
    for mod_path in SERVER_MODULES:
        try:
            importlib.import_module(mod_path)
        except Exception as e:
            failed.append((mod_path, repr(e)))
    assert not failed, f"Server modules failed to import: {failed}"
