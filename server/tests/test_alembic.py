"""Build smoke: every alembic migration declares revision + down_revision
and the chain forms a single linear history.

Catches the "I added 008 but typo'd down_revision='006' instead of '007'"
class of bug, which would silently skip a migration on boot.

Pure ast-parse — no sqlalchemy needed. Sub-millisecond.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSIONS_DIR = Path(HERE) / "alembic" / "versions"


def _module_globals(path: Path) -> dict:
    """ast-parse a Python file and pull out module-level string assignments."""
    tree = ast.parse(path.read_text())
    out: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    if isinstance(node.value, ast.Constant):
                        out[tgt.id] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None and isinstance(node.value, ast.Constant):
                out[node.target.id] = node.value.value
    return out


def test_every_version_declares_revision_metadata():
    failures = []
    for path in sorted(VERSIONS_DIR.glob("[0-9]*.py")):
        try:
            g = _module_globals(path)
            assert "revision" in g, f"{path.name} has no `revision`"
            assert "down_revision" in g, f"{path.name} has no `down_revision`"
            # Migrations should also have upgrade/downgrade functions; cheap text check.
            src = path.read_text()
            assert "def upgrade(" in src, f"{path.name} has no upgrade()"
            assert "def downgrade(" in src, f"{path.name} has no downgrade()"
        except Exception as e:
            failures.append(f"{path.name}: {e!r}")
    assert not failures, f"Alembic version-file failures: {failures}"


def test_revision_chain_is_linear_and_complete():
    versions = []
    for path in sorted(VERSIONS_DIR.glob("[0-9]*.py")):
        g = _module_globals(path)
        versions.append((g["revision"], g["down_revision"]))

    rev_set = {r for r, _ in versions}

    # Exactly one root: down_revision is None.
    roots = [r for r, d in versions if d is None]
    assert len(roots) == 1, f"Expected exactly one root migration, found {roots}"

    # No revision claims a parent that doesn't exist.
    missing = {d for _, d in versions if d is not None} - rev_set
    assert not missing, f"down_revision points to non-existent revision(s): {missing}"

    # No two migrations share a parent (that would be a fork).
    parents = [d for _, d in versions if d is not None]
    duplicates = [p for p in set(parents) if parents.count(p) > 1]
    assert not duplicates, f"Multiple migrations share a parent: {duplicates}"
