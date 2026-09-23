#!/usr/bin/env python3
"""Reject private local directories in the Git index and public documentation links."""
from pathlib import Path
import re
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(
    ["git", "ls-files", "-z"], cwd=root
).decode("utf-8", errors="surrogateescape").split("\0")
private_roots = {"devnotes", "evaluations"}
violations = [
    f"private directory is tracked: {name}"
    for name in tracked if name and name.split("/", 1)[0].lower() in private_roots
]
for filename in ("README.md", "RELEASE.md", "CHANGELOG.md"):
    text = (root / filename).read_text()
    if re.search(r"\]\([^\n)]*(?:devnotes|evaluations)/", text, re.IGNORECASE):
        violations.append(f"{filename} links to private local material")
if violations:
    print("FAIL repository privacy policy", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    sys.exit(1)
print("PASS no private directories tracked or linked from public documentation")
