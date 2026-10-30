#!/usr/bin/env python3
"""Write Audit.lean from CONTRACT.md's target tables and the axioms Lean reports.

Usage: scripts/gen-audit.py [--dry-run]

For every (Spec, theorem) pair in CONTRACT.md's tables whose theorem exists, Audit.lean gets
`#check (<theorem> : <Spec>)` and a `#guard_msgs in #print axioms <theorem>` pinned to the
axioms Lean prints now. Theorems that do not exist yet are listed and left out; check.sh then
fails on them. Needs `lake` on PATH and the proof modules built. With --dry-run, prints the
file instead of writing it. Exits non-zero if Lean fails.
"""

import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULES = ["Lifecycle.Claims", "Lifecycle.Witnesses", "Lifecycle.Necessity"]
PAIR = re.compile(r"`([A-Za-z0-9]+(?:Spec|Witness))` \| `([a-z0-9_]+)`")


def pairs() -> list[tuple[str, str]]:
    found = []
    for line in (ROOT / "CONTRACT.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("|"):
            found += PAIR.findall(line)
    return found


def lean(source: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".lean", dir=ROOT, delete=False) as f:
        f.write(source)
        path = pathlib.Path(f.name)
    try:
        run = subprocess.run(["lake", "env", "lean", path.name], cwd=ROOT,
                             capture_output=True, text=True)
    finally:
        path.unlink()
    return run.stdout + run.stderr


def main(argv: list[str]) -> int:
    dry = argv == ["--dry-run"]
    if argv and not dry:
        print("usage: scripts/gen-audit.py [--dry-run]", file=sys.stderr)
        return 2
    header = "".join(f"import {m}\n" for m in MODULES) + "\nopen Lifecycle\n\n"
    targets = pairs()
    probe = header + "".join(f"#print axioms {thm}\n" for _, thm in targets)
    out = lean(probe)
    axioms = dict(re.findall(r"'Lifecycle\.([a-z0-9_]+)' (depends on axioms: \[[^\]]*\]|"
                             r"does not depend on any axioms)", out))
    missing = [thm for _, thm in targets if thm not in axioms]
    if re.search(r"error", out) and not missing:
        print(out, file=sys.stderr)
        return 1
    body = [header.rstrip("\n"), ""]
    for spec, thm in targets:
        if thm not in axioms:
            continue
        body += [f"#check ({thm} : {spec})", f"/-- info: 'Lifecycle.{thm}' {axioms[thm]} -/",
                 f"#guard_msgs in #print axioms {thm}", ""]
    text = "\n".join(body)
    if dry:
        print(text)
    else:
        (ROOT / "Audit.lean").write_text(text, encoding="utf-8")
        print(f"gen-audit: {len(targets) - len(missing)} targets written to Audit.lean")
    for thm in missing:
        print(f"gen-audit: not yet a theorem: {thm}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
