#!/usr/bin/env python3
"""Check that no file in this directory copies Sinka Tibor's Lean work.

Usage: scripts/check-distinct.py REF_DIR [REF_DIR ...]

Each REF_DIR is a checkout of a reference (argos-formal main, its pull requests, the
reconstruction in fabric-vdr-core). The check fails when a file here is byte-identical to a
reference file, or when RUN consecutive meaningful lines of a file here, compared with
whitespace removed, also occur consecutively in a reference file. Lines shorter than
MIN_CHARS after normalisation (`end`, `by`, blank lines, lone brackets) are skipped, and
files under MIN_LINES meaningful lines (`lean-toolchain`, `.gitignore`) are exempt from the
whole-file check. Exits 0 when distinct, 1 when a match is found, 2 on bad usage.
"""

import hashlib
import pathlib
import sys

RUN = 4
MIN_CHARS = 12
MIN_LINES = 3
SUFFIXES = {".lean", ".md", ".sh", ".py", ".toml", ".json", ".yml", ".diff", ""}
SKIP_DIRS = {".lake", "tools", ".git", "build", "logs"}
HERE = pathlib.Path(__file__).resolve().parent.parent
USAGE = "usage: scripts/check-distinct.py REF_DIR [REF_DIR ...]"


def files(root: pathlib.Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in SUFFIXES and not SKIP_DIRS & set(p.relative_to(root).parts):
            yield p


def meaningful(path: pathlib.Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    lines = ("".join(line.split()) for line in text.splitlines())
    return [line for line in lines if len(line) >= MIN_CHARS]


def main(argv: list[str]) -> int:
    if not argv:
        print(USAGE, file=sys.stderr)
        return 2
    refs = [pathlib.Path(a).resolve() for a in argv]
    for ref in refs:
        if not ref.is_dir():
            print(f"not a directory: {ref}", file=sys.stderr)
            return 2

    digests: dict[str, pathlib.Path] = {}
    shingles: dict[tuple[str, ...], pathlib.Path] = {}
    for ref in refs:
        for p in files(ref):
            lines = meaningful(p)
            if len(lines) >= MIN_LINES:
                digests[hashlib.sha256(p.read_bytes()).hexdigest()] = p
            for i in range(len(lines) - RUN + 1):
                shingles.setdefault(tuple(lines[i : i + RUN]), p)

    found = 0
    for p in files(HERE):
        rel = p.relative_to(HERE)
        lines = meaningful(p)
        twin = digests.get(hashlib.sha256(p.read_bytes()).hexdigest())
        if twin and len(lines) >= MIN_LINES:
            print(f"{rel}: identical to {twin}")
            found += 1
            continue
        for i in range(len(lines) - RUN + 1):
            src = shingles.get(tuple(lines[i : i + RUN]))
            if src:
                print(f"{rel}: {RUN} lines from meaningful line {i + 1} also occur in {src}")
                found += 1
                break
    if found:
        print(f"check-distinct: {found} file(s) overlap the references", file=sys.stderr)
        return 1
    print(f"check-distinct: OK ({len(refs)} references)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
