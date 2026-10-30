#!/usr/bin/env python3
"""Insert the to-dos of paper-todos.json into a copy of the paper's chapter.

Usage: scripts/apply-paper-todos.py CHAPTER.tex [--write]

Each to-do is placed by text, not by line number, so it applies to any version of the chapter
that still has its anchor: after the first line at or below the (unique) anchor line that
contains `after`, or right after the anchor line when `after` is null. Every to-do becomes its
own paragraph, `\\atodo[inline]{...}` preceded by a blank line. A to-do already present is
skipped, so rerunning is safe. Without --write, prints the unified diff and changes nothing.
Exits 1 if an anchor is missing or repeated, an `after` line is not found, or a text has
unbalanced braces; 2 on bad usage.
"""

import difflib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent.parent
USAGE = "usage: scripts/apply-paper-todos.py CHAPTER.tex [--write]"


def balanced(text: str) -> bool:
    depth = 0
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def main(argv: list[str]) -> int:
    if not argv or len(argv) > 2 or (len(argv) == 2 and argv[1] != "--write"):
        print(USAGE, file=sys.stderr)
        return 2
    chapter = pathlib.Path(argv[0])
    data = json.loads((HERE / "paper-todos.json").read_text(encoding="utf-8"))
    lines = chapter.read_text(encoding="utf-8").splitlines(keepends=True)
    inserts: dict[int, list[str]] = {}
    errors = 0
    for todo in data["todos"]:
        line = f"{data['macro']}{{{todo['text']}}}\n"
        if not balanced(todo["text"]):
            print(f"{todo['id']}: unbalanced braces", file=sys.stderr)
            errors += 1
            continue
        if line in lines:
            continue
        hits = [i for i, text in enumerate(lines) if todo["anchor"] in text]
        if len(hits) != 1:
            print(f"{todo['id']}: anchor found {len(hits)} times: {todo['anchor']}", file=sys.stderr)
            errors += 1
            continue
        at = hits[0]
        if todo["after"] is not None:
            below = [i for i in range(at, len(lines)) if todo["after"] in lines[i]]
            if not below:
                print(f"{todo['id']}: no line with {todo['after']!r} below the anchor",
                      file=sys.stderr)
                errors += 1
                continue
            at = below[0]
        inserts.setdefault(at, []).extend(["\n", line])
    if errors:
        return 1
    out: list[str] = []
    for i, text in enumerate(lines):
        out.append(text)
        out.extend(inserts.get(i, []))
    if len(argv) == 2:
        chapter.write_text("".join(out), encoding="utf-8")
        print(f"apply-paper-todos: {sum(len(v) // 2 for v in inserts.values())} to-dos written")
    else:
        sys.stdout.writelines(difflib.unified_diff(lines, out, str(chapter), str(chapter)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
