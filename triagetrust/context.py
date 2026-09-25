"""Extract the code a triager needs to see: a window around each relevant line."""
from __future__ import annotations

import re
from pathlib import Path

_LICENSE_BLOCK = re.compile(r"^/\*\*.*?\*/\s*", re.S)


def read_source(root: str | Path, rel: str) -> str:
    root = Path(root)
    candidates = [root / rel, root / rel.lstrip("/")]
    candidates += list(root.rglob(Path(rel).name))[:3] if rel else []
    for c in candidates:
        if c.is_file():
            return c.read_text(encoding="utf-8", errors="replace")
    return ""


def strip_header(src: str) -> str:
    """Drop a leading licence comment so the model spends tokens on code."""
    return _LICENSE_BLOCK.sub("", src, count=1)


def window(src: str, lines: list[int], radius: int = 25, max_lines: int = 220) -> str:
    """Return numbered source around the given 1-based lines, merged into one excerpt."""
    all_lines = src.splitlines()
    if not all_lines:
        return ""
    if not lines:
        lines = [1]
    keep: set[int] = set()
    for ln in lines:
        lo, hi = max(1, ln - radius), min(len(all_lines), ln + radius)
        keep.update(range(lo, hi + 1))
    out, prev = [], None
    for i in sorted(keep)[:max_lines]:
        if prev is not None and i != prev + 1:
            out.append("   ...")
        out.append(f"{i:5d}  {all_lines[i - 1]}")
        prev = i
    return "\n".join(out)


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments from C-family code, keeping strings and line numbers intact.

    Test suites and real codebases both carry comments such as "get safe value back out" or
    "TODO: sanitize this". A triager that reads them is grading the comment, not the code, and
    its benchmark score overstates how it behaves on unannotated code.
    """
    out: list[str] = []
    i, n = 0, len(src)
    in_str: str | None = None
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(nxt)
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in "\"'":
            in_str = c
            out.append(c)
            i += 1
            continue
        if c == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and nxt == "*":
            end = src.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append("\n" * src.count("\n", i, end))
            i = end
            continue
        out.append(c)
        i += 1
    return "\n".join(line.rstrip() for line in "".join(out).split("\n"))
