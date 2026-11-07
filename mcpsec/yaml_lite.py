"""Minimal YAML parser — just enough for MCP server maps.

Supports: nested mappings, inline/flow scalars, lists, lists of mappings,
quoted strings, comments. Not a general YAML implementation. The scanner
only needs to walk ``mcpServers`` maps out of config files; anything this
parser can't handle raises ValueError, which surfaces as an "unreadable"
finding rather than a silent misparse.
"""

from __future__ import annotations

import re


class YAMLError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    # A '#' starts a comment only when preceded by whitespace or at start,
    # and not inside quotes.
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _unquote(s: str):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        if s[0] == '"':
            return s[1:-1].encode().decode("unicode_escape")
        return s[1:-1]
    return s


def _parse_flow(s: str):
    """Parse an inline flow value: [a, b] or {k: v} or scalar."""
    s = s.strip()
    if not s:
        return None
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_parse_flow(p) for p in _split_flow(inner)]
    if s.startswith("{") and s.endswith("}"):
        inner = s[1:-1].strip()
        out = {}
        if not inner:
            return out
        for part in _split_flow(inner):
            if ":" in part:
                k, v = part.split(":", 1)
                out[_unquote(k).strip()] = _parse_flow(v)
        return out
    return _unquote(s)


def _split_flow(s: str) -> list[str]:
    parts, depth, cur, in_s, in_d = [], 0, "", False, False
    for ch in s:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
                continue
        cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def parse(text: str) -> dict:
    """Parse the YAML subset into nested dicts/lists/scalars."""
    # Preprocess: drop comments and blank lines, record indentation.
    lines: list[tuple[int, str, int]] = []  # (indent, content, lineno)
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YAMLError(f"tab indentation at line {n}")
        content = _strip_comment(raw)
        if not content.strip():
            continue
        if content.lstrip().startswith(("...", "---")):
            continue
        indent = len(content) - len(content.lstrip())
        lines.append((indent, content.strip(), n))
    if not lines:
        return {}

    pos = 0

    def _block(indent: int):
        """Parse the block whose entries sit at `indent`. Returns obj."""
        nonlocal pos
        if pos >= len(lines):
            return None
        # Determine kind by first entry.
        first = lines[pos][1]
        if first.startswith("- ") or first == "-":
            items = []
            while pos < len(lines) and lines[pos][0] == indent and (
                lines[pos][1].startswith("- ") or lines[pos][1] == "-"
            ):
                _, line, lineno = lines[pos]
                rest = line[1:].strip()
                if not rest:
                    pos += 1
                    items.append(_block(indent + 1) if pos < len(lines) else None)
                elif ": " in rest or rest.endswith(":"):
                    # Inline mapping start on the dash line.
                    key, _, val = rest.partition(":")
                    val = val.strip()
                    pos += 1
                    d = {key.strip(): _parse_flow(val) if val else None}
                    # Continuation lines belong to same item (deeper indent).
                    while pos < len(lines) and lines[pos][0] > indent:
                        sub = _block(lines[pos][0])
                        if isinstance(sub, dict):
                            d.update(sub)
                        else:
                            break
                    items.append(d)
                else:
                    pos += 1
                    items.append(_parse_flow(rest))
            return items
        # Mapping.
        result = {}
        while pos < len(lines) and lines[pos][0] == indent:
            _, line, lineno = lines[pos]
            if line.startswith("- "):  # shouldn't happen in mapping context
                break
            if ":" not in line:
                raise YAMLError(f"line {lineno}: expected 'key: value'")
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val:
                result[key] = _parse_flow(val)
            elif pos < len(lines) and lines[pos][0] > indent:
                result[key] = _block(lines[pos][0])
            else:
                result[key] = None
        return result

    root_indent = lines[0][0]
    result = _block(root_indent)
    if pos < len(lines):
        raise YAMLError(f"line {lines[pos][2]}: unexpected indentation")
    if not isinstance(result, dict):
        raise YAMLError("top level is not a mapping")
    return result
