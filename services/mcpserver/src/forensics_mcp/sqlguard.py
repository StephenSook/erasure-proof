"""A parse gate that allows only a single read-only statement.

This is defense in depth. The real guarantee is the database role: the server connects as a
SELECT-only role in a read-only transaction, so a mutation cannot execute even if it slipped past
this gate. The gate exists so a mutation is refused before it ever reaches the database, and so a
data-modifying CTE (WITH x AS (INSERT ...)) is rejected by keyword.
"""

from __future__ import annotations

import re

# Keywords that must never appear as their own word in a read-only query (covers data-modifying
# CTEs, DDL, and privilege changes). Word boundaries mean column names like `created_at` or
# `delete_flag` do not trip it.
_FORBIDDEN = re.compile(
    r"\b(insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|call|do|merge|upsert)\b",
    re.IGNORECASE,
)

_ALLOWED_PREFIXES = ("select", "with", "show", "explain", "table", "values")


def _blank_literals_and_comments(q: str) -> str:
    """Replace single-quoted string literals and SQL comments with spaces.

    The keyword and single-statement guards must scan SQL structure, not data: a read-only query
    whose data happens to contain a forbidden word (`WHERE action = 'delete'`) or a semicolon
    (`SELECT ';'`) is legitimate and must not be refused. Structure is preserved (lengths change but
    keywords, semicolons, and the leading statement word are untouched) so the guards stay strict.
    Dollar-quoted strings are not handled here; the SELECT-only role in a read-only transaction is
    the hard guarantee, this gate is defense in depth.
    """
    out: list[str] = []
    i, n = 0, len(q)
    while i < n:
        c = q[i]
        if c == "'":  # single-quoted string literal, '' is an escaped quote
            i += 1
            while i < n:
                if q[i] == "'":
                    if i + 1 < n and q[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append(" ")
        elif c == "-" and i + 1 < n and q[i + 1] == "-":  # -- line comment
            while i < n and q[i] != "\n":
                i += 1
            out.append(" ")
        elif c == "/" and i + 1 < n and q[i + 1] == "*":  # /* block comment */
            i += 2
            while i + 1 < n and not (q[i] == "*" and q[i + 1] == "/"):
                i += 1
            i += 2
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def assert_single_select(query: str) -> str:
    """Return the normalized query if it is a single read-only statement, else raise ValueError."""
    q = query.strip().rstrip(";").strip()
    if not q:
        raise ValueError("empty query")
    scan = _blank_literals_and_comments(q)  # scan structure only, not string data or comments
    if ";" in scan:
        raise ValueError("only a single statement is allowed")
    low = scan.lower()
    if not low.lstrip().startswith(_ALLOWED_PREFIXES):
        raise ValueError("only SELECT, WITH, SHOW, EXPLAIN, TABLE, or VALUES is allowed")
    if _FORBIDDEN.search(low):
        raise ValueError("statement contains a forbidden data-modifying or DDL keyword")
    # subject_keys holds the wrapped key material, the crown jewels of the crypto-shred. The
    # free-form tool never reads it, even under the judge bearer; the purpose-built
    # confirm_key_destroyed tool answers the only forensic question that table has.
    if re.search(r"\bsubject_keys\b", low):
        raise ValueError(
            "subject_keys is not readable through run_readonly_sql; use confirm_key_destroyed"
        )
    return q
