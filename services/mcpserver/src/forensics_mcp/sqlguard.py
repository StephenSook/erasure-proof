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


def assert_single_select(query: str) -> str:
    """Return the normalized query if it is a single read-only statement, else raise ValueError."""
    q = query.strip().rstrip(";").strip()
    if not q:
        raise ValueError("empty query")
    if ";" in q:
        raise ValueError("only a single statement is allowed")
    low = q.lower()
    if not low.startswith(_ALLOWED_PREFIXES):
        raise ValueError("only SELECT, WITH, SHOW, EXPLAIN, TABLE, or VALUES is allowed")
    if _FORBIDDEN.search(low):
        raise ValueError("statement contains a forbidden data-modifying or DDL keyword")
    return q
