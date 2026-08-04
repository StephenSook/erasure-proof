import pytest

from forensics_mcp.sqlguard import assert_single_select


def test_allows_read_only_statements():
    assert assert_single_select("SELECT 1").lower().startswith("select")
    assert_single_select("WITH x AS (SELECT 1) SELECT * FROM x")
    assert_single_select("EXPLAIN SELECT 1")
    assert_single_select("SHOW TABLES")


@pytest.mark.parametrize(
    "q",
    [
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET a = 1",
        "DELETE FROM decision_log",
        "DROP TABLE subject_keys",
        "ALTER TABLE t ADD COLUMN c INT",
        "GRANT SELECT ON t TO r",
        "SELECT 1; DROP TABLE t",
        "WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x",
        "",
    ],
)
def test_rejects_mutations_ddl_and_multistatement(q):
    with pytest.raises(ValueError):
        assert_single_select(q)


def test_column_names_with_keyword_substrings_are_allowed():
    # created_at and delete_flag contain 'create'/'delete' as substrings but not as words.
    assert_single_select("SELECT created_at, delete_flag FROM agent_memory")


@pytest.mark.parametrize(
    "q",
    [
        "SELECT 'I do'",
        "SELECT count(*) FROM decision_log WHERE action = 'delete'",
        "SELECT id FROM agent_memory WHERE content ILIKE '%please call me%'",
        "SELECT ';' AS semicolon_in_a_string",
        "SELECT 1 -- delete this later\n",
        "SELECT /* drop */ 1",
    ],
)
def test_allows_forbidden_words_and_semicolons_inside_literals_and_comments(q):
    # Keywords or semicolons appearing only as string data or in comments are legitimate reads.
    assert assert_single_select(q)


@pytest.mark.parametrize(
    "q",
    [
        "DELETE FROM t WHERE note = 'safe'",
        "WITH x AS (INSERT INTO t VALUES ('a') RETURNING *) SELECT * FROM x",
        "SELECT ';'; DROP TABLE t",
    ],
)
def test_still_rejects_real_mutations_even_with_literals(q):
    with pytest.raises(ValueError):
        assert_single_select(q)


def test_subject_keys_denied_via_free_form_sql() -> None:
    import pytest

    from forensics_mcp import sqlguard

    with pytest.raises(ValueError, match="subject_keys"):
        sqlguard.assert_single_select("SELECT wrapped_key FROM subject_keys")
    # The word inside a string literal is data, not an identifier, and stays allowed.
    sqlguard.assert_single_select("SELECT 1 WHERE 'subject_keys' = 'subject_keys'")
