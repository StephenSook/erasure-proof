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
