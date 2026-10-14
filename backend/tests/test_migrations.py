"""
Schema migration tests.
"""

from sqlalchemy import create_engine, inspect, text

from app.db.database import run_migrations
from app.db.urls import is_transaction_pooler, normalize_database_url


def test_fresh_database_migrates_to_head(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    run_migrations(eng)
    run_migrations(eng)  # idempotent
    tables = set(inspect(eng).get_table_names())
    assert {"investigations", "users", "audit_events", "investigation_jobs", "alembic_version"} <= tables


def test_pre_migration_database_is_stamped_not_recreated(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with eng.begin() as conn:  # schema as created by the old create_all()
        conn.execute(text(
            "CREATE TABLE investigations (id VARCHAR(36) PRIMARY KEY, created_at DATETIME, status VARCHAR(32), "
            "source_type VARCHAR(32), source_name VARCHAR(255), input_preview TEXT, score FLOAT, severity VARCHAR(16), "
            "classification VARCHAR(64), ioc_count INTEGER, result JSON)"))
        conn.execute(text("INSERT INTO investigations (id, status, source_type, input_preview, score, severity, "
                          "classification, ioc_count, result) VALUES ('keep-me', 'success', 'raw_text', '', 0, "
                          "'LOW', 'x', 0, '{}')"))
    run_migrations(eng)
    with eng.connect() as conn:
        assert conn.execute(text("SELECT id FROM investigations")).scalar() == "keep-me"
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() is not None


def test_url_normalization():
    url = normalize_database_url("postgres://u:p@db.pooler.supabase.com:6543/postgres?sslmode=require&supa=base-pooler.x")
    assert url == "postgresql+psycopg://u:p@db.pooler.supabase.com:6543/postgres?sslmode=require"
    assert is_transaction_pooler(url)
    assert normalize_database_url("sqlite:///./x.db") == "sqlite:///./x.db"
