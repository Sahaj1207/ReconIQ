"""
Database engine, sessions and schema migrations (SQLAlchemy 2.0 + Alembic).

The effective URL comes from DATABASE_URL, else POSTGRES_URL (Vercel storage integrations),
else a local SQLite file. Migrations run automatically on first use, guarded by a Postgres
advisory lock so concurrent serverless cold starts don't race.
"""

import logging
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from app.core.config import settings
from app.db.urls import is_transaction_pooler

logger = logging.getLogger(__name__)
BACKEND_DIR = Path(__file__).resolve().parents[2]
MIGRATION_LOCK_ID = 7_460_301


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    if url.startswith("sqlite"):
        kwargs = {"connect_args": {"check_same_thread": False}}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool  # share one in-memory DB across threads
        return create_engine(url, **kwargs)
    kwargs = {"pool_pre_ping": True}
    if is_transaction_pooler(url):
        kwargs["connect_args"] = {"prepare_threshold": None}  # PgBouncer transaction mode
    if settings.serverless:
        kwargs["poolclass"] = NullPool  # short-lived instances; let the provider pool connections
    return create_engine(url, **kwargs)


engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

_ready = False
_ready_lock = threading.Lock()


def _alembic_config(connection):
    from alembic.config import Config
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.attributes["connection"] = connection
    return cfg


def run_migrations(target_engine=None) -> None:
    """Upgrades the schema to head. Databases created before migrations existed are stamped first."""
    from alembic import command

    with (target_engine or engine).begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:id)"), {"id": MIGRATION_LOCK_ID})
        tables = set(inspect(conn).get_table_names())
        cfg = _alembic_config(conn)
        if "investigations" in tables and "alembic_version" not in tables:
            command.stamp(cfg, "0001")
        command.upgrade(cfg, "head")


def init_db() -> None:
    global _ready
    with _ready_lock:
        if _ready:
            return
        run_migrations()
        _ready = True
        logger.info("Database schema is up to date")


@contextmanager
def session_scope() -> Iterator[Session]:
    init_db()  # lazy: serverless runtimes may not run the ASGI lifespan
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
