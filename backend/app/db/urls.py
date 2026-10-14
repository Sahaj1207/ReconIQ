"""
Database URL normalization.

Hosted Postgres providers hand out URLs like `postgres://...?sslmode=require&supa=base-pooler.x`.
SQLAlchemy needs an explicit driver, and libpq rejects provider-specific query parameters.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# libpq connection parameters we pass through; anything else (e.g. `supa`, `pgbouncer`) is dropped
LIBPQ_PARAMS = {"sslmode", "sslrootcert", "connect_timeout", "application_name", "options", "target_session_attrs"}


def normalize_database_url(url: str) -> str:
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    if url.startswith("postgresql+psycopg://"):
        parts = urlsplit(url)
        query = [(k, v) for k, v in parse_qsl(parts.query) if k in LIBPQ_PARAMS]
        url = urlunsplit(parts._replace(query=urlencode(query)))
    return url


def is_transaction_pooler(url: str) -> bool:
    """Supabase / PgBouncer transaction poolers listen on 6543 and can't hold prepared statements."""
    try:
        return url.startswith("postgresql") and urlsplit(url).port == 6543
    except ValueError:
        return False
