"""
Alembic environment. Runs online against the connection handed over by app.db.database
(or, from the CLI, against the application's configured database URL).
"""

from alembic import context

from app.db.database import Base, engine
from app.db import models  # noqa: F401  (register tables on Base.metadata)

target_metadata = Base.metadata


def run() -> None:
    connection = context.config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        return
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


run()
