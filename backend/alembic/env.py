from logging.config import fileConfig
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from alembic import context
from app.models import Base
config=context.config
target_metadata=Base.metadata

def do_run_migrations(connection: Connection):
    context.configure(connection=connection,target_metadata=target_metadata,compare_type=True)
    with context.begin_transaction(): context.run_migrations()
async def run_async_migrations():
    connectable=async_engine_from_config(config.get_section(config.config_ini_section),prefix='sqlalchemy.',poolclass=pool.NullPool)
    async with connectable.connect() as connection: await connection.run_sync(do_run_migrations)
    await connectable.dispose()
def run_migrations_online():
    import asyncio; asyncio.run(run_async_migrations())
run_migrations_online()
