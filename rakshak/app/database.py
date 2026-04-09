from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from app.config import settings


engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    """Create all tables on startup."""
    from app.models import user, asset, scan, cbom, report, audit, webhook, chat  # noqa
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Hackathon-friendly alter table to add OTP columns without migration tools
    from sqlalchemy import text
    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE users ADD COLUMN otp_code VARCHAR(6)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN otp_expiry DATETIME"))
    except Exception:
        pass # Columns already exist
    
    # Add domain_context_json column to chat_sessions
    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE chat_sessions ADD COLUMN domain_context_json TEXT"))
    except Exception:
        pass # Column already exists

    # Add domain column to chat_sessions
    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE chat_sessions ADD COLUMN domain VARCHAR(255)"))
    except Exception:
        pass # Column already exists

    # Older deployed SQLite databases created chat_sessions.asset_id as NOT NULL.
    # Rebuild the table once so domain-only chat sessions can be stored safely.
    try:
        async with engine.begin() as conn:
            rows = await conn.execute(text("PRAGMA table_info(chat_sessions)"))
            columns = rows.fetchall()
            asset_id_col = next((row for row in columns if row[1] == "asset_id"), None)
            if asset_id_col and int(asset_id_col[3] or 0) == 1:
                await conn.execute(text("PRAGMA foreign_keys=OFF"))
                await conn.execute(text("""
                    CREATE TABLE chat_sessions_new (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        asset_id INTEGER,
                        title VARCHAR(255) NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        created_at DATETIME NOT NULL,
                        updated_at DATETIME NOT NULL,
                        message_count INTEGER NOT NULL DEFAULT 0,
                        domain_context_json TEXT,
                        domain VARCHAR(255),
                        FOREIGN KEY(user_id) REFERENCES users (id),
                        FOREIGN KEY(asset_id) REFERENCES assets (id)
                    )
                """))
                await conn.execute(text("""
                    INSERT INTO chat_sessions_new (
                        id, user_id, asset_id, title, status, created_at, updated_at,
                        message_count, domain_context_json, domain
                    )
                    SELECT
                        id, user_id, asset_id, title, status, created_at, updated_at,
                        message_count, domain_context_json, domain
                    FROM chat_sessions
                """))
                await conn.execute(text("DROP TABLE chat_sessions"))
                await conn.execute(text("ALTER TABLE chat_sessions_new RENAME TO chat_sessions"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_chat_sessions_user_id ON chat_sessions (user_id)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_chat_sessions_asset_id ON chat_sessions (asset_id)"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_chat_sessions_created_at ON chat_sessions (created_at)"))
                await conn.execute(text("PRAGMA foreign_keys=ON"))
    except Exception:
        pass

    # Add asset_ids_json column to reports
    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE reports ADD COLUMN asset_ids_json TEXT"))
    except Exception:
        pass

    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE scheduled_reports ADD COLUMN asset_ids_json TEXT"))
    except Exception:
        pass

    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE reports ADD COLUMN domains_json TEXT"))
    except Exception:
        pass

    try:
        async with engine.begin() as conn:
            await conn.execute(text("ALTER TABLE scheduled_reports ADD COLUMN domains_json TEXT"))
    except Exception:
        pass

    try:
        async with engine.begin() as conn:
            await conn.execute(text("""
                UPDATE scan_results
                SET asset_id = (
                    SELECT assets.id
                    FROM assets
                    WHERE assets.url = scan_results.target_url
                    LIMIT 1
                )
                WHERE asset_id IS NULL
            """))
            await conn.execute(text("""
                UPDATE cbom_snapshots
                SET asset_id = (
                    SELECT assets.id
                    FROM assets
                    WHERE assets.url = cbom_snapshots.target_url
                    LIMIT 1
                )
                WHERE asset_id IS NULL
            """))
    except Exception:
        pass
