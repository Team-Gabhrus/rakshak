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
