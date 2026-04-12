import asyncio
from app.database import AsyncSessionLocal
from app.models.asset import Asset
from sqlalchemy import select

async def check():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Asset).limit(10))
        assets = res.scalars().all()
        for a in assets:
            print(f"URL: {a.url}, Name: {a.name}")

if __name__ == "__main__":
    asyncio.run(check())
