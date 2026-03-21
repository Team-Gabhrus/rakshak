import asyncio
import logging
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select
from app.config import settings
from app.models.report import ScheduledReport
from app.services.export_service import generate_report_file
import json
from app.services.email_service import send_report_email

logger = logging.getLogger(__name__)
engine = create_async_engine(settings.DATABASE_URL)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def check_scheduled_reports():
    while True:
        try:
            async with AsyncSessionLocal() as db:
                now = datetime.utcnow()
                result = await db.execute(select(ScheduledReport).where(ScheduledReport.is_active == True))
                reports = result.scalars().all()
                for report in reports:
                    if not report.next_run or now >= report.next_run:
                        logger.info(f"Running scheduled report {report.id} ({report.title})")
                        modules = json.loads(report.modules_json)
                        file_path = await generate_report_file(db, modules, report.format.value, f"sched_{report.id}", report.password if report.password_protected else None)
                        
                        if report.delivery_channel.value == "email" and report.delivery_target:
                            await send_report_email(
                                to_email=report.delivery_target,
                                subject=f"Scheduled Rakshak Report: {report.title}",
                                body="Please find attached your scheduled report.",
                                attachment_path=file_path
                            )
                            
                        report.last_run = now
                        if report.frequency.value == "daily":
                            report.next_run = now + timedelta(days=1)
                        elif report.frequency.value == "weekly":
                            report.next_run = now + timedelta(days=7)
                        elif report.frequency.value == "monthly":
                            report.next_run = now + timedelta(days=30)
                        await db.commit()
        except Exception as e:
            logger.error(f"Error checking scheduled reports: {e}")
            
        await asyncio.sleep(60)

