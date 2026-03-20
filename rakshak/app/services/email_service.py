import aiosmtplib
from email.message import EmailMessage
import os
import mimetypes
from app.config import settings
import logging

logger = logging.getLogger(__name__)

async def send_report_email(to_email: str, subject: str, body: str, attachment_path: str = None):
    """Sends an email with an optional attachment using aiosmtplib."""
    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.warning("SMTP credentials not fully set. Skipping email dispatch.")
        return

    msg = EmailMessage()
    msg["From"] = settings.SMTP_USER  # using the authenticating user as 'From' to avoid spam blocks
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    if attachment_path and os.path.exists(attachment_path):
        ctype, encoding = mimetypes.guess_type(attachment_path)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        
        with open(attachment_path, "rb") as f:
            msg.add_attachment(f.read(), maintype=maintype, subtype=subtype, filename=os.path.basename(attachment_path))

    try:
        logger.info(f"Sending email to {to_email} via {settings.SMTP_HOST}:{settings.SMTP_PORT}")
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            use_tls=(settings.SMTP_PORT == 465),
            start_tls=(settings.SMTP_PORT == 587)
        )
        logger.info(f"Report emailed successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        raise e
