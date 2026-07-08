import smtplib
from email.message import EmailMessage

from app.db.models import EmailSetting


def recipient_list(setting: EmailSetting) -> list[str]:
    if not setting.recipients:
        return []
    return [item.strip() for item in setting.recipients.replace(";", ",").split(",") if item.strip()]


def send_email(setting: EmailSetting, subject: str, body: str) -> None:
    if not setting.enabled:
        raise ValueError("Email delivery is disabled")
    if not setting.smtp_host or not setting.sender:
        raise ValueError("SMTP host and sender are required")
    recipients = recipient_list(setting)
    if not recipients:
        raise ValueError("At least one recipient is required")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = setting.sender
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    with smtplib.SMTP(setting.smtp_host, setting.smtp_port, timeout=30) as smtp:
        if setting.use_tls:
            smtp.starttls()
        if setting.smtp_username and setting.smtp_password:
            smtp.login(setting.smtp_username, setting.smtp_password)
        smtp.send_message(message)
