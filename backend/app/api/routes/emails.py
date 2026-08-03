from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
import imaplib

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import EmailMessage, EmailSetting
from app.db.session import get_db
from app.schemas import EmailCollectionRequest, EmailCollectionResult, EmailMessageOut

router = APIRouter(prefix="/emails", tags=["emails"])


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _text_payload(message) -> str:
    parts = message.walk() if message.is_multipart() else [message]
    html_fallback = ""
    for part in parts:
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except LookupError:
            text = payload.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            return " ".join(text.split())[:5000]
        html_fallback = " ".join(text.split())[:5000]
    return html_fallback


def _apply_filters(query, q: str | None = None, sender: str | None = None):
    if q:
        like = f"%{q}%"
        query = query.where(
            EmailMessage.subject.ilike(like)
            | EmailMessage.sender.ilike(like)
            | EmailMessage.body_excerpt.ilike(like)
        )
    if sender:
        query = query.where(EmailMessage.sender.ilike(f"%{sender}%"))
    return query


@router.get("/count", response_model=int)
def count_emails(
    q: str | None = None,
    sender: str | None = None,
    db: Session = Depends(get_db),
) -> int:
    return db.scalar(_apply_filters(select(func.count(EmailMessage.id)), q=q, sender=sender)) or 0


@router.get("", response_model=list[EmailMessageOut])
def list_emails(
    q: str | None = None,
    sender: str | None = None,
    sort: str = Query(default="date", pattern="^(date|name)$"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[EmailMessageOut]:
    query = _apply_filters(select(EmailMessage), q=q, sender=sender)
    order_by = (EmailMessage.subject.asc(), EmailMessage.received_at.desc().nullslast()) if sort == "name" else (
        EmailMessage.received_at.desc().nullslast(),
        EmailMessage.created_at.desc(),
    )
    rows = db.scalars(query.order_by(*order_by).offset(offset).limit(limit)).all()
    return [EmailMessageOut.model_validate(row) for row in rows]


@router.post("/collect", response_model=EmailCollectionResult)
def collect_emails(payload: EmailCollectionRequest, db: Session = Depends(get_db)) -> EmailCollectionResult:
    setting = db.scalar(select(EmailSetting).order_by(EmailSetting.id.asc()))
    if setting is None or not setting.smtp_host or not setting.smtp_username or not setting.smtp_password:
        raise HTTPException(status_code=400, detail="Email host, username, and password are required in Settings.")

    result = EmailCollectionResult()
    port = 993 if setting.use_tls else 143
    try:
        if setting.use_tls:
            client = imaplib.IMAP4_SSL(setting.smtp_host, port)
        else:
            client = imaplib.IMAP4(setting.smtp_host, port)
        client.login(setting.smtp_username, setting.smtp_password)
        client.select("INBOX")
        status, search_data = client.search(None, "FROM", f'"{payload.sender}"')
        if status != "OK":
            raise RuntimeError("IMAP search failed")
        ids = search_data[0].split()[-payload.limit :]
        result.fetched = len(ids)
        for message_number in ids:
            status, data = client.fetch(message_number, "(RFC822)")
            if status != "OK" or not data or not isinstance(data[0], tuple):
                continue
            message = message_from_bytes(data[0][1])
            message_id = message.get("Message-ID") or f"{setting.smtp_username}:{message_number.decode(errors='ignore')}"
            row = db.scalar(select(EmailMessage).where(EmailMessage.message_id == message_id))
            if row is None:
                row = EmailMessage(message_id=message_id)
            row.sender = _decode_header(message.get("From"))
            row.recipients = _decode_header(message.get("To"))
            row.subject = _decode_header(message.get("Subject")) or "(no subject)"
            row.body_excerpt = _text_payload(message)
            try:
                row.received_at = parsedate_to_datetime(message.get("Date")) if message.get("Date") else None
            except Exception:
                row.received_at = None
            row.raw_headers = {
                "from": row.sender,
                "to": row.recipients,
                "date": message.get("Date"),
            }
            db.add(row)
            result.created_or_updated += 1
        client.logout()
        db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=f"Email collection failed: {exc}") from exc
    return result
