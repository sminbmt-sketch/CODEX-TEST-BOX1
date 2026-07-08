import asyncio
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AutomationSetting, AuditLog, Vulnerability
from app.db.session import SessionLocal
from app.services.news_sources import collect_rss_feeds
from app.services.vulnerability_sources import collect_nvd_recent_feed, update_epss_scores


SCHEDULER_STATE: dict[str, object] = {
    "running": False,
    "last_checked_at": None,
    "last_error": None,
}


def get_automation_setting(db: Session) -> AutomationSetting:
    row = db.scalar(select(AutomationSetting).order_by(AutomationSetting.id.asc()))
    if row is None:
        row = AutomationSetting()
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _tz(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return ZoneInfo("Asia/Seoul")


def _should_run(setting: AutomationSetting, now_utc: datetime) -> bool:
    if not setting.enabled:
        return False
    now = now_utc.astimezone(_tz(setting.timezone))
    try:
        hour, minute = [int(part) for part in setting.run_time.split(":", maxsplit=1)]
    except ValueError:
        hour, minute = 9, 0
    if now.hour != hour or now.minute != minute:
        return False
    if setting.last_run_at and now_utc - setting.last_run_at < timedelta(hours=23):
        return False
    if setting.frequency == "weekly" and setting.day_of_week is not None and now.weekday() != setting.day_of_week:
        return False
    if setting.frequency == "monthly" and setting.day_of_month is not None and now.day != setting.day_of_month:
        return False
    return True


def _recent_cve_ids(db: Session, days: int) -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return list(
        db.scalars(
            select(Vulnerability.cve_id)
            .where(Vulnerability.published_at >= cutoff)
            .order_by(Vulnerability.published_at.desc().nullslast())
        ).all()
    )


async def run_automation_once(db: Session, setting: AutomationSetting) -> dict[str, int]:
    result = {"cve_fetched": 0, "cve_updated": 0, "epss_fetched": 0, "epss_updated": 0, "news_fetched": 0, "news_updated": 0}
    if setting.cve_enabled:
        fetched, updated = await collect_nvd_recent_feed(db)
        result["cve_fetched"] = fetched
        result["cve_updated"] = updated
        cve_ids = _recent_cve_ids(db, setting.collection_days)
        if cve_ids:
            epss_fetched, epss_updated = await update_epss_scores(db, cve_ids)
            result["epss_fetched"] = epss_fetched
            result["epss_updated"] = epss_updated
    if setting.news_enabled:
        fetched, updated = await collect_rss_feeds(db, days=setting.collection_days)
        result["news_fetched"] = fetched
        result["news_updated"] = updated
    setting.last_run_at = datetime.now(timezone.utc)
    db.add(AuditLog(action="automation_run", target="schedule", detail=result))
    db.commit()
    return result


async def scheduler_loop() -> None:
    SCHEDULER_STATE["running"] = True
    try:
        while True:
            SCHEDULER_STATE["last_checked_at"] = datetime.now(timezone.utc)
            db = SessionLocal()
            try:
                setting = get_automation_setting(db)
                if _should_run(setting, datetime.now(timezone.utc)):
                    await run_automation_once(db, setting)
                    SCHEDULER_STATE["last_error"] = None
            except Exception as exc:
                SCHEDULER_STATE["last_error"] = str(exc)
            finally:
                db.close()
            await asyncio.sleep(60)
    finally:
        SCHEDULER_STATE["running"] = False
