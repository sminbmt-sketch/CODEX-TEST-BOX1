from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import TaniumSensor
from app.services.tanium_client import TaniumGatewayClient


CORE_READ_ONLY_SENSORS = [
    {
        "name": "Computer Name",
        "description": "Endpoint hostname used to correlate Tanium results with SecureWatch inventory.",
        "category": "Identity",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Computer Name"],
    },
    {
        "name": "Tanium Client IP Address",
        "description": "Endpoint IP address reported by the Tanium Client.",
        "category": "Identity",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Tanium Client IP Address"],
    },
    {
        "name": "Installed Applications",
        "description": "Installed software names and versions.",
        "category": "Software",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Name", "Version"],
    },
    {
        "name": "Running Processes",
        "description": "Running process names on endpoints.",
        "category": "Process",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Running Processes"],
    },
    {
        "name": "Services",
        "description": "Service inventory and state.",
        "category": "Service",
        "platform": "Windows/Linux",
        "parameters": [],
        "result_columns": ["Name", "Display Name", "Status"],
    },
    {
        "name": "Open Ports",
        "description": "Listening/open network ports.",
        "category": "Network",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Port", "Protocol", "Process"],
    },
    {
        "name": "Kernel Version",
        "description": "Linux/Unix kernel version or OS kernel release.",
        "category": "OS",
        "platform": "Linux/Unix",
        "parameters": [],
        "result_columns": ["Kernel Version"],
    },
    {
        "name": "Kernel Modules",
        "description": "Loaded kernel modules. Useful for Open vSwitch and driver-level exposure checks.",
        "category": "OS",
        "platform": "Linux/Unix",
        "parameters": [],
        "result_columns": ["Kernel Modules"],
    },
    {
        "name": "File Exists",
        "description": "Checks whether a given file path exists on endpoints. Parameterized as File Exists[path].",
        "category": "File",
        "platform": "All",
        "parameters": [{"name": "path", "type": "string", "required": True}],
        "result_columns": ["File Exists"],
    },
    {
        "name": "MAC Address",
        "description": "Endpoint MAC address values.",
        "category": "Network",
        "platform": "All",
        "parameters": [],
        "result_columns": ["MAC Address"],
    },
    {
        "name": "Chassis Type",
        "description": "Hardware chassis type.",
        "category": "Hardware",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Chassis Type"],
    },
    {
        "name": "Is Virtual",
        "description": "Virtual machine indicator.",
        "category": "Hardware",
        "platform": "All",
        "parameters": [],
        "result_columns": ["Is Virtual"],
    },
]


def _string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _list_payload(data: dict[str, Any] | list[Any]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    payload = data.get("data") if isinstance(data, dict) else None
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("sensors", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    for key in ("sensors", "items", "results"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _sensor_name(item: dict[str, Any]) -> str | None:
    return _string(item.get("name") or item.get("display_name") or item.get("sensor_name"))


def _normalize_sensor(item: dict[str, Any], source: str) -> dict[str, Any] | None:
    name = _sensor_name(item)
    if not name:
        return None
    return {
        "name": name,
        "description": _string(item.get("description") or item.get("help") or item.get("notes")),
        "category": _string(item.get("category") or item.get("content_set") or item.get("contentSet")),
        "platform": _string(item.get("platform") or item.get("supported_platforms") or item.get("platforms")),
        "parameters": item.get("parameters") or item.get("parameterDefinitions") or [],
        "result_columns": item.get("columns") or item.get("result_columns") or item.get("resultColumns") or [],
        "source": source,
        "usable": True,
        "raw": item,
    }


async def fetch_tanium_sensor_catalog() -> tuple[list[dict[str, Any]], str, list[str]]:
    client = TaniumGatewayClient()
    errors: list[str] = []
    if not client.configured:
        return [], "fallback", ["tanium_not_configured"]

    for path in ("/api/v2/sensors", "/api/v2/sensors?limit=10000", "/api/v2/sensor"):
        try:
            data = await client.execute_rest("GET", path)
        except Exception as exc:
            errors.append(f"{path}: {exc}")
            continue
        sensors = [_normalize_sensor(item, "tanium_rest") for item in _list_payload(data)]
        sensors = [sensor for sensor in sensors if sensor]
        if sensors:
            return sensors, "tanium_rest", errors
    return [], "fallback", errors


def seed_core_sensors(db: Session) -> int:
    now = datetime.now(timezone.utc)
    changed = 0
    for item in CORE_READ_ONLY_SENSORS:
        row = db.scalar(select(TaniumSensor).where(TaniumSensor.name == item["name"]))
        if row is None:
            row = TaniumSensor(name=item["name"])
            db.add(row)
            changed += 1
        row.description = item["description"]
        row.category = item["category"]
        row.platform = item["platform"]
        row.parameters = item["parameters"]
        row.result_columns = item["result_columns"]
        row.source = "fallback"
        row.usable = True
        row.last_seen_at = now
        row.raw = item
    db.commit()
    return changed


async def sync_tanium_sensors(db: Session) -> tuple[int, int, str, list[str]]:
    sensors, source, errors = await fetch_tanium_sensor_catalog()
    if not sensors:
        changed = seed_core_sensors(db)
        return len(CORE_READ_ONLY_SENSORS), changed, "fallback", errors

    now = datetime.now(timezone.utc)
    changed = 0
    for item in sensors:
        row = db.scalar(select(TaniumSensor).where(TaniumSensor.name == item["name"]))
        if row is None:
            row = TaniumSensor(name=item["name"])
            db.add(row)
        row.description = item.get("description")
        row.category = item.get("category")
        row.platform = item.get("platform")
        row.parameters = item.get("parameters") or []
        row.result_columns = item.get("result_columns") or []
        row.source = item.get("source") or source
        row.usable = bool(item.get("usable", True))
        row.last_seen_at = now
        row.raw = item.get("raw") or item
        changed += 1
    db.commit()
    if len(sensors) < len(CORE_READ_ONLY_SENSORS):
        changed += seed_core_sensors(db)
    return len(sensors), changed, source, errors


def relevant_sensor_candidates(db: Session, terms: list[str], limit: int = 30) -> list[dict[str, Any]]:
    if not db.scalar(select(TaniumSensor.id).limit(1)):
        seed_core_sensors(db)
    cleaned = [term.strip() for term in terms if term and len(term.strip()) >= 2]
    query = select(TaniumSensor).where(TaniumSensor.usable.is_(True))
    if cleaned:
        filters = []
        for term in cleaned[:20]:
            pattern = f"%{term}%"
            filters.append(TaniumSensor.name.ilike(pattern))
            filters.append(TaniumSensor.description.ilike(pattern))
            filters.append(TaniumSensor.category.ilike(pattern))
        query = query.where(or_(*filters))
    rows = db.scalars(query.order_by(TaniumSensor.category.asc().nullslast(), TaniumSensor.name.asc()).limit(limit)).all()
    if len(rows) < min(8, limit):
        core_names = [item["name"] for item in CORE_READ_ONLY_SENSORS]
        core_rows = db.scalars(
            select(TaniumSensor)
            .where(TaniumSensor.name.in_(core_names), TaniumSensor.usable.is_(True))
            .order_by(TaniumSensor.name.asc())
            .limit(limit)
        ).all()
        merged = {row.name: row for row in [*rows, *core_rows]}
        rows = list(merged.values())[:limit]
    return [
        {
            "name": row.name,
            "description": row.description,
            "category": row.category,
            "platform": row.platform,
            "parameters": row.parameters or [],
            "result_columns": row.result_columns or [],
        }
        for row in rows
    ]
