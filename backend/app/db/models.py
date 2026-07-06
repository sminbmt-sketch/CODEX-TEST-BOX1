from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.session import Base


JsonType = JSON().with_variant(JSONB(), "postgresql")


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(50), index=True)
    url: Mapped[str | None] = mapped_column(Text)
    license_note: Mapped[str | None] = mapped_column(Text)
    trust_score: Mapped[float] = mapped_column(Float, default=0.5)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    articles: Mapped[list["Article"]] = relationship(back_populates="source")


class Article(Base):
    __tablename__ = "articles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id"))
    title: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text, unique=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    raw_excerpt: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[dict | list | None] = mapped_column(JsonType)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    source: Mapped[Source | None] = relationship(back_populates="articles")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(32), index=True)
    epss_score: Mapped[float | None] = mapped_column(Float, index=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    vendor: Mapped[str | None] = mapped_column(String(200), index=True)
    product: Mapped[str | None] = mapped_column(String(200), index=True)
    affected_versions: Mapped[dict | list | None] = mapped_column(JsonType)
    references: Mapped[dict | list | None] = mapped_column(JsonType)
    source_url: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    detections: Mapped[list["Detection"]] = relationship(back_populates="vulnerability")


class EndpointSnapshot(Base):
    __tablename__ = "endpoint_snapshots"
    __table_args__ = (UniqueConstraint("tanium_endpoint_id", "hostname", name="uq_endpoint_identity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tanium_endpoint_id: Mapped[str | None] = mapped_column(String(128), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    os_name: Mapped[str | None] = mapped_column(String(255), index=True)
    os_version: Mapped[str | None] = mapped_column(String(255))
    software: Mapped[dict | list | None] = mapped_column(JsonType)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    raw: Mapped[dict | list | None] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    detections: Mapped[list["Detection"]] = relationship(back_populates="endpoint")


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    endpoint_snapshot_id: Mapped[int] = mapped_column(ForeignKey("endpoint_snapshots.id"), index=True)
    match_reason: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(50), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="detections")
    endpoint: Mapped[EndpointSnapshot] = relationship(back_populates="detections")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(200), default="system", index=True)
    action: Mapped[str] = mapped_column(String(200), index=True)
    target: Mapped[str | None] = mapped_column(String(255), index=True)
    detail: Mapped[dict | list | None] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LlmSetting(Base):
    __tablename__ = "llm_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), default="disabled", index=True)
    base_url: Mapped[str | None] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(String(200))
    api_key: Mapped[str | None] = mapped_column(Text)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=180)
    max_tokens: Mapped[int] = mapped_column(Integer, default=512)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
