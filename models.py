from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from db import Base


class APIKey(Base):
    """
    Read-only model for API keys.
    Worker uses this to validate incoming requests.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, nullable=False, index=True)
    is_active = Column(Boolean, default=True)
    project_id = Column(Integer, nullable=False)


class TrafficLog(Base):
    """
    Stores sampled request metadata for observability and dashboards.
    """
    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, nullable=False)
    ip_address = Column(String, nullable=False)
    path = Column(String, nullable=False)
    decision = Column(String, nullable=False)  # ALLOW / BLOCK / THROTTLE
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class BlockedIP(Base):
    """
    Tracks IPs temporarily or permanently blocked by the worker.
    """
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    api_key_id = Column(Integer, nullable=False)
    ip_address = Column(String, nullable=False)
    reason = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
