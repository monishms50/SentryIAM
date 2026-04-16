import uuid
import enum
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timezone
from app.database import Base

class RoleEnum(enum.Enum):
    admin = "admin"
    user = "user"

class User(Base):
    __tablename__ = "users"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email          = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role           = Column(Enum(RoleEnum), nullable=False, default=RoleEnum.user)
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    failed_attempts = Column(Integer, default=0)
    locked_until   = Column(DateTime(timezone=True), nullable=True)
