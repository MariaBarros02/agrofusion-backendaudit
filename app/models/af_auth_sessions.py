from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from app.core.database import Base
import uuid
from datetime import datetime, timezone


class AuthSession(Base):
    """
    Modelo de sesión de autenticación.

    Representa una sesión activa del usuario dentro del sistema,
    utilizada para:
    - Control de acceso
    - Expiración de sesiones
    - Revocación de tokens
    - Auditoría de actividad
    """
    __tablename__ = "af_auth_sessions"
    __table_args__ = {"schema": "public"}

    # Identificador único de la sesión SSO
    sso_session_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Usuario propietario de la sesión
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=False
    )

    # Fecha de emisión de la sesión
    issued_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Fecha de expiración de la sesión
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )

    # Dirección IP asociada a la sesión
    ip = Column(INET)

    # User-Agent del cliente
    user_agent = Column(Text)

    # Última actividad registrada en la sesión
    last_activity_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Fecha de terminación explícita de la sesión (logout, cierre forzado)
    terminated_at = Column(DateTime(timezone=True))

    # Relaciones ORM
    user = relationship(
        "Users",
        back_populates="sessions"
    )

    tokens = relationship(
        "AuthToken",
        back_populates="session",
        cascade="all, delete-orphan"
    )
