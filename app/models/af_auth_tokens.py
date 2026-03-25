# app/models/af_auth_tokens.py
from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base
import uuid
from datetime import datetime, timezone


class AuthToken(Base):
    """
    Modelo de tokens de autenticación.

    Representa los tokens asociados a una sesión de autenticación:
    - Access Token (JWT)
    - Refresh Token

    Permite:
    - Revocación explícita
    - Control de expiración
    - Auditoría de sesiones activas
    """
    __tablename__ = "af_auth_tokens"
    __table_args__ = {"schema": "public"}

    # Identificador único del token
    token_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    # Sesión SSO a la que pertenece el token
    sso_session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_auth_sessions.sso_session_id"),
        nullable=False
    )

    # Access token (JWT)
    access_token = Column(
        Text,
        nullable=False
    )

    # Refresh token (string seguro)
    refresh_token = Column(
        Text,
        nullable=False
    )

    # Fecha de emisión del token
    issued_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Fecha de expiración del access token
    access_expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )

    # Fecha de expiración del refresh token
    refresh_expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )

    # Fecha en que el token fue revocado (si aplica)
    revoked_at = Column(
        DateTime(timezone=True)
    )

    # Motivo de revocación del token
    revoked_reason = Column(
        Text
    )

    # Relación con la sesión de autenticación
    session = relationship(
        "AuthSession",
        back_populates="tokens"
    )
