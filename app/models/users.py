"""
Modelo ORM para usuarios del sistema.

Gestiona información de autenticación, estado de seguridad
y auditoría de usuarios.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    Integer,
    DateTime,
    ForeignKey,
    func
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, INET
from app.core.database import Base


class Users(Base):
    """
    Modelo ORM que representa un usuario del sistema.

    Almacena credenciales, estado de seguridad, auditoría
    y metadatos de acceso.
    """
    __tablename__ = "users"
    __table_args__ = {"schema": "public"}

    # Identificador único del usuario
    user_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    # Correo electrónico del usuario
    email = Column(Text, nullable=False, unique=True, index=True)
    # Nombre completo del usuario
    name = Column(String(120), nullable=False)
    # Hash de la contraseña
    password_hash = Column(Text, nullable=False)
    # Estado del usuario definido en catálogo
    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )
    # Indica si MFA está habilitado
    is_mfa_enabled = Column(Boolean, nullable=False, default=False)
    # Fechas de creación y actualización
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    updated_at = Column(DateTime(timezone=True))
    # Número de intentos fallidos de autenticación
    failed_attempts = Column(Integer, nullable=False, default=0)
    # Fecha de bloqueo del usuario
    locked_at = Column(DateTime(timezone=True))
    # Usuario que creó el registro
    last_login_at = Column(DateTime(timezone=True))
    # Usuario que actualizó el registro
    last_login_ip = Column(INET)
    # Fecha de eliminación lógica
    deleted_at = Column(DateTime(timezone=True))
    # Usuario que creó el registro
    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )
    # Usuario que actualizó el registro
    updated_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id")
    )
    # Fecha de verificación del email
    email_verified_at = Column(DateTime(timezone=True))
    # Fecha del último cambio de contraseña
    password_changed_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
    
    #Número de identidad
    identity_number= Column(Text, nullable=False, unique=True)
    
    # Versión del registro para control de concurrencia
    row_version = Column(Integer, default=1)
    #Tiempo de bloqueo
    blocked_until = Column(DateTime(timezone=True))
    
    sessions = relationship(
        "AuthSession",
        back_populates="user",
        cascade="all, delete-orphan"
    )
