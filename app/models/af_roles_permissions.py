import uuid
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class AfRolePermission(Base):
    __tablename__ = "af_role_permissions"

    __table_args__ = (
        Index("ix_role_perms_perm", "af_perm_id"),
        Index("ix_role_perms_role", "af_role_id"),
        {"schema": "public"},
    )

    af_role_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_roles.af_role_id", ondelete="CASCADE"),
        primary_key=True
    )

    af_perm_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_permissions.af_perm_id"),
        primary_key=True
    )

    role = relationship(
        "AfRole",
        back_populates="role_permissions"
    )

    permission = relationship(
        "AfPermission",
        back_populates="role_permissions"
    )

    # -------------------------
    # Índices
    # -------------------------

    __table_args__ = (
        Index("ix_role_perms_perm", "af_perm_id"),
        Index("ix_role_perms_role", "af_role_id"),
    )