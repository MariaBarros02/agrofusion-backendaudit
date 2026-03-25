"""
Modelo ORM para módulos del sistema.

Representa los módulos funcionales de un proyecto.
Cada módulo puede tener submódulos y permisos asociados.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Integer,
    ForeignKey,
    UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AfModule(Base):
    """
    Modelo ORM que representa un módulo del sistema.
    """

    __tablename__ = "af_modules"
    __table_args__ = (
        UniqueConstraint("af_project_id", "code", name="uk_af_modules_code_per_project"),
        {"schema": "public"},
    )

    af_module_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    code = Column(String(60), nullable=False)
    name = Column(String(120), nullable=False)

    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )

    deleted_at = Column(DateTime(timezone=True))

    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    updated_at = Column(DateTime(timezone=True))

    af_project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_projects.af_project_id")
    )

    disabled_at = Column(DateTime(timezone=True))
    description = Column(Text)
    row_version = Column(Integer, default=1)

    # ---------------- RELACIONES ----------------

    status = relationship("CatTerm")

    creator = relationship(
        "Users",
        foreign_keys=[created_by],
    )

    project = relationship("Project")

    submodules = relationship(
        "AfSubmodule",
        back_populates="module"
    )

    permissions = relationship(
        "AfPermission",
        back_populates="module"
    )