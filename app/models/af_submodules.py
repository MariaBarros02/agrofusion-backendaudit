"""
Modelo ORM para submódulos del sistema.

Representa subdivisiones funcionales dentro de un módulo.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AfSubmodule(Base):
    """
    Modelo ORM que representa un submódulo del sistema.
    """

    __tablename__ = "af_submodules"
    __table_args__ = (
        UniqueConstraint("module_id", "code", name="uk_sub_per_module"),
        {"schema": "public"},
    )

    af_submodule_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    module_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_modules.af_module_id"),
        nullable=False
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
    disabled_at = Column(DateTime(timezone=True))

    description = Column(Text)
    is_editable = Column(Boolean, default=True)

    # ---------------- RELACIONES ----------------

    module = relationship(
        "AfModule",
        back_populates="submodules"
    )

    creator = relationship(
        "Users",
        foreign_keys=[created_by],
    )

    status = relationship("CatTerm")

    permissions = relationship(
        "AfPermission",
        back_populates="submodule"
    )