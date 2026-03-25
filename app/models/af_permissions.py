"""
Modelo ORM para permisos del sistema.

Define acciones permitidas sobre recursos dentro de un
namespace, opcionalmente ligados a proyecto, módulo y submódulo.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    ForeignKey,
    UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from app.core.database import Base


class AfPermission(Base):
    """
    Modelo ORM que representa un permiso del sistema.
    """

    __tablename__ = "af_permissions"
    __table_args__ = (
        UniqueConstraint(
            "namespace_id",
            "resource_id",
            "action_id",
            name="uk_perm_triad"
        ),
        {"schema": "public"},
    )

    af_perm_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    namespace_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )

    resource_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )

    action_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )

    description = Column(Text)

    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=False
    )

    deleted_at = Column(DateTime(timezone=True))

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

    af_module_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_modules.af_module_id")
    )

    af_submodule_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_submodules.af_submodule_id")
    )

    perm_type_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id")
    )

    perm_state_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id")
    )

    code = Column(String(80))
    name = Column(String(120))

    # ---------------- RELACIONES ----------------

    project = relationship("Project")

    module = relationship(
        "AfModule",
        back_populates="permissions"
    )

    submodule = relationship(
        "AfSubmodule",
        back_populates="permissions"
    )
    role_permissions = relationship("AfRolePermission", back_populates="permission")

    namespace = relationship("CatTerm", foreign_keys=[namespace_id])
    resource = relationship("CatTerm", foreign_keys=[resource_id])
    action = relationship("CatTerm", foreign_keys=[action_id])
    status = relationship("CatTerm", foreign_keys=[status_term_id])
    perm_type = relationship("CatTerm", foreign_keys=[perm_type_term_id])
    perm_state = relationship("CatTerm", foreign_keys=[perm_state_term_id])