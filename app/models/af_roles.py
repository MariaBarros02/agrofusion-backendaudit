import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class AfRole(Base):
    __tablename__ = "af_roles"

    __table_args__ = (
        UniqueConstraint("af_project_id", "name", name="uk_role_per_project"),
        Index("ix_roles_project", "af_project_id"),
        Index("ix_roles_state", "role_state_term_id"),
        {"schema": "public"},
    )

    af_role_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    af_project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_projects.af_project_id"),
        nullable=False
    )


    name = Column(String(80), nullable=False)
    description = Column(Text, nullable=True)

    deleted_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    updated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=func.now()
    )

    role_type_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=True
    )

    code = Column(String(60), nullable=True)

    role_state_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=True
    )

    status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=True
    )

    is_system = Column(Boolean, default=False)
    is_system_role = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)

    # -------------------------
    # Relaciones
    # -------------------------


    role_type = relationship(
        "CatTerm",
        foreign_keys=[role_type_term_id]
    )

    role_state = relationship(
        "CatTerm",
        foreign_keys=[role_state_term_id]
    )

    status = relationship(
        "CatTerm",
        foreign_keys=[status_term_id]
    )

    project = relationship("Project")

    role_permissions = relationship(
        "AfRolePermission",
        back_populates="role",
        cascade="all, delete-orphan"
    )