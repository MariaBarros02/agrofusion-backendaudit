import uuid
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, TSTZRANGE
from sqlalchemy.orm import relationship
from app.core.database import Base
from sqlalchemy import Column, Computed
from sqlalchemy.dialects.postgresql import TSTZRANGE

class AfUserProjectRole(Base):
    __tablename__ = "af_user_project_roles"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "af_project_id",
            "af_role_id",
            name="uq_upr"
        ),
        Index("ix_upr_user", "user_id"),
        Index("ix_upr_project", "af_project_id"),
        Index("ix_upr_role", "af_role_id"),
        Index(
            "idx_user_project_roles_assignment_status",
            "assignment_status_term_id"
        ),
        {"schema": "public"},
    )
    upr_id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=False
    )

    af_project_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_projects.af_project_id"),
        nullable=False
    )

    af_role_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.af_roles.af_role_id"),
        nullable=False
    )

    assigned_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    valid_from = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )

    valid_to = Column(
        DateTime(timezone=True),
        nullable=True
    )

    created_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True
    )

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

    # Columna generada en PostgreSQL
    valid_range = Column(
        TSTZRANGE,
        Computed("tstzrange(valid_from, valid_to)", persisted=True)
    )

    assignment_status_term_id = Column(
        UUID(as_uuid=True),
        ForeignKey("public.cat_terms.term_id"),
        nullable=True
    )

    suspension_reason = Column(Text, nullable=True)

    suspended_at = Column(DateTime(timezone=True), nullable=True)

    suspended_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True
    )

    suspension_until = Column(DateTime(timezone=True), nullable=True)

    updated_by = Column(
        UUID(as_uuid=True),
        ForeignKey("public.users.user_id"),
        nullable=True
    )

    # -------------------------
    # Relaciones
    # -------------------------

    user = relationship(
        "Users",
        foreign_keys=[user_id],
        backref="project_roles"
    )

    project = relationship(
        "Project",
        backref="user_roles"
    )

    role = relationship(
        "AfRole",
        backref="user_assignments"
    )

    assignment_status = relationship(
        "CatTerm",
        foreign_keys=[assignment_status_term_id]
    )

    creator = relationship(
        "Users",
        foreign_keys=[created_by]
    )

    suspender = relationship(
        "Users",
        foreign_keys=[suspended_by]
    )

    updater = relationship(
        "Users",
        foreign_keys=[updated_by]
    )

    # -------------------------
    # Constraints e índices
    # -------------------------

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "af_project_id",
            "af_role_id",
            name="uq_upr"
        ),
        Index("ix_upr_user", "user_id"),
        Index("ix_upr_project", "af_project_id"),
        Index("ix_upr_role", "af_role_id"),
        Index(
            "idx_user_project_roles_assignment_status",
            "assignment_status_term_id"
        ),
    )