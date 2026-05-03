"""
Resolución de clave KMS para exportaciones de auditoría (compartido worker + API).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.af_kms_keys import KeyPurpose
from app.repositories.kms_repository import KmsRepository

logger = logging.getLogger(__name__)


def resolve_signing_key_id(db: Session, project_id: UUID) -> UUID | None:
    """Elige la clave signing activa del proyecto desde BD."""
    kr = KmsRepository()
    keys = kr.get_active_keys_by_project(db, project_id, KeyPurpose.SIGNING)
    if not keys:
        keys = kr.get_active_keys_by_project(db, project_id, KeyPurpose.BOTH)
    if not keys:
        return None
    ordered = sorted(
        keys,
        key=lambda k: k.created_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return ordered[0].key_id


def resolve_signing_key_for_export(
    db: Session,
    primary_project_id: UUID,
    *,
    log_fallback: bool = True,
) -> tuple[UUID | None, UUID | None]:
    """
    Devuelve (key_id, project_id para KMS) intentando primero el proyecto del export;
    si no hay claves ahí, usa cualquier clave signing/both activa en BD.
    """
    kr = KmsRepository()
    kid = resolve_signing_key_id(db, primary_project_id)
    if kid:
        row = kr.get_key_by_id(db, kid)
        return kid, (row.project_id if row else primary_project_id)
    fb = kr.get_latest_active_signing_key_any_project(db)
    if fb:
        if log_fallback:
            logger.warning(
                "Export sin clave KMS en proyecto %s; usando clave activa del proyecto %s (key_id=%s)",
                primary_project_id,
                fb.project_id,
                fb.key_id,
            )
        return fb.key_id, fb.project_id
    return None, None
