"""
Inicializa y registra todos los modelos ORM del proyecto.

Este archivo permite que SQLAlchemy y Alembic detecten
correctamente los modelos al importar el paquete `app.models`.
"""

from app.models.users import Users
from app.models.af_error_log import AfErrorLog
from app.models.cat_terms import CatTerm
from app.models.cat_vocabularies import CatVocabulary
from app.models.af_external_projects import AfExternalProject
from app.models.af_audit_log import AfAuditLog