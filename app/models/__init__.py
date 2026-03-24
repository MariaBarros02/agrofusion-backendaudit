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
from app.models.af_kms_keys import AfKmsKey, KeyPurpose, KeyStatus, KeyAlgorithm
from app.models.af_kms_certificates import AfKmsCertificate
from app.models.af_kms_signatures import AfKmsSignature, SignatureFormat, HashAlgorithm
from app.models.af_kms_signature_validations import AfKmsSignatureValidation, ValidationResult
from app.models.af_kms_key_rotations import AfKmsKeyRotation, RotationReason
from app.models.af_audit_log import AuditLog
from app.models.af_projects import Project
from app.models.af_auth_sessions import AuthSession
from app.models.af_auth_tokens import AuthToken
from app.models.af_email_queue import AfEmailQueue
from app.models.af_email_send_log import EmailSendLog
from app.models.af_email_templates import AfEmailTemplate
