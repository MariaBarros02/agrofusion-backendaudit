"""
Repositorio para acceso a datos del módulo KMS.

Maneja todas las operaciones de base de datos relacionadas con
claves criptográficas, certificados, firmas y rotaciones.
"""

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, cast, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from typing import List, Optional
from uuid import UUID
from datetime import datetime

from app.models.af_kms_keys import AfKmsKey, KeyStatus, KeyAlgorithm, KeyPurpose
from app.models.af_kms_certificates import AfKmsCertificate, CertificateStatus
from app.models.af_kms_signatures import AfKmsSignature
from app.models.af_kms_signature_validations import AfKmsSignatureValidation
from app.models.af_kms_key_rotations import AfKmsKeyRotation, RotationReason
from app.models.af_kms_ca_root import AfKmsCaRoot, CaRootStatus


class KmsRepository:
    """
    Repositorio encargado del acceso a datos para el módulo KMS.
    """

    # ==================== Operaciones con Claves ====================

    def create_key(
        self,
        db: Session,
        *,
        project_id: UUID,
        key_alias: str,
        algorithm: KeyAlgorithm,
        key_length: int,
        key_purpose: KeyPurpose,
        public_key: str,
        key_fingerprint: str,
        kms_key_reference: Optional[str],
        valid_to: datetime,
        created_by: UUID,
        key_version: int = 1,
        private_key_encrypted: Optional[str] = None,
        supersedes_key_id: Optional[UUID] = None,
    ) -> AfKmsKey:
        """Crea un nuevo registro de clave criptográfica."""
        key = AfKmsKey(
            project_id=project_id,
            key_alias=key_alias,
            algorithm=algorithm,
            key_length=key_length,
            key_purpose=key_purpose,
            public_key=public_key,
            private_key_encrypted=private_key_encrypted,
            key_fingerprint=key_fingerprint,
            kms_key_reference=kms_key_reference,
            status=KeyStatus.ACTIVE,
            key_version=key_version,
            valid_to=valid_to,
            created_by=created_by,
            supersedes_key_id=supersedes_key_id,
        )
        db.add(key)
        db.commit()
        db.refresh(key)
        return key

    def get_active_key_by_project_and_purpose(
        self, db: Session, project_id: UUID, key_purpose: KeyPurpose
    ) -> Optional[AfKmsKey]:
        """
        Retorna la clave en estado ACTIVE para la combinación
        ``(project_id, key_purpose)`` si existe.

        Se usa para garantizar la restricción de unicidad exigida por
        RF-INT-12: solo puede existir una clave activa por proyecto y
        propósito.
        """
        return (
            db.query(AfKmsKey)
            .filter(
                and_(
                    AfKmsKey.project_id == project_id,
                    AfKmsKey.key_purpose == key_purpose,
                    AfKmsKey.status == KeyStatus.ACTIVE,
                )
            )
            .first()
        )

    def get_key_by_id(self, db: Session, key_id: UUID) -> Optional[AfKmsKey]:
        """Obtiene una clave por su ID."""
        return db.query(AfKmsKey).filter(AfKmsKey.key_id == key_id).first()

    def get_key_by_fingerprint(
        self, db: Session, fingerprint: str
    ) -> Optional[AfKmsKey]:
        """Obtiene una clave por su fingerprint."""
        return (
            db.query(AfKmsKey)
            .filter(AfKmsKey.key_fingerprint == fingerprint)
            .first()
        )

    def get_active_keys_by_project(
        self, db: Session, project_id: UUID, key_purpose: Optional[KeyPurpose] = None
    ) -> List[AfKmsKey]:
        """Obtiene claves activas de un proyecto."""
        query = db.query(AfKmsKey).filter(
            and_(
                AfKmsKey.project_id == project_id,
                AfKmsKey.status == KeyStatus.ACTIVE,
                AfKmsKey.valid_to > func.now(),
            )
        )
        if key_purpose:
            query = query.filter(AfKmsKey.key_purpose.in_([key_purpose, KeyPurpose.BOTH]))
        return query.all()

    def get_keys_by_project(
        self, db: Session, project_id: UUID, status: Optional[KeyStatus] = None
    ) -> List[AfKmsKey]:
        """Obtiene todas las claves de un proyecto."""
        query = db.query(AfKmsKey).filter(AfKmsKey.project_id == project_id)
        if status:
            query = query.filter(AfKmsKey.status == status)
        return query.order_by(AfKmsKey.created_at.desc()).all()

    def update_key_status(
        self, db: Session, key_id: UUID, status: KeyStatus, rotated_at: Optional[datetime] = None
    ) -> Optional[AfKmsKey]:
        """Actualiza el estado de una clave."""
        key = self.get_key_by_id(db, key_id)
        if key:
            key.status = status
            if rotated_at:
                key.rotated_at = rotated_at
            db.commit()
            db.refresh(key)
        return key

    def set_key_supersedes(
        self, db: Session, old_key_id: UUID, new_key_id: UUID, grace_period_end: datetime
    ) -> None:
        """Establece la relación de reemplazo entre claves."""
        old_key = self.get_key_by_id(db, old_key_id)
        if old_key:
            old_key.supersedes_key_id = new_key_id
            old_key.grace_period_end = grace_period_end
            db.commit()

    def get_key_version(self, db: Session, project_id: UUID, key_alias: str) -> int:
        """Obtiene la siguiente versión de clave para un alias."""
        max_version = (
            db.query(func.max(AfKmsKey.key_version))
            .filter(
                and_(
                    AfKmsKey.project_id == project_id,
                    AfKmsKey.key_alias == key_alias,
                )
            )
            .scalar()
        )
        return (max_version or 0) + 1

    # ==================== Operaciones con Certificados ====================

    def create_certificate(
        self,
        db: Session,
        *,
        key_id: UUID,
        certificate_pem: str,
        serial_number: str,
        subject: str,
        issuer: str,
        valid_from: datetime,
        valid_to: datetime,
        fingerprint: str,
        signature_algorithm: Optional[str] = None,
        status_value: str = CertificateStatus.ACTIVE.value,
    ) -> AfKmsCertificate:
        """Crea un nuevo registro de certificado."""
        certificate = AfKmsCertificate(
            key_id=key_id,
            certificate_pem=certificate_pem,
            serial_number=serial_number,
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            fingerprint=fingerprint,
            signature_algorithm=signature_algorithm,
            status=status_value,
        )
        db.add(certificate)
        db.commit()
        db.refresh(certificate)
        return certificate

    def get_certificate_by_key_id(
        self, db: Session, key_id: UUID
    ) -> Optional[AfKmsCertificate]:
        """Obtiene el certificado más reciente asociado a una clave."""
        return (
            db.query(AfKmsCertificate)
            .filter(AfKmsCertificate.key_id == key_id)
            .order_by(AfKmsCertificate.issued_at.desc())
            .first()
        )

    def get_active_certificate_by_key_id(
        self, db: Session, key_id: UUID
    ) -> Optional[AfKmsCertificate]:
        """Retorna el certificado ACTIVE asociado a una clave (RF-INT-14)."""
        return (
            db.query(AfKmsCertificate)
            .filter(
                and_(
                    AfKmsCertificate.key_id == key_id,
                    AfKmsCertificate.status == CertificateStatus.ACTIVE.value,
                )
            )
            .order_by(AfKmsCertificate.issued_at.desc())
            .first()
        )

    def get_certificate_by_id(
        self, db: Session, certificate_id: UUID
    ) -> Optional[AfKmsCertificate]:
        """Obtiene un certificado por su ID."""
        return (
            db.query(AfKmsCertificate)
            .filter(AfKmsCertificate.certificate_id == certificate_id)
            .first()
        )

    # ==================== Operaciones con Firmas ====================

    def create_signature(
        self,
        db: Session,
        *,
        key_id: UUID,
        document_hash: str,
        hash_algorithm: str,
        digital_signature: str,
        signature_format: str,
        rfc3161_timestamp: Optional[str],
        document_id: Optional[UUID],
        document_type: Optional[str],
        signer_user_id: Optional[UUID],
        signing_reason: Optional[str],
        project_id: UUID,
        certificate_id: Optional[UUID] = None,
    ) -> AfKmsSignature:
        """Crea un nuevo registro de firma digital (RF-INT-16)."""
        signature = AfKmsSignature(
            key_id=key_id,
            certificate_id=certificate_id,
            document_hash=document_hash,
            hash_algorithm=hash_algorithm,
            digital_signature=digital_signature,
            signature_format=signature_format,
            rfc3161_timestamp=rfc3161_timestamp,
            document_id=document_id,
            document_type=document_type,
            signer_user_id=signer_user_id,
            signing_reason=signing_reason,
            project_id=project_id,
        )
        db.add(signature)
        db.commit()
        db.refresh(signature)
        return signature

    def get_signature_by_id(
        self, db: Session, signature_id: UUID
    ) -> Optional[AfKmsSignature]:
        """Obtiene una firma por su ID."""
        return (
            db.query(AfKmsSignature)
            .filter(AfKmsSignature.signature_id == signature_id)
            .first()
        )

    def get_signatures_by_document(
        self, db: Session, document_id: UUID
    ) -> List[AfKmsSignature]:
        """Obtiene todas las firmas de un documento."""
        return (
            db.query(AfKmsSignature)
            .filter(AfKmsSignature.document_id == document_id)
            .order_by(AfKmsSignature.signed_at.desc())
            .all()
        )

    def get_signatures_by_project(
        self, db: Session, project_id: UUID, limit: int = 100, offset: int = 0
    ) -> List[AfKmsSignature]:
        """Obtiene firmas de un proyecto con paginación."""
        return (
            db.query(AfKmsSignature)
            .filter(AfKmsSignature.project_id == project_id)
            .order_by(AfKmsSignature.signed_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )

    def count_signatures_by_project(self, db: Session, project_id: UUID) -> int:
        """Cuenta el total de firmas de un proyecto."""
        return (
            db.query(func.count(AfKmsSignature.signature_id))
            .filter(AfKmsSignature.project_id == project_id)
            .scalar()
        )

    # ============ RF-INT-19: consulta y auditoría ============

    def _latest_validation_subquery(self, db: Session):
        """
        Subconsulta que selecciona, por cada ``signature_id``, la última
        validación registrada (por ``validated_at``) y su resultado.
        """
        sub = (
            db.query(
                AfKmsSignatureValidation.signature_id.label("signature_id"),
                AfKmsSignatureValidation.validation_result.label("validation_result"),
                AfKmsSignatureValidation.validated_at.label("validated_at"),
                func.row_number()
                .over(
                    partition_by=AfKmsSignatureValidation.signature_id,
                    order_by=AfKmsSignatureValidation.validated_at.desc(),
                )
                .label("rn"),
            )
            .subquery()
        )
        return sub

    def search_signatures_rfint19(
        self,
        db: Session,
        *,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        signer_user_id: Optional[UUID] = None,
        signer_name: Optional[str] = None,
        search_q: Optional[str] = None,
        document_type: Optional[str] = None,
        audit_export_only: bool = False,
        key_algorithm: Optional[str] = None,
        validation_status: Optional[str] = None,
        limit: int = 5,
        offset: int = 0,
    ) -> tuple[list, int]:
        """
        Búsqueda paginada de firmas para RF-INT-19.

        Devuelve tuplas (AfKmsSignature, validation_status, expires_at,
        signer_name, key_algorithm, export_name) y el total.
        """
        from app.models.users import Users as _Users  # import tardío para evitar ciclos
        from app.models.af_audit_exports import AfAuditExport

        latest_val = self._latest_validation_subquery(db)

        base = (
            db.query(
                AfKmsSignature,
                latest_val.c.validation_result.label("validation_status"),
                AfKmsCertificate.valid_to.label("expires_at"),
                _Users.name.label("signer_name"),
                AfKmsKey.algorithm.label("key_algorithm"),
                AfAuditExport.export_name.label("export_name"),
            )
            .outerjoin(
                latest_val,
                and_(
                    latest_val.c.signature_id == AfKmsSignature.signature_id,
                    latest_val.c.rn == 1,
                ),
            )
            .outerjoin(
                AfKmsCertificate,
                AfKmsCertificate.certificate_id == AfKmsSignature.certificate_id,
            )
            .outerjoin(_Users, _Users.user_id == AfKmsSignature.signer_user_id)
            .outerjoin(AfKmsKey, AfKmsKey.key_id == AfKmsSignature.key_id)
            .outerjoin(
                AfAuditExport,
                AfAuditExport.export_id
                == cast(AfKmsSignature.document_id, PGUUID(as_uuid=True)),
            )
        )

        if date_from:
            base = base.filter(AfKmsSignature.signed_at >= date_from)
        if date_to:
            base = base.filter(AfKmsSignature.signed_at <= date_to)
        if signer_user_id:
            base = base.filter(AfKmsSignature.signer_user_id == signer_user_id)
        if signer_name and signer_name.strip():
            base = base.filter(_Users.name.ilike(f"%{signer_name.strip()}%"))
        if search_q and search_q.strip():
            t = f"%{search_q.strip()}%"
            base = base.filter(
                or_(
                    cast(AfKmsSignature.signature_id, String).ilike(t),
                    cast(AfKmsSignature.document_id, String).ilike(t),
                    AfKmsSignature.document_hash.ilike(t),
                    AfAuditExport.export_name.ilike(t),
                )
            )
        if audit_export_only:
            base = base.filter(AfKmsSignature.document_type == "AUDIT_EXPORT")
        elif document_type:
            base = base.filter(AfKmsSignature.document_type == document_type)
        if key_algorithm and key_algorithm.strip():
            base = base.filter(
                cast(AfKmsKey.algorithm, String).ilike(f"%{key_algorithm.strip()}%")
            )
        if validation_status:
            base = base.filter(
                func.lower(latest_val.c.validation_result)
                == validation_status.lower()
            )

        total = base.with_entities(func.count(AfKmsSignature.signature_id)).scalar() or 0

        rows = (
            base.order_by(AfKmsSignature.signed_at.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return rows, int(total)

    # ==================== Operaciones con Validaciones ====================

    def create_validation(
        self,
        db: Session,
        *,
        signature_id: UUID,
        validation_result: str,
        validation_reason: Optional[str],
        validated_by: Optional[UUID],
    ) -> AfKmsSignatureValidation:
        """Crea un nuevo registro de validación."""
        validation = AfKmsSignatureValidation(
            signature_id=signature_id,
            validation_result=validation_result,
            validation_reason=validation_reason,
            validated_by=validated_by,
        )
        db.add(validation)
        db.commit()
        db.refresh(validation)
        return validation

    def get_validations_by_signature(
        self, db: Session, signature_id: UUID
    ) -> List[AfKmsSignatureValidation]:
        """Obtiene todas las validaciones de una firma."""
        return (
            db.query(AfKmsSignatureValidation)
            .filter(AfKmsSignatureValidation.signature_id == signature_id)
            .order_by(AfKmsSignatureValidation.validated_at.desc())
            .all()
        )

    # ==================== Operaciones con Rotaciones ====================

    def create_rotation(
        self,
        db: Session,
        *,
        old_key_id: UUID,
        new_key_id: UUID,
        rotation_reason: RotationReason,
        grace_period_days: int,
        rotated_by: Optional[UUID],
    ) -> AfKmsKeyRotation:
        """Crea un nuevo registro de rotación."""
        rotation = AfKmsKeyRotation(
            old_key_id=old_key_id,
            new_key_id=new_key_id,
            rotation_reason=rotation_reason,
            grace_period_days=grace_period_days,
            rotated_by=rotated_by,
        )
        db.add(rotation)
        db.commit()
        db.refresh(rotation)
        return rotation

    def get_rotations_by_key(
        self, db: Session, key_id: UUID
    ) -> List[AfKmsKeyRotation]:
        """Obtiene todas las rotaciones relacionadas con una clave."""
        return (
            db.query(AfKmsKeyRotation)
            .filter(
                or_(
                    AfKmsKeyRotation.old_key_id == key_id,
                    AfKmsKeyRotation.new_key_id == key_id,
                )
            )
            .order_by(AfKmsKeyRotation.rotated_at.desc())
            .all()
        )

    # ==================== Operaciones con Root CA ====================

    def get_active_ca_root(self, db: Session) -> Optional[AfKmsCaRoot]:
        """Retorna la Root CA activa (si existe)."""
        return (
            db.query(AfKmsCaRoot)
            .filter(AfKmsCaRoot.status == CaRootStatus.ACTIVE.value)
            .order_by(AfKmsCaRoot.created_at.desc())
            .first()
        )

    def get_ca_root_by_id(self, db: Session, ca_id: UUID) -> Optional[AfKmsCaRoot]:
        """Obtiene una Root CA por su identificador."""
        return (
            db.query(AfKmsCaRoot)
            .filter(AfKmsCaRoot.ca_id == ca_id)
            .first()
        )

    def list_ca_roots(self, db: Session) -> List[AfKmsCaRoot]:
        """Lista el histórico de Root CAs ordenado por fecha de creación."""
        return (
            db.query(AfKmsCaRoot)
            .order_by(AfKmsCaRoot.created_at.desc())
            .all()
        )

    def create_ca_root(
        self,
        db: Session,
        *,
        private_key_encrypted: str,
        public_key: str,
        certificate_pem: str,
        fingerprint: str,
        serial_number: str,
        subject: str,
        issuer: str,
        valid_from: datetime,
        valid_to: datetime,
        created_by: Optional[UUID] = None,
    ) -> AfKmsCaRoot:
        """
        Persiste una nueva Root CA con estado ACTIVE.

        El caller es responsable de garantizar que no exista otra Root CA activa
        (ver ``get_active_ca_root``); si existiera, debe ser rotada o revocada
        antes.
        """
        ca = AfKmsCaRoot(
            private_key_encrypted=private_key_encrypted,
            public_key=public_key,
            certificate_pem=certificate_pem,
            fingerprint=fingerprint,
            serial_number=serial_number,
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            status=CaRootStatus.ACTIVE.value,
            created_by=created_by,
        )
        db.add(ca)
        db.commit()
        db.refresh(ca)
        return ca

    def update_ca_root_status(
        self,
        db: Session,
        ca_id: UUID,
        status_value: CaRootStatus,
        rotated_at: Optional[datetime] = None,
    ) -> Optional[AfKmsCaRoot]:
        """Actualiza el estado (active/rotated/revoked) de una Root CA."""
        ca = self.get_ca_root_by_id(db, ca_id)
        if ca:
            ca.status = (
                status_value.value
                if isinstance(status_value, CaRootStatus)
                else str(status_value)
            )
            if rotated_at is not None:
                ca.rotated_at = rotated_at
            db.commit()
            db.refresh(ca)
        return ca

