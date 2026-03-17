"""
Servicio de gestión de claves criptográficas y firmas digitales (KMS).

Implementa la lógica de negocio para:
- Generación y gestión de claves criptográficas
- Firma digital de documentos
- Validación de firmas
- Rotación de claves
"""

import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session

from app.repositories.kms_repository import KmsRepository
from app.models.af_kms_keys import KeyAlgorithm, KeyPurpose, KeyStatus
from app.models.af_kms_signatures import HashAlgorithm, SignatureFormat
from app.models.af_kms_signature_validations import ValidationResult
from app.models.af_kms_key_rotations import RotationReason
from app.core.errors import audit_error
from fastapi import status


class KmsService:
    """
    Servicio de gestión de claves criptográficas y firmas digitales.
    """

    def __init__(self):
        self.kms_repo = KmsRepository()
        self.backend = default_backend()

    # ==================== Generación de Claves ====================

    def generate_key_pair(
        self,
        algorithm: KeyAlgorithm,
    ) -> Tuple[bytes, bytes]:
        """
        Genera un par de claves criptográficas (privada/pública).

        Args:
            algorithm: Algoritmo criptográfico a usar

        Returns:
            Tupla (clave_privada_bytes, clave_publica_bytes)
        """
        if algorithm in [KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096]:
            key_size = 2048 if algorithm == KeyAlgorithm.RSA_2048 else 4096
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self.backend,
            )
        elif algorithm == KeyAlgorithm.ECDSA_P256:
            private_key = ec.generate_private_key(
                ec.SECP256R1(), backend=self.backend
            )
        elif algorithm == KeyAlgorithm.ECDSA_P384:
            private_key = ec.generate_private_key(
                ec.SECP384R1(), backend=self.backend
            )
        else:
            raise ValueError(f"Algoritmo no soportado: {algorithm}")

        # Serializar claves
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    def calculate_key_fingerprint(self, public_key_pem: str) -> str:
        """Calcula el fingerprint SHA-256 de una clave pública."""
        public_key_bytes = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()
        return fingerprint

    def get_key_length(self, algorithm: KeyAlgorithm) -> int:
        """Obtiene la longitud de clave en bits según el algoritmo."""
        algorithm_lengths = {
            KeyAlgorithm.RSA_2048: 2048,
            KeyAlgorithm.RSA_4096: 4096,
            KeyAlgorithm.ECDSA_P256: 256,
            KeyAlgorithm.ECDSA_P384: 384,
        }
        return algorithm_lengths.get(algorithm, 2048)

    def create_key(
        self,
        db: Session,
        *,
        project_id: UUID,
        key_alias: str,
        algorithm: KeyAlgorithm,
        key_purpose: KeyPurpose,
        valid_to: Optional[datetime],
        created_by: Optional[UUID] = None,
        kms_key_reference: Optional[str] = None,
    ):
        """
        Crea una nueva clave criptográfica y la registra en la base de datos.

        NOTA: En producción, la clave privada debe almacenarse en un HSM o KMS externo.
        Este método simula el almacenamiento seguro.
        """
        # Validar que no exista otra clave activa con el mismo alias en el proyecto
        existing_keys = self.kms_repo.get_keys_by_project(db, project_id)
        for key in existing_keys:
            if key.key_alias == key_alias and key.status == KeyStatus.ACTIVE:
                raise audit_error(
                    "KEY_ALIAS_EXISTS",
                    status.HTTP_400_BAD_REQUEST,
                    {"key_alias": key_alias},
                )

        # Generar par de claves
        private_pem, public_pem = self.generate_key_pair(algorithm)
        public_key_str = public_pem.decode() if isinstance(public_pem, bytes) else public_pem

        # Calcular fingerprint
        fingerprint = self.calculate_key_fingerprint(public_key_str)

        # Verificar que no exista otra clave con el mismo fingerprint
        existing = self.kms_repo.get_key_by_fingerprint(db, fingerprint)
        if existing:
            raise audit_error(
                "DUPLICATE_KEY_FINGERPRINT",
                status.HTTP_400_BAD_REQUEST,
            )

        # Establecer fecha de expiración por defecto (1 año)
        if not valid_to:
            valid_to = datetime.now(timezone.utc) + timedelta(days=365)

        # Obtener longitud de clave
        key_length = self.get_key_length(algorithm)

        # Obtener versión de clave
        key_version = self.kms_repo.get_key_version(db, project_id, key_alias)

        # Crear registro en BD
        key = self.kms_repo.create_key(
            db=db,
            project_id=project_id,
            key_alias=key_alias,
            algorithm=algorithm,
            key_length=key_length,
            key_purpose=key_purpose,
            public_key=public_key_str,
            key_fingerprint=fingerprint,
            kms_key_reference=kms_key_reference,
            valid_to=valid_to,
            created_by=created_by,
            key_version=key_version,
        )

        # En producción: almacenar clave privada en HSM/KMS externo
        # usando kms_key_reference como identificador

        return key

    # ==================== Firma Digital ====================

    def sign_document(
        self,
        db: Session,
        *,
        document_hash: str,
        key_id: UUID,
        hash_algorithm: HashAlgorithm,
        signature_format: SignatureFormat,
        include_timestamp: bool,
        document_id: Optional[UUID],
        document_type: Optional[str],
        signer_user_id: Optional[UUID],
        signing_reason: Optional[str],
        project_id: Optional[UUID] = None,
    ):
        """
        Firma digitalmente un documento usando una clave del KMS.

        NOTA: En producción, la firma debe realizarse en el HSM/KMS externo.
        Este método simula la operación usando la clave privada.
        """
        # Obtener clave
        key = self.kms_repo.get_key_by_id(db, key_id)
        if not key:
            raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        # Usar siempre el proyecto de auditoría por defecto si no se especifica
        # El usuario indicó que el proyecto válido en BD es:
        # a3747ffe-f4c2-4bfc-aafb-ea97f5aeb68e
        from uuid import UUID as _UUID

        default_project_id = _UUID("a3747ffe-f4c2-4bfc-aafb-ea97f5aeb68e")

        if not project_id:
            project_id = default_project_id
        else:
            # Si se pasa un project_id distinto al de la clave, no bloqueamos,
            # pero podríamos validarlo en el futuro si la BD lo requiere.
            # Por ahora solo aseguramos que exista algún project_id válido.
            pass

        # Validar que la clave esté activa
        if key.status != KeyStatus.ACTIVE:
            raise audit_error(
                "KEY_NOT_ACTIVE",
                status.HTTP_400_BAD_REQUEST,
                {"status": key.status},
            )

        # Validar que la clave no haya expirado
        if key.valid_to < datetime.now(timezone.utc):
            raise audit_error("KEY_EXPIRED", status.HTTP_400_BAD_REQUEST)

        # Validar propósito de la clave
        if key.key_purpose not in [KeyPurpose.SIGNING, KeyPurpose.BOTH]:
            raise audit_error(
                "KEY_PURPOSE_INVALID",
                status.HTTP_400_BAD_REQUEST,
                {"purpose": key.key_purpose},
            )

        # Validar y preparar hash del documento
        # El hash puede venir como string hexadecimal (64 chars para SHA-256)
        # o como bytes en base64
        try:
            # Intentar decodificar como hexadecimal primero
            if len(document_hash) == 64:  # SHA-256 hexadecimal
                hash_bytes = bytes.fromhex(document_hash)
            elif len(document_hash) == 96:  # SHA-384 hexadecimal
                hash_bytes = bytes.fromhex(document_hash)
            elif len(document_hash) == 128:  # SHA-512 hexadecimal
                hash_bytes = bytes.fromhex(document_hash)
            else:
                # Si no es hexadecimal válido, intentar como base64
                import base64
                hash_bytes = base64.b64decode(document_hash)
        except (ValueError, Exception) as e:
            raise audit_error(
                "INVALID_HASH_FORMAT", 
                status.HTTP_400_BAD_REQUEST,
                {"error": f"Hash inválido: {str(e)}", "hash_length": len(document_hash)}
            )

        # En producción: llamar al KMS externo para firmar
        # Por ahora, simulamos la firma usando cryptography
        # NOTA: Esto es solo para desarrollo. En producción usar HSM/KMS.
        digital_signature_b64 = self._simulate_signature(
            hash_bytes, key.algorithm, hash_algorithm
        )

        # Generar timestamp RFC 3161 si se solicita
        rfc3161_timestamp = None
        if include_timestamp:
            # En producción: obtener timestamp de un TSA (Time Stamping Authority)
            rfc3161_timestamp = self._generate_rfc3161_timestamp()

        # Crear registro de firma
        signature = self.kms_repo.create_signature(
            db=db,
            key_id=key_id,
            document_hash=document_hash,
            hash_algorithm=hash_algorithm.value,
            digital_signature=digital_signature_b64,
            signature_format=signature_format.value,
            rfc3161_timestamp=rfc3161_timestamp,
            document_id=document_id,
            document_type=document_type,
            signer_user_id=signer_user_id,
            signing_reason=signing_reason,
            project_id=project_id,
        )

        return signature

    def _simulate_signature(
        self, hash_bytes: bytes, algorithm: KeyAlgorithm, hash_alg: HashAlgorithm
    ) -> str:
        """
        Simula la firma digital (solo para desarrollo).

        En producción, esto debe hacerse en el HSM/KMS externo.
        """
        # Mapear algoritmo de hash
        hash_map = {
            HashAlgorithm.SHA256: hashes.SHA256(),
            HashAlgorithm.SHA384: hashes.SHA384(),
            HashAlgorithm.SHA512: hashes.SHA512(),
        }
        hash_obj = hash_map.get(hash_alg, hashes.SHA256())

        # Generar una firma simulada (en producción usar clave privada del KMS)
        # Por ahora, generamos un hash del hash + timestamp como simulación
        timestamp = datetime.now(timezone.utc).isoformat().encode()
        simulated_signature = hashlib.sha256(hash_bytes + timestamp).digest()
        return base64.b64encode(simulated_signature).decode()

    def _generate_rfc3161_timestamp(self) -> str:
        """Genera un timestamp RFC 3161 simulado."""
        # En producción: integrar con un TSA real
        timestamp = datetime.now(timezone.utc).isoformat()
        return f"RFC3161_TIMESTAMP:{timestamp}"

    # ==================== Validación de Firmas ====================

    def verify_signature(
        self,
        db: Session,
        *,
        document_hash: str,
        digital_signature: str,
        signature_id: Optional[UUID],
        key_id: Optional[UUID],
        hash_algorithm: HashAlgorithm,
        validated_by: Optional[UUID],
    ):
        """
        Valida una firma digital.

        Verifica que la firma corresponda al hash del documento
        usando la clave pública asociada.
        """
        # Obtener información de la firma
        if signature_id:
            signature = self.kms_repo.get_signature_by_id(db, signature_id)
            if not signature:
                raise audit_error("SIGNATURE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            key_id = signature.key_id
            stored_hash = signature.document_hash
            stored_sig = signature.digital_signature

            # Validar que el hash coincida
            if stored_hash != document_hash:
                validation = self.kms_repo.create_validation(
                    db=db,
                    signature_id=signature_id,
                    validation_result=ValidationResult.INVALID.value,
                    validation_reason="Document hash mismatch",
                    validated_by=validated_by,
                )
                return validation

            # Usar la firma almacenada si no se proporciona
            if not digital_signature:
                digital_signature = stored_sig

        # Obtener clave pública
        if not key_id:
            raise audit_error("KEY_ID_REQUIRED", status.HTTP_400_BAD_REQUEST)

        key = self.kms_repo.get_key_by_id(db, key_id)
        if not key:
            raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        # Validar estado de la clave
        if key.status == KeyStatus.REVOKED:
            validation = self.kms_repo.create_validation(
                db=db,
                signature_id=signature_id or UUID("00000000-0000-0000-0000-000000000000"),
                validation_result=ValidationResult.REVOKED.value,
                validation_reason="Key has been revoked",
                validated_by=validated_by,
            )
            return validation

        if key.status == KeyStatus.EXPIRED or key.valid_to < datetime.now(timezone.utc):
            validation = self.kms_repo.create_validation(
                db=db,
                signature_id=signature_id or UUID("00000000-0000-0000-0000-000000000000"),
                validation_result=ValidationResult.EXPIRED.value,
                validation_reason="Key has expired",
                validated_by=validated_by,
            )
            return validation

        # Verificar firma criptográficamente
        is_valid = self._verify_signature_cryptographic(
            document_hash, digital_signature, key.public_key, key.algorithm, hash_algorithm
        )

        # Crear registro de validación
        validation_result = ValidationResult.VALID if is_valid else ValidationResult.INVALID
        validation_reason = None if is_valid else "Cryptographic verification failed"

        validation = self.kms_repo.create_validation(
            db=db,
            signature_id=signature_id or UUID("00000000-0000-0000-0000-000000000000"),
            validation_result=validation_result.value,
            validation_reason=validation_reason,
            validated_by=validated_by,
        )

        return validation

    def _verify_signature_cryptographic(
        self,
        document_hash: str,
        digital_signature: str,
        public_key_pem: str,
        algorithm: KeyAlgorithm,
        hash_algorithm: HashAlgorithm,
    ) -> bool:
        """
        Verifica la firma criptográficamente usando la clave pública.

        En producción, esto debe hacerse en el HSM/KMS externo.
        """
        try:
            # Cargar clave pública
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
                backend=self.backend,
            )

            # Decodificar hash y firma
            hash_bytes = bytes.fromhex(document_hash)
            signature_bytes = base64.b64decode(digital_signature)

            # Mapear algoritmo de hash
            hash_map = {
                HashAlgorithm.SHA256: hashes.SHA256(),
                HashAlgorithm.SHA384: hashes.SHA384(),
                HashAlgorithm.SHA512: hashes.SHA512(),
            }
            hash_obj = hash_map.get(hash_algorithm, hashes.SHA256())

            # Verificar firma según algoritmo
            if algorithm in [KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096]:
                public_key.verify(
                    signature_bytes,
                    hash_bytes,
                    padding.PKCS1v15(),
                    hash_obj,
                )
            elif algorithm in [KeyAlgorithm.ECDSA_P256, KeyAlgorithm.ECDSA_P384]:
                public_key.verify(
                    signature_bytes,
                    hash_bytes,
                    ec.ECDSA(hash_obj),
                )
            else:
                return False

            return True
        except Exception:
            # Cualquier error en la verificación significa firma inválida
            return False

    # ==================== Rotación de Claves ====================

    def rotate_key(
        self,
        db: Session,
        *,
        key_id: UUID,
        rotation_reason: RotationReason,
        grace_period_days: int,
        rotated_by: Optional[UUID] = None,
    ):
        """
        Rota una clave criptográfica generando una nueva y marcando la anterior como rotada.
        """
        # Obtener clave a rotar
        old_key = self.kms_repo.get_key_by_id(db, key_id)
        if not old_key:
            raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        # Validar que la clave esté activa
        if old_key.status != KeyStatus.ACTIVE:
            raise audit_error(
                "KEY_NOT_ACTIVE",
                status.HTTP_400_BAD_REQUEST,
                {"status": old_key.status},
            )

        # Generar nueva clave con los mismos parámetros
        new_key = self.create_key(
            db=db,
            project_id=old_key.project_id,
            key_alias=old_key.key_alias,
            algorithm=old_key.algorithm,
            key_purpose=old_key.key_purpose,
            valid_to=old_key.valid_to,
            created_by=rotated_by,
            kms_key_reference=None,
        )

        # Actualizar versión de la nueva clave
        new_key.key_version = self.kms_repo.get_key_version(
            db, old_key.project_id, old_key.key_alias
        )
        db.commit()

        # Calcular fin del período de gracia
        grace_period_end = datetime.now(timezone.utc) + timedelta(days=grace_period_days)

        # Marcar clave anterior como rotada
        self.kms_repo.update_key_status(
            db, old_key.key_id, KeyStatus.ROTATED, datetime.now(timezone.utc)
        )

        # Establecer relación de reemplazo
        self.kms_repo.set_key_supersedes(
            db, old_key.key_id, new_key.key_id, grace_period_end
        )

        # Crear registro de rotación
        rotation = self.kms_repo.create_rotation(
            db=db,
            old_key_id=old_key.key_id,
            new_key_id=new_key.key_id,
            rotation_reason=rotation_reason,
            grace_period_days=grace_period_days,
            rotated_by=rotated_by,
        )

        return rotation, new_key

