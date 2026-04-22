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

import json as _json
from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
from cryptography.hazmat.backends import default_backend
from sqlalchemy.orm import Session

from app.repositories.kms_repository import KmsRepository
from app.repositories.audit_repository import AuditRepository
from app.models.af_kms_keys import KeyAlgorithm, KeyPurpose, KeyStatus
from app.models.af_kms_certificates import CertificateStatus
from app.models.af_kms_signatures import HashAlgorithm, SignatureFormat
from app.models.af_kms_signature_validations import ValidationResult
from app.models.af_kms_key_rotations import RotationReason
from app.core.errors import audit_error
from app.services.kms_ca_service import KmsCaService
from app.services.kms_cert_validation_service import (
    CertificateValidationService,
    CertValidationState,
    ValidationMode,
)
from fastapi import status


class KmsService:
    """
    Servicio de gestión de claves criptográficas y firmas digitales.
    """

    def __init__(self):
        self.kms_repo = KmsRepository()
        self.audit_repo = AuditRepository()
        self.ca_service = KmsCaService()
        self.cert_validator = CertificateValidationService()
        self.backend = default_backend()

    def get_agrofusion_project(self, db: Session):
        """
        Obtiene el proyecto interno AGROFUSION para operaciones de auditoría.
        """
        project = self.audit_repo.get_project_by_code(db, code="AGROFUSION")
        if not project:
            raise RuntimeError("Project AGROFUSION not found")
        return project

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
        """
        Calcula el fingerprint SHA-256 de una clave pública (RF-INT-12).

        La huella se computa sobre la clave pública serializada en formato
        **DER** (SubjectPublicKeyInfo), no sobre el PEM. SHA-256 es el único
        algoritmo permitido para esta operación; MD5 y SHA-1 están prohibidos.
        """
        pem_bytes = (
            public_key_pem.encode("utf-8")
            if isinstance(public_key_pem, str)
            else public_key_pem
        )
        public_key_obj = serialization.load_pem_public_key(pem_bytes, backend=self.backend)
        der_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der_bytes).hexdigest()

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
        skip_alias_validation: bool = False,
        skip_active_uniqueness_check: bool = False,
        supersedes_key_id: Optional[UUID] = None,
    ):
        """
        Crea una nueva clave criptográfica y la registra en la base de datos
        cumpliendo RF-INT-12.

        Flujo:
            1. Valida precondición: existe una Root CA activa (RF-INT-11).
            2. Valida algoritmos permitidos (RSA≥2048 o ECDSA P-256/P-384).
            3. Valida restricción de unicidad: solo una clave con status=ACTIVE
               por combinación ``(project_id, key_purpose)``.
            4. Genera el par de claves.
            5. Calcula fingerprint SHA-256 sobre la clave pública en DER.
            6. Cifra la clave privada con AES-256-GCM usando ``KMS_MASTER_KEY``.
            7. Persiste en ``af_kms_keys``.

        La clave privada nunca se almacena en texto plano y nunca es retornada
        por la capa API.
        """
        # 1. Precondición RF-INT-11: debe existir una Root CA activa.
        active_ca = self.ca_service.get_active_ca(db)
        if active_ca is None:
            raise audit_error(
                "CA_ROOT_NOT_FOUND",
                status.HTTP_400_BAD_REQUEST,
                {"error": "No existe una Root CA activa. Inicialícela antes de crear claves."},
            )

        # 2. Algoritmos permitidos.
        allowed_algorithms = {
            KeyAlgorithm.RSA_2048,
            KeyAlgorithm.RSA_4096,
            KeyAlgorithm.ECDSA_P256,
            KeyAlgorithm.ECDSA_P384,
        }
        if algorithm not in allowed_algorithms:
            raise audit_error(
                "INVALID_KEY_ALGORITHM",
                status.HTTP_400_BAD_REQUEST,
                {"algorithm": getattr(algorithm, "value", str(algorithm))},
            )

        # 3a. Validar alias único a nivel de proyecto (salvo rotación).
        if not skip_alias_validation:
            existing_keys = self.kms_repo.get_keys_by_project(db, project_id)
            for key in existing_keys:
                if key.key_alias == key_alias and key.status == KeyStatus.ACTIVE:
                    raise audit_error(
                        "KEY_ALIAS_EXISTS",
                        status.HTTP_400_BAD_REQUEST,
                        {"key_alias": key_alias},
                    )

        # 3b. Restricción de unicidad RF-INT-12: solo una clave activa
        # por (project_id, key_purpose). Se omite durante una rotación,
        # ya que la clave anterior se marcará como ROTATED dentro de la
        # misma transacción lógica.
        if not skip_active_uniqueness_check:
            duplicate_active = self.kms_repo.get_active_key_by_project_and_purpose(
                db, project_id, key_purpose
            )
            if duplicate_active is not None:
                raise audit_error(
                    "ACTIVE_KEY_ALREADY_EXISTS",
                    status.HTTP_409_CONFLICT,
                    {
                        "project_id": str(project_id),
                        "key_purpose": getattr(key_purpose, "value", str(key_purpose)),
                        "existing_key_id": str(duplicate_active.key_id),
                    },
                )

        # 4. Generar par de claves.
        private_pem, public_pem = self.generate_key_pair(algorithm)
        public_key_str = public_pem.decode() if isinstance(public_pem, bytes) else public_pem

        # 5. Calcular fingerprint SHA-256 sobre DER.
        fingerprint = self.calculate_key_fingerprint(public_key_str)

        # Evitar colisiones de fingerprint (teóricamente improbables).
        existing = self.kms_repo.get_key_by_fingerprint(db, fingerprint)
        if existing:
            raise audit_error(
                "DUPLICATE_KEY_FINGERPRINT",
                status.HTTP_400_BAD_REQUEST,
            )

        # 6. Cifrar clave privada con AES-256-GCM (IV aleatorio por registro).
        private_key_encrypted = self.ca_service._encrypt_private_key(private_pem)

        # 7. Fechas de vigencia.
        if not valid_to:
            valid_to = datetime.now(timezone.utc) + timedelta(days=365)

        key_length = self.get_key_length(algorithm)
        key_version = self.kms_repo.get_key_version(db, project_id, key_alias)

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
            private_key_encrypted=private_key_encrypted,
            supersedes_key_id=supersedes_key_id,
        )

        # 8. RF-INT-14: emitir automáticamente el certificado X.509 v3 firmado
        # por la Root CA interna. Si la emisión falla, se revierte la creación
        # de la clave mediante un rollback transaccional para mantener la
        # relación 1:1 (key_version ↔ certificado). Esto no constituye una
        # "eliminación física" en sentido de negocio: la clave nunca llegó a
        # quedar publicada satisfactoriamente porque el flujo atómico falló.
        try:
            self.ca_service.issue_certificate_for_key(db=db, key=key)
        except Exception:
            try:
                db.delete(key)
                db.commit()
            except Exception:
                db.rollback()
            raise

        return key

    # ==================== Firma Digital ====================

    def sign_document(
        self,
        db: Session,
        *,
        document_hash: str,
        key_id: UUID,
        hash_algorithm: HashAlgorithm,
        signature_format: Optional[SignatureFormat] = None,
        include_timestamp: bool = False,
        document_id: Optional[UUID],
        document_type: Optional[str],
        signer_user_id: Optional[UUID],
        signing_reason: Optional[str],
        project_id: Optional[UUID] = None,
    ):
        """
        Firma digitalmente un documento cumpliendo RF-INT-16.

        - Selecciona el formato (JWS o PKCS#7) automáticamente según
          ``document_type`` (el parámetro ``signature_format`` solo se usa
          en llamadas internas de compatibilidad).
        - Valida estado de la clave (active) y el certificado asociado
          (RF-INT-15 modo CURRENT).
        - Descifra la clave privada temporalmente con ``KMS_MASTER_KEY``,
          firma el hash y destruye inmediatamente la clave en memoria.
        - Persiste el objeto de firma COMPLETO (token JWS o CMS DER base64).
        """
        # Obtener clave
        key = self.kms_repo.get_key_by_id(db, key_id)
        if not key:
            raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        # Usar siempre el proyecto AGROFUSION por defecto si no se especifica.
        # No dependemos de un UUID hardcodeado para evitar acoplamiento a datos.
        default_project_id = self.get_agrofusion_project(db).af_project_id

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

        # RF-INT-15: Validación de integridad del certificado asociado
        # (modo CURRENT) antes de ejecutar la firma digital.
        cert_validation = self.cert_validator.validate_certificate(
            db,
            key_id=key.key_id,
            validation_mode=ValidationMode.CURRENT,
        )
        if not cert_validation.is_valid:
            raise audit_error(
                "KMS_ERR_INVALID_CERT",
                status.HTTP_400_BAD_REQUEST,
                {
                    "message": (
                        "El certificado asociado a la clave no es válido. "
                        "La operación de firma ha sido abortada."
                    ),
                    "key_id": str(key.key_id),
                    "certificate_id": cert_validation.certificate_id,
                    "result": cert_validation.result,
                    "reason": cert_validation.reason,
                    "checked_at": cert_validation.checked_at,
                },
            )

        # Rechazar algoritmos de hash débiles (RF-INT-16 prohíbe MD5 y SHA-1).
        if hash_algorithm not in (HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512):
            raise audit_error(
                "WEAK_HASH_ALGORITHM_NOT_ALLOWED",
                status.HTTP_400_BAD_REQUEST,
                {"hash_algorithm": str(hash_algorithm)},
            )

        # Obtener certificado asociado y localizarlo en BD (necesario para
        # incluirlo dentro del objeto de firma PKCS#7/CMS).
        cert_row = self.kms_repo.get_certificate_by_key_id(db, key.key_id)
        if cert_row is None:
            raise audit_error(
                "CERTIFICATE_NOT_FOUND",
                status.HTTP_400_BAD_REQUEST,
                {"key_id": str(key.key_id)},
            )

        # Validar y preparar hash del documento (hex).
        try:
            if len(document_hash) in (64, 96, 128):
                hash_bytes = bytes.fromhex(document_hash)
            else:
                hash_bytes = base64.b64decode(document_hash)
        except (ValueError, Exception) as e:
            raise audit_error(
                "INVALID_HASH_FORMAT",
                status.HTTP_400_BAD_REQUEST,
                {"error": f"Hash inválido: {str(e)}", "hash_length": len(document_hash)},
            )

        # Selección automática del formato (RF-INT-16). El usuario NO
        # puede forzarlo desde el request.
        resolved_format = self._select_signature_format(document_type)

        # Timestamp RFC 3161 si se solicita.
        rfc3161_timestamp = (
            self._generate_rfc3161_timestamp() if include_timestamp else None
        )

        # Firma real utilizando la clave privada cifrada. La clave se
        # descifra en memoria volátil y se destruye inmediatamente después
        # de usarse. Nunca se registra ni se expone.
        digital_signature_object = self._sign_in_kms(
            key=key,
            cert_row=cert_row,
            hash_bytes=hash_bytes,
            hash_algorithm=hash_algorithm,
            resolved_format=resolved_format,
            document_hash_hex=document_hash,
            document_id=document_id,
            document_type=document_type,
        )

        # Persistir el objeto completo de firma (nunca un valor crudo).
        signature = self.kms_repo.create_signature(
            db=db,
            key_id=key_id,
            certificate_id=cert_row.certificate_id,
            document_hash=document_hash,
            hash_algorithm=hash_algorithm.value,
            digital_signature=digital_signature_object,
            signature_format=resolved_format.value,
            rfc3161_timestamp=rfc3161_timestamp,
            document_id=document_id,
            document_type=document_type,
            signer_user_id=signer_user_id,
            signing_reason=signing_reason,
            project_id=project_id,
        )

        return signature

    # ==================== Firma real dentro del KMS (RF-INT-16) ====================

    # Mapa ``document_type`` → formato de firma. Cualquier tipo que sugiera
    # contenido estructurado JSON usa JWS; el resto (pdf, xml, csv, zip...)
    # se firma como PKCS#7/CMS.
    _JSON_DOCUMENT_TYPES = {
        "json",
        "application/json",
        "api",
        "structured",
        "data",
        "jws",
    }

    @classmethod
    def _select_signature_format(cls, document_type: Optional[str]) -> SignatureFormat:
        """Selecciona JWS (JSON/estructurado) o PKCS#7 (binario) según RF-INT-16."""
        if document_type is None:
            return SignatureFormat.PKCS7
        normalized = document_type.strip().lower()
        if normalized in cls._JSON_DOCUMENT_TYPES:
            return SignatureFormat.JWS
        # Tipos binarios explícitos mapean a PKCS#7 (el sistema nunca elige XAdES/CAdES).
        return SignatureFormat.PKCS7

    @staticmethod
    def _hash_obj(hash_alg: HashAlgorithm):
        return {
            HashAlgorithm.SHA256: hashes.SHA256(),
            HashAlgorithm.SHA384: hashes.SHA384(),
            HashAlgorithm.SHA512: hashes.SHA512(),
        }[hash_alg]

    @staticmethod
    def _jws_alg_label(key_algorithm: KeyAlgorithm, hash_alg: HashAlgorithm) -> str:
        """Etiqueta del header JWS (RFC 7515) según clave y hash."""
        if key_algorithm in (KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096):
            return {
                HashAlgorithm.SHA256: "RS256",
                HashAlgorithm.SHA384: "RS384",
                HashAlgorithm.SHA512: "RS512",
            }[hash_alg]
        if key_algorithm == KeyAlgorithm.ECDSA_P256:
            return {
                HashAlgorithm.SHA256: "ES256",
                HashAlgorithm.SHA384: "ES384",
                HashAlgorithm.SHA512: "ES512",
            }[hash_alg]
        if key_algorithm == KeyAlgorithm.ECDSA_P384:
            return "ES384"
        return "RS256"

    @staticmethod
    def _b64url(raw: bytes) -> str:
        """Base64URL sin padding (RFC 7515)."""
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    def _sign_in_kms(
        self,
        *,
        key,
        cert_row,
        hash_bytes: bytes,
        hash_algorithm: HashAlgorithm,
        resolved_format: SignatureFormat,
        document_hash_hex: str,
        document_id: Optional[UUID],
        document_type: Optional[str],
    ) -> str:
        """
        Ejecuta la firma con la clave privada dentro del KMS y devuelve el
        objeto de firma completo en formato serializado (JWS o CMS base64).

        La clave privada se descifra en memoria volátil usando
        ``KMS_MASTER_KEY``, se firma con ella y se destruye inmediatamente.
        En ningún momento se expone por logs, APIs ni respuestas.
        """
        private_pem_bytes: Optional[bytes] = None
        private_key = None
        try:
            # Descifrado temporal.
            private_pem_bytes = self.ca_service.decrypt_private_key(
                key.private_key_encrypted
            )
            private_key = serialization.load_pem_private_key(
                private_pem_bytes, password=None, backend=self.backend
            )

            # Construcción del objeto de firma según el formato resuelto.
            if resolved_format == SignatureFormat.JWS:
                return self._build_jws_token(
                    private_key=private_key,
                    key_algorithm=key.algorithm,
                    hash_algorithm=hash_algorithm,
                    cert_row=cert_row,
                    document_hash_hex=document_hash_hex,
                    document_id=document_id,
                    document_type=document_type,
                )
            return self._build_pkcs7_cms(
                private_key=private_key,
                hash_bytes=hash_bytes,
                hash_algorithm=hash_algorithm,
                cert_row=cert_row,
            )
        finally:
            # Destrucción defensiva de la clave privada en memoria.
            # Python no permite borrar memoria real de objetos inmutables,
            # pero eliminar referencias ayuda al GC a recogerlas.
            private_key = None
            if private_pem_bytes is not None:
                try:
                    private_pem_bytes = bytes(len(private_pem_bytes))
                except Exception:
                    pass
                private_pem_bytes = None

    def _raw_sign(
        self,
        *,
        private_key,
        data: bytes,
        hash_algorithm: HashAlgorithm,
    ) -> bytes:
        """Firma ``data`` con la clave privada correspondiente."""
        hash_obj = self._hash_obj(hash_algorithm)
        if isinstance(private_key, rsa.RSAPrivateKey):
            return private_key.sign(data, padding.PKCS1v15(), hash_obj)
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(data, ec.ECDSA(hash_obj))
        raise audit_error(
            "UNSUPPORTED_KEY_ALGORITHM",
            status.HTTP_400_BAD_REQUEST,
            {"reason": "Tipo de clave no soportado para firma"},
        )

    def _build_jws_token(
        self,
        *,
        private_key,
        key_algorithm: KeyAlgorithm,
        hash_algorithm: HashAlgorithm,
        cert_row,
        document_hash_hex: str,
        document_id: Optional[UUID],
        document_type: Optional[str],
    ) -> str:
        """
        Genera un token JWS compacto ``header.payload.signature`` en
        Base64URL cumpliendo RFC 7515.
        """
        alg = self._jws_alg_label(key_algorithm, hash_algorithm)
        header = {
            "alg": alg,
            "typ": "JWT",
            "kid": str(cert_row.key_id),
            "x5t#S256": cert_row.fingerprint,
        }
        payload = {
            "document_hash": document_hash_hex,
            "document_id": str(document_id) if document_id else None,
            "document_type": document_type,
            "hash_algorithm": hash_algorithm.value,
            "signed_at": datetime.now(timezone.utc).isoformat(),
            "certificate_id": str(cert_row.certificate_id),
        }

        header_b64 = self._b64url(_json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = self._b64url(_json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        signature_bytes = self._raw_sign(
            private_key=private_key,
            data=signing_input,
            hash_algorithm=hash_algorithm,
        )

        # Para ECDSA convertir DER → R||S concatenado (formato JOSE).
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            r, s = decode_dss_signature(signature_bytes)
            key_size_bytes = (private_key.curve.key_size + 7) // 8
            signature_bytes = r.to_bytes(key_size_bytes, "big") + s.to_bytes(key_size_bytes, "big")

        signature_b64 = self._b64url(signature_bytes)
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _build_pkcs7_cms(
        self,
        *,
        private_key,
        hash_bytes: bytes,
        hash_algorithm: HashAlgorithm,
        cert_row,
    ) -> str:
        """
        Genera un objeto CMS/PKCS#7 (detached signature) en DER serializado
        en Base64. Incluye el certificado del firmante dentro del objeto.
        """
        signer_cert = _x509.load_pem_x509_certificate(
            cert_row.certificate_pem.encode("utf-8")
            if isinstance(cert_row.certificate_pem, str)
            else cert_row.certificate_pem,
            backend=self.backend,
        )

        builder = _pkcs7.PKCS7SignatureBuilder().set_data(hash_bytes).add_signer(
            signer_cert, private_key, self._hash_obj(hash_algorithm)
        )
        # NoAttributes + DetachedSignature + Binary: el valor firmado es
        # directamente ``hash_bytes``, lo cual permite una verificación
        # criptográfica determinista sin parsear signedAttributes.
        cms_der = builder.sign(
            serialization.Encoding.DER,
            [
                _pkcs7.PKCS7Options.DetachedSignature,
                _pkcs7.PKCS7Options.Binary,
                _pkcs7.PKCS7Options.NoAttributes,
            ],
        )
        return base64.b64encode(cms_der).decode("ascii")

    def _generate_rfc3161_timestamp(self) -> str:
        """Genera un timestamp RFC 3161 simulado (placeholder para TSA real)."""
        timestamp = datetime.now(timezone.utc).isoformat()
        return f"RFC3161_TIMESTAMP:{timestamp}"

    # ==================== Verificadores por Formato (RF-INT-17) ====================

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Decodifica Base64URL con padding recuperado (RFC 7515)."""
        s = data.strip()
        pad = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + ("=" * pad))

    def _verify_jws_token(
        self,
        *,
        jws_token: str,
        document_hash_hex: str,
        public_key_pem: str,
        algorithm: KeyAlgorithm,
    ) -> tuple[bool, Optional[str]]:
        """
        Verifica un token JWS compacto (RFC 7515):
            header_b64.payload_b64.signature_b64

        1. Recompone ``signing_input = header_b64 . payload_b64``.
        2. Verifica criptográficamente la firma con la clave pública.
        3. Confirma que el ``document_hash`` del payload coincide con el
           hash recalculado del documento.
        """
        if not jws_token or jws_token.count(".") != 2:
            return False, "JWS token mal formado"

        header_b64, payload_b64, signature_b64 = jws_token.split(".")
        try:
            header = _json.loads(self._b64url_decode(header_b64))
            payload = _json.loads(self._b64url_decode(payload_b64))
            signature_bytes = self._b64url_decode(signature_b64)
        except Exception as exc:  # noqa: BLE001
            return False, f"No se pudo parsear el JWS: {exc}"

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        alg = header.get("alg", "")

        # Selección de hash según el encabezado ``alg``.
        hash_obj_map = {
            "RS256": hashes.SHA256(),
            "RS384": hashes.SHA384(),
            "RS512": hashes.SHA512(),
            "ES256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }
        hash_obj = hash_obj_map.get(alg)
        if hash_obj is None:
            return False, f"Algoritmo JWS no soportado: {alg}"

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
                backend=self.backend,
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"No se pudo cargar la clave pública: {exc}"

        try:
            if algorithm in (KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096):
                public_key.verify(signature_bytes, signing_input, padding.PKCS1v15(), hash_obj)
            elif algorithm in (KeyAlgorithm.ECDSA_P256, KeyAlgorithm.ECDSA_P384):
                # JOSE ES* usa R||S fijo; convertir a DER para cryptography.
                curve_size = (public_key.curve.key_size + 7) // 8  # type: ignore[attr-defined]
                if len(signature_bytes) != 2 * curve_size:
                    return False, "Firma ECDSA JOSE con tamaño incorrecto"
                r = int.from_bytes(signature_bytes[:curve_size], "big")
                s = int.from_bytes(signature_bytes[curve_size:], "big")
                der = encode_dss_signature(r, s)
                public_key.verify(der, signing_input, ec.ECDSA(hash_obj))
            else:
                return False, f"Algoritmo de clave no soportado: {algorithm}"
        except InvalidSignature:
            return False, "Firma JWS no válida (InvalidSignature)"
        except Exception as exc:  # noqa: BLE001
            return False, f"Error verificando JWS: {exc}"

        # Integridad del payload: el hash del documento debe coincidir.
        payload_hash = payload.get("document_hash")
        if payload_hash and payload_hash.strip().lower() != document_hash_hex.strip().lower():
            return False, "El hash del payload JWS no coincide con el del documento"

        return True, None

    def _verify_pkcs7_cms(
        self,
        *,
        cms_b64: str,
        document_hash_hex: str,
        public_key_pem: str,
        algorithm: KeyAlgorithm,
        hash_algorithm: HashAlgorithm,
    ) -> tuple[bool, Optional[str]]:
        """
        Verifica un objeto CMS/PKCS#7 detached generado por este KMS.

        Nuestra construcción firma los bytes ``hash_bytes`` del documento
        (ver ``_build_pkcs7_cms``). Para validar recomponemos el
        ``signed_data`` esperado (``bytes.fromhex(document_hash_hex)``) y
        verificamos la firma con la clave pública.
        """
        try:
            cms_der = base64.b64decode(cms_b64)
        except Exception as exc:  # noqa: BLE001
            return False, f"Base64 CMS inválido: {exc}"

        # Reconstruimos el mensaje firmado (mismo criterio que al firmar).
        try:
            signed_data = bytes.fromhex(document_hash_hex)
        except ValueError:
            return False, "document_hash no está en hexadecimal"

        # Estrategia: localizar la firma (OCTET STRING) dentro del SignerInfo
        # del CMS. Como generamos el PKCS#7 con NoAttributes, la firma está
        # directamente sobre ``hash_bytes`` y el último OCTET STRING del
        # SignerInfo corresponde al valor de firma.
        from pyasn1.codec.der.decoder import decode as asn1_decode  # type: ignore
        from pyasn1.type.univ import OctetString as _OctetString  # type: ignore

        try:
            content_info, _ = asn1_decode(cms_der)
            # ContentInfo → SEQUENCE { OID, content [0] EXPLICIT } — pyasn1
            # devuelve directamente la SignedData ya decodificada en [1].
            signed_data = content_info.getComponentByPosition(1)
            # signerInfos es el último componente de SignedData.
            signer_infos = signed_data.getComponentByPosition(len(signed_data) - 1)
            signer_info = signer_infos.getComponentByPosition(0)

            signature_bytes = None
            for idx in range(len(signer_info) - 1, -1, -1):
                comp = signer_info.getComponentByPosition(idx)
                if isinstance(comp, _OctetString):
                    signature_bytes = bytes(comp)
                    break
            if signature_bytes is None:
                return False, "No se pudo extraer la firma del CMS"
        except Exception as exc:  # noqa: BLE001
            return False, f"Estructura CMS inesperada: {exc}"

        hash_obj = self._hash_obj(hash_algorithm)

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
                backend=self.backend,
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"No se pudo cargar la clave pública: {exc}"

        try:
            if algorithm in (KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096):
                public_key.verify(signature_bytes, signed_data, padding.PKCS1v15(), hash_obj)
            elif algorithm in (KeyAlgorithm.ECDSA_P256, KeyAlgorithm.ECDSA_P384):
                public_key.verify(signature_bytes, signed_data, ec.ECDSA(hash_obj))
            else:
                return False, f"Algoritmo de clave no soportado: {algorithm}"
        except InvalidSignature:
            return False, "Firma PKCS#7 no válida (InvalidSignature)"
        except Exception as exc:  # noqa: BLE001
            return False, f"Error verificando PKCS#7: {exc}"

        return True, None

    # ==================== Validación de Firmas ====================

    def verify_signature(
        self,
        db: Session,
        *,
        document_hash: Optional[str] = None,
        document_content: Optional[str] = None,
        digital_signature: Optional[str] = None,
        signature_id: Optional[UUID],
        key_id: Optional[UUID],
        hash_algorithm: HashAlgorithm,
        validated_by: Optional[UUID],
    ):
        """
        Valida una firma digital (RF-INT-17).

        Flujo canónico:
            1. Si hay ``signature_id`` se cargan todos los datos desde BD
               (clave, certificado, formato, hash y ``signed_at``).
            2. Si se envía ``document_content`` se recalcula el hash y se
               compara con el almacenado (detección de manipulación).
            3. Se invoca RF-INT-15 en modo **historical** con
               ``reference_date = signed_at``.
            4. Se verifica criptográficamente la firma según su formato real
               (JWS o PKCS#7), no como base64 crudo.
            5. El resultado se clasifica en ``valid | invalid | expired |
               revoked`` y se registra el evento de validación.
        """
        signature_record = None
        signature_format_stored: Optional[str] = None

        if signature_id:
            signature_record = self.kms_repo.get_signature_by_id(db, signature_id)
            if not signature_record:
                raise audit_error("SIGNATURE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
            key_id = signature_record.key_id
            stored_hash = signature_record.document_hash
            stored_sig = signature_record.digital_signature
            signature_format_stored = (
                signature_record.signature_format.value
                if hasattr(signature_record.signature_format, "value")
                else str(signature_record.signature_format)
            )

            # RF-INT-17: el usuario puede validar solo con el documento —
            # sin datos técnicos — y el sistema recalcula el hash.
            if document_content is not None and not document_hash:
                hash_map = {
                    HashAlgorithm.SHA256: hashlib.sha256,
                    HashAlgorithm.SHA384: hashlib.sha384,
                    HashAlgorithm.SHA512: hashlib.sha512,
                }
                hasher = hash_map.get(hash_algorithm, hashlib.sha256)
                document_hash = hasher(
                    document_content.encode("utf-8")
                ).hexdigest()

            # Si el cliente no envió nada, asumimos validación interna:
            # usamos el hash y la firma almacenados.
            if not document_hash:
                document_hash = stored_hash
            if not digital_signature:
                digital_signature = stored_sig

            # Detección de modificaciones: hash recalculado vs almacenado.
            if stored_hash.strip() != document_hash.strip():
                validation = self.kms_repo.create_validation(
                    db=db,
                    signature_id=signature_id,
                    validation_result=ValidationResult.INVALID.value,
                    validation_reason="Document hash mismatch (document tampered)",
                    validated_by=validated_by,
                )
                return validation

        # Para firmas externas (sin signature_id) se exigen los datos mínimos.
        if not signature_id:
            if not document_hash or not digital_signature or not key_id:
                raise audit_error(
                    "VERIFY_MISSING_PARAMS",
                    status.HTTP_400_BAD_REQUEST,
                    {
                        "message": (
                            "Para validar una firma externa debe enviar "
                            "document_hash, digital_signature y key_id, o "
                            "utilizar signature_id para validar una firma del sistema."
                        ),
                    },
                )

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

        # RF-INT-13: Clave en estado ROTATED.
        # Las firmas generadas ANTES de la rotación siguen siendo válidas
        # de forma permanente (cumplían todos los criterios al momento
        # de su creación). Cualquier firma cuyo ``signed_at`` sea posterior
        # al ``rotated_at`` de la clave se considera inválida porque la
        # clave dejó de estar autorizada para emitir firmas en ese momento.
        if key.status == KeyStatus.ROTATED:
            if signature_record is not None and signature_record.signed_at is not None and key.rotated_at is not None:
                sig_ts = signature_record.signed_at
                rot_ts = key.rotated_at
                # Normalizar ambos a UTC aware para comparar sin errores de tz naïve/aware.
                if sig_ts.tzinfo is None:
                    sig_ts = sig_ts.replace(tzinfo=timezone.utc)
                if rot_ts.tzinfo is None:
                    rot_ts = rot_ts.replace(tzinfo=timezone.utc)
                if sig_ts > rot_ts:
                    validation = self.kms_repo.create_validation(
                        db=db,
                        signature_id=signature_id or UUID("00000000-0000-0000-0000-000000000000"),
                        validation_result=ValidationResult.REVOKED.value,
                        validation_reason="Signature created after key rotation",
                        validated_by=validated_by,
                    )
                    return validation
            else:
                # Sin registro de firma disponible: permitimos la verificación
                # solo si estamos dentro del período de gracia. Fuera de él,
                # no podemos garantizar que la firma sea histórica legítima.
                now_utc = datetime.now(timezone.utc)
                grace_end = key.grace_period_end
                if grace_end is not None:
                    if grace_end.tzinfo is None:
                        grace_end = grace_end.replace(tzinfo=timezone.utc)
                    if now_utc > grace_end:
                        validation = self.kms_repo.create_validation(
                            db=db,
                            signature_id=signature_id or UUID("00000000-0000-0000-0000-000000000000"),
                            validation_result=ValidationResult.REVOKED.value,
                            validation_reason="Rotated key grace period expired",
                            validated_by=validated_by,
                        )
                        return validation

        # RF-INT-15: Validación de integridad del certificado en MODO
        # HISTÓRICO (usamos signed_at de la firma como fecha de referencia).
        # Si no hay registro de firma, validamos en modo CURRENT.
        if signature_record is not None and signature_record.signed_at is not None:
            cert_validation = self.cert_validator.validate_certificate(
                db,
                key_id=key.key_id,
                validation_mode=ValidationMode.HISTORICAL,
                reference_date=signature_record.signed_at,
            )
        else:
            cert_validation = self.cert_validator.validate_certificate(
                db,
                key_id=key.key_id,
                validation_mode=ValidationMode.CURRENT,
            )

        if not cert_validation.is_valid:
            result_map = {
                CertValidationState.EXPIRED.value: ValidationResult.EXPIRED,
                CertValidationState.REVOKED.value: ValidationResult.REVOKED,
            }
            mapped = result_map.get(cert_validation.result, ValidationResult.INVALID)
            validation = self.kms_repo.create_validation(
                db=db,
                signature_id=signature_id or UUID("00000000-0000-0000-0000-000000000000"),
                validation_result=mapped.value,
                validation_reason=(
                    cert_validation.reason
                    or f"Certificate validation failed: {cert_validation.result}"
                ),
                validated_by=validated_by,
            )
            return validation

        # RF-INT-17: verificación criptográfica según formato real de firma.
        # El formato se toma del registro (JWS o PKCS7). Para firmas externas
        # sin registro, se infiere observando la cadena.
        fmt_label = signature_format_stored
        if fmt_label is None:
            fmt_label = (
                SignatureFormat.JWS.value
                if "." in (digital_signature or "") and (digital_signature or "").count(".") == 2
                else SignatureFormat.PKCS7.value
            )

        try:
            if fmt_label == SignatureFormat.JWS.value:
                is_valid, verify_reason = self._verify_jws_token(
                    jws_token=digital_signature,
                    document_hash_hex=document_hash,
                    public_key_pem=key.public_key,
                    algorithm=key.algorithm,
                )
            elif fmt_label == SignatureFormat.PKCS7.value:
                is_valid, verify_reason = self._verify_pkcs7_cms(
                    cms_b64=digital_signature,
                    document_hash_hex=document_hash,
                    public_key_pem=key.public_key,
                    algorithm=key.algorithm,
                    hash_algorithm=hash_algorithm,
                )
            else:
                is_valid = False
                verify_reason = f"Formato de firma no soportado: {fmt_label}"
        except Exception as exc:  # noqa: BLE001
            is_valid = False
            verify_reason = f"Cryptographic verification error: {exc}"

        validation_result = ValidationResult.VALID if is_valid else ValidationResult.INVALID
        validation_reason = None if is_valid else (verify_reason or "Cryptographic verification failed")

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

        # Marcar primero la clave anterior como ROTATED para liberar
        # la restricción de unicidad (solo una ACTIVE por project+purpose).
        now = datetime.now(timezone.utc)
        self.kms_repo.update_key_status(db, old_key.key_id, KeyStatus.ROTATED, now)

        # Calcular fin del período de gracia y registrar en la clave rotada.
        grace_period_end = now + timedelta(days=grace_period_days)
        old_key.grace_period_end = grace_period_end
        db.commit()

        # Vigencia fresca para la nueva clave: conserva la duración
        # original de la clave anterior pero reinicia el conteo desde ahora.
        # Fallback a 1 año si la clave anterior no tenía fechas consistentes.
        fresh_valid_to = None
        if old_key.valid_from and old_key.valid_to:
            old_from = old_key.valid_from
            old_to = old_key.valid_to
            if old_from.tzinfo is None:
                old_from = old_from.replace(tzinfo=timezone.utc)
            if old_to.tzinfo is None:
                old_to = old_to.replace(tzinfo=timezone.utc)
            duration = old_to - old_from
            if duration.days > 0:
                fresh_valid_to = now + duration

        # Generar nueva clave enlazada semánticamente a la anterior:
        # según RF-INT-12, ``supersedes_key_id`` en la NUEVA clave apunta
        # a la clave anterior. Se omiten las validaciones de alias/unicidad
        # porque la vieja ya está en estado ROTATED dentro de esta misma
        # transacción lógica.
        new_key = self.create_key(
            db=db,
            project_id=old_key.project_id,
            key_alias=old_key.key_alias,
            algorithm=old_key.algorithm,
            key_purpose=old_key.key_purpose,
            valid_to=fresh_valid_to,
            created_by=rotated_by,
            kms_key_reference=None,
            skip_alias_validation=True,
            skip_active_uniqueness_check=True,
            supersedes_key_id=old_key.key_id,
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

    # ==================== RF-INT-20: Revocación ====================

    def revoke_key(
        self,
        db: Session,
        *,
        key_id: UUID,
        reason: str,
        actor_id: Optional[UUID] = None,
    ) -> dict:
        """
        Revoca una clave criptográfica de forma transaccional (RF-INT-20).

        Flujo:
            1. Verifica existencia.
            2. Verifica que no esté ya revocada (irreversible).
            3. Actualiza ``af_kms_keys.status = 'revoked'``.
            4. Si existe un certificado activo asociado, lo revoca
               también dentro de la misma transacción
               (``af_kms_certificates.status = 'revoked'`` +
               ``revoked_at``).
            5. Si cualquier paso falla, se hace rollback completo.

        No registra el evento de auditoría (eso se hace en la capa de
        ruta, donde se tiene acceso al ``Request`` y se decide el
        ``action_code`` apropiado).

        Retorna un diccionario con ``key_id``, ``revoked_at`` y (si
        aplica) ``cascaded_certificate_id``.
        """
        now = datetime.now(timezone.utc)

        key = self.kms_repo.get_key_by_id(db, key_id)
        if key is None:
            raise audit_error("KEY_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        if key.status == KeyStatus.REVOKED:
            raise audit_error(
                "KEY_ALREADY_REVOKED",
                status.HTTP_409_CONFLICT,
                {"key_id": str(key_id)},
            )

        try:
            key.status = KeyStatus.REVOKED
            # No hay columna ``revoked_at`` en af_kms_keys; la fecha queda
            # trazada en ``af_audit_log.created_at``.

            # Cascada: revocar también el certificado activo asociado.
            cascaded_cert_id: Optional[UUID] = None
            active_cert = self.kms_repo.get_active_certificate_by_key_id(db, key_id)
            if active_cert is not None:
                active_cert.status = CertificateStatus.REVOKED
                active_cert.revoked_at = now
                cascaded_cert_id = active_cert.certificate_id

            db.commit()
            db.refresh(key)
        except Exception:
            db.rollback()
            raise

        return {
            "key_id": key.key_id,
            "revoked_at": now,
            "cascaded_certificate_id": cascaded_cert_id,
            "reason": reason,
        }

    def revoke_certificate(
        self,
        db: Session,
        *,
        certificate_id: UUID,
        reason: str,
        actor_id: Optional[UUID] = None,
    ) -> dict:
        """
        Revoca un certificado digital de forma transaccional (RF-INT-20).

        Actualiza ``af_kms_certificates.status = 'revoked'`` y
        ``revoked_at`` a la hora actual. La operación es irreversible.
        """
        now = datetime.now(timezone.utc)

        cert = self.kms_repo.get_certificate_by_id(db, certificate_id)
        if cert is None:
            raise audit_error("CERTIFICATE_NOT_FOUND", status.HTTP_404_NOT_FOUND)

        if cert.status == CertificateStatus.REVOKED:
            raise audit_error(
                "CERTIFICATE_ALREADY_REVOKED",
                status.HTTP_409_CONFLICT,
                {"certificate_id": str(certificate_id)},
            )

        try:
            cert.status = CertificateStatus.REVOKED
            cert.revoked_at = now
            db.commit()
            db.refresh(cert)
        except Exception:
            db.rollback()
            raise

        return {
            "certificate_id": cert.certificate_id,
            "key_id": cert.key_id,
            "revoked_at": now,
            "reason": reason,
        }

