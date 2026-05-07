"""
Servicio de gestión de la Autoridad Certificadora Raíz (Root CA) interna.

Implementa el requerimiento funcional RF-INT-11:
- Generación controlada de la Root CA autofirmada del sistema.
- Cifrado de la clave privada con AES-256-GCM usando ``KMS_MASTER_KEY``.
- Construcción de un certificado X.509 v3 con subject == issuer.
- Cálculo del fingerprint SHA-256 sobre el certificado en formato DER.
- Persistencia en ``af_kms_ca_root`` garantizando una única Root CA activa.
- Registro del evento ``KMS_CA_CREATED`` en auditoría.

Algoritmos prohibidos (MD5 y SHA-1) no se utilizan en ninguna parte del
proceso (generación de claves, firma del certificado, fingerprint o
cifrado de la clave privada).
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import audit_error
from app.models.af_kms_ca_root import AfKmsCaRoot, CaRootStatus
from app.models.af_kms_certificates import AfKmsCertificate, CertificateStatus
from app.models.af_kms_keys import AfKmsKey, KeyAlgorithm, KeyStatus
from app.repositories.kms_repository import KmsRepository


# Prefijo para etiquetar el formato del ciphertext almacenado. Así podemos
# evolucionar el esquema de cifrado sin romper registros existentes.
_AES_GCM_PREFIX = "AESGCM256:v1:"
# Tamaño estándar recomendado para IV (nonce) en AES-GCM: 96 bits (12 bytes).
_GCM_IV_SIZE = 12


@dataclass
class _GeneratedKeyPair:
    algorithm: KeyAlgorithm
    private_key: object  # instancia de cryptography private key
    public_key: object
    private_pem: bytes
    public_pem: bytes


class KmsCaService:
    """
    Servicio encargado de la gestión de la Root CA interna del sistema.
    """

    # Algoritmos criptográficos permitidos (RF-INT-11: prohibe MD5 y SHA-1).
    _ALLOWED_ALGORITHMS = {
        KeyAlgorithm.RSA_2048,
        KeyAlgorithm.RSA_4096,
        KeyAlgorithm.ECDSA_P256,
        KeyAlgorithm.ECDSA_P384,
    }

    def __init__(self) -> None:
        self.kms_repo = KmsRepository()
        self.backend = default_backend()

    # ---------------------------------------------------------------
    # Clave maestra / cifrado AES-256-GCM
    # ---------------------------------------------------------------

    def _derive_master_key(self) -> bytes:
        """
        Deriva una clave de 32 bytes (AES-256) a partir de ``KMS_MASTER_KEY``.

        Se aplica SHA-256 sobre el valor del entorno para garantizar una clave
        de longitud fija, independientemente del formato del secreto aportado.
        """
        raw = settings.kms_master_key
        if not raw:
            raise audit_error(
                "KMS_MASTER_KEY_MISSING",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                {"error": "KMS_MASTER_KEY no está configurada en el entorno"},
            )
        return hashlib.sha256(raw.encode("utf-8")).digest()

    def _encrypt_private_key(self, private_pem: bytes) -> str:
        """
        Cifra la clave privada en PEM usando AES-256-GCM con IV aleatorio.

        Devuelve la cadena almacenable en base de datos con el formato:
            ``AESGCM256:v1:<base64(iv || ciphertext || tag)>``
        """
        master_key = self._derive_master_key()
        aesgcm = AESGCM(master_key)
        iv = os.urandom(_GCM_IV_SIZE)
        # AESGCM.encrypt concatena el tag (16 bytes) al final del ciphertext.
        ciphertext_with_tag = aesgcm.encrypt(iv, private_pem, associated_data=None)
        payload = iv + ciphertext_with_tag
        return _AES_GCM_PREFIX + base64.b64encode(payload).decode("ascii")

    def decrypt_private_key(self, encrypted_value: str) -> bytes:
        """
        Descifra la clave privada previamente cifrada por
        :meth:`_encrypt_private_key`.

        Uso restringido a operaciones internas del servidor; nunca se expone
        por API.
        """
        if not encrypted_value.startswith(_AES_GCM_PREFIX):
            raise ValueError("Formato de clave privada cifrada no soportado")
        b64 = encrypted_value[len(_AES_GCM_PREFIX):]
        payload = base64.b64decode(b64)
        if len(payload) < _GCM_IV_SIZE + 16:
            raise ValueError("Payload de clave privada cifrada corrupto")
        iv, ciphertext_with_tag = payload[:_GCM_IV_SIZE], payload[_GCM_IV_SIZE:]
        master_key = self._derive_master_key()
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(iv, ciphertext_with_tag, associated_data=None)

    # ---------------------------------------------------------------
    # Generación de material criptográfico
    # ---------------------------------------------------------------

    def _resolve_algorithm(self, algorithm: Optional[str]) -> KeyAlgorithm:
        value = algorithm or settings.kms_ca_root_algorithm
        try:
            algo = KeyAlgorithm(value)
        except ValueError:
            raise audit_error(
                "INVALID_CA_ALGORITHM",
                status.HTTP_400_BAD_REQUEST,
                {"algorithm": value},
            )
        if algo not in self._ALLOWED_ALGORITHMS:
            raise audit_error(
                "INVALID_CA_ALGORITHM",
                status.HTTP_400_BAD_REQUEST,
                {"algorithm": value},
            )
        return algo

    def _generate_keypair(self, algorithm: KeyAlgorithm) -> _GeneratedKeyPair:
        if algorithm == KeyAlgorithm.RSA_2048:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend,
            )
        elif algorithm == KeyAlgorithm.RSA_4096:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=self.backend,
            )
        elif algorithm == KeyAlgorithm.ECDSA_P256:
            private_key = ec.generate_private_key(ec.SECP256R1(), backend=self.backend)
        elif algorithm == KeyAlgorithm.ECDSA_P384:
            private_key = ec.generate_private_key(ec.SECP384R1(), backend=self.backend)
        else:
            raise audit_error(
                "INVALID_CA_ALGORITHM",
                status.HTTP_400_BAD_REQUEST,
                {"algorithm": algorithm.value if algorithm else None},
            )

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

        return _GeneratedKeyPair(
            algorithm=algorithm,
            private_key=private_key,
            public_key=public_key,
            private_pem=private_pem,
            public_pem=public_pem,
        )

    # ---------------------------------------------------------------
    # Construcción del certificado X.509 v3
    # ---------------------------------------------------------------

    @staticmethod
    def _parse_subject(subject_dn: str) -> x509.Name:
        """
        Convierte un DN simple tipo ``CN=...,O=...,C=...`` a ``x509.Name``.

        Soporta CN, O, OU, L, ST/S, C, emailAddress. Atributos desconocidos
        se ignoran silenciosamente.
        """
        oid_map = {
            "CN": NameOID.COMMON_NAME,
            "O": NameOID.ORGANIZATION_NAME,
            "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
            "L": NameOID.LOCALITY_NAME,
            "ST": NameOID.STATE_OR_PROVINCE_NAME,
            "S": NameOID.STATE_OR_PROVINCE_NAME,
            "C": NameOID.COUNTRY_NAME,
            "EMAILADDRESS": NameOID.EMAIL_ADDRESS,
        }
        attrs = []
        for part in [p.strip() for p in subject_dn.split(",") if p.strip()]:
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            key = k.strip().upper()
            value = v.strip()
            oid = oid_map.get(key)
            if oid is None or not value:
                continue
            attrs.append(x509.NameAttribute(oid, value))
        if not attrs:
            # Garantizamos al menos un CN para que el certificado sea válido.
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_dn or "AgroFusion Root CA"))
        return x509.Name(attrs)

    def _build_self_signed_certificate(
        self,
        keypair: _GeneratedKeyPair,
        subject_dn: str,
        validity_days: int,
    ) -> Tuple[x509.Certificate, bytes, bytes, str]:
        """
        Construye el certificado X.509 v3 autofirmado de la Root CA.

        Retorna:
            - objeto ``x509.Certificate``
            - ``cert_pem`` (bytes)
            - ``cert_der`` (bytes)
            - ``fingerprint_sha256`` (hex string)
        """
        subject = self._parse_subject(subject_dn)
        issuer = subject  # Autofirmado

        now = datetime.now(timezone.utc)
        valid_from = now - timedelta(minutes=1)  # tolerancia a desfaces de reloj
        valid_to = now + timedelta(days=validity_days)

        serial_number = x509.random_serial_number()

        # Hash de firma: SHA-256 para RSA, SHA-256/SHA-384 para ECDSA.
        if keypair.algorithm == KeyAlgorithm.ECDSA_P384:
            sign_hash = hashes.SHA384()
        else:
            sign_hash = hashes.SHA256()

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(keypair.public_key)
            .serial_number(serial_number)
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(keypair.public_key),
                critical=False,
            )
        )

        certificate = builder.sign(
            private_key=keypair.private_key,
            algorithm=sign_hash,
            backend=self.backend,
        )

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        fingerprint_hex = hashlib.sha256(cert_der).hexdigest()
        return certificate, cert_pem, cert_der, fingerprint_hex

    # ---------------------------------------------------------------
    # API pública
    # ---------------------------------------------------------------

    def get_active_ca(self, db: Session) -> Optional[AfKmsCaRoot]:
        """Retorna la Root CA activa o ``None`` si no existe."""
        return self.kms_repo.get_active_ca_root(db)

    def initialize_root_ca(
        self,
        db: Session,
        *,
        algorithm: Optional[str] = None,
        subject: Optional[str] = None,
        validity_days: Optional[int] = None,
        created_by: Optional[UUID] = None,
    ) -> AfKmsCaRoot:
        """
        Genera y persiste la Root CA del sistema siguiendo RF-INT-11.

        Si ya existe una Root CA activa, cancela la operación con
        ``CA_ROOT_ALREADY_EXISTS`` (HTTP 409).
        """
        # 1. No debe existir otra Root CA activa.
        existing = self.kms_repo.get_active_ca_root(db)
        if existing is not None:
            raise audit_error(
                "CA_ROOT_ALREADY_EXISTS",
                status.HTTP_409_CONFLICT,
                {"ca_id": str(existing.ca_id)},
            )

        # 2. Resolver parámetros y validar algoritmo.
        resolved_algorithm = self._resolve_algorithm(algorithm)
        resolved_subject = (subject or settings.kms_ca_root_subject).strip()
        resolved_validity = validity_days or settings.kms_ca_root_validity_days
        if resolved_validity < 3650:
            raise audit_error(
                "CA_ROOT_VALIDITY_TOO_SHORT",
                status.HTTP_400_BAD_REQUEST,
                {"validity_days": resolved_validity, "minimum_required": 3650},
            )

        # 3. Generar par de claves.
        keypair = self._generate_keypair(resolved_algorithm)

        # 4. Construir certificado X.509 v3 autofirmado.
        certificate, cert_pem, _cert_der, fingerprint_hex = self._build_self_signed_certificate(
            keypair=keypair,
            subject_dn=resolved_subject,
            validity_days=resolved_validity,
        )

        # 5. Cifrar la clave privada con AES-256-GCM.
        private_key_encrypted = self._encrypt_private_key(keypair.private_pem)

        # 6. Persistir en base de datos.
        subject_str = certificate.subject.rfc4514_string()
        issuer_str = certificate.issuer.rfc4514_string()
        valid_from = certificate.not_valid_before_utc if hasattr(certificate, "not_valid_before_utc") else certificate.not_valid_before.replace(tzinfo=timezone.utc)
        valid_to = certificate.not_valid_after_utc if hasattr(certificate, "not_valid_after_utc") else certificate.not_valid_after.replace(tzinfo=timezone.utc)
        serial_number_str = format(certificate.serial_number, "x").upper()

        ca = self.kms_repo.create_ca_root(
            db=db,
            private_key_encrypted=private_key_encrypted,
            public_key=keypair.public_pem.decode("ascii"),
            certificate_pem=cert_pem.decode("ascii"),
            fingerprint=fingerprint_hex,
            serial_number=serial_number_str,
            subject=subject_str,
            issuer=issuer_str,
            valid_from=valid_from,
            valid_to=valid_to,
            created_by=created_by,
        )
        return ca

    # ---------------------------------------------------------------
    # Emisión de certificados para claves de proyecto (RF-INT-14)
    # ---------------------------------------------------------------

    @staticmethod
    def _build_leaf_subject(project_id: UUID) -> x509.Name:
        """
        Construye el subject de un certificado hijo siguiendo el formato
        obligatorio de RF-INT-14: ``CN={project_id}, O=AgroFusion, C=CO``.
        """
        return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, str(project_id)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgroFusion"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CO"),
        ])

    def _load_ca_private_key(self, ca: AfKmsCaRoot):
        """Descifra y carga la clave privada de la Root CA."""
        private_pem_bytes = self.decrypt_private_key(ca.private_key_encrypted)
        return serialization.load_pem_private_key(
            private_pem_bytes, password=None, backend=self.backend
        )

    @staticmethod
    def _signature_algorithm_label(ca_algorithm: KeyAlgorithm, sign_hash: hashes.HashAlgorithm) -> str:
        """
        Devuelve una etiqueta legible (cumpliendo con lo requerido por RF-INT-14)
        del algoritmo de firma usado por la Root CA.
        """
        hash_name = sign_hash.name.upper()
        if ca_algorithm in (KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096):
            return f"{hash_name}withRSA"
        if ca_algorithm in (KeyAlgorithm.ECDSA_P256, KeyAlgorithm.ECDSA_P384):
            return f"{hash_name}withECDSA"
        return hash_name

    def issue_certificate_for_key(
        self,
        db: Session,
        *,
        key: AfKmsKey,
    ) -> AfKmsCertificate:
        """
        Emite un certificado X.509 v3 para una clave de proyecto (RF-INT-14).

        Proceso:
            1. Valida que la clave esté en estado ``active``.
            2. Obtiene la Root CA activa (RF-INT-11).
            3. Construye el subject como ``CN={project_id}, O=AgroFusion, C=CO``.
            4. Construye un certificado X.509 v3 con la clave pública del usuario,
               firmado por la Root CA usando SHA-256 o superior.
            5. Verifica que la clave pública del certificado coincide con la
               almacenada en ``af_kms_keys`` (RF-INT-14 – criterio de coherencia).
            6. Calcula el fingerprint SHA-256 sobre el DER.
            7. Persiste en ``af_kms_certificates`` con ``status = active``.

        Solo es invocado internamente por ``KmsService.create_key``; no existe
        endpoint público que lo exponga (RF-INT-14).
        """
        # 1. Validar estado de la clave.
        if key.status != KeyStatus.ACTIVE:
            raise audit_error(
                "KEY_NOT_ACTIVE",
                status.HTTP_400_BAD_REQUEST,
                {"status": getattr(key.status, "value", str(key.status))},
            )

        # 2. Root CA activa.
        ca = self.kms_repo.get_active_ca_root(db)
        if ca is None:
            raise audit_error(
                "CA_ROOT_NOT_FOUND",
                status.HTTP_400_BAD_REQUEST,
                {"error": "No existe una Root CA activa para emitir certificados."},
            )

        ca_private_key = self._load_ca_private_key(ca)

        # 3. Cargar clave pública del usuario (del registro af_kms_keys).
        user_public_key = serialization.load_pem_public_key(
            key.public_key.encode("utf-8") if isinstance(key.public_key, str) else key.public_key,
            backend=self.backend,
        )

        # 4. Construir subject y issuer.
        subject = self._build_leaf_subject(key.project_id)
        issuer = self._parse_subject(ca.subject)

        # 5. Período de validez = el de la clave.
        valid_from = key.valid_from
        valid_to = key.valid_to
        if valid_from and valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=timezone.utc)
        if valid_to and valid_to.tzinfo is None:
            valid_to = valid_to.replace(tzinfo=timezone.utc)
        if valid_from is None or valid_to is None or valid_to <= valid_from:
            raise audit_error(
                "CERT_INVALID_VALIDITY",
                status.HTTP_400_BAD_REQUEST,
                {"valid_from": str(valid_from), "valid_to": str(valid_to)},
            )

        # 6. Hash de firma: SHA-256 o superior (prohíbe MD5 y SHA-1).
        ca_algo = KeyAlgorithm(self._infer_ca_algorithm(ca))
        sign_hash: hashes.HashAlgorithm = (
            hashes.SHA384() if ca_algo == KeyAlgorithm.ECDSA_P384 else hashes.SHA256()
        )

        # 7. Construir certificado X.509 v3.
        serial_number = x509.random_serial_number()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(user_public_key)
            .serial_number(serial_number)
            .not_valid_before(valid_from)
            .not_valid_after(valid_to)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(user_public_key),
                critical=False,
            )
        )

        certificate = builder.sign(
            private_key=ca_private_key,
            algorithm=sign_hash,
            backend=self.backend,
        )

        # 8. Validar coherencia de clave pública (RF-INT-14).
        cert_pub_der = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        stored_pub_der = user_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_pub_der != stored_pub_der:
            raise audit_error(
                "CERT_KEY_MISMATCH",
                status.HTTP_400_BAD_REQUEST,
                {"key_id": str(key.key_id)},
            )

        # 9. Serializar y calcular fingerprint sobre DER.
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        fingerprint_hex = hashlib.sha256(cert_der).hexdigest()
        serial_str = format(certificate.serial_number, "x").upper()
        signature_algo = self._signature_algorithm_label(ca_algo, sign_hash)

        subject_str = certificate.subject.rfc4514_string()
        issuer_str = certificate.issuer.rfc4514_string()

        return self.kms_repo.create_certificate(
            db=db,
            key_id=key.key_id,
            certificate_pem=cert_pem.decode("ascii"),
            serial_number=serial_str,
            subject=subject_str,
            issuer=issuer_str,
            valid_from=valid_from,
            valid_to=valid_to,
            fingerprint=fingerprint_hex,
            signature_algorithm=signature_algo,
            status_value=CertificateStatus.ACTIVE.value,
        )

    @staticmethod
    def _infer_ca_algorithm(ca: AfKmsCaRoot) -> str:
        """
        Infiere el algoritmo de la Root CA inspeccionando su clave pública PEM.

        El objetivo es evitar tener que guardar el algoritmo en la tabla
        ``af_kms_ca_root``: se deduce con la librería ``cryptography``.
        """
        pk = serialization.load_pem_public_key(
            ca.public_key.encode("utf-8") if isinstance(ca.public_key, str) else ca.public_key,
            backend=default_backend(),
        )
        if isinstance(pk, rsa.RSAPublicKey):
            size = pk.key_size
            return (
                KeyAlgorithm.RSA_4096.value if size >= 4096 else KeyAlgorithm.RSA_2048.value
            )
        if isinstance(pk, ec.EllipticCurvePublicKey):
            curve_name = pk.curve.name.lower()
            if "384" in curve_name:
                return KeyAlgorithm.ECDSA_P384.value
            return KeyAlgorithm.ECDSA_P256.value
        # Fallback razonable.
        return KeyAlgorithm.RSA_2048.value
