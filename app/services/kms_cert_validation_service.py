"""
Servicio de validación de integridad de certificados digitales (RF-INT-15).

Este módulo implementa la verificación en dos modos:
    * ``current``   – valida el estado presente del certificado
                      (usado por RF-INT-17 al crear firmas).
    * ``historical`` – valida el estado que tenía el certificado en una
                      fecha específica de referencia (usado por RF-INT-19
                      al verificar firmas históricas).

Resultados posibles (RF-INT-15):
    - ``valid``    : certificado íntegro, firmado por la Root CA y vigente.
    - ``invalid``  : certificado alterado o con firma CA no válida.
    - ``expired``  : fuera del período ``valid_from`` / ``valid_to``.
    - ``revoked``  : revocado (``status='revoked'``) o con ``revoked_at``
                     previo a la fecha de referencia en modo histórico.

Criterios verificados en cada ejecución:
    1. Coherencia del fingerprint (SHA-256 sobre DER).
    2. Firma criptográfica del certificado realizada por la Root CA.
    3. Rango de validez respecto a la fecha de referencia.
    4. Estado actual / histórico del certificado.

El proceso es estrictamente lectura: nunca modifica ``af_kms_certificates``
ni realiza revocaciones automáticas (esas son acciones manuales — RF-INT-13).
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from sqlalchemy.orm import Session

from app.models.af_kms_certificates import AfKmsCertificate, CertificateStatus
from app.repositories.kms_repository import KmsRepository


class ValidationMode(str, enum.Enum):
    """Modo de evaluación del certificado (RF-INT-15)."""

    CURRENT = "current"
    HISTORICAL = "historical"


class CertValidationState(str, enum.Enum):
    """Estados posibles del resultado de validación (RF-INT-15)."""

    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class CertValidationResult:
    """Resultado detallado de una validación de certificado."""

    result: str
    reason: Optional[str]
    certificate_id: Optional[str]
    key_id: Optional[str]
    validation_mode: str
    reference_date: str
    checked_at: str
    fingerprint_ok: bool
    ca_signature_ok: bool
    period_ok: bool
    status_ok: bool

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_valid(self) -> bool:
        return self.result == CertValidationState.VALID.value


class CertificateValidationService:
    """
    Servicio que implementa el RF-INT-15: validación de integridad,
    autenticidad y vigencia de certificados X.509 emitidos por la
    Root CA interna.
    """

    def __init__(self) -> None:
        self.kms_repo = KmsRepository()
        self.backend = default_backend()

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------

    @staticmethod
    def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
        """Normaliza un datetime a UTC aware."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _load_cert(self, pem: str) -> x509.Certificate:
        return x509.load_pem_x509_certificate(
            pem.encode("utf-8") if isinstance(pem, str) else pem,
            backend=self.backend,
        )

    def _verify_ca_signature(
        self,
        cert: x509.Certificate,
        ca_public_key_pem: str,
    ) -> bool:
        """Verifica que el certificado haya sido firmado por la Root CA."""
        try:
            ca_public_key = serialization.load_pem_public_key(
                ca_public_key_pem.encode("utf-8")
                if isinstance(ca_public_key_pem, str)
                else ca_public_key_pem,
                backend=self.backend,
            )

            tbs_bytes = cert.tbs_certificate_bytes
            signature_bytes = cert.signature
            sig_hash_alg = cert.signature_hash_algorithm

            if isinstance(ca_public_key, rsa.RSAPublicKey):
                ca_public_key.verify(
                    signature_bytes,
                    tbs_bytes,
                    padding.PKCS1v15(),
                    sig_hash_alg,
                )
                return True
            if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    signature_bytes,
                    tbs_bytes,
                    ec.ECDSA(sig_hash_alg),
                )
                return True
            return False
        except (InvalidSignature, ValueError, TypeError):
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------

    def resolve_certificate_for_key_at(
        self,
        db: Session,
        *,
        key_id: UUID,
        reference_date: Optional[datetime] = None,
    ) -> Optional[AfKmsCertificate]:
        """
        Selecciona el certificado aplicable a una clave para una fecha dada.

        Por RF-INT-14 la relación es 1:1 por ``key_version``, por lo que el
        certificado asociado al ``key_id`` es único. Se retorna ``None`` si
        no existe.
        """
        # Mientras la relación sea 1:1 por key_id, basta con obtener el
        # certificado emitido para esa clave.
        return self.kms_repo.get_certificate_by_key_id(db, key_id)

    def validate_certificate(
        self,
        db: Session,
        *,
        certificate_id: Optional[UUID] = None,
        key_id: Optional[UUID] = None,
        validation_mode: ValidationMode = ValidationMode.CURRENT,
        reference_date: Optional[datetime] = None,
    ) -> CertValidationResult:
        """
        Valida un certificado X.509 según el RF-INT-15.

        Args:
            certificate_id: Identificador del certificado a validar.
            key_id:         Alternativamente, la clave cuyo certificado
                            activo se desea validar.
            validation_mode: ``CURRENT`` o ``HISTORICAL``.
            reference_date:  Fecha de referencia (obligatoria en modo
                             histórico).

        Returns:
            ``CertValidationResult`` con el veredicto y el desglose
            de las verificaciones realizadas.
        """
        now_utc = datetime.now(timezone.utc)
        mode = ValidationMode(validation_mode) if not isinstance(validation_mode, ValidationMode) else validation_mode

        # Determinar fecha de referencia.
        if mode == ValidationMode.HISTORICAL:
            if reference_date is None:
                return self._fail(
                    state=CertValidationState.INVALID,
                    reason="reference_date es obligatorio en modo histórico",
                    certificate_id=certificate_id,
                    key_id=key_id,
                    validation_mode=mode,
                    reference_date=None,
                    now_utc=now_utc,
                )
            ref_date = self._as_utc(reference_date) or now_utc
        else:
            ref_date = now_utc

        # 1. Cargar certificado de BD.
        cert: Optional[AfKmsCertificate] = None
        if certificate_id is not None:
            cert = self.kms_repo.get_certificate_by_id(db, certificate_id) \
                if hasattr(self.kms_repo, "get_certificate_by_id") else None
            if cert is None:
                # Búsqueda más laxa si no existe helper por id.
                cert = (
                    db.query(AfKmsCertificate)
                    .filter(AfKmsCertificate.certificate_id == certificate_id)
                    .first()
                )
        elif key_id is not None:
            cert = self.resolve_certificate_for_key_at(
                db, key_id=key_id, reference_date=ref_date
            )

        if cert is None:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="Certificate not found",
                certificate_id=certificate_id,
                key_id=key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
            )

        # 2. Cargar Root CA activa (ancla de confianza).
        ca = self.kms_repo.get_active_ca_root(db)
        if ca is None:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="No active internal Root CA",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
            )

        # 3. Parsear certificado PEM.
        try:
            x509_cert = self._load_cert(cert.certificate_pem)
        except Exception:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="Certificate PEM could not be parsed (corrupted)",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
            )

        # 4. Integridad: fingerprint SHA-256 sobre DER == almacenado.
        der_bytes = x509_cert.public_bytes(serialization.Encoding.DER)
        recomputed_fp = hashlib.sha256(der_bytes).hexdigest()
        fingerprint_ok = (
            cert.fingerprint is not None
            and recomputed_fp.lower() == cert.fingerprint.lower()
        )
        if not fingerprint_ok:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="Certificate fingerprint mismatch (tampered)",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
                fingerprint_ok=False,
            )

        # 5. Firma de la Root CA (ancla de confianza).
        ca_signature_ok = self._verify_ca_signature(x509_cert, ca.public_key)
        if not ca_signature_ok:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="Certificate signature not issued by internal Root CA",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
                fingerprint_ok=True,
                ca_signature_ok=False,
            )

        # 6. Período de vigencia respecto a la fecha de referencia.
        valid_from = self._as_utc(cert.valid_from)
        valid_to = self._as_utc(cert.valid_to)
        if valid_from is None or valid_to is None:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="Certificate has no validity period",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
                fingerprint_ok=True,
                ca_signature_ok=True,
            )

        if ref_date < valid_from:
            return self._fail(
                state=CertValidationState.INVALID,
                reason="Certificate not yet valid at reference_date",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
                fingerprint_ok=True,
                ca_signature_ok=True,
            )

        if ref_date > valid_to:
            return self._fail(
                state=CertValidationState.EXPIRED,
                reason="Certificate expired at reference_date",
                certificate_id=cert.certificate_id,
                key_id=cert.key_id,
                validation_mode=mode,
                reference_date=ref_date,
                now_utc=now_utc,
                fingerprint_ok=True,
                ca_signature_ok=True,
                period_ok=False,
            )

        # 7. Revocación.
        cert_status = (cert.status or "").lower() or CertificateStatus.ACTIVE.value
        revoked_at = self._as_utc(cert.revoked_at)

        if mode == ValidationMode.CURRENT:
            if cert_status == CertificateStatus.REVOKED.value or revoked_at is not None:
                return self._fail(
                    state=CertValidationState.REVOKED,
                    reason="Certificate is revoked",
                    certificate_id=cert.certificate_id,
                    key_id=cert.key_id,
                    validation_mode=mode,
                    reference_date=ref_date,
                    now_utc=now_utc,
                    fingerprint_ok=True,
                    ca_signature_ok=True,
                    period_ok=True,
                    status_ok=False,
                )
        else:  # HISTORICAL
            # Solo consideramos "revocado" si la revocación ocurrió antes o
            # exactamente en la fecha de referencia.
            if revoked_at is not None and revoked_at <= ref_date:
                return self._fail(
                    state=CertValidationState.REVOKED,
                    reason=(
                        "Certificate was revoked before reference_date "
                        f"(revoked_at={revoked_at.isoformat()})"
                    ),
                    certificate_id=cert.certificate_id,
                    key_id=cert.key_id,
                    validation_mode=mode,
                    reference_date=ref_date,
                    now_utc=now_utc,
                    fingerprint_ok=True,
                    ca_signature_ok=True,
                    period_ok=True,
                    status_ok=False,
                )

        # 8. Validación satisfactoria.
        return CertValidationResult(
            result=CertValidationState.VALID.value,
            reason=None,
            certificate_id=str(cert.certificate_id),
            key_id=str(cert.key_id),
            validation_mode=mode.value,
            reference_date=ref_date.isoformat(),
            checked_at=now_utc.isoformat(),
            fingerprint_ok=True,
            ca_signature_ok=True,
            period_ok=True,
            status_ok=True,
        )

    # ------------------------------------------------------------------
    # Helpers privados
    # ------------------------------------------------------------------

    def _fail(
        self,
        *,
        state: CertValidationState,
        reason: str,
        certificate_id,
        key_id,
        validation_mode: ValidationMode,
        reference_date: Optional[datetime],
        now_utc: datetime,
        fingerprint_ok: bool = False,
        ca_signature_ok: bool = False,
        period_ok: bool = False,
        status_ok: bool = False,
    ) -> CertValidationResult:
        return CertValidationResult(
            result=state.value,
            reason=reason,
            certificate_id=str(certificate_id) if certificate_id else None,
            key_id=str(key_id) if key_id else None,
            validation_mode=validation_mode.value,
            reference_date=reference_date.isoformat() if reference_date else "",
            checked_at=now_utc.isoformat(),
            fingerprint_ok=fingerprint_ok,
            ca_signature_ok=ca_signature_ok,
            period_ok=period_ok,
            status_ok=status_ok,
        )
