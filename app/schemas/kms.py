"""
Schemas Pydantic para el módulo KMS (Key Management Service).

Define los modelos de validación de entrada y salida
para las operaciones de gestión de claves y firmas digitales.
"""

from pydantic import BaseModel, Field, validator, computed_field, ConfigDict
from typing import Optional, List
from datetime import datetime
from enum import Enum
from uuid import UUID
from app.models.af_kms_keys import KeyPurpose, KeyStatus, KeyAlgorithm
from app.models.af_kms_signatures import SignatureFormat, HashAlgorithm
from app.models.af_kms_signature_validations import ValidationResult
from app.models.af_kms_key_rotations import RotationReason
from app.models.af_kms_ca_root import CaRootStatus


# ==================== Schemas para Generación de Claves ====================

class KeyCreateRequest(BaseModel):
    """Request para crear una nueva clave criptográfica."""
    
    project_id: Optional[UUID] = Field(
        None,
        description="Reservado: por ahora el backend ignora este campo y asocia la clave al proyecto AGROFUSION.",
    )
    key_alias: str = Field(..., min_length=1, max_length=255, description="Alias amigable de la clave")
    algorithm: str = Field(
        ...,
        description="Algoritmo criptográfico permitido: RSA-2048, RSA-4096, ECDSA-P256 o ECDSA-P384. RSA < 2048, MD5 y SHA-1 están prohibidos.",
    )
    key_purpose: str = Field(
        default="signing",
        description="Propósito de la clave. RF-INT-12 restringe las claves de proyecto a 'signing' (firma digital).",
    )
    valid_to: Optional[datetime] = Field(None, description="Fecha de expiración (opcional)")

    @validator('key_alias')
    def validate_alias(cls, v):
        if not v or not v.strip():
            raise ValueError("key_alias no puede estar vacío")
        return v.strip()

    @validator('algorithm')
    def validate_algorithm(cls, v):
        try:
            algo = KeyAlgorithm(v)
        except ValueError:
            raise ValueError(
                "Algoritmo inválido. Opciones permitidas: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384"
            )
        allowed = {
            KeyAlgorithm.RSA_2048,
            KeyAlgorithm.RSA_4096,
            KeyAlgorithm.ECDSA_P256,
            KeyAlgorithm.ECDSA_P384,
        }
        if algo not in allowed:
            raise ValueError(
                "Algoritmo no permitido por RF-INT-12. Usa RSA-2048+, ECDSA-P256 o ECDSA-P384."
            )
        return algo

    @validator('key_purpose')
    def validate_purpose(cls, v):
        try:
            purpose = KeyPurpose(v)
        except ValueError:
            raise ValueError("Propósito inválido. RF-INT-12 solo admite 'signing'.")
        if purpose != KeyPurpose.SIGNING:
            raise ValueError(
                "RF-INT-12 restringe las claves de proyecto al propósito 'signing'."
            )
        return purpose


class KeyResponse(BaseModel):
    """Response con información de una clave criptográfica."""
    
    key_id: UUID
    project_id: UUID
    key_alias: str
    algorithm: KeyAlgorithm
    key_length: int
    key_purpose: KeyPurpose
    key_fingerprint: str
    kms_key_reference: Optional[str]
    status: KeyStatus
    key_version: int
    valid_from: datetime
    valid_to: datetime
    created_by: UUID
    created_at: datetime
    rotated_at: Optional[datetime]
    supersedes_key_id: Optional[UUID]
    grace_period_end: Optional[datetime]
    
    class Config:
        from_attributes = True


class KeyPublicInfoResponse(BaseModel):
    """Response con información pública de una clave (sin datos sensibles)."""
    
    key_id: UUID
    key_alias: str
    algorithm: KeyAlgorithm
    key_length: int
    key_purpose: KeyPurpose
    key_fingerprint: str
    status: KeyStatus
    key_version: int
    valid_from: datetime
    valid_to: datetime
    public_key: str  # Clave pública en formato PEM
    
    class Config:
        from_attributes = True


# ==================== Schemas para Certificados ====================

class CertificateCreateRequest(BaseModel):
    """
    Schema legado — RF-INT-14 prohíbe la emisión manual.

    Se conserva la clase para compatibilidad con integraciones previas
    al requerimiento, pero ningún endpoint la utiliza como body aceptado.
    """

    key_id: UUID = Field(..., description="ID de la clave asociada")
    certificate_pem: str = Field(..., description="Certificado en formato PEM")
    serial_number: str = Field(..., description="Número de serie del certificado")
    subject: str = Field(..., description="Subject DN del certificado")
    issuer: str = Field(..., description="Issuer DN de la CA")
    valid_from: datetime = Field(..., description="Fecha de validez desde")
    valid_to: datetime = Field(..., description="Fecha de validez hasta")


class CertificateResponse(BaseModel):
    """Response con información de un certificado X.509 (RF-INT-14)."""

    certificate_id: UUID
    key_id: UUID
    certificate_pem: str
    serial_number: str
    subject: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    fingerprint: str
    signature_algorithm: Optional[str] = None
    status: Optional[str] = None
    revoked_at: Optional[datetime] = None
    issued_at: datetime

    class Config:
        from_attributes = True


# ==================== Schemas para Firma Digital ====================

class SignatureCreateRequest(BaseModel):
    """
    Request para crear una firma digital (RF-INT-16).

    - ``document_id`` y ``document_type`` son obligatorios.
    - El algoritmo de hash mínimo es SHA-256 (MD5 y SHA-1 están prohibidos).
    - El formato de firma (JWS o PKCS#7) lo determina el sistema según
      ``document_type``; no se acepta como entrada del cliente.
    - La clave privada nunca se envía en la request ni se expone en la
      respuesta.
    """

    document_hash: str = Field(
        ...,
        min_length=64,
        max_length=128,
        description="Hash del documento (hex de SHA-256, SHA-384 o SHA-512)",
    )
    key_id: UUID = Field(..., description="ID de la clave a usar para firmar")
    hash_algorithm: str = Field(
        ...,
        description="Algoritmo de hash usado: SHA-256, SHA-384 o SHA-512",
    )
    include_timestamp: bool = Field(default=False, description="Incluir timestamp RFC 3161")
    document_id: UUID = Field(..., description="ID del documento asociado (obligatorio)")
    document_type: str = Field(
        ...,
        max_length=100,
        description=(
            "Tipo de documento. El sistema selecciona el formato de firma: "
            "JSON/structured → JWS; binario (PDF, XML, CSV, ZIP...) → PKCS#7."
        ),
    )
    signer_user_id: Optional[UUID] = Field(None, description="ID del usuario firmante")
    signing_reason: Optional[str] = Field(None, description="Razón de la firma")
    project_id: Optional[UUID] = Field(
        None,
        description="ID del proyecto (opcional, se usa el de la clave si no se envía)",
    )

    @validator("hash_algorithm")
    def validate_hash_algorithm(cls, v):
        try:
            alg = HashAlgorithm(v)
        except ValueError:
            raise ValueError(
                "Algoritmo de hash inválido. Opciones permitidas: SHA-256, SHA-384, SHA-512. "
                "MD5 y SHA-1 están prohibidos por RF-INT-16."
            )
        return alg


class SignatureResponse(BaseModel):
    """Response con información de una firma digital (RF-INT-16)."""

    model_config = ConfigDict(from_attributes=True)

    signature_id: UUID
    key_id: UUID
    certificate_id: Optional[UUID] = None
    document_hash: str
    hash_algorithm: HashAlgorithm
    digital_signature: str
    signature_format: SignatureFormat
    signed_at: datetime
    rfc3161_timestamp: Optional[str]
    document_id: Optional[UUID]
    document_type: Optional[str]
    signer_user_id: Optional[UUID]
    signing_reason: Optional[str]
    project_id: Optional[UUID] = None

    @computed_field
    @property
    def created_at(self) -> datetime:
        """Misma marca temporal que `signed_at` si la tabla no tiene columna `created_at`."""
        return self.signed_at


class SignatureVerifyRequest(BaseModel):
    """
    Request para validar una firma digital (RF-INT-17).

    Puede completarse con la mínima información:
      - ``signature_id``: el sistema reconstruye todo (documento_hash, formato,
        clave y certificado) desde la base de datos.
      - ``document_content`` (opcional, texto): si se envía, el sistema
        recalcula el hash con ``hash_algorithm`` y lo coteja con el almacenado.

    Los campos ``document_hash`` y ``digital_signature`` son opcionales y solo
    se usan para validar firmas externas / exportadas que no estén en BD.
    """

    signature_id: Optional[UUID] = Field(
        None,
        description="ID de la firma registrada en el sistema (permite validar sin aportar datos técnicos)",
    )
    document_content: Optional[str] = Field(
        None,
        description="Documento original en texto. Si se envía, el sistema recalcula el hash internamente.",
    )
    document_hash: Optional[str] = Field(
        None,
        description="Hash del documento (hex). Opcional si se envía signature_id o document_content.",
    )
    digital_signature: Optional[str] = Field(
        None,
        description="Firma en formato JWS o CMS Base64. Opcional si se envía signature_id.",
    )
    key_id: Optional[UUID] = Field(
        None,
        description="ID de la clave pública (solo necesario para firmas externas sin signature_id).",
    )
    hash_algorithm: str = Field(default="SHA-256", description="Algoritmo de hash: SHA-256 / SHA-384 / SHA-512")

    @validator("hash_algorithm")
    def validate_hash_algorithm(cls, v):
        try:
            return HashAlgorithm(v)
        except ValueError:
            raise ValueError(
                "Algoritmo de hash inválido. Opciones: SHA-256, SHA-384, SHA-512. "
                "MD5 y SHA-1 están prohibidos."
            )


class SignatureVerifyResponse(BaseModel):
    """Response con resultado de validación de firma."""
    
    validation_id: UUID
    signature_id: Optional[UUID]
    validation_result: ValidationResult
    validation_reason: Optional[str]
    validated_by: Optional[UUID]
    validated_at: datetime
    
    class Config:
        from_attributes = True


# ==================== RF-INT-18: Presentación al usuario ====================

class SignatureTechnicalDetails(BaseModel):
    """
    Datos técnicos de solo lectura asociados a una firma digital (RF-INT-18).

    La UI debe mostrarlos como campos de solo lectura; el usuario no los
    introduce manualmente.
    """

    hash_documento: Optional[str] = Field(
        None, description="Hash del documento firmado (hex)"
    )
    algoritmo_hash: Optional[str] = Field(
        None, description="Algoritmo de hash usado (ej. SHA-256)"
    )
    formato_firma: Optional[str] = Field(
        None, description="Formato de la firma (JWS o PKCS#7)"
    )
    certificate_id: Optional[UUID] = Field(
        None, description="Identificador del certificado asociado"
    )
    certificate_serial: Optional[str] = Field(
        None, description="Número de serie del certificado"
    )
    certificate_fingerprint: Optional[str] = Field(
        None, description="Huella SHA-256 del certificado (hex)"
    )
    algoritmo_firma: Optional[str] = Field(
        None, description="Algoritmo de firma (ej. RSA-SHA256)"
    )


class SignatureValidationFriendlyResponse(BaseModel):
    """
    Respuesta orientada al usuario final para el proceso de validación de
    firmas digitales (RF-INT-18).

    Traduce el resultado técnico de RF-INT-17 a lenguaje comprensible y
    expone los mínimos requeridos por la interfaz: estado, firmante, fecha
    de firma e identificador de documento. Los datos técnicos viajan en un
    bloque aparte marcado como de solo lectura.
    """

    estado: str = Field(
        ...,
        description="Estado de la firma en lenguaje comprensible: Válida | Inválida | Expirada | Revocada",
    )
    resultado_general: str = Field(
        ...,
        description="Descripción general y comprensible del resultado de la validación",
    )
    firmante: Optional[str] = Field(
        None,
        description="Nombre del firmante resuelto desde el módulo de usuarios",
    )
    firmante_email: Optional[str] = Field(
        None, description="Correo del firmante (informativo)"
    )
    fecha_firma: Optional[datetime] = Field(
        None, description="Fecha y hora en que se generó la firma (signed_at)"
    )
    identificador_documento: Optional[UUID] = Field(
        None, description="Identificador del documento firmado"
    )
    tipo_documento: Optional[str] = Field(
        None, description="Tipo del documento firmado (ej. json, pdf, xml)"
    )
    razon_firma: Optional[str] = Field(
        None, description="Motivo o razón de firma (si fue registrado)"
    )
    validation_id: UUID = Field(
        ..., description="Identificador único del registro de validación"
    )
    signature_id: Optional[UUID] = Field(
        None, description="Identificador de la firma validada"
    )
    datos_tecnicos: SignatureTechnicalDetails = Field(
        default_factory=SignatureTechnicalDetails,
        description="Información técnica de solo lectura (hash, algoritmo, certificado, etc.)",
    )


# ==================== Schemas para Rotación de Claves ====================

class KeyRotationRequest(BaseModel):
    """Request para rotar una clave criptográfica.
    
    NOTA: El key_id viene en la URL como parámetro de ruta, no en el body.
    """
    
    rotation_reason: str = Field(..., description="Razón de la rotación: scheduled, compromised, manual, policy")
    grace_period_days: int = Field(default=30, ge=0, le=365, description="Período de gracia en días")
    
    @validator('rotation_reason')
    def validate_rotation_reason(cls, v):
        try:
            return RotationReason(v)
        except ValueError:
            raise ValueError(f"Razón de rotación inválida. Opciones: scheduled, compromised, manual, policy")


class KeyRotationResponse(BaseModel):
    """Response con información de una rotación de clave."""

    model_config = ConfigDict(from_attributes=True)

    rotation_id: UUID
    old_key_id: UUID
    new_key_id: UUID
    rotation_reason: RotationReason
    grace_period_days: int
    rotated_by: Optional[UUID] = None
    rotated_at: datetime


# ==================== Schemas para Listados ====================

class KeyListResponse(BaseModel):
    """Response con lista de claves."""
    
    keys: List[KeyResponse]
    total: int


class SignatureListResponse(BaseModel):
    """Response con lista de firmas."""
    
    signatures: List[SignatureResponse]
    total: int


# ==================== RF-INT-19: Consulta y auditoría ====================

class SignatureQueryItem(BaseModel):
    """
    Elemento del listado de firmas digitales (RF-INT-19).

    Expone únicamente los atributos funcionales requeridos para que el
    usuario autorizado consulte las firmas. No incluye el valor de la firma
    digital ni contenido de certificados.
    """

    model_config = ConfigDict(from_attributes=True)

    signature_id: UUID
    validation_status: str = Field(
        ...,
        description="Estado de la última validación: valid | invalid | expired | revoked | unknown",
    )
    signature_format: SignatureFormat
    expires_at: Optional[datetime] = Field(
        None,
        description="Fecha en que expira la firma (derivada de valid_to del certificado asociado)",
    )
    document_type: Optional[str]
    signer_user_id: Optional[UUID]
    signer_name: Optional[str] = Field(
        None, description="Nombre del firmante resuelto desde el módulo de usuarios"
    )
    signed_at: datetime
    document_id: Optional[UUID]
    key_algorithm: Optional[str] = Field(
        None,
        description="Algoritmo de la clave asociada (af_kms_keys.algorithm)",
    )
    export_name: Optional[str] = Field(
        None,
        description="Nombre de la exportación (af_audit_exports) cuando document_id es export_id",
    )


class SignatureQueryResponse(BaseModel):
    """Listado paginado de firmas (RF-INT-19) con total_count."""

    items: List[SignatureQueryItem]
    total_count: int = Field(..., description="Total de firmas que coinciden con los filtros")
    limit: int = Field(..., description="Tamaño de página (registros por solicitud)")
    offset: int = Field(..., description="Offset aplicado a la consulta")


class SignatureQueryDetail(SignatureQueryItem):
    """
    Detalle funcional de una firma (RF-INT-19).

    No expone ``digital_signature`` ni el contenido del certificado. Los
    identificadores ``key_id`` y ``certificate_id`` se incluyen solo para
    trazabilidad interna / auditoría técnica.
    """

    document_hash: Optional[str] = None
    hash_algorithm: Optional[HashAlgorithm] = None
    signing_reason: Optional[str] = None
    key_id: Optional[UUID] = None
    certificate_id: Optional[UUID] = None


class KmsAuditEventItem(BaseModel):
    """Evento de auditoría relacionado con el módulo KMS (RF-INT-19)."""

    audit_id: UUID
    action_code: str
    actor_id: Optional[UUID]
    actor_name: Optional[str]
    created_at: datetime
    outcome: Optional[str]
    target_type: Optional[str]
    target_id: Optional[str]
    metadata: Optional[dict] = Field(
        None, description="Datos adicionales del evento (target_json)"
    )


class KmsAuditEventsResponse(BaseModel):
    """Listado paginado de eventos de auditoría KMS (RF-INT-19)."""

    events: List[KmsAuditEventItem]
    total_count: int
    limit: int
    offset: int


# ==================== RF-INT-20: Revocación ====================

class RevocationReason(str, Enum):
    """Motivos válidos de revocación (RF-INT-20)."""

    COMPROMISED = "compromised"
    MANUAL = "manual"
    POLICY = "policy"


class RevokeRequest(BaseModel):
    """Request para revocar una clave o certificado (RF-INT-20)."""

    reason: RevocationReason = Field(
        ..., description="Motivo de la revocación: compromised | manual | policy"
    )
    note: Optional[str] = Field(
        None,
        description="Nota administrativa opcional que se guardará en el evento de auditoría",
        max_length=500,
    )


class RevokeResponse(BaseModel):
    """Respuesta a una operación de revocación (RF-INT-20)."""

    resource_type: str = Field(
        ..., description="Tipo de recurso revocado: 'key' o 'certificate'"
    )
    resource_id: UUID
    status: str = Field("revoked", description="Estado resultante")
    revoked_at: datetime
    reason: RevocationReason
    audit_id: Optional[UUID] = Field(
        None, description="Identificador del evento de auditoría registrado"
    )
    cascaded_certificate_id: Optional[UUID] = Field(
        None,
        description="Si se revocó una clave y tenía un certificado activo, este es el certificate_id que también quedó revocado en la misma transacción",
    )
    message: str = Field("Revocación ejecutada correctamente")


# ==================== Schemas Root CA (RF-INT-11) ====================

class CaRootInitRequest(BaseModel):
    """Request para inicializar la Root CA interna del sistema."""

    algorithm: Optional[str] = Field(
        None,
        description="Algoritmo: RSA-2048, RSA-4096, ECDSA-P256 o ECDSA-P384. Si se omite se usa el valor por defecto configurado.",
    )
    subject: Optional[str] = Field(
        None,
        description="Subject DN de la Root CA. Ej: CN=AgroFusion Root CA. Si se omite se usa el valor configurado.",
    )
    validity_days: Optional[int] = Field(
        None,
        ge=3650,
        le=36525,
        description="Vigencia del certificado en días (mínimo 3650 = 10 años).",
    )

    @validator("algorithm")
    def _validate_algorithm(cls, v):
        if v is None:
            return v
        try:
            return KeyAlgorithm(v).value
        except ValueError:
            raise ValueError(
                "Algoritmo inválido. Opciones: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384"
            )


class CaRootResponse(BaseModel):
    """Metadatos públicos de la Root CA (nunca incluye la clave privada)."""

    model_config = ConfigDict(from_attributes=True)

    ca_id: UUID
    subject: str
    issuer: str
    serial_number: str
    fingerprint: str
    public_key: str
    certificate_pem: str
    valid_from: datetime
    valid_to: datetime
    status: CaRootStatus
    created_at: datetime
    rotated_at: Optional[datetime] = None
    created_by: Optional[UUID] = None


class CaRootCertificateResponse(BaseModel):
    """Respuesta para exportación del certificado público de la Root CA."""

    subject: str
    issuer: str
    serial_number: str
    fingerprint: str
    valid_from: datetime
    valid_to: datetime
    certificate_pem: str
    public_key: str

