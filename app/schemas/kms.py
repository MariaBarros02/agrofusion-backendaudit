"""
Schemas Pydantic para el módulo KMS (Key Management Service).

Define los modelos de validación de entrada y salida
para las operaciones de gestión de claves y firmas digitales.
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from app.models.af_kms_keys import KeyPurpose, KeyStatus, KeyAlgorithm
from app.models.af_kms_signatures import SignatureFormat, HashAlgorithm
from app.models.af_kms_signature_validations import ValidationResult
from app.models.af_kms_key_rotations import RotationReason


# ==================== Schemas para Generación de Claves ====================

class KeyCreateRequest(BaseModel):
    """Request para crear una nueva clave criptográfica."""
    
    project_id: UUID = Field(..., description="ID del proyecto/tenant")
    key_alias: str = Field(..., min_length=1, max_length=255, description="Alias amigable de la clave")
    algorithm: str = Field(..., description="Algoritmo criptográfico: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384")
    key_purpose: str = Field(..., description="Propósito de la clave: signing, encryption, both")
    valid_to: Optional[datetime] = Field(None, description="Fecha de expiración (opcional)")
    
    @validator('key_alias')
    def validate_alias(cls, v):
        if not v or not v.strip():
            raise ValueError("key_alias no puede estar vacío")
        return v.strip()
    
    @validator('algorithm')
    def validate_algorithm(cls, v):
        try:
            return KeyAlgorithm(v)
        except ValueError:
            raise ValueError(f"Algoritmo inválido. Opciones: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384")
    
    @validator('key_purpose')
    def validate_purpose(cls, v):
        try:
            return KeyPurpose(v)
        except ValueError:
            raise ValueError(f"Propósito inválido. Opciones: signing, encryption, both")


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
    """Request para registrar un certificado X.509."""
    
    key_id: UUID = Field(..., description="ID de la clave asociada")
    certificate_pem: str = Field(..., description="Certificado en formato PEM")
    serial_number: str = Field(..., description="Número de serie del certificado")
    subject: str = Field(..., description="Subject DN del certificado")
    issuer: str = Field(..., description="Issuer DN de la CA")
    valid_from: datetime = Field(..., description="Fecha de validez desde")
    valid_to: datetime = Field(..., description="Fecha de validez hasta")


class CertificateResponse(BaseModel):
    """Response con información de un certificado."""
    
    certificate_id: UUID
    key_id: UUID
    certificate_pem: str
    serial_number: str
    subject: str
    issuer: str
    valid_from: datetime
    valid_to: datetime
    fingerprint: str
    issued_at: datetime
    
    class Config:
        from_attributes = True


# ==================== Schemas para Firma Digital ====================

class SignatureCreateRequest(BaseModel):
    """Request para crear una firma digital."""
    
    document_hash: str = Field(..., min_length=64, max_length=128, description="Hash del documento (SHA-256, SHA-384 o SHA-512)")
    key_id: UUID = Field(..., description="ID de la clave a usar para firmar")
    hash_algorithm: str = Field(..., description="Algoritmo de hash usado: SHA-256, SHA-384, SHA-512")
    signature_format: str = Field(default="PKCS7", description="Formato de firma: PKCS7, JWS, XAdES, CAdES")
    include_timestamp: bool = Field(default=False, description="Incluir timestamp RFC 3161")
    document_id: Optional[UUID] = Field(None, description="ID del documento asociado")
    document_type: Optional[str] = Field(None, max_length=100, description="Tipo de documento")
    signer_user_id: Optional[UUID] = Field(None, description="ID del usuario firmante")
    signing_reason: Optional[str] = Field(None, description="Razón de la firma")
    project_id: Optional[UUID] = Field(None, description="ID del proyecto (opcional, se usa el de la clave si no se proporciona)")
    
    @validator('hash_algorithm')
    def validate_hash_algorithm(cls, v):
        try:
            return HashAlgorithm(v)
        except ValueError:
            raise ValueError(f"Algoritmo de hash inválido. Opciones: SHA-256, SHA-384, SHA-512")
    
    @validator('signature_format')
    def validate_signature_format(cls, v):
        try:
            return SignatureFormat(v)
        except ValueError:
            raise ValueError(f"Formato de firma inválido. Opciones: PKCS7, JWS, XAdES, CAdES")


class SignatureResponse(BaseModel):
    """Response con información de una firma digital."""
    
    signature_id: UUID
    key_id: UUID
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
    project_id: UUID
    created_at: datetime
    
    class Config:
        from_attributes = True


class SignatureVerifyRequest(BaseModel):
    """Request para validar una firma digital."""
    
    document_hash: str = Field(..., description="Hash del documento original")
    digital_signature: str = Field(..., description="Firma digital en base64")
    signature_id: Optional[UUID] = Field(None, description="ID de la firma (si existe en BD)")
    key_id: Optional[UUID] = Field(None, description="ID de la clave pública (si signature_id no está disponible)")
    hash_algorithm: str = Field(default="SHA-256", description="Algoritmo de hash usado: SHA-256, SHA-384, SHA-512")
    
    @validator('hash_algorithm')
    def validate_hash_algorithm(cls, v):
        try:
            return HashAlgorithm(v)
        except ValueError:
            raise ValueError(f"Algoritmo de hash inválido. Opciones: SHA-256, SHA-384, SHA-512")


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
    
    rotation_id: UUID
    old_key_id: UUID
    new_key_id: UUID
    rotation_reason: RotationReason
    grace_period_days: int
    rotated_by: UUID
    rotated_at: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True


# ==================== Schemas para Listados ====================

class KeyListResponse(BaseModel):
    """Response con lista de claves."""
    
    keys: List[KeyResponse]
    total: int


class SignatureListResponse(BaseModel):
    """Response con lista de firmas."""
    
    signatures: List[SignatureResponse]
    total: int

