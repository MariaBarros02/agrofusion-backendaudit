"""
Configuración central de la aplicación.

Carga variables de entorno utilizando Pydantic Settings
y valida su estructura para el backend.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
import os

class Settings(BaseSettings):
    """
    Configuración de la aplicación cargada desde variables de entorno.

    Utiliza Pydantic para validación automática y tipado seguro.
    """
    #Entorno de ejecución
    ENV: str = "development"
    # URLs y base de datos
    frontend_base_url: str
    database_url: str
    # Seguridad y autenticación JWT
    secret_key: str
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    algorithm: str = "HS256"
    jwt_issuer: str = "agrofusion-backendauth"
    # Configuración de correo SMTP
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from_name: str
    sso_private_key_path: str | None = None
    # Archivos generados de exportación (PDF/CSV/…); metadatos en af_audit_exports.
    # Por defecto bajo el proyecto; en producción suele apuntarse a un volumen (exports_base_path en .env).
    exports_base_path: str = "./data/exports"
    audit_export_permission_code: str = "030"
    export_download_ttl_minutes: int = 60
    export_signing_key_id: str | None = None
    export_worker_poll_seconds: float = 2.0
    export_chunk_size: int = 10000
    export_file_retention_days: int = 7
    export_pdf_max_rows: int = 5000
    # URL pública del API de auditoría para enlaces de descarga en correo (opcional)
    audit_api_public_url: str = ""
    # ==================== KMS / Root CA (RF-INT-11) ====================
    # Clave maestra usada para cifrar la clave privada de la Root CA con
    # AES-256-GCM. Se deriva a 32 bytes mediante SHA-256 del valor aportado,
    # por lo que cualquier cadena suficientemente entrópica es válida.
    # En producción debe provenir de un secret manager o HSM.
    kms_master_key: str = "CHANGE_ME_MASTER_KEY_AGROFUSION_DEV"
    # Subject (CN) por defecto para la Root CA interna.
    kms_ca_root_subject: str = "CN=AgroFusion Root CA,O=AgroFusion,C=CO"
    # Algoritmo permitido para la Root CA (RSA-2048 | RSA-4096 | ECDSA-P256 | ECDSA-P384).
    kms_ca_root_algorithm: str = "RSA-2048"
    # Vigencia mínima del certificado de la Root CA en días (>= 3650 = 10 años).
    kms_ca_root_validity_days: int = 3650
    # Si es True, la aplicación intenta generar la Root CA automáticamente
    # durante el arranque (seed) cuando no exista una activa.
    kms_ca_root_autoseed: bool = True
    # Configuración de Pydantic Settings:
    # - Carga variables desde el archivo .env según el entorno
    # - Rechaza variables no definidas explícitamente

    model_config = SettingsConfigDict(
        env_file=f".env.{os.getenv('ENV', 'development')}",
        extra="forbid",  
    )

# Instancia única de configuración para toda la aplicación
settings = Settings()
