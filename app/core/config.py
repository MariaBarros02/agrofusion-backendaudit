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

    # Configuración de Pydantic Settings:
    # - Carga variables desde el archivo .env según el entorno
    # - Rechaza variables no definidas explícitamente

    model_config = SettingsConfigDict(
        env_file=f".env.{os.getenv('ENV', 'development')}",
        extra="forbid",  
    )

# Instancia única de configuración para toda la aplicación
settings = Settings()
