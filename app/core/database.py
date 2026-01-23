"""
Configuración de base de datos usando SQLAlchemy.

Este módulo define:
- El engine de conexión
- La sesión de base de datos
- La clase Base para modelos ORM
- La dependencia `get_db` para FastAPI
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

# Engine principal de SQLAlchemy construido a partir de la URL de configuración
engine = create_engine(settings.database_url)

# Fábrica de sesiones para manejar transacciones de base de datos
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Clase base para todos los modelos ORM del proyecto
Base = declarative_base()

# Importa todos los modelos para que SQLAlchemy los registre correctamente
import app.models 

def get_db():
    """
    Dependencia de FastAPI que provee una sesión de base de datos.

    - Abre una sesión por request
    - Garantiza el cierre de la conexión al finalizar
    - Se utiliza con Depends(get_db)
    """
    db = SessionLocal()
    try:
        # Se entrega la sesión activa a la ruta o servicio
        yield db
    finally:
        # Se cierra la sesión para liberar recursos
        db.close()


