"""
Script para crear las tablas del módulo KMS.
Ejecutar una vez antes de probar los endpoints.
"""
from app.core.database import engine, Base
from app.models import *  # Importar todos los modelos

if __name__ == "__main__":
    print("Creando tablas del módulo KMS...")
    try:
        # Crear todas las tablas
        Base.metadata.create_all(bind=engine, checkfirst=True)
        print("OK: Tablas creadas exitosamente")
    except Exception as e:
        print(f"ERROR al crear tablas: {e}")
        print("\nSi el error es por foreign keys, intenta eliminar las tablas manualmente y vuelve a ejecutar.")
        raise

