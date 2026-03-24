from sqlalchemy.orm import Session
from fastapi import status, HTTPException
from sqlalchemy import func
from app.core.errors import audit_error
from app.models.cat_terms import CatTerm
from app.models.af_permissions import AfPermission
from app.models.af_roles_permissions import AfRolePermission
class PermissionsService:
    """
    Servicio principal para permisos
    """
    
    
    def validate_permission(self, db: Session, role_info: dict, permission_code: str) -> bool:
        """
        Valida si un rol tiene permiso para ejecutar una acción.
        
        Args:
            db (Session): Sesión de base de datos
            role_info (dict): Información del rol (debe contener 'id')
            permission_code (str): Código del permiso a validar
        
        Returns:
            bool: True si tiene permiso o el permiso está inactivo, 
                False si no tiene permiso
        
        Raises:
            HTTPException: Si el rol no existe (404)
        """
        
        # Si no hay información del rol, no se puede validar
        if not role_info or 'id' not in role_info:
            auth_error("ROLE_NOT_FOUND", status.HTTP_404_NOT_FOUND)
        
        # 1. Verificar si el permiso existe y su estado
        permission = (
            db.query(
                AfPermission.af_perm_id,
                AfPermission.status_term_id
            )
            .filter(AfPermission.code == permission_code)
            .first()
        )
        
        # Si el permiso no existe, denegar acceso
        if not permission:
            return False
        
        permission_id, permission_state = permission


        status_term = (
            db.query(CatTerm.code)
            .filter(
                CatTerm.term_id == permission_state,
            )
            .scalar()
        )
        
        # 2. Si el permiso está inactivo, permitir acceso directo
        if status_term == "INACTIVE":
            return True
        
        # 3. Si el permiso está activo, validar que el rol lo tenga asociado
        has_permission = (
            db.query(AfRolePermission)
            .filter(
                AfRolePermission.af_role_id == role_info['id'],
                AfRolePermission.af_perm_id == permission_id
            )
            .first()
            is not None
        )
        
        return has_permission