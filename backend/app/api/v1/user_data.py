from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, require_user
from app.core.data_export import data_exporter, data_deletion_service
from app.models import User
from app.schemas.user import UserResponse


router = APIRouter(prefix="/user-data", tags=["User Data"])


@router.get("/export", dependencies=[Depends(require_user)])
async def export_user_data(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    format: str = Query("json", description="Export format", regex="^(json|csv|xml)$"),
    include_encrypted: bool = Query(
        False,
        description="Include decrypted sensitive data (requires additional verification)"
    ),
) -> Response:
    """
    Export all user data for GDPR compliance.
    
    Formats:
    - json: Single JSON file with all data
    - csv: ZIP file containing CSV files for each data type
    - xml: Single XML file with all data
    """
    try:
        # For encrypted data, could add additional verification here
        # (e.g., recent password confirmation, 2FA, etc.)
        
        # Export data
        data = await data_exporter.export_user_data(
            db=db,
            user_id=current_user.id,
            format=format,
            include_encrypted=include_encrypted
        )
        
        # Determine content type and filename
        content_types = {
            "json": "application/json",
            "csv": "application/zip",
            "xml": "application/xml",
        }
        
        extensions = {
            "json": "json",
            "csv": "zip",
            "xml": "xml",
        }
        
        filename = f"user_data_{current_user.id}.{extensions[format]}"
        
        return Response(
            content=data,
            media_type=content_types[format],
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export user data: {str(e)}"
        )


@router.delete("/delete", dependencies=[Depends(require_user)])
async def delete_user_data(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    background_tasks: BackgroundTasks,
    confirmation: str = Query(..., description="Type 'DELETE' to confirm"),
    soft_delete: bool = Query(
        True,
        description="Soft delete (anonymize) vs hard delete"
    ),
) -> dict:
    """
    Delete or anonymize all user data for GDPR compliance.
    
    - Soft delete: Anonymizes personal data but keeps records for audit
    - Hard delete: Completely removes all user data
    """
    # Validate confirmation
    if confirmation != "DELETE":
        raise HTTPException(
            status_code=400,
            detail="Invalid confirmation. Type 'DELETE' to confirm."
        )
    
    try:
        # Perform deletion
        deletion_counts = await data_deletion_service.delete_user_data(
            db=db,
            user_id=current_user.id,
            soft_delete=soft_delete
        )
        
        # Log the deletion in audit log before user is deleted
        from app.core.audit import audit_logger
        await audit_logger.log_user_data_deletion(
            db=db,
            user_id=current_user.id,
            deletion_type="soft" if soft_delete else "hard",
            deletion_counts=deletion_counts
        )
        
        await db.commit()
        
        # Clear any cached data for this user
        # background_tasks.add_task(clear_user_cache, current_user.id)
        
        return {
            "message": f"User data {'anonymized' if soft_delete else 'deleted'} successfully",
            "deletion_counts": deletion_counts,
            "user_id": current_user.id,
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete user data: {str(e)}"
        )


@router.get("/export/{user_id}", dependencies=[Depends(require_user)])
async def export_user_data_admin(
    user_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    format: str = Query("json", description="Export format", regex="^(json|csv|xml)$"),
) -> Response:
    """
    Export user data (admin only).
    
    Allows administrators to export any user's data for compliance requests.
    """
    # Check admin permission
    if current_user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can export other users' data"
        )
    
    try:
        # Never include encrypted data in admin exports
        data = await data_exporter.export_user_data(
            db=db,
            user_id=user_id,
            format=format,
            include_encrypted=False
        )
        
        # Determine content type and filename
        content_types = {
            "json": "application/json",
            "csv": "application/zip",
            "xml": "application/xml",
        }
        
        extensions = {
            "json": "json",
            "csv": "zip",
            "xml": "xml",
        }
        
        filename = f"user_data_{user_id}.{extensions[format]}"
        
        # Log admin access
        from app.core.audit import audit_logger
        await audit_logger.log_admin_data_export(
            db=db,
            admin_id=current_user.id,
            target_user_id=user_id,
            format=format
        )
        
        return Response(
            content=data,
            media_type=content_types[format],
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export user data: {str(e)}"
        )