from datetime import datetime, timedelta
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.auth.dependencies import get_current_user, require_admin, require_analyst
from app.models.audit_log import AuditLog, AuditAction
from app.models.user import User
from app.schemas.audit_log import (
    AuditLogResponse,
    AuditLogFilter,
    AuditLogExport,
    AuditLogSummary
)
import csv
import io
import json


router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("/", response_model=List[AuditLogResponse], dependencies=[Depends(require_analyst)])
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    actor_id: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    is_error: Optional[bool] = None,
    sort_by: str = Query("created_at", pattern="^(created_at|action|actor_id|ip_address)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$")
):
    """
    List audit logs with filtering and pagination.
    
    Requires analyst or admin role.
    
    Args:
        db: Database session
        skip: Number of records to skip
        limit: Maximum number of records to return
        actor_id: Filter by actor ID
        action: Filter by action
        resource_type: Filter by resource type
        resource_id: Filter by resource ID
        ip_address: Filter by IP address
        start_date: Filter by start date
        end_date: Filter by end date
        is_error: Filter by error status
        sort_by: Sort field
        sort_order: Sort order (asc/desc)
        
    Returns:
        List of audit logs
    """
    query = select(AuditLog)
    
    # Apply filters
    filters = []
    if actor_id:
        filters.append(AuditLog.actor_id == actor_id)
    if action:
        filters.append(AuditLog.action == action)
    if resource_type:
        filters.append(AuditLog.resource_type == resource_type)
    if resource_id:
        filters.append(AuditLog.resource_id == resource_id)
    if ip_address:
        filters.append(AuditLog.ip_address == ip_address)
    if start_date:
        filters.append(AuditLog.created_at >= start_date)
    if end_date:
        filters.append(AuditLog.created_at <= end_date)
    if is_error is not None:
        if is_error:
            filters.append(
                or_(
                    AuditLog.error_message.isnot(None),
                    AuditLog.response_status >= 400
                )
            )
        else:
            filters.append(
                and_(
                    AuditLog.error_message.is_(None),
                    or_(
                        AuditLog.response_status.is_(None),
                        AuditLog.response_status < 400
                    )
                )
            )
    
    if filters:
        query = query.where(and_(*filters))
    
    # Apply sorting
    sort_column = getattr(AuditLog, sort_by)
    if sort_order == "desc":
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(sort_column)
    
    # Apply pagination
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs


@router.get("/summary", response_model=AuditLogSummary, dependencies=[Depends(require_analyst)])
async def get_audit_log_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    start_date: Optional[datetime] = Query(None, description="Start date for summary"),
    end_date: Optional[datetime] = Query(None, description="End date for summary"),
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None
):
    """
    Get audit log summary statistics.
    
    Args:
        db: Database session
        start_date: Start date for summary
        end_date: End date for summary
        actor_id: Filter by specific actor
        resource_type: Filter by resource type
        
    Returns:
        Audit log summary
    """
    # Build base query
    query = select(AuditLog)
    filters = []
    
    if start_date:
        filters.append(AuditLog.created_at >= start_date)
    if end_date:
        filters.append(AuditLog.created_at <= end_date)
    if actor_id:
        filters.append(AuditLog.actor_id == actor_id)
    if resource_type:
        filters.append(AuditLog.resource_type == resource_type)
    
    if filters:
        query = query.where(and_(*filters))
    
    # Get total events
    total_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total_events = total_result.scalar()
    
    # Get unique actors
    actors_result = await db.execute(
        select(func.count(func.distinct(AuditLog.actor_id))).where(and_(*filters) if filters else True)
    )
    unique_actors = actors_result.scalar()
    
    # Get unique IPs
    ips_result = await db.execute(
        select(func.count(func.distinct(AuditLog.ip_address))).where(and_(*filters) if filters else True)
    )
    unique_ips = ips_result.scalar()
    
    # Get error count
    error_filters = filters + [
        or_(
            AuditLog.error_message.isnot(None),
            AuditLog.response_status >= 400
        )
    ]
    errors_result = await db.execute(
        select(func.count()).select_from(AuditLog).where(and_(*error_filters))
    )
    error_count = errors_result.scalar()
    
    # Get authentication events
    auth_actions = [
        AuditAction.USER_LOGIN,
        AuditAction.USER_LOGOUT,
        AuditAction.USER_REGISTER,
        AuditAction.TOKEN_REFRESH,
        AuditAction.USER_LOGIN_FAILED
    ]
    auth_filters = filters + [AuditLog.action.in_(auth_actions)]
    auth_result = await db.execute(
        select(func.count()).select_from(AuditLog).where(and_(*auth_filters))
    )
    authentication_events = auth_result.scalar()
    
    # Get action breakdown
    action_query = select(
        AuditLog.action,
        func.count().label('count')
    )
    if filters:
        action_query = action_query.where(and_(*filters))
    action_query = action_query.group_by(AuditLog.action).order_by(desc('count')).limit(20)
    
    action_result = await db.execute(action_query)
    action_breakdown = {row.action: row.count for row in action_result}
    
    # Get top actors
    top_actors_query = select(
        AuditLog.actor_id,
        AuditLog.actor_email,
        func.count().label('event_count')
    ).where(AuditLog.actor_id.isnot(None))
    
    if filters:
        top_actors_query = top_actors_query.where(and_(*filters))
    
    top_actors_query = top_actors_query.group_by(
        AuditLog.actor_id,
        AuditLog.actor_email
    ).order_by(desc('event_count')).limit(10)
    
    top_actors_result = await db.execute(top_actors_query)
    top_actors = [
        {
            "actor_id": row.actor_id,
            "actor_email": row.actor_email,
            "event_count": row.event_count
        }
        for row in top_actors_result
    ]
    
    # Get top IPs
    top_ips_query = select(
        AuditLog.ip_address,
        func.count().label('event_count')
    ).where(AuditLog.ip_address.isnot(None))
    
    if filters:
        top_ips_query = top_ips_query.where(and_(*filters))
    
    top_ips_query = top_ips_query.group_by(AuditLog.ip_address).order_by(desc('event_count')).limit(10)
    
    top_ips_result = await db.execute(top_ips_query)
    top_ips = [
        {
            "ip_address": row.ip_address,
            "event_count": row.event_count
        }
        for row in top_ips_result
    ]
    
    # Get time range
    time_range_query = select(
        func.min(AuditLog.created_at).label('start'),
        func.max(AuditLog.created_at).label('end')
    )
    if filters:
        time_range_query = time_range_query.where(and_(*filters))
    
    time_range_result = await db.execute(time_range_query)
    time_range_row = time_range_result.first()
    
    return AuditLogSummary(
        total_events=total_events or 0,
        unique_actors=unique_actors or 0,
        unique_ips=unique_ips or 0,
        error_count=error_count or 0,
        authentication_events=authentication_events or 0,
        action_breakdown=action_breakdown,
        top_actors=top_actors,
        top_ips=top_ips,
        time_range={
            "start": time_range_row.start if time_range_row and time_range_row.start else datetime.utcnow(),
            "end": time_range_row.end if time_range_row and time_range_row.end else datetime.utcnow()
        }
    )


@router.get("/my-activity", response_model=List[AuditLogResponse])
async def get_my_activity(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    days: int = Query(7, ge=1, le=90, description="Number of days to look back")
):
    """
    Get current user's activity log.
    
    Args:
        db: Database session
        current_user: Current authenticated user
        skip: Number of records to skip
        limit: Maximum number of records
        days: Number of days to look back
        
    Returns:
        User's audit logs
    """
    start_date = datetime.utcnow() - timedelta(days=days)
    
    query = select(AuditLog).where(
        and_(
            AuditLog.actor_id == str(current_user.id),
            AuditLog.created_at >= start_date
        )
    ).order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs


@router.get("/security-events", response_model=List[AuditLogResponse], dependencies=[Depends(require_admin)])
async def get_security_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    hours: int = Query(24, ge=1, le=168, description="Number of hours to look back")
):
    """
    Get recent security events (admin only).
    
    Args:
        db: Database session
        skip: Number of records to skip
        limit: Maximum number of records
        hours: Number of hours to look back
        
    Returns:
        Security-related audit logs
    """
    start_date = datetime.utcnow() - timedelta(hours=hours)
    
    security_actions = [
        AuditAction.USER_LOGIN_FAILED,
        AuditAction.SECURITY_VIOLATION,
        AuditAction.RATE_LIMIT_EXCEEDED,
        AuditAction.CSRF_FAILURE,
        AuditAction.SQL_INJECTION_ATTEMPT,
        AuditAction.XSS_ATTEMPT,
        AuditAction.UNAUTHORIZED_ACCESS,
    ]
    
    query = select(AuditLog).where(
        and_(
            AuditLog.action.in_(security_actions),
            AuditLog.created_at >= start_date
        )
    ).order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs


@router.post("/export", dependencies=[Depends(require_admin)])
async def export_audit_logs(
    export_request: AuditLogExport,
    db: Annotated[AsyncSession, Depends(get_db)],
    response: Response
):
    """
    Export audit logs in JSON or CSV format (admin only).
    
    Args:
        export_request: Export parameters
        db: Database session
        response: FastAPI response
        
    Returns:
        File download response
    """
    # Build query
    query = select(AuditLog)
    
    if export_request.filter:
        filters = []
        if export_request.filter.actor_id:
            filters.append(AuditLog.actor_id == export_request.filter.actor_id)
        if export_request.filter.action:
            filters.append(AuditLog.action == export_request.filter.action)
        if export_request.filter.resource_type:
            filters.append(AuditLog.resource_type == export_request.filter.resource_type)
        if export_request.filter.resource_id:
            filters.append(AuditLog.resource_id == export_request.filter.resource_id)
        if export_request.filter.ip_address:
            filters.append(AuditLog.ip_address == export_request.filter.ip_address)
        if export_request.filter.start_date:
            filters.append(AuditLog.created_at >= export_request.filter.start_date)
        if export_request.filter.end_date:
            filters.append(AuditLog.created_at <= export_request.filter.end_date)
        if export_request.filter.actions:
            filters.append(AuditLog.action.in_(export_request.filter.actions))
        
        if filters:
            query = query.where(and_(*filters))
    
    query = query.order_by(desc(AuditLog.created_at))
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    # Format response based on requested format
    if export_request.format == "csv":
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        headers = [
            "ID", "Created At", "Actor ID", "Actor Email", "Actor Role",
            "Action", "Resource Type", "Resource ID", "IP Address",
            "User Agent", "Request Method", "Request Path",
            "Response Status", "Response Time (ms)", "Error Message"
        ]
        if export_request.include_details:
            headers.append("Details")
        
        writer.writerow(headers)
        
        # Write data
        for log in logs:
            row = [
                str(log.id),
                log.created_at.isoformat() if log.created_at else "",
                log.actor_id or "",
                log.actor_email or "",
                log.actor_role or "",
                log.action,
                log.resource_type or "",
                log.resource_id or "",
                log.ip_address or "",
                log.user_agent or "",
                log.request_method or "",
                log.request_path or "",
                str(log.response_status) if log.response_status else "",
                str(log.response_time_ms) if log.response_time_ms else "",
                log.error_message or ""
            ]
            if export_request.include_details and log.details:
                row.append(json.dumps(log.details))
            
            writer.writerow(row)
        
        # Set response headers
        content = output.getvalue()
        response.headers["Content-Disposition"] = "attachment; filename=audit_logs.csv"
        response.headers["Content-Type"] = "text/csv"
        
        return Response(content=content, media_type="text/csv")
    
    else:  # JSON format
        # Convert logs to dictionaries
        data = []
        for log in logs:
            log_dict = log.to_dict()
            if not export_request.include_details:
                log_dict.pop("details", None)
            data.append(log_dict)
        
        # Set response headers
        content = json.dumps(data, indent=2, default=str)
        response.headers["Content-Disposition"] = "attachment; filename=audit_logs.json"
        response.headers["Content-Type"] = "application/json"
        
        return Response(content=content, media_type="application/json")


@router.delete("/cleanup", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
async def cleanup_old_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    days: int = Query(90, ge=30, le=365, description="Delete logs older than this many days")
):
    """
    Delete old audit logs (admin only).
    
    Args:
        db: Database session
        days: Delete logs older than this many days
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Delete old logs
    result = await db.execute(
        select(AuditLog).where(AuditLog.created_at < cutoff_date)
    )
    old_logs = result.scalars().all()
    
    for log in old_logs:
        await db.delete(log)
    
    await db.commit()
    
    # Log the cleanup action
    from app.middleware.audit_log import log_security_event
    from fastapi import Request
    # Note: In production, get the actual request object
    # await log_security_event(
    #     action="audit_log.cleanup",
    #     request=request,
    #     details={"deleted_count": len(old_logs), "cutoff_days": days}
    # )