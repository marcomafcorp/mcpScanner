from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.core.security import require_admin, require_analyst
from app.core.log_monitoring import security_monitor, log_aggregator
from app.models import User


router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


@router.get("/security/checks", dependencies=[Depends(require_analyst)])
async def run_security_checks(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Run security monitoring checks on-demand.
    
    Returns current security alerts and anomalies.
    """
    try:
        results = await security_monitor.run_all_checks(db)
        
        # Count total alerts
        total_alerts = sum(len(alerts) for alerts in results.values())
        high_severity = sum(
            1 for alerts in results.values() 
            for alert in alerts 
            if alert.get("severity") == "high"
        )
        
        return {
            "status": "completed",
            "total_alerts": total_alerts,
            "high_severity_alerts": high_severity,
            "results": results,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run security checks: {str(e)}"
        )


@router.get("/activity/summary", dependencies=[Depends(require_analyst)])
async def get_activity_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
) -> dict:
    """
    Get activity summary for the specified time period.
    
    Maximum lookback is 7 days (168 hours).
    """
    try:
        summary = await log_aggregator.get_activity_summary(db, hours)
        return {
            "status": "success",
            "summary": summary,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate activity summary: {str(e)}"
        )


@router.get("/errors/summary", dependencies=[Depends(require_analyst)])
async def get_error_summary(
    db: Annotated[AsyncSession, Depends(get_db)],
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
) -> dict:
    """
    Get error summary for the specified time period.
    
    Maximum lookback is 7 days (168 hours).
    """
    try:
        summary = await log_aggregator.get_error_summary(db, hours)
        return {
            "status": "success",
            "summary": summary,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate error summary: {str(e)}"
        )


@router.post("/thresholds", dependencies=[Depends(require_admin)])
async def update_monitoring_thresholds(
    thresholds: dict,
) -> dict:
    """
    Update security monitoring thresholds.
    
    Available thresholds:
    - failed_logins_per_user: Failed login attempts per user
    - failed_logins_per_ip: Failed login attempts per IP
    - rate_limit_violations: Rate limit violations
    - unauthorized_access: 401/403 responses
    - scan_rate_per_user: Scans per user
    """
    try:
        # Validate threshold keys
        valid_keys = set(security_monitor.thresholds.keys())
        invalid_keys = set(thresholds.keys()) - valid_keys
        
        if invalid_keys:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid threshold keys: {invalid_keys}"
            )
        
        # Update thresholds
        for key, value in thresholds.items():
            if not isinstance(value, int) or value <= 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Threshold values must be positive integers"
                )
            security_monitor.thresholds[key] = value
        
        return {
            "status": "updated",
            "thresholds": security_monitor.thresholds,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update thresholds: {str(e)}"
        )


@router.get("/thresholds", dependencies=[Depends(require_analyst)])
async def get_monitoring_thresholds() -> dict:
    """Get current security monitoring thresholds."""
    return {
        "thresholds": security_monitor.thresholds,
        "time_windows": security_monitor.time_windows,
    }