from celery import Celery
from celery.schedules import crontab

from app.core.config import settings


# Create Celery instance
celery_app = Celery(
    "mcp_scanner",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.scanners.tasks",
        "app.tasks.data_retention",
        "app.tasks.security_monitoring",
    ]
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Task routing
    task_routes={
        "app.scanners.tasks.*": {"queue": "scans"},
        "app.tasks.data_retention.*": {"queue": "maintenance"},
        "app.tasks.security_monitoring.*": {"queue": "monitoring"},
    },
    # Task time limits
    task_time_limit=3600,  # 1 hour hard limit
    task_soft_time_limit=3000,  # 50 minutes soft limit
    # Result backend settings
    result_expires=3600,  # Results expire after 1 hour
    # Worker settings
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
)

# Configure periodic tasks
celery_app.conf.beat_schedule = {
    # Daily data retention cleanup at 2 AM UTC
    "cleanup-old-data": {
        "task": "app.tasks.data_retention.cleanup_old_data_task",
        "schedule": crontab(hour=2, minute=0),
        "kwargs": {"dry_run": False},
    },
    # Weekly retention report on Sundays at 3 AM UTC
    "retention-report": {
        "task": "app.tasks.data_retention.generate_retention_report_task",
        "schedule": crontab(day_of_week=0, hour=3, minute=0),
    },
    # Daily dry-run cleanup report at 1 AM UTC
    "cleanup-dry-run": {
        "task": "app.tasks.data_retention.cleanup_old_data_task",
        "schedule": crontab(hour=1, minute=0),
        "kwargs": {"dry_run": True},
    },
    # Security checks every 15 minutes
    "security-checks": {
        "task": "app.tasks.security_monitoring.run_security_checks_task",
        "schedule": crontab(minute="*/15"),
    },
    # Daily activity report at 6 AM UTC
    "daily-activity-report": {
        "task": "app.tasks.security_monitoring.generate_activity_report_task",
        "schedule": crontab(hour=6, minute=0),
        "kwargs": {"hours": 24},
    },
    # Critical event monitoring every 5 minutes
    "critical-events": {
        "task": "app.tasks.security_monitoring.alert_on_critical_events_task",
        "schedule": crontab(minute="*/5"),
    },
}