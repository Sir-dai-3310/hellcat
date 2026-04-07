"""
Hellcat Celery Task Queue
=========================
Async task infrastructure with 4 queues (scan/analysis/report/ai).
Gracefully degrades when Redis is unavailable.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("hellcat.tasks")

BROKER_URL = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/1"))
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/2"))

_celery_app = None


def get_celery_app():
    """Lazy-init Celery app. Returns None if celery/redis unavailable."""
    global _celery_app
    if _celery_app is not None:
        return _celery_app
    try:
        from celery import Celery
        app = Celery("hellcat", broker=BROKER_URL, backend=RESULT_BACKEND)
        app.conf.update(
            result_expires=3600,
            task_serializer="json",
            result_serializer="json",
            accept_content=["json"],
            timezone="UTC",
            enable_utc=True,
            task_track_started=True,
            task_time_limit=3600,
            task_soft_time_limit=3300,
            worker_prefetch_multiplier=1,
            worker_max_tasks_per_child=1000,
            task_routes={
                "hellcat.core.tasks.scan.*":     {"queue": "scan"},
                "hellcat.core.tasks.analysis.*": {"queue": "analysis"},
                "hellcat.core.tasks.report.*":   {"queue": "report"},
                "hellcat.core.tasks.ai.*":       {"queue": "ai"},
            },
        )
        _celery_app = app
        logger.info("Celery initialized — broker=%s", BROKER_URL)
        return app
    except ImportError:
        logger.warning("Celery not installed — async tasks disabled")
        return None
    except Exception as exc:
        logger.warning("Celery init failed: %s — async tasks disabled", exc)
        return None


def is_celery_available() -> bool:
    return get_celery_app() is not None


def submit_task(task_name: str, *args: Any, **kwargs: Any) -> Optional[str]:
    """Submit async task. Returns task_id or None if Celery unavailable."""
    app = get_celery_app()
    if app is None:
        return None
    try:
        result = app.send_task(task_name, args=args, kwargs=kwargs)
        return result.id
    except Exception as exc:
        logger.error("Task submission failed: %s", exc)
        return None


def get_task_status(task_id: str) -> Dict[str, Any]:
    """Query task status. Returns dict with state/result/error."""
    app = get_celery_app()
    if app is None:
        return {"state": "UNAVAILABLE", "error": "Celery not available"}
    try:
        result = app.AsyncResult(task_id)
        info: Dict[str, Any] = {"state": result.state, "task_id": task_id}
        if result.ready():
            info["result"] = result.result
        if result.failed():
            info["error"] = str(result.result)
        return info
    except Exception as exc:
        return {"state": "ERROR", "error": str(exc)}
