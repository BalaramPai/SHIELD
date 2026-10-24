
from fastapi import APIRouter, HTTPException, Query

from apps.api.service import ShieldAPIService

router = APIRouter()
service = ShieldAPIService()


@router.get("/health")
def health_check():
    try:
        elasticsearch_available = bool(service.es.ping())
    except Exception:
        elasticsearch_available = False

    return {
        "status": "healthy" if elasticsearch_available else "degraded",
        "service": "shield-api",
        "elasticsearch": elasticsearch_available,
    }


@router.get("/system-health")
def get_system_health():
    """Return storage status and sensor/detector activity freshness."""
    return service.get_system_health()


@router.get("/overview")
def get_overview(minutes: int = Query(default=60, ge=5, le=1440)):
    return service.get_overview(minutes)


@router.get("/status")
def get_status():
    result = service.get_current_status()
    if result is None:
        return {
            "status": "unknown",
            "message": "No detection status is available yet.",
        }
    return result


@router.get("/incidents")
def get_incidents(limit: int = Query(default=20, ge=1, le=100)):
    return service.get_recent_incidents(limit)


@router.get("/incidents/{event_id}")
def get_incident(event_id: str):
    result = service.get_incident(event_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{event_id}' was not found.",
        )
    return result


@router.get("/events")
def search_events(
    limit: int = Query(default=50, ge=1, le=500),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    dst_port: int | None = None,
):
    return service.search_events(
        limit=limit,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        dst_port=dst_port,
    )


@router.get("/devices")
def get_devices(limit: int = Query(default=50, ge=1, le=200)):
    return service.get_devices(limit)


@router.get("/devices/{ip_address}")
def get_device_activity(
    ip_address: str,
    limit: int = Query(default=50, ge=1, le=200),
):
    return service.get_device_activity(ip_address=ip_address, limit=limit)


@router.get("/detector")
def get_detector_status():
    return service.get_detector_status()
