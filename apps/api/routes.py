# File: apps/api/routes.py
# Purpose: Defines the HTTP API routes exposed by the SHIELD security platform.

from fastapi import APIRouter, HTTPException, Query

from apps.api.service import ShieldAPIService


router = APIRouter()
service = ShieldAPIService()


@router.get("/health")
def health_check():
    """Check whether the SHIELD API and Elasticsearch are available."""
    elasticsearch_available = service.es.ping()

    return {
        "status": "healthy" if elasticsearch_available else "degraded",
        "service": "shield-api",
        "elasticsearch": elasticsearch_available,
    }


@router.get("/status")
def get_status():
    """Return the latest detection-engine status."""
    result = service.get_current_status()

    if result is None:
        return {
            "status": "unknown",
            "message": "No detection status is available yet.",
        }

    return result


@router.get("/incidents")
def get_incidents(
    limit: int = Query(default=20, ge=1, le=100),
):
    """Return the most recent detected security incidents."""
    return service.get_recent_incidents(limit)


@router.get("/incidents/{event_id}")
def get_incident(event_id: str):
    """Return details for a specific detection result."""
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
    """Search recent network telemetry using optional filters."""
    return service.search_events(
        limit=limit,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        dst_port=dst_port,
    )


@router.get("/devices")
def get_devices(
    limit: int = Query(default=50, ge=1, le=200),
):
    """Return devices observed by the SHIELD sensor."""
    return service.get_devices(limit)


@router.get("/devices/{ip_address}")
def get_device_activity(
    ip_address: str,
    limit: int = Query(default=50, ge=1, le=200),
):
    """Return recent network activity for a specific IP address."""
    return service.get_device_activity(
        ip_address=ip_address,
        limit=limit,
    )


@router.get("/detector")
def get_detector_status():
    """Return information about the detection engine."""
    return service.get_detector_status()