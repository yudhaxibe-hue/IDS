"""
FastAPI REST routes for Explainable Adaptive IDS.
Provides authenticated endpoints for monitoring control, alert queries,
explainability inspection, and drift diagnostics.
"""
import os
import platform
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel

from backend.api.auth import verify_local_request, verify_loopback_only, get_session_token
from app.lifecycle import app_state
from backend.database.db import get_event_counts, get_db_connection

# Base router for loopback endpoints
router = APIRouter(prefix="/api")


class MonitoringStartRequest(BaseModel):
    mode: str = "demo"  # "demo" or "live"
    interface: Optional[str] = None


class MonitoringActionResponse(BaseModel):
    success: bool
    message: str
    mode: str
    interface: Optional[str] = None


@router.get("/health", dependencies=[Depends(verify_loopback_only)])
async def health_check():
    """Loopback-only health check returning basic engine state."""
    return {
        "status": "healthy",
        "system": platform.system(),
        "architecture": platform.machine(),
        "python_version": platform.python_version()
    }


# Protected routes requiring both loopback AND valid per-session token
protected_router = APIRouter(dependencies=[Depends(verify_local_request)])


@protected_router.get("/status")
async def get_system_status():
    """Retrieve aggregate application and detection telemetry."""
    summary = app_state.get_summary()
    counts = get_event_counts()
    return {
        **summary,
        "counts": counts,
        "platform": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine()
        }
    }


@protected_router.get("/interfaces")
async def list_interfaces():
    """
    List observable network interfaces on the local host.
    Includes permission diagnostic for macOS BPF or Windows Npcap.
    """
    interfaces = []
    has_bpf_permission = True
    bpf_note = ""

    if platform.system() == "Darwin":
        bpf0 = "/dev/bpf0"
        if os.path.exists(bpf0):
            has_bpf_permission = os.access(bpf0, os.R_OK)
            if not has_bpf_permission:
                bpf_note = "Read access to /dev/bpf* required for live capture. Use Replay/Demo mode or configure BPF permissions."
        else:
            has_bpf_permission = False
            bpf_note = "BPF capture device not found on this system."

    interfaces = [
        {"name": "en0", "description": "Primary Network Adapter (Wi-Fi / Ethernet)", "is_default": True},
        {"name": "lo0", "description": "Loopback Interface (127.0.0.1)", "is_default": False},
        {"name": "demo_replay", "description": "Offline Simulation Replay Stream", "is_default": False}
    ]

    return {
        "interfaces": interfaces,
        "capture_permissions": {
            "has_permission": has_bpf_permission,
            "diagnostic_note": bpf_note
        }
    }


@protected_router.post("/monitoring/start", response_model=MonitoringActionResponse)
async def start_monitoring(payload: MonitoringStartRequest):
    """Start live packet capture or offline demo replay."""
    if payload.mode not in ("live", "demo"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mode must be either 'live' or 'demo'."
        )

    target_interface = payload.interface or "en0"
    app_state.set_monitoring(True, mode=payload.mode, interface=target_interface)

    return MonitoringActionResponse(
        success=True,
        message=f"Monitoring started in {payload.mode.upper()} mode on interface '{target_interface}'.",
        mode=payload.mode,
        interface=target_interface
    )


@protected_router.post("/monitoring/stop", response_model=MonitoringActionResponse)
async def stop_monitoring():
    """Stop active packet monitoring or replay stream."""
    app_state.set_monitoring(False, mode="idle")
    return MonitoringActionResponse(
        success=True,
        message="Monitoring stopped successfully.",
        mode="idle"
    )


@protected_router.get("/events")
async def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    is_malicious: Optional[int] = Query(None)
):
    """Fetch paginated history of classified network events and alerts."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM events"
        params: List[Any] = []
        
        if is_malicious is not None:
            query += " WHERE is_malicious = ?"
            params.append(is_malicious)
            
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]
        
        cursor.execute("SELECT COUNT(*) as total FROM events" + (" WHERE is_malicious = ?" if is_malicious is not None else ""), [is_malicious] if is_malicious is not None else [])
        total = cursor.fetchone()["total"]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": rows
    }


@protected_router.get("/events/{event_id}")
async def get_event_detail(event_id: int):
    """Retrieve full details for an individual event, including its XAI explanation."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Event not found.")
        return dict(row)


@protected_router.get("/drift")
async def get_drift_status():
    """Fetch concept drift monitoring status and historical shift logs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM drift_logs ORDER BY id DESC LIMIT 20")
        logs = [dict(row) for row in cursor.fetchall()]

    return {
        "status": app_state.drift_status,
        "active_model_version": app_state.active_model_version,
        "recent_logs": logs
    }


@protected_router.get("/about")
async def get_about_info():
    """Return academic prototype details and version metadata."""
    return {
        "project_title": "Explainable Adaptive AI-Based Intrusion Detection System for Changing Network Threats",
        "academic_degree": "Master of Engineering (M.E.) Prototype",
        "version": "1.0.0-baseline",
        "core_pillars": [
            "Machine Learning Detection (Random Forest / Extra Trees)",
            "Explainable AI (SHAP TreeExplainer & Plain-Language Attribution)",
            "Controlled Concept Drift Adaptation (Statistical Testing & Model Rollback)"
        ],
        "privacy": "100% Local Inference, Loopback-Only Binding, No Telemetry, No External APIs",
        "license": "MIT License"
    }


@protected_router.get("/model/info")
async def get_model_info():
    """Return active model details, evaluation metrics, and feature schema."""
    detector = app_state.detector
    if not detector or not detector.is_loaded:
        return {
            "model_loaded": False,
            "message": "No active model loaded."
        }

    return {
        "model_loaded": True,
        "version": detector.model_version,
        "taxonomy": detector.taxonomy,
        "feature_count": len(detector.feature_names),
        "feature_names": detector.feature_names,
        "metadata": detector.metadata
    }


@protected_router.post("/explain")
async def explain_flow(payload: Dict[str, Any]):
    """
    Score a flow vector and compute SHAP explanation with deterministic plain-language summary.
    """
    detector = app_state.detector
    explainer = app_state.explainer

    if not detector or not detector.is_loaded:
        raise HTTPException(status_code=503, detail="ThreatDetector is not loaded.")
    if not explainer or not explainer.is_initialized:
        raise HTTPException(status_code=503, detail="XAI explainer is not initialized.")

    detection = detector.predict_flow(payload)
    explanation = explainer.explain_prediction(detection, top_k=5)

    return {
        "detection": detection.to_dict(),
        "explanation": explanation.to_dict()
    }


@protected_router.get("/explain/{event_id}")
async def explain_saved_event(event_id: int):
    """
    Fetch or re-compute the SHAP explanation for a persisted event from SQLite.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Event not found.")
        
        event_dict = dict(row)

    # Check if explanation was already persisted
    if event_dict.get("explanation_json"):
        import json
        try:
            persisted = json.loads(event_dict["explanation_json"])
            if persisted and persisted.get("is_available"):
                return persisted
        except Exception:
            pass

    # Re-compute if raw features are present
    detector = app_state.detector
    explainer = app_state.explainer
    if detector and detector.is_loaded and explainer and explainer.is_initialized and event_dict.get("features_json"):
        import json
        raw_feats = json.loads(event_dict["features_json"])
        detection = detector.predict_flow(raw_feats)
        explanation = explainer.explain_prediction(detection, top_k=5)
        return explanation.to_dict()

    return {
        "is_available": False,
        "summary": f"Historical alert #{event_id} flagged as {event_dict.get('attack_category')} with score {event_dict.get('confidence_score')}.",
        "top_features": []
    }


# Include protected router inside the base /api router
router.include_router(protected_router)
