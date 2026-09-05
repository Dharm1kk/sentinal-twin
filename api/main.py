"""
Minimal FastAPI backend (Stage 6 support layer).

Exposes just enough for a dashboard to poll: trigger a replay session,
fetch its alerts, and fetch pipeline/graph stats. Not wired to a real
NetFlow collector -- that's the ingest gateway's job (Stage 2), which is
out of scope for this prototype per the brief's phased plan.

Run with: uvicorn api.main:app --reload --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from simulate.flow_generator import generate_session, stream_session
from detect.pipeline import SentinelTwinPipeline

app = FastAPI(title="SentinelTwin API", version="0.1.0")

_pipeline: SentinelTwinPipeline | None = None
_alert_log: list[dict] = []


class RunSessionRequest(BaseModel):
    duration_s: float = 120.0
    seed: int = 42
    speed_factor: float = 500.0  # fast-forward by default for API use


@app.on_event("startup")
def _startup() -> None:
    global _pipeline
    _pipeline = SentinelTwinPipeline()
    training_flows = generate_session(duration_s=267, benign_rate_per_s=15.0, seed=1, include_attacks=False)
    _pipeline.train_baseline(training_flows)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "trained": _pipeline is not None}


@app.post("/session/run")
def run_session(req: RunSessionRequest) -> dict:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="pipeline not initialized")

    session = generate_session(duration_s=req.duration_s, benign_rate_per_s=15.0, seed=req.seed, include_attacks=True)
    new_alerts = []
    for flow in stream_session(session, speed_factor=req.speed_factor):
        alerts = _pipeline.process_flow(flow)
        for a in alerts:
            d = a.to_dict()
            new_alerts.append(d)
            _alert_log.append(d)

    return {
        "flows_replayed": len(session),
        "alerts_raised": len(new_alerts),
        "stats": _pipeline.stats.summary(),
    }


@app.get("/alerts")
def get_alerts(limit: int = 100, min_confidence: float = 0.0) -> dict:
    filtered = [a for a in _alert_log if a["confidence"] >= min_confidence]
    return {"count": len(filtered), "alerts": filtered[-limit:]}


@app.get("/graph")
def get_graph() -> dict:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="pipeline not initialized")
    return _pipeline.graph.to_cytoscape_json()


@app.get("/graph/shared-destinations")
def shared_destinations() -> dict:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="pipeline not initialized")
    return _pipeline.graph.shared_fingerprint_hosts()


@app.get("/incident/{incident_id}")
def incident(incident_id: str) -> dict:
    if _pipeline is None:
        raise HTTPException(status_code=503, detail="pipeline not initialized")
    return _pipeline.graph.incident_summary(incident_id)
