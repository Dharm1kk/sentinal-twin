"""
Sentinel - Passive Cyber Investigation & Threat Detection Engine
FastAPI Main Application Server
Strictly adheres to Sentinel Specification.
"""

import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure Sentinel root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.api import router

app = FastAPI(
    title="Sentinel - Passive Cyber Threat Detection Engine",
    description="Windows-First Unidirectional Cyber Threat Detection Platform",
    version="1.0.0"
)

# Enable CORS for investigation frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 router
app.include_router(router)


@app.get("/")
def root():
    return {
        "engine": "Sentinel",
        "positioning": "Windows-First Passive Cyber Investigation Engine",
        "link_mode": "UNIDIRECTIONAL_HARDWARE_DATA_DIODE_READ_ONLY",
        "status": "OPERATIONAL",
        "api_docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
