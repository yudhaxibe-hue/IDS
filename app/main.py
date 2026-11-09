"""
Main FastAPI application entry point.
Configures lifespan events, CORS restricted to loopback, and registers API routers.
"""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.lifecycle import on_startup, on_shutdown
from backend.api.routes import router as api_router

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown lifecycle hooks."""
    on_startup()
    yield
    on_shutdown()


def create_app() -> FastAPI:
    """Factory creating and configuring the FastAPI instance."""
    app = FastAPI(
        title="Explainable Adaptive IDS",
        description="Local loopback API for Explainable Adaptive AI-Based Intrusion Detection System",
        version="1.0.0",
        lifespan=lifespan
    )

    # Restrict CORS to local loopback origins only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:*",
            "http://localhost:*"
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # Register API routes
    app.include_router(api_router)

    # Mount static frontend assets for pywebview
    if FRONTEND_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    return app


app = create_app()
