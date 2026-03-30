import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.asr.factory import create_asr_engine
from app.config import settings
from app.routers import transcription, websocket

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: load ASR model
    engine = create_asr_engine()
    await engine.load_model()

    # Inject engine into routers
    transcription.set_engine(engine)
    websocket.set_engine(engine)

    yield

    # Shutdown: cleanup if needed
    logging.getLogger(__name__).info("Shutting down")


app = FastAPI(
    title="Indian Scam Detector API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(transcription.router, prefix="/api")
app.include_router(websocket.router, prefix="/api")

# Serve built frontend (for Docker / production)
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
if _STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=_STATIC_DIR / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve React SPA — all non-API routes return index.html."""
        file = _STATIC_DIR / full_path
        if file.is_file():
            return FileResponse(file)
        return FileResponse(_STATIC_DIR / "index.html")
