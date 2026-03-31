from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Scam Detector"
    debug: bool = False

    # ASR engine: "faster_whisper" | "indic_conformer" | "hybrid"
    asr_engine: str = "hybrid"

    # Whisper model for English ASR
    # distil-small.en: 166M params, ~350MB RAM, 3.4% WER — optimal for CPU
    whisper_model: str = "distil-small.en"

    # Paths
    base_dir: Path = Path(__file__).resolve().parent.parent
    models_dir: Path = base_dir / "models"
    db_path: Path = base_dir / "data" / "scam_detector.db"

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:5175", "http://localhost:3000"]

    # Audio
    sample_rate: int = 16000
    chunk_duration_seconds: int = 5

    model_config = {"env_file": ".env", "env_prefix": "SCAM_"}


settings = Settings()
