from app.asr.base import ASREngine
from app.config import settings


def create_asr_engine() -> ASREngine:
    """Factory function that returns the configured ASR engine.

    Configure via SCAM_ASR_ENGINE env var or .env file.
    Options: faster_whisper, indic_conformer, hybrid (default)
    """
    engine_name = settings.asr_engine

    if engine_name == "faster_whisper":
        from app.asr.faster_whisper_engine import FasterWhisperEngine

        return FasterWhisperEngine()

    if engine_name == "indic_conformer":
        from app.asr.indic_conformer_engine import IndicConformerEngine

        return IndicConformerEngine()

    if engine_name == "hybrid":
        from app.asr.hybrid_engine import HybridEngine

        return HybridEngine()

    raise ValueError(
        f"Unknown ASR engine '{engine_name}'. "
        "Choose from: faster_whisper, indic_conformer, hybrid"
    )
