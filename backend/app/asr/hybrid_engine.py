"""Hybrid ASR engine: routes to the best engine per language.

- Indian languages (te, hi, ta, bn, etc.) → IndicConformer (purpose-built, fast)
- English → faster-whisper (proven, accurate)
"""

import logging

import numpy as np

from app.asr.base import ASREngine
from app.models.schemas import TranscriptionResult

logger = logging.getLogger(__name__)

# Languages supported by IndicConformer 600M
_INDIC_LANGUAGES = frozenset({
    "as", "bn", "brx", "doi", "kok", "gu", "hi", "kn", "ks",
    "mai", "ml", "mr", "mni", "ne", "or", "pa", "sa", "sat",
    "sd", "ta", "te", "ur",
})


class HybridEngine(ASREngine):
    """Routes transcription to the best engine based on language.

    - Indian languages → IndicConformer (fast, accurate for Indian scripts)
    - English / auto → faster-whisper (strong English, auto-detect capability)
    """

    def __init__(self) -> None:
        from app.asr.faster_whisper_engine import FasterWhisperEngine
        from app.asr.indic_conformer_engine import IndicConformerEngine

        self._whisper = FasterWhisperEngine()
        self._indic = IndicConformerEngine()

    async def load_model(self) -> None:
        logger.info("Loading hybrid engine (faster-whisper + IndicConformer)...")
        # Load both engines
        await self._whisper.load_model()
        await self._indic.load_model()
        logger.info("Hybrid engine ready")

    async def transcribe(
        self, audio: np.ndarray, language: str = "hi"
    ) -> TranscriptionResult:
        if language in _INDIC_LANGUAGES:
            return await self._indic.transcribe(audio, language=language)
        else:
            # "en" or anything else → whisper
            return await self._whisper.transcribe(audio, language=language)

    def is_loaded(self) -> bool:
        return self._whisper.is_loaded() and self._indic.is_loaded()

    def get_name(self) -> str:
        return "hybrid (whisper + indic-conformer)"
