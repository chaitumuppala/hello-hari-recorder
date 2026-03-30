import logging
import os
import time

import numpy as np

from app.asr.base import ASREngine
from app.models.schemas import TranscriptionResult

logger = logging.getLogger(__name__)


class IndicConformerEngine(ASREngine):
    """ASR engine using AI4Bharat IndicConformer (600M multilingual).

    Purpose-built for Indian languages — supports all 22 scheduled languages
    including Telugu, Hindi, Tamil, Bengali, etc.
    Uses Conformer architecture with CTC decoding for speed.

    Requires: transformers, torch, torchaudio, onnxruntime
    Model: ai4bharat/indic-conformer-600m-multilingual
    """

    def __init__(self) -> None:
        self._model = None
        self._loaded = False

    async def load_model(self) -> None:
        try:
            from transformers import AutoModel

            logger.info("Loading IndicConformer 600M multilingual model...")
            t0 = time.monotonic()
            self._model = AutoModel.from_pretrained(
                "ai4bharat/indic-conformer-600m-multilingual",
                trust_remote_code=True,
                token=os.environ.get("HF_TOKEN"),
            )
            elapsed = time.monotonic() - t0
            self._loaded = True
            logger.info("IndicConformer loaded in %.1fs", elapsed)

        except ImportError as e:
            logger.error(
                "Missing dependency for IndicConformer: %s. "
                "Install with: pip install transformers torch torchaudio onnxruntime",
                e,
            )
            raise

    async def transcribe(
        self, audio: np.ndarray, language: str = "hi"
    ) -> TranscriptionResult:
        import torch

        if not self._model:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        # IndicConformer supports 22 Indian languages only — no English.
        # Map unsupported codes to closest Indian language.
        _LANG_MAP = {
            "auto": "hi",
            "en": "hi",        # English → Hindi (best fallback for Indian English)
            "en-in": "hi",
        }
        language = _LANG_MAP.get(language, language)

        # Convert numpy float32 array to torch tensor [1, samples]
        audio_tensor = torch.from_numpy(audio).unsqueeze(0).float()

        audio_duration = len(audio) / 16000  # assume 16kHz

        start = time.monotonic()
        # CTC decoding is faster than RNNT
        text = self._model(audio_tensor, language, "ctc")
        elapsed = time.monotonic() - start

        # Model returns a string directly
        if isinstance(text, list):
            text = text[0] if text else ""

        # Strip language tag prefix (e.g. "TE", "HI") that model prepends
        text = str(text).strip()
        if len(text) >= 2 and text[:2].isupper() and (len(text) == 2 or not text[2].isupper()):
            text = text[2:]

        logger.info(
            "IndicConformer %.1fs audio in %.3fs (%.1fx RT) | lang=%s | text=%r",
            audio_duration, elapsed, audio_duration / max(elapsed, 0.001),
            language, str(text)[:200],
        )

        return TranscriptionResult(
            text=str(text).strip(),
            language=language,
            confidence=0.9,  # IndicConformer doesn't provide per-utterance confidence
            start_time=0.0,
            end_time=audio_duration,
        )

    def is_loaded(self) -> bool:
        return self._loaded

    def get_name(self) -> str:
        return "indic-conformer (600M)"
