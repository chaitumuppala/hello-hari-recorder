import logging
import time

import numpy as np

from app.asr.base import ASREngine
from app.config import settings
from app.models.schemas import TranscriptionResult

logger = logging.getLogger(__name__)


class FasterWhisperEngine(ASREngine):
    """ASR engine using faster-whisper (CTranslate2).

    Best for x86 Linux/WSL. May not work on ARM64 Windows.
    Use whisper_cpp on ARM64 instead.
    """

    def __init__(self) -> None:
        self._model = None
        self._model_name = settings.whisper_model

    async def load_model(self) -> None:
        try:
            from faster_whisper import WhisperModel

            logger.info("Loading faster-whisper model '%s'", self._model_name)
            self._model = WhisperModel(
                self._model_name,
                device="cpu",
                compute_type="int8",
                cpu_threads=0,  # 0 = use all available cores
            )
            logger.info("faster-whisper model loaded successfully")

        except ImportError:
            logger.error(
                "faster-whisper not installed. "
                "Install with: pip install faster-whisper"
            )
            raise

    async def transcribe(
        self, audio: np.ndarray, language: str = "hi"
    ) -> TranscriptionResult:
        if not self._model:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        audio_f32 = audio.astype(np.float32)

        # "auto" or empty means let Whisper detect the language per-segment.
        # This handles code-switched speech (Telugu+English, Hindi+English)
        # much better than forcing a single language.
        lang_param = None if language == "auto" else language

        start = time.monotonic()
        segments, info = self._model.transcribe(
            audio_f32,
            language=lang_param,
            beam_size=1,  # greedy decoding — fastest
            vad_filter=True,
            vad_parameters=dict(min_silence_duration_ms=500),
        )
        segments_list = list(segments)
        elapsed = time.monotonic() - start

        full_text = " ".join(
            seg.text.strip() for seg in segments_list if seg.text.strip()
        )

        logger.info(
            "Transcribed %.1fs audio in %.2fs | detected_lang=%s (%.0f%%)",
            info.duration, elapsed,
            info.language, info.language_probability * 100,
        )

        return TranscriptionResult(
            text=full_text,
            language=info.language,
            confidence=info.language_probability,
            start_time=0.0,
            end_time=info.duration,
        )

    def is_loaded(self) -> bool:
        return self._model is not None

    def get_name(self) -> str:
        return f"faster-whisper ({self._model_name})"
