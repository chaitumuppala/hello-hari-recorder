from abc import ABC, abstractmethod

import numpy as np

from app.models.schemas import TranscriptionResult


class ASREngine(ABC):
    """Abstract base class for all ASR engines.

    Implement this interface to add a new ASR backend.
    Currently supported: faster-whisper (English), IndicConformer (Indian languages),
    hybrid (routes by language — recommended).
    """

    @abstractmethod
    async def load_model(self) -> None:
        """Load the ASR model into memory."""

    @abstractmethod
    async def transcribe(
        self, audio: np.ndarray, language: str = "hi"
    ) -> TranscriptionResult:
        """Transcribe audio array to text.

        Args:
            audio: numpy array of float32 audio samples at 16kHz mono.
            language: ISO 639-1 language code.

        Returns:
            TranscriptionResult with transcribed text and metadata.
        """

    @abstractmethod
    def is_loaded(self) -> bool:
        """Check if the model is loaded and ready."""

    @abstractmethod
    def get_name(self) -> str:
        """Return the engine name for health checks."""
