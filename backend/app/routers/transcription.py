import io
import logging
import time as _time
from datetime import datetime

import numpy as np
from fastapi import APIRouter, HTTPException, UploadFile

from app.asr.base import ASREngine
from app.config import settings
from app.db.database import get_recent_records, save_record
from app.detection.scam_detector import analyze_text
from app.models.schemas import CallRecord, HealthResponse, ScamAnalysis

logger = logging.getLogger(__name__)

router = APIRouter()

# Will be set by main.py after engine initialization
asr_engine: ASREngine | None = None


def set_engine(engine: ASREngine) -> None:
    global asr_engine
    asr_engine = engine


@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        asr_engine=asr_engine.get_name() if asr_engine else "not loaded",
        model_loaded=asr_engine.is_loaded() if asr_engine else False,
    )


@router.post("/transcribe")
async def transcribe_audio(file: UploadFile, language: str = "hi"):
    """Upload a WAV/PCM audio file for transcription + scam analysis."""
    if not asr_engine or not asr_engine.is_loaded():
        raise HTTPException(status_code=503, detail="ASR engine not ready")

    content = await file.read()

    try:
        audio = _decode_audio(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid audio: {e}")

    t0 = _time.monotonic()
    result = await asr_engine.transcribe(audio, language=language)
    transcribe_ms = round((_time.monotonic() - t0) * 1000)

    logger.info(
        "STAGE_2_ASR | text=%r | language=%s | confidence=%.2f | latency=%dms",
        result.text[:200], result.language, result.confidence, transcribe_ms,
    )

    t1 = _time.monotonic()
    analysis = analyze_text(result.text)
    detect_ms = round((_time.monotonic() - t1) * 1000)

    logger.info(
        "STAGE_3_DETECT | score=%.2f | is_scam=%s | patterns=%s | latency=%dms",
        analysis.risk_score, analysis.is_scam,
        ", ".join(analysis.matched_patterns), detect_ms,
    )

    record = CallRecord(
        timestamp=datetime.now(),
        transcription=result.text,
        language=result.language,
        scam_analysis=analysis,
        audio_duration=result.end_time - result.start_time,
    )
    record_id = save_record(record)

    return {
        "id": record_id,
        "transcription": result.text,
        "language": result.language,
        "scam_analysis": analysis.model_dump(),
        "audio_duration": record.audio_duration,
        "debug": {
            "asr_latency_ms": transcribe_ms,
            "detect_latency_ms": detect_ms,
            "asr_confidence": result.confidence,
            "pattern_hits": analysis.debug_details,
        },
    }


@router.post("/analyze-text", response_model=ScamAnalysis)
async def analyze_text_only(text: str):
    """Analyze text for scam patterns without audio transcription."""
    return analyze_text(text)


@router.get("/history")
async def get_history(limit: int = 50):
    """Get recent call analysis records."""
    records = get_recent_records(limit=min(limit, 200))
    return [r.model_dump() for r in records]


def _decode_audio(raw_bytes: bytes) -> np.ndarray:
    """Decode uploaded audio bytes to numpy float32 array at 16kHz."""
    # Try WAV first
    if raw_bytes[:4] == b"RIFF":
        import wave

        with wave.open(io.BytesIO(raw_bytes), "rb") as wf:
            frames = wf.readframes(wf.getnframes())
            dtype = np.int16 if wf.getsampwidth() == 2 else np.float32
            audio = np.frombuffer(frames, dtype=dtype)
            if dtype == np.int16:
                audio = audio.astype(np.float32) / 32768.0
            return audio

    # Assume raw PCM 16-bit signed, 16kHz mono
    audio = np.frombuffer(raw_bytes, dtype=np.int16)
    return audio.astype(np.float32) / 32768.0
