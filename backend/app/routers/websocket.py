import asyncio
import json
import logging
import time as _time
import uuid
from datetime import datetime

import numpy as np
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.asr.base import ASREngine
from app.config import settings
from app.db.database import create_session, end_session, save_record
from app.detection.scam_detector import analyze_text
from app.models.schemas import CallRecord

logger = logging.getLogger(__name__)

router = APIRouter()

asr_engine: ASREngine | None = None


def set_engine(engine: ASREngine) -> None:
    global asr_engine
    asr_engine = engine


class _SessionState:
    """Mutable state for one streaming session."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.transcript_window: list[str] = []
        self.session_max_score: float = 0.0
        self.session_max_analysis = None
        self.window_size = 6
        self.total_chunks: int = 0
        self.total_audio_seconds: float = 0.0
        self.all_transcripts: list[str] = []


async def _process_chunk(
    chunk: bytes,
    language: str,
    state: _SessionState,
    websocket: WebSocket,
    *,
    log_prefix: str = "",
) -> bool:
    """Transcribe one audio chunk, run detection, send result.

    Returns False if the client disconnected (send failed).
    """
    audio = np.frombuffer(chunk, dtype=np.int16).astype(np.float32) / 32768.0

    t0 = _time.monotonic()
    result = await asr_engine.transcribe(audio, language=language)
    transcribe_ms = round((_time.monotonic() - t0) * 1000)

    logger.info(
        "%sSTAGE_2_ASR | text=%r | language=%s | confidence=%.2f | latency=%dms",
        log_prefix, result.text[:200], result.language, result.confidence, transcribe_ms,
    )

    if not result.text.strip():
        logger.info("%sSTAGE_2_ASR | SILENCE (no text) | latency=%dms", log_prefix, transcribe_ms)
        try:
            await websocket.send_json({"type": "silence", "text": ""})
        except Exception:
            return False
        return True

    # Sliding window
    state.transcript_window.append(result.text.strip())
    if len(state.transcript_window) > state.window_size:
        state.transcript_window = state.transcript_window[-state.window_size:]

    # Analyze both chunk and window
    t1 = _time.monotonic()
    chunk_analysis = analyze_text(result.text)
    window_text = " ".join(state.transcript_window)
    window_analysis = analyze_text(window_text)
    detect_ms = round((_time.monotonic() - t1) * 1000)

    if window_analysis.risk_score > chunk_analysis.risk_score:
        current_analysis = window_analysis
        analysis_source = "window"
    else:
        current_analysis = chunk_analysis
        analysis_source = "chunk"

    # Sticky max
    if current_analysis.risk_score > state.session_max_score:
        state.session_max_score = current_analysis.risk_score
        state.session_max_analysis = current_analysis

    if state.session_max_score >= 0.6 and current_analysis.risk_score < state.session_max_score:
        analysis = state.session_max_analysis
        analysis_source = "session_max"
    else:
        analysis = current_analysis

    logger.info(
        "%sSTAGE_3_DETECT | source=%s | chunk=%.2f | window=%.2f | "
        "current=%.2f | session_max=%.2f | is_scam=%s | latency=%dms",
        log_prefix, analysis_source,
        chunk_analysis.risk_score, window_analysis.risk_score,
        current_analysis.risk_score, state.session_max_score,
        analysis.is_scam, detect_ms,
    )

    save_record(CallRecord(
        timestamp=datetime.now(),
        transcription=result.text,
        language=result.language,
        scam_analysis=analysis,
        audio_duration=result.end_time - result.start_time,
    ), session_id=state.session_id)

    # Track session-level metrics
    state.total_chunks += 1
    state.total_audio_seconds += result.end_time - result.start_time
    state.all_transcripts.append(result.text.strip())

    try:
        await websocket.send_json({
            "type": "transcription",
            "text": result.text,
            "language": result.language,
            "scam_analysis": analysis.model_dump(),
            "audio_duration": result.end_time - result.start_time,
            "debug": {
                "asr_latency_ms": transcribe_ms,
                "detect_latency_ms": detect_ms,
                "asr_confidence": result.confidence,
                "pattern_hits": analysis.debug_details,
                "analysis_source": analysis_source,
                "window_text": window_text,
                "window_score": window_analysis.risk_score,
                "chunk_score": chunk_analysis.risk_score,
            },
        })
    except Exception:
        return False
    return True


@router.websocket("/ws/stream")
async def websocket_stream(websocket: WebSocket):
    """Real-time audio streaming endpoint.

    Uses async producer/consumer pattern so audio is never lost:
    - Receiver task: continuously reads audio from WebSocket into a queue
    - Processor task: pulls chunks from queue, runs ASR + detection, sends results

    Protocol:
    1. Client connects
    2. Client sends JSON config: {"language": "hi", "chunk_size": 5}
    3. Client sends binary audio frames
    4. Server responds with transcription results
    5. Either side can close the connection
    """
    await websocket.accept()

    session_id = uuid.uuid4().hex[:16]
    user_agent = dict(websocket.headers).get("user-agent", "")
    logger.info("WebSocket client connected | session=%s", session_id)

    if not asr_engine or not asr_engine.is_loaded():
        await websocket.send_json({"error": "ASR engine not ready"})
        await websocket.close(code=1011)
        return

    # Receive config
    language = "hi"
    try:
        config = await websocket.receive_json()
        language = config.get("language", "hi")
        logger.info("Stream config: language=%s | session=%s", language, session_id)
    except Exception:
        logger.warning("No config received, using defaults")

    # Persist session start
    create_session(session_id, language, user_agent)

    chunk_bytes = settings.sample_rate * 2 * settings.chunk_duration_seconds  # 16-bit
    # Queue holds complete 5s audio chunks (as bytes) ready for processing
    audio_queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=100)

    async def receiver():
        """Continuously receive audio and enqueue complete chunks."""
        audio_buffer = bytearray()
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    break

                if "bytes" in msg and msg["bytes"]:
                    audio_buffer.extend(msg["bytes"])
                    while len(audio_buffer) >= chunk_bytes:
                        chunk = bytes(audio_buffer[:chunk_bytes])
                        audio_buffer = audio_buffer[chunk_bytes:]
                        await audio_queue.put(chunk)
                elif "text" in msg and msg["text"]:
                    try:
                        data = json.loads(msg["text"])
                        if data.get("type") == "stop":
                            logger.info("STOP signal received, %d chunks queued", audio_queue.qsize())
                            break
                    except json.JSONDecodeError:
                        pass
        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected (receiver)")
        except Exception:
            logger.debug("Receiver ended")
        finally:
            # Signal processor to drain remaining and stop
            await audio_queue.put(None)

    async def processor():
        """Pull chunks from queue, transcribe, detect, send results."""
        state = _SessionState(session_id)

        while True:
            chunk = await audio_queue.get()
            if chunk is None:
                break

            queued = audio_queue.qsize()
            if queued > 0:
                logger.info("QUEUE | %d chunks waiting | session=%s", queued, session_id)

            audio_duration_sec = len(chunk) / 2 / settings.sample_rate
            logger.info(
                "STAGE_1_AUDIO | chunk_bytes=%d | duration=%.1fs | language=%s | queued=%d | session=%s",
                len(chunk), audio_duration_sec, language, queued, session_id,
            )

            ok = await _process_chunk(chunk, language, state, websocket)
            if not ok:
                logger.debug("Send failed — client disconnected")
                break

        # Drain remaining queued chunks after stop/disconnect
        remaining = 0
        while not audio_queue.empty():
            chunk = audio_queue.get_nowait()
            if chunk is None:
                break
            remaining += 1
            logger.info("DRAIN | chunk %d", remaining)
            ok = await _process_chunk(chunk, language, state, websocket, log_prefix="DRAIN | ")
            if not ok:
                break

        if remaining:
            logger.info("DRAIN | processed %d remaining chunks after stop | session=%s", remaining, session_id)

        # Persist session summary
        final_analysis = state.session_max_analysis
        end_session(
            session_id,
            total_chunks=state.total_chunks,
            total_audio_seconds=state.total_audio_seconds,
            final_risk_score=state.session_max_score,
            final_is_scam=bool(final_analysis and final_analysis.is_scam),
            final_matched_patterns=(
                final_analysis.matched_patterns if final_analysis else []
            ),
            full_transcript=" ".join(state.all_transcripts),
        )
        logger.info(
            "SESSION_END | session=%s | chunks=%d | audio=%.1fs | risk=%.2f | scam=%s",
            session_id, state.total_chunks, state.total_audio_seconds,
            state.session_max_score, bool(final_analysis and final_analysis.is_scam),
        )

        try:
            await websocket.send_json({"type": "done", "total_chunks": remaining})
            await websocket.close()
        except Exception:
            pass

    # Run receiver and processor concurrently
    receiver_task = asyncio.create_task(receiver())
    processor_task = asyncio.create_task(processor())

    try:
        # Wait for both to complete — receiver ends on disconnect,
        # processor ends when it gets the None sentinel
        await asyncio.gather(receiver_task, processor_task)
    except Exception:
        logger.exception("WebSocket error")
        receiver_task.cancel()
        processor_task.cancel()
