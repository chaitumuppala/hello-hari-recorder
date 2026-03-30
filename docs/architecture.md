# Architecture

## System Overview

```
┌──────────────────────────────────────┐
│  Browser (PWA)                       │
│  React 19 + Vite 6 + TypeScript     │
│  Web Audio API → mic capture         │
│  ShieldIndicator + DebugPanel        │
│  User selects language, starts rec   │
└──────────┬───────────────────────────┘
           │ WebSocket (PCM 16-bit 16kHz)
           │ REST API (/api/*)
┌──────────▼───────────────────────────┐
│  FastAPI Backend                     │
│                                      │
│  ┌─ Hybrid ASR Engine ─────────────┐ │
│  │  English → faster-whisper       │ │
│  │           (distil-small.en,     │ │
│  │            CTranslate2, int8)   │ │
│  │                                 │ │
│  │  Indian langs → IndicConformer  │ │
│  │           (AI4Bharat 600M,      │ │
│  │            ONNX + CTC decode)   │ │
│  └─────────────────────────────────┘ │
│               │                      │
│               ▼                      │
│  ┌─ Scam Detector (3-layer) ──────┐ │
│  │  550+ exact phrases             │ │
│  │  13-archetype co-occurrence     │ │
│  │  Cross-language boosters        │ │
│  └─────────────────────────────────┘ │
│               │                      │
│  ┌─ WebSocket Pipeline ───────────┐ │
│  │  Sliding window (6 chunks)     │ │
│  │  Sticky session max (≥0.6)     │ │
│  │  Async producer/consumer       │ │
│  └─────────────────────────────────┘ │
│               │                      │
│  ┌─ SQLite (local only) ──────────┐ │
│  │  Call history + analysis       │ │
│  └─────────────────────────────────┘ │
└──────────────────────────────────────┘
```

Everything runs on-device. No data leaves the machine.

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | React 19 + Vite 6 + TypeScript | PWA support, fast HMR, modern ecosystem |
| Audio capture | Web Audio API (ScriptProcessorNode) | Browser-native, streams PCM chunks via WebSocket |
| Backend | FastAPI + WebSocket | Async Python, real-time streaming, auto-generated API docs |
| ASR (English) | faster-whisper (distil-small.en, 166M params) | CTranslate2 int8, greedy decode, VAD, ~350MB RAM |
| ASR (Indian langs) | AI4Bharat IndicConformer (600M params) | ONNX + CTC, 22 languages, sub-500ms inference |
| Detection | Exact phrases + keyword co-occurrence + boosters | Deterministic, fast, explainable, no ML infra needed |
| Database | SQLite | Zero-config, local-first, single-file |
| Deployment | Docker (multi-stage) | Node 20 build + Python 3.11-slim runtime, port 7860 |

---

## Hybrid ASR Engine

The ASR layer is abstracted behind an `ASREngine` ABC with four methods: `load_model()`, `transcribe()`, `is_loaded()`, `get_name()`. Three implementations exist:

### faster-whisper (English)

- **Model**: `distil-small.en` — distilled, English-only, 166M parameters
- **Runtime**: CTranslate2 with int8 quantization
- **Decoding**: Greedy (beam_size=1) for minimum latency
- **VAD**: Enabled with 500ms silence threshold
- **Threads**: Auto-detect available CPU cores
- **Input**: numpy float32 at 16kHz
- **Language detection**: Auto-detect per segment (handles code-switching)

### IndicConformer (Indian Languages)

- **Model**: `ai4bharat/indic-conformer-600m-multilingual`
- **Runtime**: ONNX with CTC decoding (faster than RNNT)
- **Languages**: 22 Indian languages — all 10 supported scripts + more
- **Input**: numpy float32 at 16kHz
- **Confidence**: Fixed 0.9 (model doesn't provide per-utterance confidence)
- **Latency**: ~350-540ms per 5s chunk on CPU

### Hybrid (Recommended)

Routes by language code at transcription time:

```
_INDIC_LANGUAGES = {as, bn, brx, doi, kok, gu, hi, kn, ks, mai,
                    ml, mr, mni, ne, or, pa, sa, sat, sd, ta, te, ur}

if language in _INDIC_LANGUAGES → IndicConformer
else → faster-whisper
```

Both engines are lazy-loaded on first use.

---

## WebSocket Pipeline

### Connection Flow

```
Client                              Server
  │                                   │
  ├── ws://host/api/ws/stream ───────►│
  │                                   │  Create _SessionState
  │   {"type":"config",               │
  │    "language":"hi"} ─────────────►│  Set language
  │                                   │
  │   [PCM binary frames] ──────────►│  → Queue
  │                                   │  Processor reads queue
  │                                   │  → Transcribe (ASR)
  │                                   │  → Analyze (Detector)
  │   {"type":"transcription",        │
  │◄── "text":"...",                  │  ← Send result
  │    "scam_analysis":{...}}         │
  │                                   │
  │   {"type":"stop"} ───────────────►│  Drain queue, close
```

### Concurrency Model

Two async tasks run per connection:

1. **Receiver**: Reads WebSocket frames → queues audio chunks
2. **Processor**: Dequeues chunks → transcribes → analyzes → sends results

Connected via `asyncio.Queue`. The processor continues draining the queue after the client sends a stop message.

### Session State

```python
class _SessionState:
    transcript_window: list[str]    # Sliding buffer (max 6)
    session_max_score: float        # Sticky maximum
    session_max_analysis: dict      # Best analysis so far
```

---

## REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | ASR engine status, model loaded status |
| `/api/transcribe` | POST | Upload audio file → transcription + scam analysis |
| `/api/analyze-text` | POST | Text-only scam analysis (no ASR) |
| `/api/history` | GET | Recent call records (max 200) |

---

## Frontend Components

| Component | Purpose |
|-----------|---------|
| **ShieldIndicator** | Large visual shield — green (SAFE/LISTENING), orange (SUSPICIOUS), red (SCAM DETECTED), with risk % |
| **AudioRecorder** | Language selector (11 langs), start/stop, matched pattern pills, debug toggle |
| **DebugPanel** | Collapsible: ASR output, analysis source, pattern hits, verdict per chunk |
| **ScamAlert** | Alert banner with risk score, explanation, matched category tags |
| **TranscriptionView** | Live scrolling transcript with language badges |

### Audio Capture

`useAudioRecorder` hook:
1. `navigator.mediaDevices.getUserMedia()` → MediaStream
2. ScriptProcessorNode (bufferSize) → PCM 16-bit 16kHz
3. Binary frames sent over WebSocket
4. Responses update React state → UI re-renders

---

## Project Structure

```
hello-hari-recorder/
├── backend/
│   ├── app/
│   │   ├── main.py                       # FastAPI app, lifespan, static SPA serving
│   │   ├── config.py                     # Pydantic settings (env-based)
│   │   ├── asr/
│   │   │   ├── base.py                   # ASR engine ABC
│   │   │   ├── factory.py                # Engine factory (3 engines)
│   │   │   ├── hybrid_engine.py          # Routes: EN→whisper, Indian→conformer
│   │   │   ├── faster_whisper_engine.py  # CTranslate2, int8, greedy, VAD
│   │   │   └── indic_conformer_engine.py # AI4Bharat 600M, ONNX, CTC
│   │   ├── detection/
│   │   │   ├── scam_detector.py          # 550+ patterns, 9 categories, scoring
│   │   │   └── scam_archetypes.py        # 13 archetypes × 10 scripts
│   │   ├── db/
│   │   │   └── database.py               # SQLite CRUD
│   │   ├── models/
│   │   │   └── schemas.py                # Pydantic models
│   │   └── routers/
│   │       ├── transcription.py          # REST endpoints
│   │       └── websocket.py              # WS: sliding window, session state
│   ├── tests/
│   │   └── test_scam_detector.py         # 53 tests (4 classes)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── AudioRecorder.tsx          # Main UI
│   │   │   ├── ShieldIndicator.tsx        # Visual shield
│   │   │   ├── DebugPanel.tsx             # Pipeline trace
│   │   │   ├── TranscriptionView.tsx      # Live transcript
│   │   │   └── ScamAlert.tsx              # Alert banner
│   │   ├── hooks/
│   │   │   └── useAudioRecorder.ts        # WebSocket + ScriptProcessorNode
│   │   ├── services/
│   │   │   └── api.ts                     # HTTP/WS client
│   │   └── types/
│   │       └── index.ts                   # TypeScript interfaces (11 langs)
│   ├── package.json
│   └── vite.config.ts                     # PWA manifest, /api proxy
├── docs/                                  # This documentation
├── Dockerfile                             # Multi-stage: Node 20 + Python 3.11-slim
├── docker-compose.yml                     # Port 7860, named volumes
├── .dockerignore
└── .editorconfig
```

---

## Key Dependencies

### Backend

| Package | Version | Purpose |
|---------|---------|---------|
| faster-whisper | ≥1.0.0 | CTranslate2 Whisper port |
| transformers | ≥4.40.0 | IndicConformer model loading |
| onnxruntime | 1.20.1 | ONNX inference for conformer |
| torch + torchaudio | CPU | Audio processing, model backends |
| fastapi | ≥0.115.0 | Web framework |
| uvicorn | ≥0.34.0 | ASGI server |
| pydantic-settings | ≥2.0.0 | Environment-based config |

### Frontend

| Package | Version | Purpose |
|---------|---------|---------|
| react | ^19.0.0 | UI framework |
| vite | ^6.0.0 | Build tool, dev server |
| vite-plugin-pwa | ^0.21.0 | PWA manifest, service worker |
| typescript | ~5.6.0 | Type safety |
