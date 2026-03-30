# Setup Guide

## Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Python | 3.10+ | With pip |
| Node.js | 20+ | For frontend build |
| WSL2 + Ubuntu | — | Required for PyTorch/ONNX on ARM64 Windows |
| Git | — | |
| HuggingFace token | — | For IndicConformer gated model (optional if using English-only) |

---

## Local Development

### Backend

```bash
# In WSL2 terminal (or Linux/Mac)
cd backend

# Create virtual environment
python3 -m venv venv-wsl
source venv-wsl/bin/activate

# Install dependencies
pip install -r requirements.txt

# Login to HuggingFace (needed for IndicConformer)
huggingface-cli login

# Start the server
SCAM_ASR_ENGINE=hybrid SCAM_WHISPER_MODEL=distil-small.en \
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Models download automatically on first run:
- **distil-small.en** (~350MB) — faster-whisper English model
- **IndicConformer 600M** (~600MB) — AI4Bharat multilingual model

### Frontend

```bash
# In a separate terminal (Windows, WSL2, or Mac)
cd frontend
npm install
npm run dev
```

### Open the App

Navigate to **http://localhost:5173**

1. Select a language from the dropdown
2. Click **Start Recording**
3. Speak or play audio on speaker
4. Watch the shield indicator and pattern matches in real-time

---

## Docker (Production)

```bash
# Build and run
docker compose up --build

# With HuggingFace token for IndicConformer
HF_TOKEN=your_token docker compose up --build
```

The app serves at **http://localhost:7860** with the React frontend bundled into the FastAPI server.

### Docker Architecture

Multi-stage Dockerfile:
1. **Stage 1** (Node 20-slim): `npm ci` → `npm run build` → produces `dist/`
2. **Stage 2** (Python 3.11-slim): Installs backend deps, copies built frontend, serves via uvicorn

Named volumes:
- `hf_cache` — HuggingFace model cache (persists across container restarts)
- `app_data` — SQLite database

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAM_ASR_ENGINE` | `hybrid` | ASR engine: `hybrid`, `faster_whisper`, or `indic_conformer` |
| `SCAM_WHISPER_MODEL` | `distil-small.en` | Whisper model name (any CTranslate2-compatible) |
| `SCAM_DEBUG` | `true` | Enable debug output in API responses |
| `HF_TOKEN` | — | HuggingFace token for gated IndicConformer model |

### Engine Options

| Engine | Use Case | Models Loaded |
|--------|----------|---------------|
| `hybrid` | Full multilingual (recommended) | distil-small.en + IndicConformer |
| `faster_whisper` | English-only, lighter footprint | distil-small.en only |
| `indic_conformer` | Indian languages only | IndicConformer only |

---

## Testing

### Unit Tests (no model required)

```bash
cd backend
source venv-wsl/bin/activate
pytest tests/test_scam_detector.py -v
```

**53 tests** across 4 classes:
- **TestScamDetector** — 9 pattern categories, cross-language indicators, false positive checks
- **TestArchetypeRegistry** — archetype structure validation
- **TestArchetypeDetection** — co-occurrence detection for all 13 archetypes
- **TestEndToEndArchetypes** — full pipeline integration

### API Smoke Tests

```bash
# Health check
curl http://localhost:8000/api/health

# English scam text
curl -X POST "http://localhost:8000/api/analyze-text?text=this+is+from+mumbai+police+you+are+under+digital+arrest"

# Hindi scam text
curl -s -X POST "http://localhost:8000/api/analyze-text" -G \
  --data-urlencode "text=यह CBI से बोल रहा हूं आपके खिलाफ warrant जारी हुआ है"

# Safe text (should return risk_score: 0)
curl -X POST "http://localhost:8000/api/analyze-text?text=Good+morning+your+delivery+arrives+tomorrow"
```

### End-to-End Testing

Requires a running backend with models loaded:

1. Open http://localhost:5173
2. Select a language
3. Click **Start Recording**
4. Speak or play a scam script on speaker
5. Verify: shield turns red, pattern pills appear, debug panel shows pipeline trace

---

## Troubleshooting

| Issue | Solution |
|-------|---------|
| `ModuleNotFoundError: torch` | Ensure you're in the WSL2 venv, not Windows Python |
| IndicConformer download fails | Run `huggingface-cli login` with your token first |
| Port 8000 already in use | Kill existing process: `lsof -ti:8000 \| xargs kill` |
| Frontend can't reach backend | Check Vite proxy config — backend must be on port 8000 |
| ARM64 Windows + PyTorch | Use WSL2 Ubuntu — native Windows ARM64 lacks ONNX/PyTorch support |
