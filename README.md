# Indian Scam Call Detection — Proof of Concept

## The Problem

India loses an estimated **₹1.25 lakh crore annually** to phone scams. "Digital arrest" fraud, TRAI impersonation, courier drug threats, OTP theft, and fake investment schemes target millions — with the elderly, small-town workers, and first-time smartphone users being the most vulnerable. People have lost life savings. Some have taken their own lives.

Existing defenses (Truecaller, carrier spam filters, TRAI DND) work on caller reputation and known numbers. They fail against **fresh SIM cards, VoIP spoofing, and social engineering** — the core tools of modern scam operations.

**There is no widely available tool that analyzes what is actually being said on a call and warns the user in real-time.**

This project is a proof of concept to change that.

---

## What This POC Does

A local-first Progressive Web App that:

1. **Captures audio** via the browser microphone (user puts a suspicious call on speaker)
2. **Transcribes speech** using a hybrid on-device ASR engine — faster-whisper for English, AI4Bharat IndicConformer for 22 Indian languages
3. **Detects scam patterns** using 585+ exact-match phrases across 10 categories and a 13-archetype multilingual keyword co-occurrence engine spanning 10 Indian scripts
4. **Alerts the user** in real-time with a shield indicator, risk score, matched categories, and plain-language explanation
5. **Stores everything locally** — no cloud, no data leaves the device

### Supported Languages (11)

| Language | Code | Script |
|----------|------|--------|
| English | en | Latin |
| Hindi | hi | देवनागरी |
| Telugu | te | తెలుగు |
| Tamil | ta | தமிழ் |
| Bengali | bn | বাংলা |
| Marathi | mr | मराठी |
| Gujarati | gu | ગુજરાતી |
| Kannada | kn | ಕನ್ನಡ |
| Malayalam | ml | മലയാളം |
| Punjabi | pa | ਪੰਜਾਬੀ |
| Odia | or | ଓଡ଼ିଆ |

---

## Why This Approach

### Deliberate Trade-offs

| Decision | Reasoning |
|----------|-----------|
| **PWA, not native app** | Zero install friction. Works on any device with a browser. No app store gatekeeping. Trade-off: cannot access call audio directly — user must use speaker mode. We frame this as a **privacy feature**: no background listening, no always-on microphone, user-initiated analysis only. |
| **ASR + pattern matching, not audio classification** | Audio classification (detecting scam by vocal patterns, prosody, call center noise) is the ideal approach. But it requires **labeled training data** — recordings of real scam calls vs legitimate calls — that does not exist in the public domain today. Pattern matching works now, with what we have. |
| **585 hand-crafted patterns + 13-archetype co-occurrence, not an LLM** | Patterns are deterministic, fast, explainable, and run on any hardware. No API keys, no inference costs, no hallucination risk. The co-occurrence engine scales detection to new languages without needing hundreds of exact phrases per language. A small on-device LLM can be added alongside as a complementary layer — not as a replacement. |
| **Local-only, no cloud** | Scam call audio contains sensitive personal information. Users will not trust a tool that uploads their conversations. Local-first is a trust requirement, not just a technical preference. |
| **Hybrid ASR (faster-whisper + IndicConformer)** | faster-whisper excels at English with low latency. IndicConformer is purpose-built for 22 Indian languages by AI4Bharat with sub-500ms inference. The hybrid engine routes automatically by language selection. |

### What We Know Works

The scam detection engine is ported from [hello-hari](https://github.com/anthropics-ai/hello-hari), a working Android app that uses Vosk ASR with the same pattern database. The patterns are not theoretical — they are extracted from real scam call scripts reported by Indian users.

**Validated results:**
- English scam scripts → **100% SCAM** detection
- Hindi scam scripts → **100% SCAM** detection
- Telugu scam scripts → **75% SCAM** detection
- Tamil, Kannada, Malayalam, Bengali, Marathi, Gujarati, Punjabi, Odia → **95% SCAM** detection
- Safe/legitimate conversations → **0% false positives**

### What We Know Is Limited

| Limitation | Impact | Path Forward |
|------------|--------|-------------|
| **PWA cannot access call audio directly** | User must use speaker mode and manually start recording | Push for platform-level scam detection APIs from Google/Apple. This POC demonstrates the demand. |
| **ASR errors break exact-phrase matching** | Whisper may transcribe "digital arrest" as "digital a rest" — and the pattern won't fire | The co-occurrence engine mitigates this by matching individual keywords (2 of 3 keyword groups is enough). Fuzzy matching and LLM layers can further improve this. |
| **Exact patterns miss novel scam scripts** | Scammers evolve their language. Static patterns need maintenance. | The 13-archetype keyword co-occurrence engine catches paraphrased variants. Community-contributed pattern database. LLM-based fallback for unknown scripts. |
| **No labeled audio dataset** | Cannot train an audio classifier (the best approach) | This POC, if successful, can be the basis for partnerships with CERT-In, state cyber cells, and telecom providers who have access to such data. |

---

## The Vision

This POC is not the final product. It is the **proof that on-device, multilingual scam detection is feasible** — built to demonstrate the concept to:

1. **Government agencies** (CERT-In, I4C, state cyber crime cells) — who can provide labeled scam call recordings for training audio classifiers
2. **Telecom providers** (Jio, Airtel, BSNL, Vi) — who can integrate detection at the network level
3. **Researchers** (IITs, IIITs, ISI) — who can build on this with better models, more languages, and larger datasets
4. **Platform companies** (Google, Apple) — who can expose call audio APIs for legitimate protection use cases, the way they exposed accessibility APIs

### Graduated Strategy

```
Phase 1 (NOW):  Hybrid ASR + pattern matching + co-occurrence on-device
                → 585+ patterns, 13 archetypes, 11 languages
                → Zero infrastructure, zero cost, zero data risk

Phase 2 (NEXT): Add small on-device LLM (Phi-3-mini, Gemma-2B)
                → Catches paraphrased/novel scam scripts
                → Runs alongside patterns, not instead of them
                → Community pattern database (crowdsourced)

Phase 3 (WITH PARTNERS): Audio classification model
                → Train on real scam call data from authorities
                → Language-agnostic (works by sound, not text)
                → Sub-second detection, no ASR needed

Phase 4 (AT SCALE): Platform/telecom integration
                → Detection at the carrier level before the call reaches the user
                → Number reputation + audio analysis + pattern matching
```

---

## Architecture

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
│  │  Layer 1: 585+ exact phrases   │ │
│  │           10 pattern categories │ │
│  │  Layer 2: 13-archetype keyword  │ │
│  │           co-occurrence engine  │ │
│  │           (10 scripts + EN)     │ │
│  │  Layer 3: Cross-language        │ │
│  │           indicator bonuses     │ │
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
  Everything runs on-device.
  No data leaves the machine.
```

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

### Hybrid ASR Design

The ASR engine is abstracted behind an interface (`ASREngine` ABC). The hybrid engine routes by language:

```
English (en)           → faster-whisper distil-small.en (CTranslate2, int8)
Indian languages (22)  → IndicConformer 600M (ONNX, CTC decoding)
```

Switch engines via environment variable:

```env
SCAM_ASR_ENGINE=hybrid            # Recommended: routes automatically
SCAM_ASR_ENGINE=faster_whisper    # English-only, lighter
SCAM_ASR_ENGINE=indic_conformer   # Indian languages only
```

---

## Detection Engine

### Layer 1: Exact Phrase Matching (585+ patterns)

| Category | Risk Level | Languages | Example Phrases |
|----------|-----------|-----------|-----------------|
| **Digital Arrest** | Critical (90-100) | EN, HI, TE | "you are under digital arrest", "warrant issued against you" |
| **TRAI / Telecom** | High (75-90) | EN, HI | "TRAI se bol raha hun", "SIM will be disconnected" |
| **Courier / Customs** | High (75-90) | EN, HI | "FedEx parcel seized", "drugs found in your package" |
| **Investment Fraud** | Medium-High (62-85) | EN, HI, TE | "guaranteed 10x returns", "crypto trading opportunity" |
| **Bank / OTP** | High (20-90) | EN, HI, TE + 8 scripts | "share your OTP", "account will be blocked" |
| **Family Emergency** | High (75-95) | EN, HI | "your son has been arrested", "surgery money needed urgently" |
| **Romance Scam** | Medium (65-85) | EN, HI | "military deployment", "visa fee needed" |
| **Hindi Advanced** | High (72-95) | HI (Devanagari + romanized) | "collector sahab ka order", "court hazir hona padega" |
| **Telugu Advanced** | High (65-90) | TE (script + romanized) | "మీ ఖాతా మూసివేయబడుతుంది", "warrant vachindi mee meeda" |
| **Hinglish** | High (70-95) | HI+EN code-switched | "aapka computer infected hai", "OTP share karo" |

### Layer 2: Multi-Archetype Keyword Co-occurrence (13 archetypes × 10 scripts)

Each archetype defines three keyword groups: **context**, **threat**, and **demand**. When keywords from 2+ groups appear in the same text, the archetype fires. This catches paraphrased and novel scam scripts without needing exact phrases.

| Archetype | Context Keywords | Threat Keywords | Demand Keywords |
|-----------|-----------------|-----------------|-----------------|
| **Bank / OTP** | bank, account, UPI | blocked, suspended, frozen | OTP, PIN, transfer |
| **Digital Arrest** | CBI, police, court | arrest, warrant, jail | fine, penalty, pay |
| **TRAI / Telecom** | TRAI, SIM, mobile | disconnect, cancel, suspend | press 1, Aadhaar, verify |
| **KYC / Aadhaar** | KYC, Aadhaar, PAN | expired, closed, deactivated | update, link, verify |
| **Family Emergency** | son, daughter, family | accident, hospital, arrested | money, transfer, urgently |
| **Tech Support** | computer, virus, Windows | infected, hacked, compromised | TeamViewer, AnyDesk, remote |
| **Courier / Customs** | parcel, FedEx, customs | drugs, seized, illegal | fine, fee, clearance |
| **Investment / Crypto** | stock, crypto, trading | loss, crash, opportunity | invest, deposit, guaranteed |
| **Lottery / Prize** | lottery, prize, winner | tax, claim, expires | fee, processing, bank details |
| **Insurance / Policy** | insurance, policy, LIC | expired, lapsed, cancelled | premium, renewal, pay |
| **Electricity / Utility** | electricity, bill, meter | overdue, disconnect, 2 hours | pay, app, link |
| **Job / Employment** | job, government, vacancy | last date, limited, selected | registration, fee, deposit |
| **Loan / Credit** | loan, credit, pre-approved | rejected, CIBIL, EMI | processing, fee, advance |

**Co-occurrence scoring:**
- Context + Threat → 70%
- Context + Demand → 75%
- Threat + Demand → 80%
- Context + Threat + Demand → 95%

All 13 archetypes include keywords in: **English, Hindi, Telugu, Tamil, Bengali, Marathi, Gujarati, Kannada, Malayalam, Punjabi, and Odia**.

### Layer 3: Cross-language Indicator Bonuses

One-time score additions when specific indicator types appear:

- **Urgency** (+15): "immediately", "turant", "jaldi"
- **Authority impersonation** (+20): "police", "CBI", "court", "collector"
- **Financial credentials** (+25): "OTP", "CVV", "UPI pin", "bank details"
- **Tech support pretexts** (+12): "TeamViewer", "AnyDesk", "virus detected"

### Real-time Pipeline

```
Audio chunk (5s) → ASR transcription → Scam analysis
                                          ├── Per-chunk score
                                          ├── Sliding window score (6 chunks = 30s context)
                                          └── Session max score (sticky ≥ 0.6, never drops)
```

---

## UI Components

| Component | Purpose |
|-----------|---------|
| **ShieldIndicator** | Large visual shield — green (SAFE/LISTENING), orange (SUSPICIOUS), red (SCAM DETECTED), with risk percentage |
| **AudioRecorder** | Language selector (11 languages), start/stop recording, matched pattern pills |
| **DebugPanel** | Collapsible per-chunk trace: ASR output, analysis source (chunk/window/session_max), pattern hits, verdict |
| **ScamAlert** | Alert banner with risk score, explanation, and matched category tags |
| **TranscriptionView** | Live scrolling transcript with language badges |

---

## Local Setup

### Prerequisites

- **Python 3.10+** with pip
- **Node.js 20+**
- **WSL2 with Ubuntu** (required for PyTorch/ONNX on ARM64 Windows)
- **Git**
- **HuggingFace token** (for IndicConformer gated model — `huggingface-cli login`)

### Backend (in WSL2)

```bash
cd backend
python3 -m venv venv-wsl
source venv-wsl/bin/activate
pip install -r requirements.txt

# Start the hybrid engine (recommended)
SCAM_ASR_ENGINE=hybrid SCAM_WHISPER_MODEL=distil-small.en \
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Models download automatically on first run:
- **distil-small.en** (~350MB) — faster-whisper English model
- **IndicConformer 600M** (~600MB) — AI4Bharat multilingual model (requires HuggingFace login for gated repo)

### Frontend (in a separate terminal, Windows or WSL2)

```bash
cd frontend
npm install
npm run dev
```

### Open the App

Navigate to **http://localhost:5173** — select a language, hit **Start Recording**, and speak.

### Docker (production)

```bash
# Build and run
docker compose up --build

# With HuggingFace token for IndicConformer
HF_TOKEN=your_token docker compose up --build
```

The app serves at **http://localhost:7860** with the React frontend bundled into the FastAPI server.

---

## Testing

### Unit Tests (53 tests — no model needed)

```bash
cd backend
source venv-wsl/bin/activate
pytest tests/test_scam_detector.py -v
```

**53 tests** across 4 test classes:
- **TestScamDetector** (~28 tests) — all 10 pattern categories, cross-language indicators, Telugu/Hindi/Hinglish detection, false positive checks
- **TestArchetypeRegistry** (3 tests) — archetype structure validation (all 13 registered, keyword sets non-empty, labels present)
- **TestArchetypeDetection** (~18 tests) — co-occurrence detection for each of the 13 archetypes + safe text checks
- **TestEndToEndArchetypes** (4 tests) — full pipeline integration (archetype score flows into final verdict)

### API Tests

```bash
# Health check
curl http://localhost:8000/api/health

# Text-only scam analysis (English)
curl -X POST "http://localhost:8000/api/analyze-text?text=this+is+from+mumbai+police+you+are+under+digital+arrest"

# Text-only scam analysis (Hindi)
curl -s -X POST "http://localhost:8000/api/analyze-text" -G \
  --data-urlencode "text=यह CBI से बोल रहा हूं आपके खिलाफ warrant जारी हुआ है"

# Legitimate text (should return risk_score: 0)
curl -X POST "http://localhost:8000/api/analyze-text?text=Good+morning+your+delivery+arrives+tomorrow"
```

### End-to-End Testing (needs running backend with model)

1. Open the PWA at http://localhost:5173
2. Select a language from the dropdown
3. Click **Start Recording** and speak a scam script on speaker
4. Verify: transcription appears, shield turns red, pattern pills show matches, debug panel shows pipeline trace

---

## Project Structure

```
hello-hari-recorder/
├── backend/
│   ├── app/
│   │   ├── main.py                       # FastAPI app, lifespan, static SPA serving
│   │   ├── config.py                     # Pydantic settings (env-based)
│   │   ├── asr/
│   │   │   ├── base.py                   # ASR engine interface (ABC)
│   │   │   ├── factory.py                # Engine factory (3 engines)
│   │   │   ├── hybrid_engine.py          # Routes: EN→whisper, Indian→conformer
│   │   │   ├── faster_whisper_engine.py  # CTranslate2, int8, greedy, VAD
│   │   │   └── indic_conformer_engine.py # AI4Bharat 600M, ONNX, CTC
│   │   ├── detection/
│   │   │   ├── scam_detector.py          # 585+ patterns, 10 categories, scoring
│   │   │   └── scam_archetypes.py        # 13 archetypes × 10 scripts
│   │   ├── db/
│   │   │   └── database.py               # SQLite CRUD
│   │   ├── models/
│   │   │   └── schemas.py                # Pydantic models
│   │   └── routers/
│   │       ├── transcription.py          # REST: /health, /transcribe, /analyze-text, /history
│   │       └── websocket.py              # WS: /ws/stream (sliding window, session state)
│   ├── tests/
│   │   └── test_scam_detector.py         # 53 tests (4 classes)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── AudioRecorder.tsx          # Main UI: record, language, pattern pills
│   │   │   ├── ShieldIndicator.tsx        # Visual shield (safe/suspicious/scam)
│   │   │   ├── DebugPanel.tsx             # Collapsible pipeline trace
│   │   │   ├── TranscriptionView.tsx      # Live transcript display
│   │   │   └── ScamAlert.tsx              # Alert banner with categories
│   │   ├── hooks/
│   │   │   └── useAudioRecorder.ts        # WebSocket + ScriptProcessorNode
│   │   ├── services/
│   │   │   └── api.ts                     # HTTP/WS client (ws/wss detection)
│   │   └── types/
│   │       └── index.ts                   # TypeScript interfaces (11 languages)
│   ├── package.json
│   └── vite.config.ts                     # PWA manifest, /api proxy
├── Dockerfile                             # Multi-stage: Node 20 + Python 3.11-slim
├── docker-compose.yml                     # Port 7860, named volumes
├── .dockerignore
├── .editorconfig
└── scripts/
    └── setup/
        └── download_models.py
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAM_ASR_ENGINE` | `hybrid` | ASR engine: `hybrid`, `faster_whisper`, or `indic_conformer` |
| `SCAM_WHISPER_MODEL` | `distil-small.en` | Whisper model name (any CTranslate2-compatible model) |
| `SCAM_DEBUG` | `true` | Enable debug output in API responses |
| `HF_TOKEN` | — | HuggingFace token for gated IndicConformer model |

---

## Alternative Approaches Evaluated

### Audio Classification (Best Theoretical Approach)

**What**: Train a model to classify audio segments as scam vs. legitimate directly from acoustic features — prosody, tone, pacing, call center background noise, VoIP artifacts — without any speech-to-text step.

**Why it's better**: Language-agnostic, tolerant of noise, no ASR accuracy dependency, smaller models (5-20MB).

**Why we can't do it today**: Requires labeled training data — thousands of hours of real scam calls annotated as scam vs. legitimate. This data does not exist in the public domain. Indian cyber crime cells have it, but it isn't published. This POC aims to demonstrate enough value to open that conversation.

### LLM-Based Classification

**What**: Replace pattern matching with an LLM prompt — "Analyze this transcript for scam indicators."

**Why it's appealing**: Handles paraphrasing, novel scripts, and ASR errors. Understands intent, not just keywords.

**Why it's not the primary approach**: Adds inference latency, model size (even small LLMs are 1-4GB), and a dependency that doesn't add enough value over patterns for known scam types. Hallucination risk for a security-critical classification.

**Planned for Phase 2**: A small on-device LLM (Phi-3-mini or Gemma-2B) running alongside the pattern engine — patterns catch known scripts fast, LLM catches novel ones. Both feed into the same scoring system.

### Telecom-Level Integration (Best at Scale)

**What**: Detect scams at the carrier network before the call reaches the user — number reputation, call metadata analysis, VoIP origin flagging.

**Why it's the right answer at scale**: No device-side processing needed. Covers every user on the network.

**Why it's not our approach**: Requires partnership with Jio/Airtel/BSNL/Vi and regulatory backing. This POC can serve as the technical demonstration for that pitch.

---

## How to Contribute

**Patterns**: Add scam phrases to [scam_detector.py](backend/app/detection/scam_detector.py) or keywords to [scam_archetypes.py](backend/app/detection/scam_archetypes.py). If you've received a scam call in any Indian language, the exact phrases and keywords used are valuable. Open a PR or issue.

**New archetypes**: Identify a scam type not covered by the 13 existing archetypes? Add a new entry to `SCAM_ARCHETYPES` with context/threat/demand keyword sets in as many scripts as possible.

**Audio samples**: If you have recordings of scam calls (with consent), these are critical for future audio classification work. Contact the maintainers.

**Testing**: Run the POC against real scam scripts and report what it catches vs. misses.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Built to protect. No data leaves your device.**