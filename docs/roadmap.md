# Roadmap

## Current State (Phase 1)

**On-device ASR + pattern matching + keyword co-occurrence.**

| Metric | Value |
|--------|-------|
| Exact phrases | 550+ across 9 categories |
| Archetypes | 13 scam types × 10 Indian scripts |
| Languages | 11 (English + 10 Indian) |
| ASR engines | faster-whisper (EN) + IndicConformer (22 Indian langs) |
| False positives | 0% on tested safe conversations |
| Infrastructure cost | Zero — runs entirely on-device |

### Known Limitations

| Limitation | Impact | Mitigated By |
|------------|--------|--------------|
| **PWA cannot access call audio** | User must use speaker mode | Privacy feature — no background listening |
| **ASR errors break exact phrases** | "digital arrest" → "digital a rest" | Layer 2 co-occurrence matches individual keywords |
| **Static patterns miss novel scripts** | Scammers evolve language | Co-occurrence engine + community updates |
| **No labeled audio dataset** | Cannot train audio classifier | This POC demonstrates value to data holders |
| **Speaker mode + ambient noise** | Reduces ASR accuracy | VAD filtering, sliding window smoothing |

---

## Phase 2: On-device LLM Layer

Add a small language model running alongside the pattern engine — not replacing it.

| Component | Candidate | Why |
|-----------|-----------|-----|
| LLM | Phi-3-mini (3.8B) or Gemma-2B | Small enough for on-device, strong reasoning |
| Role | Classify transcripts the pattern engine scores < 0.3 | Catch novel/paraphrased scripts |
| Integration | Score feeds into same 0-100 system | Consistent UX |

**Patterns catch known scripts fast. LLM catches novel ones. Both feed into the same scoring system.**

Additional Phase 2 goals:
- **Community pattern database** — crowdsourced pattern contributions via GitHub
- **Fuzzy matching** — token-overlap matching to handle ASR transcription errors
- **Confidence calibration** — tune scoring thresholds against a larger test corpus

---

## Phase 3: Audio Classification (With Partners)

Train a model to detect scams directly from audio — no ASR, no text, no language dependency.

| Requirement | Why | Who Has It |
|-------------|-----|-----------|
| Labeled scam call recordings | Training data for audio classifier | CERT-In, I4C, state cyber cells, telcos |
| Legitimate call baseline | Negative class for training | Any organization with recorded call centers |
| Annotation pipeline | Quality labels | Research institutions |

**Model candidates**: Fine-tuned wav2vec2, Audio Spectrogram Transformer, MFCC + lightweight CNN.

**Why it's the best approach at scale**: Language-agnostic (works by sound, not words). Tolerant of noise. Smaller models (5-20MB). Sub-second inference. But requires data that doesn't exist publicly today.

This POC exists to demonstrate enough value to open that conversation.

---

## Phase 4: Telecom Integration

Detection at the carrier network level, before the call reaches the user.

| Partner | Integration Point |
|---------|-------------------|
| Jio / Airtel / BSNL / Vi | Network-level audio analysis |
| Google / Apple | Call audio APIs for on-device protection |
| CERT-In / I4C | Regulatory backing, data sharing agreements |

**Why it's the right answer at scale**: No device-side processing. Covers every user on the network. But requires partnerships and regulatory framework.

---

## Alternative Approaches Evaluated

### Audio Classification (Ideal, Data-Blocked)

Classify scam from acoustic features — prosody, tone, call center noise, VoIP artifacts. Language-agnostic, noise-tolerant. **Blocked by lack of labeled training data.** This POC aims to unlock that data.

### LLM-Only Classification (Appealing, Wrong Trade-off)

Replace patterns with LLM prompt: "Analyze this transcript for scam indicators." Handles paraphrasing and novel scripts. **But**: adds 1-4GB model size, inference latency, hallucination risk for a security-critical classification. Better as a complementary layer (Phase 2), not a replacement.

### Vosk ASR (Viable Alternative)

Small on-device ASR models (~40-50MB per language). Used successfully in the hello-hari Android app. Near-instant inference. Runs natively on ARM64. Trade-off: less accurate than faster-whisper/IndicConformer for general transcription, but patterns were originally written against Vosk output. Worth testing head-to-head.

### Telecom-Level Only (Right at Scale, Wrong for POC)

No device-side processing. Carrier-level detection. **But**: requires Jio/Airtel/BSNL/Vi partnership and regulatory backing. This POC demonstrates the technical feasibility to pitch for those partnerships.

---

## Partnership Asks

| Partner Type | What We Need | What We Offer |
|--------------|-------------|---------------|
| **Cyber crime cells** | Labeled scam call recordings | Working POC, open-source detection engine |
| **Telecoms** | Network integration, call metadata | Detection technology, pattern database |
| **Researchers** | Larger datasets, model improvements | Open codebase, defined problem space |
| **Platforms** | Call audio API access | Proven user-safety use case |
