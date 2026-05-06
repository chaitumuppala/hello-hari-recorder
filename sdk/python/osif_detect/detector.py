"""Standalone scam detection engine — loads OSIF v2 JSON, no server needed.

This is the SDK's core. It reimplements the detection logic from
scam_detector.py + scam_archetypes.py + narrative_tracker.py in a
single self-contained module that depends only on the JSON file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# ── Phase constants ──────────────────────────────────────────────────
PHASE_IDLE = "IDLE"
PHASE_HOOK = "HOOK"
PHASE_ESCALATE = "ESCALATE"
PHASE_ISOLATE = "ISOLATE"
PHASE_TRAP = "TRAP"

PHASE_SCORES = {
    PHASE_IDLE: 0,
    PHASE_HOOK: 15,
    PHASE_ESCALATE: 40,
    PHASE_ISOLATE: 65,
    PHASE_TRAP: 95,
}


@dataclass
class DetectionResult:
    """Result from analyzing text."""
    is_scam: bool = False
    risk_score: float = 0.0
    matched_patterns: list[str] = field(default_factory=list)
    explanation: str = ""
    narrative_phase: str = PHASE_IDLE
    narrative_archetype: str | None = None
    narrative_phase_label: str = ""
    narrative_phase_score: int = 0


class DetectionSession:
    """Stateful session for streaming transcript chunks with narrative tracking."""

    def __init__(self, detector: "ScamDetector") -> None:
        self._detector = detector
        self._chunks: list[str] = []
        self._narrative_states: dict[str, dict] = {}
        # Initialize narrative states for each archetype that has phases
        for arch_id in detector._narrative_phases:
            self._narrative_states[arch_id] = {
                "phase_index": 0,
                "phase": PHASE_IDLE,
                "confidence": 0.0,
            }

    def analyze_chunk(self, text: str) -> DetectionResult:
        """Analyze a new transcript chunk, advancing narrative state."""
        self._chunks.append(text)

        # Advance narrative for this chunk
        self._advance_narrative(text)

        # Run stateless detection on full window
        window = " ".join(self._chunks[-6:])  # Match backend's window_size
        result = self._detector.analyze(window)

        # Overlay narrative state
        best = self._get_best_narrative()
        result.narrative_phase = best["phase"]
        result.narrative_archetype = best.get("archetype")
        result.narrative_phase_label = best.get("label", "")
        result.narrative_phase_score = PHASE_SCORES.get(best["phase"], 0)

        # Boost score with narrative progression
        if result.narrative_phase_score > 0:
            combined = min(100, int(result.risk_score * 100) + result.narrative_phase_score)
            result.risk_score = round(combined / 100.0, 2)
            result.is_scam = result.risk_score >= 0.6

        return result

    def _advance_narrative(self, text: str) -> None:
        lower = text.lower()
        words = set(lower.split())

        for arch_id, state in self._narrative_states.items():
            phases_def = self._detector._narrative_phases.get(arch_id)
            if not phases_def:
                continue
            phase_list = phases_def.get("phases", [])
            idx = state["phase_index"]
            if idx >= len(phase_list):
                continue

            # Try to advance through multiple phases per chunk
            advanced = False
            while idx < len(phase_list):
                next_phase = phase_list[idx]
                trigger_type = next_phase["triggers"]
                matched = self._check_trigger(lower, words, arch_id, trigger_type, phases_def)
                if matched:
                    state["phase_index"] = idx + 1
                    state["phase"] = next_phase["id"]
                    state["confidence"] = min(1.0, state.get("confidence", 0) + 0.25)
                    advanced = True
                    idx = state["phase_index"]
                else:
                    break

            if not advanced:
                # Phase skip: only after HOOK has been reached
                if state["phase_index"] < 1:
                    continue
                for skip_idx in range(idx + 1, len(phase_list)):
                    skip_phase = phase_list[skip_idx]
                    skip_trigger = skip_phase["triggers"]
                    skip_matched = self._check_trigger_strict(
                        lower, words, arch_id, skip_trigger, phases_def
                    )
                    if skip_matched:
                        skipped = skip_idx - idx
                        state["phase_index"] = skip_idx + 1
                        state["phase"] = skip_phase["id"]
                        state["confidence"] = min(
                            1.0, state.get("confidence", 0) + 0.25 - (0.05 * skipped)
                        )
                        break

    def _check_trigger(self, lower, words, arch_id, trigger_type, phases_def) -> str | None:
        arch = self._detector._archetypes_by_id.get(arch_id)
        if not arch:
            return None

        if trigger_type == "context":
            return _match_any(lower, words, arch.get("context", []))
        elif trigger_type == "threat":
            return _match_any(lower, words, arch.get("threat", []))
        elif trigger_type == "demand":
            return _match_any(lower, words, arch.get("demand", []))
        else:
            # Check extra keyword sets (secrecy_keywords, urgency_keywords, etc.)
            extra_key = f"{trigger_type}_keywords"
            extra = phases_def.get(extra_key, [])
            return _match_any(lower, words, extra)

    def _check_trigger_strict(self, lower, words, arch_id, trigger_type, phases_def) -> str | None:
        """Strict check for phase skipping — substring only, no stem match."""
        arch = self._detector._archetypes_by_id.get(arch_id)
        if not arch:
            return None
        if trigger_type == "context":
            return _match_any_strict(lower, arch.get("context", []))
        elif trigger_type == "threat":
            return _match_any_strict(lower, arch.get("threat", []))
        elif trigger_type == "demand":
            return _match_any_strict(lower, arch.get("demand", []))
        else:
            extra_key = f"{trigger_type}_keywords"
            extra = phases_def.get(extra_key, [])
            return _match_any_strict(lower, extra)

    def _get_best_narrative(self) -> dict:
        best = {"phase": PHASE_IDLE, "archetype": None, "label": ""}
        best_idx = 0
        for arch_id, state in self._narrative_states.items():
            if state["phase_index"] > best_idx:
                best_idx = state["phase_index"]
                best["phase"] = state["phase"]
                best["archetype"] = arch_id
                phases_def = self._detector._narrative_phases.get(arch_id, {})
                for p in phases_def.get("phases", []):
                    if p["id"] == state["phase"]:
                        best["label"] = p.get("description", "")
        return best

    def reset(self) -> None:
        self._chunks.clear()
        for state in self._narrative_states.values():
            state["phase_index"] = 0
            state["phase"] = PHASE_IDLE
            state["confidence"] = 0.0


def _match_any(lower: str, words: set[str], keywords: list[str]) -> str | None:
    """Check if any keyword appears in text (substring or stem match)."""
    for kw in keywords:
        kw_lower = kw.lower()
        if kw_lower in lower:
            return kw
        for word in words:
            if len(word) >= 4 and len(kw_lower) >= 4:
                if word.startswith(kw_lower) or kw_lower.startswith(word):
                    return kw
    return None


def _match_any_strict(lower: str, keywords: list[str]) -> str | None:
    """Strict substring-only match — no stem/prefix matching."""
    for kw in keywords:
        if kw.lower() in lower:
            return kw
    return None


class ScamDetector:
    """Standalone scam detection engine loaded from OSIF JSON."""

    def __init__(self, data: dict) -> None:
        self._data = data
        self._pattern_categories = data.get("pattern_categories", [])
        self._indicator_sets = data.get("indicator_sets", {})
        self._indicator_bonuses = data.get("indicator_bonuses", {})
        self._archetypes = data.get("archetypes", [])
        self._narrative_phases = data.get("narrative_phases", {})
        self._constants = data.get("constants", {})

        # Build lookup
        self._archetypes_by_id = {a["id"]: a for a in self._archetypes}

    @classmethod
    def from_json(cls, path: str | Path) -> "ScamDetector":
        """Load detector from an OSIF JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(data)

    @classmethod
    def from_dict(cls, data: dict) -> "ScamDetector":
        """Create detector from a pre-loaded dict."""
        return cls(data)

    def analyze(self, text: str) -> DetectionResult:
        """Analyze text for scam patterns (stateless, single-shot)."""
        if not text or not text.strip():
            return DetectionResult(explanation="No text to analyze.")

        lower = text.lower()
        words = set(lower.split())
        total_score = 0
        matched: list[str] = []

        # Layer 1: exact phrase matching
        repeat_bonus = self._constants.get("category_repeat_bonus", 0.1)
        for cat in self._pattern_categories:
            cat_score = 0
            cat_hits = 0
            for phrase, weight in cat.get("patterns", {}).items():
                if phrase.lower() in lower:
                    cat_score += weight
                    cat_hits += 1
            if cat_hits > 1:
                cat_score = int(cat_score * (1.0 + (cat_hits - 1) * repeat_bonus))
            if cat_score > 0:
                matched.append(cat.get("label", cat.get("id", "")))
                total_score += cat_score

        # Layer 2: archetype co-occurrence
        cooccur = self._constants.get("cooccurrence_scores", {})
        best_cooccur = 0
        for arch in self._archetypes:
            ctx = _match_any(lower, words, arch.get("context", []))
            thr = _match_any(lower, words, arch.get("threat", []))
            dem = _match_any(lower, words, arch.get("demand", []))
            score = 0
            if ctx and thr and dem:
                score = cooccur.get("context_threat_demand", 95)
            elif thr and dem:
                score = cooccur.get("threat_demand", 80)
            elif ctx and dem:
                score = cooccur.get("context_demand", 75)
            elif ctx and thr:
                score = cooccur.get("context_threat", 70)
            if score > best_cooccur:
                best_cooccur = score
        total_score += best_cooccur

        # Layer 3: indicator bonuses
        for indicator_name, bonus in self._indicator_bonuses.items():
            kw_list = self._indicator_sets.get(indicator_name, [])
            if _match_any(lower, words, kw_list):
                total_score += bonus

        # Cap and normalize
        total_score = min(self._constants.get("risk_cap", 100), total_score)
        risk_score = round(total_score / 100.0, 2)
        is_scam = risk_score >= self._constants.get("scam_threshold", 0.6)

        explanation = ""
        if is_scam:
            explanation = f"SCAM DETECTED ({total_score}%): {', '.join(matched[:3])}"
        elif total_score > 0:
            explanation = f"Low risk ({total_score}%): {', '.join(matched[:2])}"
        else:
            explanation = "No scam patterns detected."

        return DetectionResult(
            is_scam=is_scam,
            risk_score=risk_score,
            matched_patterns=matched,
            explanation=explanation,
        )

    def create_session(self) -> DetectionSession:
        """Create a stateful session for streaming transcript chunks."""
        return DetectionSession(self)

    @property
    def schema_version(self) -> int:
        return self._data.get("schema_version", 1)

    @property
    def stats(self) -> dict:
        return self._data.get("stats", {})
