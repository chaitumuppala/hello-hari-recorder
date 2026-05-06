"""Narrative State Machine for scam call phase tracking.

Tracks the temporal progression of a scam call through manipulation phases:
  IDLE → HOOK → ESCALATE → ISOLATE → TRAP

Each archetype defines which keyword categories trigger each phase transition.
The tracker consumes transcript chunks over time and advances the state when
the expected phase's trigger keywords appear.

Key insight: scam calls follow a predictable psychological manipulation arc.
Detecting the *sequence* of manipulation tactics — not just individual keywords —
dramatically reduces false positives and enables early warning.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.detection.scam_archetypes import (
    NARRATIVE_PHASES,
    PHASE_ESCALATE,
    PHASE_HOOK,
    PHASE_IDLE,
    PHASE_ISOLATE,
    PHASE_TRAP,
    SCAM_ARCHETYPES,
    _match_keywords,
)


def _match_keywords_strict(text_lower: str, words: set[str], keywords: set[str]) -> str | None:
    """Stricter keyword matching — substring only, no stem/prefix matching.

    Used for phase-skip checks where loose matching causes false positives
    (e.g. 'card' in 'your new card will be sent' matching 'card details').
    """
    for kw in keywords:
        kw_lower = kw.lower()
        if kw_lower in text_lower:
            return kw
    return None

logger = logging.getLogger(__name__)

PHASE_ORDER = [PHASE_IDLE, PHASE_HOOK, PHASE_ESCALATE, PHASE_ISOLATE, PHASE_TRAP]
PHASE_SCORES = {
    PHASE_IDLE: 0,
    PHASE_HOOK: 15,
    PHASE_ESCALATE: 40,
    PHASE_ISOLATE: 65,
    PHASE_TRAP: 95,
}


@dataclass
class NarrativeState:
    """Current state of narrative tracking for a single archetype."""
    archetype_id: str
    phase: str = PHASE_IDLE
    phase_index: int = 0
    confidence: float = 0.0
    history: list[str] = field(default_factory=list)
    trigger_log: list[str] = field(default_factory=list)


@dataclass
class NarrativeResult:
    """Result of narrative analysis across all archetypes for a session."""
    best_archetype: str | None = None
    best_phase: str = PHASE_IDLE
    phase_score: int = 0
    confidence: float = 0.0
    phase_label: str = ""
    all_states: dict[str, NarrativeState] = field(default_factory=dict)


class NarrativeTracker:
    """Tracks scam narrative progression across transcript chunks.

    Usage:
        tracker = NarrativeTracker()
        for chunk in transcript_chunks:
            result = tracker.advance(chunk)
            print(result.best_phase, result.phase_score)
    """

    def __init__(self) -> None:
        self._states: dict[str, NarrativeState] = {}
        self._archetype_map: dict[str, tuple[set[str], set[str], set[str]]] = {}

        # Build lookup: archetype_id -> (context, threat, demand) keyword sets
        for label, ctx, thr, dem in SCAM_ARCHETYPES:
            self._archetype_map[label] = (ctx, thr, dem)
            if label in NARRATIVE_PHASES:
                self._states[label] = NarrativeState(archetype_id=label)

    def advance(self, text: str) -> NarrativeResult:
        """Process a transcript chunk and advance narrative states.

        Each archetype's state machine checks whether the current chunk
        contains keywords matching the *next expected phase's* trigger type.
        If so, the state advances.  If the next phase doesn't match but a
        *later* phase does (scammers skip steps), we advance to that phase,
        reducing confidence slightly for the skip.

        Returns the best (furthest-advanced) archetype result.
        """
        if not text or not text.strip():
            return self._build_result()

        lower = text.lower()
        words = set(lower.split())

        for arch_id, state in self._states.items():
            if arch_id not in NARRATIVE_PHASES:
                continue
            if arch_id not in self._archetype_map:
                continue

            phases_def = NARRATIVE_PHASES[arch_id]
            phase_list = phases_def["phases"]
            ctx_kws, thr_kws, dem_kws = self._archetype_map[arch_id]

            next_idx = state.phase_index

            if next_idx >= len(phase_list):
                continue  # Already at TRAP, fully advanced

            # Try to advance through as many phases as this chunk supports.
            # A single chunk like "press 1 to avoid disconnection" may
            # contain both urgency (ISOLATE) and demand (TRAP) triggers.
            advanced_this_chunk = False
            while next_idx < len(phase_list):
                next_phase_def = phase_list[next_idx]
                trigger_type = next_phase_def["triggers"]

                matched = self._check_trigger(
                    lower, words, trigger_type, arch_id,
                    ctx_kws, thr_kws, dem_kws, phases_def
                )

                if matched:
                    state.phase = next_phase_def["id"]
                    state.phase_index = next_idx + 1
                    state.confidence = min(1.0, state.confidence + 0.25)
                    state.history.append(state.phase)
                    state.trigger_log.append(
                        f"{state.phase}: {trigger_type}={matched}"
                    )
                    logger.info(
                        "NARRATIVE | %s advanced to %s (trigger=%s, matched=%s)",
                        arch_id, state.phase, trigger_type, matched
                    )
                    advanced_this_chunk = True
                    next_idx = state.phase_index  # Check next phase too
                else:
                    break  # This phase didn't match; stop sequential advance

            if not advanced_this_chunk:
                # Phase skip: check if any later phase matches this chunk.
                # Real scammers don't always follow the exact sequence —
                # they may jump from ESCALATE directly to TRAP.
                # GUARD: Only allow skipping if HOOK has already been
                # reached (phase_index >= 1).  Skipping from IDLE would
                # cause false positives on innocent conversations.
                if state.phase_index < 1:
                    continue  # Must reach HOOK first before any skipping

                for skip_idx in range(next_idx + 1, len(phase_list)):
                    skip_phase_def = phase_list[skip_idx]
                    skip_trigger = skip_phase_def["triggers"]
                    # Use STRICT matching for skips — no stem/prefix
                    # matching, only exact substring. This prevents
                    # 'card' in 'new card sent' from matching 'card details'.
                    skip_matched = self._check_trigger_strict(
                        lower, words, skip_trigger, arch_id,
                        ctx_kws, thr_kws, dem_kws, phases_def
                    )
                    if skip_matched:
                        skipped = skip_idx - next_idx
                        state.phase = skip_phase_def["id"]
                        state.phase_index = skip_idx + 1
                        # Reduce confidence slightly for skipped phases
                        state.confidence = min(
                            1.0, state.confidence + 0.25 - (0.05 * skipped)
                        )
                        state.history.append(state.phase)
                        state.trigger_log.append(
                            f"{state.phase}: {skip_trigger}={skip_matched} (skipped {skipped})"
                        )
                        logger.info(
                            "NARRATIVE | %s SKIPPED to %s (trigger=%s, matched=%s, skipped=%d)",
                            arch_id, state.phase, skip_trigger, skip_matched, skipped
                        )
                        break

        return self._build_result()

    def _check_trigger(
        self,
        lower: str,
        words: set[str],
        trigger_type: str,
        arch_id: str,
        ctx_kws: set[str],
        thr_kws: set[str],
        dem_kws: set[str],
        phases_def: dict,
    ) -> str | None:
        """Check if text contains keywords for the given trigger type."""
        if trigger_type == "context":
            return _match_keywords(lower, words, ctx_kws)
        elif trigger_type == "threat":
            return _match_keywords(lower, words, thr_kws)
        elif trigger_type == "demand":
            return _match_keywords(lower, words, dem_kws)
        elif trigger_type == "secrecy":
            extra = phases_def.get("secrecy_keywords", set())
            return _match_keywords(lower, words, extra)
        elif trigger_type == "urgency":
            extra = phases_def.get("urgency_keywords", set())
            return _match_keywords(lower, words, extra)
        elif trigger_type == "authority":
            extra = phases_def.get("authority_keywords", set())
            return _match_keywords(lower, words, extra)
        elif trigger_type == "social_proof":
            extra = phases_def.get("social_proof_keywords", set())
            return _match_keywords(lower, words, extra)
        elif trigger_type == "control":
            extra = phases_def.get("control_keywords", set())
            return _match_keywords(lower, words, extra)
        return None

    def _check_trigger_strict(
        self,
        lower: str,
        words: set[str],
        trigger_type: str,
        arch_id: str,
        ctx_kws: set[str],
        thr_kws: set[str],
        dem_kws: set[str],
        phases_def: dict,
    ) -> str | None:
        """Strict trigger check for phase skipping — substring only, no stem matching."""
        if trigger_type == "context":
            return _match_keywords_strict(lower, words, ctx_kws)
        elif trigger_type == "threat":
            return _match_keywords_strict(lower, words, thr_kws)
        elif trigger_type == "demand":
            return _match_keywords_strict(lower, words, dem_kws)
        else:
            extra_key = f"{trigger_type}_keywords"
            extra = phases_def.get(extra_key, set())
            return _match_keywords_strict(lower, words, extra)

    def _build_result(self) -> NarrativeResult:
        """Build result from the archetype with the most advanced phase."""
        best_arch = None
        best_phase = PHASE_IDLE
        best_idx = 0
        best_conf = 0.0

        for arch_id, state in self._states.items():
            if state.phase_index > best_idx or (
                state.phase_index == best_idx and state.confidence > best_conf
            ):
                best_arch = arch_id
                best_phase = state.phase
                best_idx = state.phase_index
                best_conf = state.confidence

        phase_score = PHASE_SCORES.get(best_phase, 0)

        phase_label = ""
        if best_arch and best_arch in NARRATIVE_PHASES:
            for p in NARRATIVE_PHASES[best_arch]["phases"]:
                if p["id"] == best_phase:
                    phase_label = p["description"]
                    break

        return NarrativeResult(
            best_archetype=best_arch,
            best_phase=best_phase,
            phase_score=phase_score,
            confidence=best_conf,
            phase_label=phase_label,
            all_states=dict(self._states),
        )

    def get_state(self) -> NarrativeResult:
        """Get current state without advancing."""
        return self._build_result()

    def reset(self) -> None:
        """Reset all archetype states to IDLE."""
        for state in self._states.values():
            state.phase = PHASE_IDLE
            state.phase_index = 0
            state.confidence = 0.0
            state.history.clear()
            state.trigger_log.clear()
