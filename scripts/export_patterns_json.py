"""Export all scam detection patterns to a single JSON file.

This is the single source of truth bridge between:
  - hello-hari-recorder (Python backend + web PWA)
  - hello-hari (Android app)

Both platforms load the same patterns.json and run the same algorithm,
so adding a phrase once propagates everywhere.

Run:
    python -m scripts.export_patterns_json [output_path]

Default output: backend/app/detection/patterns.json
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make the backend package importable when running as a script
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "backend"))

# We only need the plain data tables — stub out pydantic so the exporter
# runs with zero third-party deps (CI/pre-commit friendly).
if "pydantic" not in sys.modules:
    import types

    _pyd = types.ModuleType("pydantic")

    class _BaseModel:  # minimal shim; we never instantiate ScamAnalysis here
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    def _Field(*a, **kw):  # noqa: N802 - mimics pydantic API
        return kw.get("default")

    _pyd.BaseModel = _BaseModel
    _pyd.Field = _Field
    sys.modules["pydantic"] = _pyd

from app.detection import scam_archetypes, scam_detector  # noqa: E402


SCHEMA_VERSION = 1


def _sorted_set(s: set[str]) -> list[str]:
    """Deterministic ordering so the JSON is diff-friendly."""
    return sorted(s)


def _sorted_dict(d: dict[str, int]) -> dict[str, int]:
    return {k: d[k] for k in sorted(d)}


def build_patterns() -> dict:
    """Read Python data structures and emit a platform-neutral dict."""

    # Layer 1: exact-phrase pattern categories
    pattern_categories: list[dict] = []
    for cat_id, cat_dict in scam_detector.PATTERN_CATEGORIES:
        pattern_categories.append({
            "id": cat_id,
            "label": scam_detector.CATEGORY_LABELS.get(cat_id, cat_id),
            "patterns": _sorted_dict(cat_dict),
        })

    # Cross-language indicator sets (URGENCY, AUTHORITY, FINANCIAL_RISK, TECH_SUPPORT, SECRECY)
    indicator_sets = {
        "URGENCY": _sorted_set(scam_detector.URGENCY_WORDS),
        "AUTHORITY": _sorted_set(scam_detector.AUTHORITY_WORDS),
        "FINANCIAL_RISK": _sorted_set(scam_detector.FINANCIAL_RISK_TERMS),
        "TECH_SUPPORT": _sorted_set(scam_detector.TECH_SUPPORT_TERMS),
        "SECRECY": _sorted_set(scam_detector.SECRECY_ISOLATION_TERMS),
    }

    indicator_labels = {
        "URGENCY": scam_detector.CATEGORY_LABELS["URGENCY"],
        "AUTHORITY": scam_detector.CATEGORY_LABELS["AUTHORITY"],
        "FINANCIAL_RISK": scam_detector.CATEGORY_LABELS["FINANCIAL_RISK"],
        "TECH_SUPPORT": scam_detector.CATEGORY_LABELS["TECH_SUPPORT"],
        "SECRECY": scam_detector.CATEGORY_LABELS["SECRECY"],
    }

    # Layer 2: keyword co-occurrence archetypes
    archetypes: list[dict] = []
    for label, ctx_kws, thr_kws, dem_kws in scam_archetypes.SCAM_ARCHETYPES:
        archetypes.append({
            "id": label,
            "label": scam_archetypes.ARCHETYPE_LABELS[label],
            "context": _sorted_set(ctx_kws),
            "threat": _sorted_set(thr_kws),
            "demand": _sorted_set(dem_kws),
        })

    # Stats — useful for sanity checks & telemetry
    total_exact_phrases = sum(len(c["patterns"]) for c in pattern_categories)
    total_indicator_terms = sum(len(v) for v in indicator_sets.values())
    total_archetype_keywords = sum(
        len(a["context"]) + len(a["threat"]) + len(a["demand"])
        for a in archetypes
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/export_patterns_json.py",
        "source_repo": "hello-hari-recorder",

        # Algorithm constants — both platforms MUST use these identically.
        # See backend/app/detection/scam_detector.py analyze_text().
        "constants": {
            "risk_cap": 100,
            "scam_threshold": 0.6,
            "category_repeat_bonus": 0.1,  # +10% per extra hit in same category
            "cooccurrence_scores": {
                "context_threat_demand": 95,
                "threat_demand": 80,
                "context_demand": 75,
                "context_threat": 70,
            },
            "stem_match_min_length": 4,  # _match_keywords prefix rule
        },

        "indicator_bonuses": {
            "URGENCY": 15,
            "AUTHORITY": 20,
            "FINANCIAL_RISK": 25,
            "TECH_SUPPORT": 12,
            "SECRECY": 20,
        },
        "indicator_labels": indicator_labels,

        "pattern_categories": pattern_categories,
        "indicator_sets": indicator_sets,
        "archetypes": archetypes,

        "stats": {
            "pattern_categories_count": len(pattern_categories),
            "total_exact_phrases": total_exact_phrases,
            "indicator_sets_count": len(indicator_sets),
            "total_indicator_terms": total_indicator_terms,
            "archetypes_count": len(archetypes),
            "total_archetype_keywords": total_archetype_keywords,
        },
    }


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        _REPO_ROOT / "backend" / "app" / "detection" / "patterns.json"
    )
    data = build_patterns()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write("\n")

    s = data["stats"]
    print(f"Wrote {output}")
    print(
        f"  schema_version={data['schema_version']} | "
        f"categories={s['pattern_categories_count']} | "
        f"exact_phrases={s['total_exact_phrases']} | "
        f"indicators={s['total_indicator_terms']} | "
        f"archetypes={s['archetypes_count']} | "
        f"archetype_keywords={s['total_archetype_keywords']}"
    )


if __name__ == "__main__":
    main()
