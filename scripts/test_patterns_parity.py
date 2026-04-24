"""Parity test: patterns.json JSON-consumer vs. analyze_text() (hardcoded Python).

This mirrors the Java ScamPatternEngine algorithm exactly using only data
from patterns.json. If the scores match analyze_text()'s scores for a broad
test corpus, the JSON export is complete and the Java engine (which follows
the same spec) can be trusted for parity.

Run:
    python scripts/test_patterns_parity.py
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

# --- Path & dep setup (same trick as export_patterns_json.py) ---
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "backend"))

if "pydantic" not in sys.modules:
    p = types.ModuleType("pydantic")

    class _BaseModel:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

    def _Field(*a, **kw):  # noqa: N802
        return kw.get("default")

    p.BaseModel = _BaseModel
    p.Field = _Field
    sys.modules["pydantic"] = p

from app.detection.scam_detector import analyze_text  # noqa: E402


# --- JSON-consumer port (mirrors ScamPatternEngine.java exactly) ---

PATTERNS_FILE = _REPO_ROOT / "backend" / "app" / "detection" / "patterns.json"
INDICATOR_TAGS = ("URGENCY", "AUTHORITY", "FINANCIAL_RISK", "TECH_SUPPORT", "SECRECY")


class JsonEngine:
    def __init__(self, bundle: dict):
        self.risk_cap = bundle["constants"]["risk_cap"]
        self.repeat_bonus = bundle["constants"]["category_repeat_bonus"]
        self.stem_min = bundle["constants"]["stem_match_min_length"]
        co = bundle["constants"]["cooccurrence_scores"]
        self.s_ctd = co["context_threat_demand"]
        self.s_td  = co["threat_demand"]
        self.s_cd  = co["context_demand"]
        self.s_ct  = co["context_threat"]

        self.ind_bonus = bundle["indicator_bonuses"]
        self.categories = bundle["pattern_categories"]
        self.ind_sets = {k: [t.lower() for t in v] for k, v in bundle["indicator_sets"].items()}
        self.archetypes = [
            {
                "id": a["id"],
                "context": [x.lower() for x in a["context"]],
                "threat":  [x.lower() for x in a["threat"]],
                "demand":  [x.lower() for x in a["demand"]],
            }
            for a in bundle["archetypes"]
        ]

    def _check_patterns(self, text, patterns, detected, cat_id):
        score, count = 0, 0
        for phrase, pts in patterns.items():
            if phrase in text:
                score += pts
                count += 1
                detected.append(f"[{cat_id}] {phrase} (+{pts})")
        if count > 1:
            score = int(score * (1.0 + (count - 1) * self.repeat_bonus))
        return score

    def _check_indicator(self, text, tag, detected):
        terms = self.ind_sets.get(tag, [])
        bonus = self.ind_bonus.get(tag, 0)
        for t in terms:
            if t in text:
                detected.append(f"[{tag}] {t} (+{bonus})")
                return bonus
        return 0

    def _match_kw(self, lower, words, kws):
        for kw in kws:
            if kw in lower:
                return kw
            if len(kw) >= self.stem_min:
                for w in words:
                    if len(w) >= self.stem_min and (w.startswith(kw) or kw.startswith(w)):
                        return kw
        return None

    def _cooccur(self, lower, detected):
        words = set(lower.split())
        collapsed = lower.replace(" ", "")
        best = 0
        for a in self.archetypes:
            c = self._match_kw(lower, words, a["context"])
            t = self._match_kw(lower, words, a["threat"])
            d = self._match_kw(lower, words, a["demand"])
            if d is None:
                d = self._match_kw(collapsed, set(collapsed.split()), a["demand"])

            score = 0
            if c and t and d:
                score = self.s_ctd
                detected.append(f"[KEYWORD_COOCCUR:{a['id']}] context({c}) + threat({t}) + demand({d}) (+{score})")
            elif t and d:
                score = self.s_td
                detected.append(f"[KEYWORD_COOCCUR:{a['id']}] threat({t}) + demand({d}) (+{score})")
            elif c and d:
                score = self.s_cd
                detected.append(f"[KEYWORD_COOCCUR:{a['id']}] context({c}) + demand({d}) (+{score})")
            elif c and t:
                score = self.s_ct
                detected.append(f"[KEYWORD_COOCCUR:{a['id']}] context({c}) + threat({t}) (+{score})")

            if score > best:
                best = score
        return best

    def analyze(self, text: str):
        if not text or not text.strip():
            return {"score": 0, "is_scam": False}
        lower = text.lower()
        total = 0
        detected: list[str] = []
        for cat in self.categories:
            s = self._check_patterns(lower, cat["patterns"], detected, cat["id"])
            total += s
        total += self._cooccur(lower, detected)
        for tag in INDICATOR_TAGS:
            total += self._check_indicator(lower, tag, detected)
        total = min(self.risk_cap, total)
        return {"score": total, "is_scam": total >= 60, "hits": len(detected)}


# --- Test corpus (English + code-switched + Indic scripts) ---

TEST_CORPUS = [
    # English — digital arrest
    "sir you are under digital arrest, do not disconnect this call",
    # English — courier / customs
    "your parcel contains illegal items and has been seized by customs",
    # English — TRAI
    "your mobile number will be disconnected in 2 hours due to illegal activity",
    # English — bank OTP
    "please share the otp you just received to verify your account",
    # English — investment
    "guaranteed 10x returns on bitcoin investment, join now",
    # English — tech support
    "your computer is infected with virus, please install teamviewer",
    # Hinglish — banking
    "aapka account freeze ho jayega agar aap otp nahi dete",
    # Hindi devanagari
    "आपका खाता बंद हो जाएगा अगर आपने ओटीपी नहीं बताया",
    # Telugu
    "మీ బ్యాంక్ ఖాతా స్తంభింపబడుతుంది OTP చెప్పండి",
    # Family emergency
    "your son has been in an accident, send money urgently for treatment",
    # Clean (should score 0)
    "hi mom, how are you doing today?",
    "i will pick up groceries on my way home",
    # Borderline — urgency only
    "please hurry up and send this immediately",
    # Mixed
    "immediately share your otp and cvv, this is urgent bank verification",
]


def main() -> int:
    with PATTERNS_FILE.open(encoding="utf-8") as f:
        bundle = json.load(f)
    engine = JsonEngine(bundle)

    mismatches = 0
    print(f"{'score(hardcoded)':>18} | {'score(json)':>12} | scam | input")
    print("-" * 90)

    for text in TEST_CORPUS:
        ref = analyze_text(text)
        ref_score = int(round(ref.risk_score * 100))
        j = engine.analyze(text)
        ok = ref_score == j["score"]
        flag = " " if ok else "X"
        print(f"{flag} {ref_score:>16} | {j['score']:>12} | {str(j['is_scam']):>5} | {text[:60]!r}")
        if not ok:
            mismatches += 1

    print("-" * 90)
    if mismatches == 0:
        print(f"PASS — {len(TEST_CORPUS)} cases, all scores match.")
        return 0
    print(f"FAIL — {mismatches}/{len(TEST_CORPUS)} mismatches.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
