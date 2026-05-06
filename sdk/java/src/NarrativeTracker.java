package com.hellohari;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Narrative State Machine for scam call phase tracking (Java port).
 *
 * Tracks the temporal progression of a scam call through manipulation phases:
 *   IDLE → HOOK → ESCALATE → ISOLATE → TRAP
 *
 * Loaded from the "narrative_phases" section of OSIF v2 patterns.json.
 */
public class NarrativeTracker {

    public static final String PHASE_IDLE = "IDLE";
    public static final String PHASE_HOOK = "HOOK";
    public static final String PHASE_ESCALATE = "ESCALATE";
    public static final String PHASE_ISOLATE = "ISOLATE";
    public static final String PHASE_TRAP = "TRAP";

    private static final Map<String, Integer> PHASE_SCORES = new HashMap<>();
    static {
        PHASE_SCORES.put(PHASE_IDLE, 0);
        PHASE_SCORES.put(PHASE_HOOK, 15);
        PHASE_SCORES.put(PHASE_ESCALATE, 40);
        PHASE_SCORES.put(PHASE_ISOLATE, 65);
        PHASE_SCORES.put(PHASE_TRAP, 95);
    }

    /** Per-archetype state. */
    private static class ArchetypeState {
        String archetypeId;
        String phase = PHASE_IDLE;
        int phaseIndex = 0;
        double confidence = 0.0;

        ArchetypeState(String id) { this.archetypeId = id; }
    }

    /** Phase definition from JSON. */
    private static class PhaseDef {
        String id;          // HOOK, ESCALATE, etc.
        String triggers;    // "context", "threat", "demand", "secrecy", etc.
        String description;
    }

    /** Archetype narrative config. */
    private static class ArchetypeNarrative {
        String label;
        List<PhaseDef> phases = new ArrayList<>();
        Map<String, Set<String>> extraKeywords = new HashMap<>(); // e.g. "secrecy_keywords"
    }

    private final Map<String, ArchetypeNarrative> narrativePhases = new HashMap<>();
    private final Map<String, ArchetypeState> states = new HashMap<>();

    // Archetype keyword data for trigger matching (from main patterns.json archetypes)
    private final Map<String, List<String>> archetypeContext = new HashMap<>();
    private final Map<String, List<String>> archetypeThreat = new HashMap<>();
    private final Map<String, List<String>> archetypeDemand = new HashMap<>();

    /**
     * Load narrative phases from the OSIF v2 JSON.
     *
     * @param root the full patterns.json root object
     */
    public void loadFromJson(JSONObject root) throws JSONException {
        // Load narrative_phases
        JSONObject npObj = root.optJSONObject("narrative_phases");
        if (npObj == null) return;

        Iterator<String> keys = npObj.keys();
        while (keys.hasNext()) {
            String archId = keys.next();
            JSONObject def = npObj.getJSONObject(archId);

            ArchetypeNarrative an = new ArchetypeNarrative();
            an.label = def.optString("label", "");

            JSONArray phasesArr = def.optJSONArray("phases");
            if (phasesArr != null) {
                for (int i = 0; i < phasesArr.length(); i++) {
                    JSONObject p = phasesArr.getJSONObject(i);
                    PhaseDef pd = new PhaseDef();
                    pd.id = p.getString("id");
                    pd.triggers = p.getString("triggers");
                    pd.description = p.optString("description", "");
                    an.phases.add(pd);
                }
            }

            // Load extra keyword sets (secrecy_keywords, urgency_keywords, etc.)
            Iterator<String> defKeys = def.keys();
            while (defKeys.hasNext()) {
                String key = defKeys.next();
                if (key.endsWith("_keywords")) {
                    JSONArray arr = def.optJSONArray(key);
                    if (arr != null) {
                        Set<String> kwSet = new HashSet<>();
                        for (int i = 0; i < arr.length(); i++) {
                            kwSet.add(arr.getString(i));
                        }
                        an.extraKeywords.put(key, kwSet);
                    }
                }
            }

            narrativePhases.put(archId, an);
            states.put(archId, new ArchetypeState(archId));
        }

        // Load archetype keyword lists for trigger matching
        JSONArray archetypes = root.optJSONArray("archetypes");
        if (archetypes != null) {
            for (int i = 0; i < archetypes.length(); i++) {
                JSONObject arch = archetypes.getJSONObject(i);
                String id = arch.getString("id");
                archetypeContext.put(id, jsonArrayToList(arch.optJSONArray("context")));
                archetypeThreat.put(id, jsonArrayToList(arch.optJSONArray("threat")));
                archetypeDemand.put(id, jsonArrayToList(arch.optJSONArray("demand")));
            }
        }
    }

    /**
     * Process a transcript chunk and advance narrative states.
     *
     * @param text transcript chunk
     * @return result with best phase info
     */
    public NarrativeResult advance(String text) {
        if (text == null || text.trim().isEmpty()) return buildResult();

        String lower = text.toLowerCase(Locale.ROOT);
        Set<String> words = new HashSet<>();
        for (String w : lower.split("\\s+")) {
            if (!w.isEmpty()) words.add(w);
        }

        for (Map.Entry<String, ArchetypeState> entry : states.entrySet()) {
            String archId = entry.getKey();
            ArchetypeState state = entry.getValue();
            ArchetypeNarrative narrative = narrativePhases.get(archId);
            if (narrative == null) continue;

            int idx = state.phaseIndex;
            if (idx >= narrative.phases.size()) continue;

            // Try to advance through multiple phases per chunk
            boolean advanced = false;
            while (idx < narrative.phases.size()) {
                PhaseDef nextPhase = narrative.phases.get(idx);
                String matched = checkTrigger(lower, words, archId, nextPhase.triggers, narrative);
                if (matched != null) {
                    state.phase = nextPhase.id;
                    state.phaseIndex = idx + 1;
                    state.confidence = Math.min(1.0, state.confidence + 0.25);
                    advanced = true;
                    idx = state.phaseIndex;
                } else {
                    break;
                }
            }

            if (!advanced) {
                // Phase skip: only after HOOK reached (phaseIndex >= 1)
                if (state.phaseIndex < 1) continue;

                for (int skipIdx = idx + 1; skipIdx < narrative.phases.size(); skipIdx++) {
                    PhaseDef skipPhase = narrative.phases.get(skipIdx);
                    // Use strict matching for skips (substring only, no stem)
                    String skipMatched = checkTriggerStrict(lower, archId, skipPhase.triggers, narrative);
                    if (skipMatched != null) {
                        int skipped = skipIdx - idx;
                        state.phase = skipPhase.id;
                        state.phaseIndex = skipIdx + 1;
                        state.confidence = Math.min(1.0, state.confidence + 0.25 - (0.05 * skipped));
                        break;
                    }
                }
            }
        }

        return buildResult();
    }

    /** Get current state without advancing. */
    public NarrativeResult getState() {
        return buildResult();
    }

    /** Reset all states. */
    public void reset() {
        for (ArchetypeState state : states.values()) {
            state.phase = PHASE_IDLE;
            state.phaseIndex = 0;
            state.confidence = 0.0;
        }
    }

    private String checkTrigger(String lower, Set<String> words, String archId,
                                String triggerType, ArchetypeNarrative narrative) {
        switch (triggerType) {
            case "context":
                return matchAny(lower, words, archetypeContext.getOrDefault(archId, List.of()));
            case "threat":
                return matchAny(lower, words, archetypeThreat.getOrDefault(archId, List.of()));
            case "demand":
                return matchAny(lower, words, archetypeDemand.getOrDefault(archId, List.of()));
            default:
                String extraKey = triggerType + "_keywords";
                Set<String> extra = narrative.extraKeywords.getOrDefault(extraKey, Set.of());
                return matchAny(lower, words, new ArrayList<>(extra));
        }
    }

    /** Strict trigger check for phase skipping — substring only, no stem matching. */
    private String checkTriggerStrict(String lower, String archId,
                                      String triggerType, ArchetypeNarrative narrative) {
        switch (triggerType) {
            case "context":
                return matchAnyStrict(lower, archetypeContext.getOrDefault(archId, List.of()));
            case "threat":
                return matchAnyStrict(lower, archetypeThreat.getOrDefault(archId, List.of()));
            case "demand":
                return matchAnyStrict(lower, archetypeDemand.getOrDefault(archId, List.of()));
            default:
                String extraKey = triggerType + "_keywords";
                Set<String> extra = narrative.extraKeywords.getOrDefault(extraKey, Set.of());
                return matchAnyStrict(lower, new ArrayList<>(extra));
        }
    }

    private String matchAny(String lower, Set<String> words, List<String> keywords) {
        for (String kw : keywords) {
            String kwLower = kw.toLowerCase(Locale.ROOT);
            if (lower.contains(kwLower)) return kw;
            if (kwLower.length() >= 4) {
                for (String word : words) {
                    if (word.length() >= 4) {
                        if (word.startsWith(kwLower) || kwLower.startsWith(word)) return kw;
                    }
                }
            }
        }
        return null;
    }

    /** Strict substring-only match — no stem/prefix matching. */
    private String matchAnyStrict(String lower, List<String> keywords) {
        for (String kw : keywords) {
            if (lower.contains(kw.toLowerCase(Locale.ROOT))) return kw;
        }
        return null;
    }

    private NarrativeResult buildResult() {
        String bestArch = null;
        String bestPhase = PHASE_IDLE;
        int bestIdx = 0;

        for (Map.Entry<String, ArchetypeState> entry : states.entrySet()) {
            ArchetypeState state = entry.getValue();
            if (state.phaseIndex > bestIdx) {
                bestIdx = state.phaseIndex;
                bestArch = entry.getKey();
                bestPhase = state.phase;
            }
        }

        int phaseScore = PHASE_SCORES.getOrDefault(bestPhase, 0);
        String phaseLabel = "";
        if (bestArch != null) {
            ArchetypeNarrative narrative = narrativePhases.get(bestArch);
            if (narrative != null) {
                for (PhaseDef p : narrative.phases) {
                    if (p.id.equals(bestPhase)) {
                        phaseLabel = p.description;
                        break;
                    }
                }
            }
        }

        return new NarrativeResult(bestArch, bestPhase, phaseScore, phaseLabel);
    }

    private List<String> jsonArrayToList(JSONArray arr) {
        List<String> list = new ArrayList<>();
        if (arr == null) return list;
        for (int i = 0; i < arr.length(); i++) {
            try { list.add(arr.getString(i)); } catch (JSONException ignored) {}
        }
        return list;
    }

    /** Result of narrative analysis. */
    public static class NarrativeResult {
        public final String bestArchetype;
        public final String phase;
        public final int phaseScore;
        public final String phaseLabel;

        NarrativeResult(String bestArchetype, String phase, int phaseScore, String phaseLabel) {
            this.bestArchetype = bestArchetype;
            this.phase = phase;
            this.phaseScore = phaseScore;
            this.phaseLabel = phaseLabel;
        }
    }
}
