import { useState } from 'react';

interface ScamAnalysis {
  is_scam: boolean;
  risk_score: number;
  matched_patterns: string[];
  explanation: string;
  debug_details: string[];
  narrative_phase: string;
  narrative_archetype: string | null;
  narrative_phase_label: string;
  narrative_phase_score: number;
}

const PHASE_COLORS: Record<string, string> = {
  IDLE: '#64748b',
  HOOK: '#f59e0b',
  ESCALATE: '#f97316',
  ISOLATE: '#ef4444',
  TRAP: '#dc2626',
};

const PHASE_LABELS: Record<string, string> = {
  IDLE: 'No manipulation detected',
  HOOK: 'Establishing fake identity',
  ESCALATE: 'Introducing threats/fear',
  ISOLATE: 'Demanding secrecy/isolation',
  TRAP: 'Demanding money/credentials',
};

export default function TestWorkbench() {
  const [text, setText] = useState('');
  const [chunks, setChunks] = useState('');
  const [mode, setMode] = useState<'single' | 'session'>('single');
  const [result, setResult] = useState<ScamAnalysis | null>(null);
  const [loading, setLoading] = useState(false);

  const analyze = async () => {
    setLoading(true);
    try {
      const body = mode === 'session'
        ? { text: '', chunks: chunks.split('\n').filter(c => c.trim()) }
        : { text };

      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error('Analysis failed:', err);
    }
    setLoading(false);
  };

  const phaseColor = result ? PHASE_COLORS[result.narrative_phase] || '#64748b' : '#64748b';

  return (
    <div style={{ padding: '24px', maxWidth: '900px', margin: '0 auto', fontFamily: 'system-ui' }}>
      <h2 style={{ color: '#E2E8F0', marginBottom: '8px' }}>OSIF Test Workbench</h2>
      <p style={{ color: '#94a3b8', fontSize: '14px', marginBottom: '24px' }}>
        Paste a scam transcript to see detection results + narrative phase progression
      </p>

      {/* Mode toggle */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
        <button
          onClick={() => setMode('single')}
          style={{
            padding: '8px 16px', borderRadius: '6px', border: 'none', cursor: 'pointer',
            background: mode === 'single' ? '#3b82f6' : '#1e293b', color: '#E2E8F0',
          }}
        >
          Single Text
        </button>
        <button
          onClick={() => setMode('session')}
          style={{
            padding: '8px 16px', borderRadius: '6px', border: 'none', cursor: 'pointer',
            background: mode === 'session' ? '#3b82f6' : '#1e293b', color: '#E2E8F0',
          }}
        >
          Session (Chunks)
        </button>
      </div>

      {/* Input */}
      {mode === 'single' ? (
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Paste scam transcript here..."
          rows={6}
          style={{
            width: '100%', padding: '12px', borderRadius: '8px', border: '1px solid #334155',
            background: '#1e293b', color: '#E2E8F0', fontSize: '14px', resize: 'vertical',
          }}
        />
      ) : (
        <textarea
          value={chunks}
          onChange={e => setChunks(e.target.value)}
          placeholder={"Paste chunks (one per line):\nthis is inspector sharma from cbi\ndrug trafficking case registered against you\ndon't tell anyone about this call\ntransfer 50000 as security deposit"}
          rows={8}
          style={{
            width: '100%', padding: '12px', borderRadius: '8px', border: '1px solid #334155',
            background: '#1e293b', color: '#E2E8F0', fontSize: '14px', resize: 'vertical',
          }}
        />
      )}

      <button
        onClick={analyze}
        disabled={loading}
        style={{
          marginTop: '12px', padding: '10px 24px', borderRadius: '8px', border: 'none',
          background: '#3b82f6', color: 'white', fontSize: '14px', fontWeight: 600,
          cursor: loading ? 'wait' : 'pointer',
        }}
      >
        {loading ? 'Analyzing...' : 'Analyze'}
      </button>

      {/* Results */}
      {result && (
        <div style={{ marginTop: '24px' }}>
          {/* Risk Score */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '16px', padding: '16px',
            background: result.is_scam ? '#450a0a' : '#1e293b', borderRadius: '12px',
            border: `2px solid ${result.is_scam ? '#dc2626' : '#334155'}`,
          }}>
            <div style={{
              fontSize: '36px', fontWeight: 700,
              color: result.is_scam ? '#ef4444' : '#22c55e',
            }}>
              {Math.round(result.risk_score * 100)}%
            </div>
            <div>
              <div style={{ color: '#E2E8F0', fontWeight: 600, fontSize: '16px' }}>
                {result.is_scam ? 'SCAM DETECTED' : 'Low Risk'}
              </div>
              <div style={{ color: '#94a3b8', fontSize: '13px', marginTop: '4px' }}>
                {result.explanation}
              </div>
            </div>
          </div>

          {/* Narrative Phase */}
          <div style={{
            marginTop: '16px', padding: '16px', background: '#1e293b',
            borderRadius: '12px', border: `2px solid ${phaseColor}`,
          }}>
            <div style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>
              Narrative Phase
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '8px' }}>
              {/* Phase progression dots */}
              {['HOOK', 'ESCALATE', 'ISOLATE', 'TRAP'].map((phase, i) => {
                const active = ['HOOK', 'ESCALATE', 'ISOLATE', 'TRAP'].indexOf(result.narrative_phase) >= i;
                return (
                  <div key={phase} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <div style={{
                      width: '12px', height: '12px', borderRadius: '50%',
                      background: active ? PHASE_COLORS[phase] : '#334155',
                      boxShadow: active ? `0 0 8px ${PHASE_COLORS[phase]}` : 'none',
                    }} />
                    <span style={{
                      fontSize: '11px', color: active ? '#E2E8F0' : '#64748b',
                      fontWeight: active ? 600 : 400,
                    }}>
                      {phase}
                    </span>
                    {i < 3 && <span style={{ color: '#334155', margin: '0 4px' }}>→</span>}
                  </div>
                );
              })}
            </div>
            <div style={{ color: phaseColor, fontSize: '14px', fontWeight: 600, marginTop: '8px' }}>
              {result.narrative_phase}: {result.narrative_phase_label || PHASE_LABELS[result.narrative_phase]}
            </div>
            {result.narrative_archetype && (
              <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px' }}>
                Archetype: {result.narrative_archetype} | Phase score: {result.narrative_phase_score}
              </div>
            )}
          </div>

          {/* Matched Patterns */}
          {result.matched_patterns.length > 0 && (
            <div style={{ marginTop: '16px', padding: '16px', background: '#1e293b', borderRadius: '12px' }}>
              <div style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
                Matched Categories ({result.matched_patterns.length})
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {result.matched_patterns.map((p, i) => (
                  <span key={i} style={{
                    padding: '4px 10px', borderRadius: '12px', fontSize: '12px',
                    background: '#334155', color: '#E2E8F0',
                  }}>
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Debug Details */}
          {result.debug_details && result.debug_details.length > 0 && (
            <details style={{ marginTop: '16px' }}>
              <summary style={{ color: '#64748b', fontSize: '12px', cursor: 'pointer' }}>
                Debug: {result.debug_details.length} pattern hits
              </summary>
              <div style={{
                marginTop: '8px', padding: '12px', background: '#0f172a', borderRadius: '8px',
                fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace', maxHeight: '200px',
                overflow: 'auto',
              }}>
                {result.debug_details.map((d, i) => <div key={i}>{d}</div>)}
              </div>
            </details>
          )}

          {/* OSIF badge */}
          <div style={{ marginTop: '16px', color: '#475569', fontSize: '11px', textAlign: 'center' }}>
            OSIF v{2} | 574 patterns | 13 archetypes | 13 narrative models
          </div>
        </div>
      )}
    </div>
  );
}
