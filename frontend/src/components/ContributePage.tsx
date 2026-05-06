import { useState, useEffect } from 'react';

const CATEGORIES = [
  'DIGITAL_ARREST', 'TRAI_SCAM', 'COURIER_SCAM', 'INVESTMENT_FRAUD',
  'BANK_OTP', 'FAMILY_EMERGENCY', 'HINDI_SCAM', 'TELUGU_SCAM', 'HINGLISH_SCAM',
];

const LANGUAGES = ['en', 'hi', 'te', 'ta', 'kn', 'ml', 'bn', 'mr', 'gu', 'pa', 'or'];

interface PendingPattern {
  id: number;
  phrase: string;
  category: string;
  language: string;
  severity: number;
  source: string;
  status: string;
  submitted_at: string;
}

export default function ContributePage() {
  const [phrase, setPhrase] = useState('');
  const [category, setCategory] = useState('DIGITAL_ARREST');
  const [language, setLanguage] = useState('en');
  const [severity, setSeverity] = useState(80);
  const [source, setSource] = useState('');
  const [pending, setPending] = useState<PendingPattern[]>([]);
  const [msg, setMsg] = useState('');

  const fetchPending = async () => {
    const res = await fetch('/patterns/pending');
    const data = await res.json();
    setPending(data);
  };

  useEffect(() => { fetchPending(); }, []);

  const submit = async () => {
    if (!phrase.trim()) return;
    await fetch('/patterns/contribute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phrase, category, language, severity, source: source || 'authority' }),
    });
    setMsg(`Pattern "${phrase}" submitted for review`);
    setPhrase('');
    fetchPending();
    setTimeout(() => setMsg(''), 3000);
  };

  const approve = async (id: number) => {
    await fetch(`/patterns/${id}/approve`, { method: 'POST' });
    fetchPending();
  };

  const reject = async (id: number) => {
    await fetch(`/patterns/${id}/reject`, { method: 'POST' });
    fetchPending();
  };

  return (
    <div style={{ padding: '24px', maxWidth: '900px', margin: '0 auto', fontFamily: 'system-ui' }}>
      <h2 style={{ color: '#E2E8F0', marginBottom: '8px' }}>Pattern Contribution</h2>
      <p style={{ color: '#94a3b8', fontSize: '14px', marginBottom: '24px' }}>
        Add new scam phrases from FIR data or case reports. Approved patterns go live instantly.
      </p>

      {/* Add form */}
      <div style={{ background: '#1e293b', borderRadius: '12px', padding: '20px', marginBottom: '24px' }}>
        <div style={{ marginBottom: '12px' }}>
          <label style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>
            Scam Phrase
          </label>
          <input
            value={phrase}
            onChange={e => setPhrase(e.target.value)}
            placeholder="e.g., aapke naam pe FIR darj ho chuki hai"
            style={{
              width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155',
              background: '#0f172a', color: '#E2E8F0', fontSize: '14px',
            }}
          />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '12px' }}>
          <div>
            <label style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>Category</label>
            <select value={category} onChange={e => setCategory(e.target.value)}
              style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #334155', background: '#0f172a', color: '#E2E8F0' }}>
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>Language</label>
            <select value={language} onChange={e => setLanguage(e.target.value)}
              style={{ width: '100%', padding: '8px', borderRadius: '6px', border: '1px solid #334155', background: '#0f172a', color: '#E2E8F0' }}>
              {LANGUAGES.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div>
            <label style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>
              Severity: {severity}
            </label>
            <input type="range" min={20} max={100} value={severity} onChange={e => setSeverity(+e.target.value)}
              style={{ width: '100%' }} />
          </div>
        </div>
        <div style={{ marginBottom: '12px' }}>
          <label style={{ color: '#94a3b8', fontSize: '12px', display: 'block', marginBottom: '4px' }}>
            Source (e.g., "AP Cyber Crime Cell", "I4C Case #1234")
          </label>
          <input
            value={source}
            onChange={e => setSource(e.target.value)}
            placeholder="authority name or case reference"
            style={{
              width: '100%', padding: '10px', borderRadius: '6px', border: '1px solid #334155',
              background: '#0f172a', color: '#E2E8F0', fontSize: '14px',
            }}
          />
        </div>
        <button onClick={submit} style={{
          padding: '10px 24px', borderRadius: '8px', border: 'none',
          background: '#22c55e', color: 'white', fontSize: '14px', fontWeight: 600, cursor: 'pointer',
        }}>
          Submit Pattern
        </button>
        {msg && <span style={{ color: '#22c55e', marginLeft: '12px', fontSize: '13px' }}>{msg}</span>}
      </div>

      {/* Pending review list */}
      <h3 style={{ color: '#E2E8F0', marginBottom: '12px' }}>
        Pending Review ({pending.length})
      </h3>
      {pending.length === 0 && (
        <p style={{ color: '#64748b', fontSize: '14px' }}>No pending patterns</p>
      )}
      {pending.map(p => (
        <div key={p.id} style={{
          background: '#1e293b', borderRadius: '8px', padding: '12px 16px',
          marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <div>
            <div style={{ color: '#E2E8F0', fontSize: '14px' }}>"{p.phrase}"</div>
            <div style={{ color: '#64748b', fontSize: '11px', marginTop: '4px' }}>
              {p.category} | {p.language} | severity: {p.severity} | source: {p.source} | {p.submitted_at}
            </div>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button onClick={() => approve(p.id)} style={{
              padding: '6px 14px', borderRadius: '6px', border: 'none',
              background: '#22c55e', color: 'white', fontSize: '12px', cursor: 'pointer',
            }}>Approve</button>
            <button onClick={() => reject(p.id)} style={{
              padding: '6px 14px', borderRadius: '6px', border: 'none',
              background: '#ef4444', color: 'white', fontSize: '12px', cursor: 'pointer',
            }}>Reject</button>
          </div>
        </div>
      ))}
    </div>
  );
}
