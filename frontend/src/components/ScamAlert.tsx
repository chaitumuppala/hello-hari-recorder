import type { ScamAnalysis } from "../types";

export function ScamAlert({ analysis }: { analysis: ScamAnalysis }) {
  if (!analysis.is_scam && analysis.risk_score < 0.3) return null;

  const icon = analysis.is_scam ? "🚨" : "⚠️";

  return (
    <div
      style={{
        ...alertStyle,
        ...(analysis.is_scam ? dangerStyle : warningStyle),
      }}
    >
      <div style={{ fontSize: "2rem" }}>{icon}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 700, fontSize: "1.1rem" }}>
          {analysis.is_scam ? "SCAM DETECTED" : "Suspicious Activity"}
        </div>
        <div style={{ marginTop: 4, opacity: 0.9 }}>
          {analysis.explanation}
        </div>
        {analysis.matched_patterns.length > 0 && (
          <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
            {analysis.matched_patterns.map((p, i) => (
              <span key={i} style={tagStyle}>
                {p}
              </span>
            ))}
          </div>
        )}
      </div>
      <div style={scoreStyle}>
        {Math.round(analysis.risk_score * 100)}%
      </div>
    </div>
  );
}

const alertStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "flex-start",
  gap: 12,
  padding: "16px 20px",
  borderRadius: 12,
  color: "#fff",
  marginBottom: 12,
};

const dangerStyle: React.CSSProperties = {
  background: "linear-gradient(135deg, #dc2626, #991b1b)",
  border: "2px solid #fca5a5",
};

const warningStyle: React.CSSProperties = {
  background: "linear-gradient(135deg, #d97706, #92400e)",
  border: "2px solid #fcd34d",
};

const tagStyle: React.CSSProperties = {
  background: "rgba(255,255,255,0.2)",
  padding: "2px 8px",
  borderRadius: 4,
  fontSize: "0.8rem",
};

const scoreStyle: React.CSSProperties = {
  fontSize: "1.5rem",
  fontWeight: 800,
  minWidth: 60,
  textAlign: "center",
};
