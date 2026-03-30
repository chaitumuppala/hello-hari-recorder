import type { ScamAnalysis, StreamStatus } from "../types";

interface Props {
  status: StreamStatus;
  analysis: ScamAnalysis | null;
  chunkCount: number;
}

export function ShieldIndicator({ status, analysis, chunkCount }: Props) {
  const state = getState(status, analysis);

  return (
    <div style={wrapperStyle}>
      {/* Outer glow ring */}
      <div
        style={{
          ...ringStyle,
          boxShadow: `0 0 40px 8px ${state.glow}, inset 0 0 30px 4px ${state.glow}`,
          borderColor: state.border,
        }}
      >
        {/* Inner circle */}
        <div style={{ ...circleStyle, background: state.bg }}>
          <div style={{ fontSize: "2.8rem", lineHeight: 1 }}>{state.icon}</div>
          <div
            style={{
              fontSize: "1.1rem",
              fontWeight: 700,
              letterSpacing: "0.06em",
              marginTop: 4,
            }}
          >
            {state.label}
          </div>
          {analysis && analysis.risk_score > 0 && (
            <div
              style={{
                fontSize: "2rem",
                fontWeight: 800,
                marginTop: 2,
                lineHeight: 1,
              }}
            >
              {Math.round(analysis.risk_score * 100)}%
            </div>
          )}
        </div>
      </div>

      {/* Sub-text */}
      <div style={subTextStyle}>
        {status === "idle" && chunkCount === 0 && "Ready to analyze"}
        {status === "connecting" && "Connecting to backend..."}
        {status === "streaming" && `Listening — ${chunkCount} chunk${chunkCount !== 1 ? "s" : ""} analyzed`}
        {status === "error" && "Connection error — check backend"}
        {status === "idle" && chunkCount > 0 && `Analysis complete — ${chunkCount} chunk${chunkCount !== 1 ? "s" : ""}`}
      </div>
    </div>
  );
}

function getState(status: StreamStatus, analysis: ScamAnalysis | null) {
  if (status === "error") {
    return {
      icon: "⚡",
      label: "ERROR",
      bg: "radial-gradient(circle, #1e293b 0%, #0f172a 100%)",
      glow: "rgba(100,116,139,0.3)",
      border: "#475569",
    };
  }

  if (status === "connecting") {
    return {
      icon: "⏳",
      label: "CONNECTING",
      bg: "radial-gradient(circle, #1e293b 0%, #0f172a 100%)",
      glow: "rgba(217,119,6,0.3)",
      border: "#d97706",
    };
  }

  if (!analysis || analysis.risk_score === 0) {
    const listening = status === "streaming";
    return {
      icon: listening ? "🎙️" : "🛡️",
      label: listening ? "LISTENING" : "SAFE",
      bg: listening
        ? "radial-gradient(circle, #1a2e1a 0%, #0f172a 100%)"
        : "radial-gradient(circle, #0f2a1a 0%, #0f172a 100%)",
      glow: listening ? "rgba(22,163,106,0.35)" : "rgba(22,163,106,0.2)",
      border: "#16a34a",
    };
  }

  if (analysis.is_scam) {
    return {
      icon: "🚨",
      label: "SCAM DETECTED",
      bg: "radial-gradient(circle, #3b1111 0%, #1a0505 100%)",
      glow: "rgba(220,38,38,0.5)",
      border: "#dc2626",
    };
  }

  return {
    icon: "⚠️",
    label: "SUSPICIOUS",
    bg: "radial-gradient(circle, #3b2a11 0%, #1a1205 100%)",
    glow: "rgba(217,119,6,0.4)",
    border: "#d97706",
  };
}

const wrapperStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  gap: 16,
  padding: "20px 0",
};

const ringStyle: React.CSSProperties = {
  width: 200,
  height: 200,
  borderRadius: "50%",
  border: "3px solid",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  transition: "all 0.5s ease",
};

const circleStyle: React.CSSProperties = {
  width: 180,
  height: 180,
  borderRadius: "50%",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  color: "#e2e8f0",
  transition: "all 0.5s ease",
};

const subTextStyle: React.CSSProperties = {
  fontSize: "0.85rem",
  color: "#94a3b8",
  textAlign: "center",
};
