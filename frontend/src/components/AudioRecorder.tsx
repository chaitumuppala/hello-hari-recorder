import { useState } from "react";
import { LANGUAGES } from "../types";
import { useAudioRecorder } from "../hooks/useAudioRecorder";
import { ShieldIndicator } from "./ShieldIndicator";
import { DebugPanel } from "./DebugPanel";

const isDebugMode = new URLSearchParams(window.location.search).has("debug");

export function AudioRecorder() {
  const [language, setLanguage] = useState("te");
  const [showDebug, setShowDebug] = useState(false);
  const { status, events, start, stop } = useAudioRecorder(language);

  // Derive latest analysis from most recent event with scam_analysis
  const latestEvent = [...events].reverse().find((e) => e.scam_analysis);
  const latestAnalysis = latestEvent?.scam_analysis ?? null;
  const chunkCount = events.filter((e) => e.type === "transcription").length;

  return (
    <div style={containerStyle}>
      {/* Header */}
      <header style={headerStyle}>
        <h1 style={{ margin: 0, fontSize: "1.4rem", letterSpacing: "-0.02em" }}>
          Scam Call Detector
        </h1>
        <p style={{ margin: "4px 0 0", opacity: 0.5, fontSize: "0.8rem" }}>
          Put the call on speaker and press record
        </p>
      </header>

      {/* Shield — the main visual */}
      <ShieldIndicator
        status={status}
        analysis={latestAnalysis}
        chunkCount={chunkCount}
      />

      {/* Controls */}
      <div style={controlsStyle}>
        <select
          value={language}
          onChange={(e) => setLanguage(e.target.value)}
          disabled={status === "streaming"}
          style={selectStyle}
        >
          {LANGUAGES.map((lang) => (
            <option key={lang.code} value={lang.code}>
              {lang.native} ({lang.name})
            </option>
          ))}
        </select>

        <button
          onClick={status === "streaming" ? stop : start}
          disabled={status === "connecting"}
          style={{
            ...buttonStyle,
            ...(status === "streaming" ? stopButtonStyle : startButtonStyle),
          }}
        >
          {status === "connecting"
            ? "Connecting..."
            : status === "streaming"
              ? "Stop"
              : "Start Recording"}
        </button>
      </div>

      {/* Matched categories as pills */}
      {latestAnalysis && latestAnalysis.matched_patterns.length > 0 && (
        <div style={pillContainerStyle}>
          {latestAnalysis.matched_patterns.map((p, i) => (
            <span
              key={i}
              style={{
                ...pillStyle,
                background: latestAnalysis.is_scam
                  ? "rgba(220,38,38,0.25)"
                  : "rgba(217,119,6,0.25)",
                borderColor: latestAnalysis.is_scam ? "#fca5a5" : "#fcd34d",
              }}
            >
              {p}
            </span>
          ))}
        </div>
      )}

      {/* Debug toggle — only visible with ?debug URL param */}
      {isDebugMode && (
        <>
          <button
            onClick={() => setShowDebug(!showDebug)}
            style={debugToggleStyle}
          >
            {showDebug ? "Hide" : "Show"} Debug Panel
          </button>
          {showDebug && <DebugPanel events={events} />}
        </>
      )}
    </div>
  );
}

const containerStyle: React.CSSProperties = {
  maxWidth: 480,
  margin: "0 auto",
  padding: "16px 20px",
  display: "flex",
  flexDirection: "column",
  gap: 16,
  minHeight: "100vh",
  color: "#e2e8f0",
};

const headerStyle: React.CSSProperties = {
  textAlign: "center",
  padding: "8px 0",
};

const controlsStyle: React.CSSProperties = {
  display: "flex",
  gap: 10,
  alignItems: "center",
};

const selectStyle: React.CSSProperties = {
  flex: 1,
  padding: "10px 12px",
  borderRadius: 10,
  border: "1px solid #334155",
  background: "#1e293b",
  color: "#e2e8f0",
  fontSize: "0.95rem",
};

const buttonStyle: React.CSSProperties = {
  padding: "10px 20px",
  borderRadius: 10,
  border: "none",
  fontSize: "0.95rem",
  fontWeight: 600,
  cursor: "pointer",
  color: "#fff",
  minWidth: 160,
};

const startButtonStyle: React.CSSProperties = {
  background: "linear-gradient(135deg, #16a34a, #15803d)",
};

const stopButtonStyle: React.CSSProperties = {
  background: "linear-gradient(135deg, #dc2626, #991b1b)",
};

const pillContainerStyle: React.CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: 8,
  justifyContent: "center",
};

const pillStyle: React.CSSProperties = {
  padding: "4px 12px",
  borderRadius: 20,
  fontSize: "0.78rem",
  fontWeight: 500,
  border: "1px solid",
};

const debugToggleStyle: React.CSSProperties = {
  background: "none",
  border: "1px solid #334155",
  color: "#64748b",
  padding: "6px 14px",
  borderRadius: 8,
  cursor: "pointer",
  fontSize: "0.8rem",
  alignSelf: "center",
};
