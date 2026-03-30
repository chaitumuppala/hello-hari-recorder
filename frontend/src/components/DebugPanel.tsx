import type { TranscriptionEvent } from "../types";

export function DebugPanel({ events }: { events: TranscriptionEvent[] }) {
  const transcriptionEvents = events.filter((e) => e.type === "transcription");

  if (transcriptionEvents.length === 0) {
    return (
      <div style={containerStyle}>
        <div style={headerStyle}>Debug Pipeline</div>
        <p style={{ opacity: 0.5, fontSize: "0.8rem", textAlign: "center" }}>
          No audio chunks processed yet. Start recording to see the pipeline.
        </p>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      <div style={headerStyle}>
        Debug Pipeline ({transcriptionEvents.length} chunks)
      </div>
      <div style={scrollStyle}>
        {transcriptionEvents.map((event, i) => (
          <div key={i} style={chunkStyle}>
            <div style={chunkHeaderStyle}>
              Chunk #{i + 1}
              {event.audio_duration && (
                <span style={metaStyle}>{event.audio_duration.toFixed(1)}s audio</span>
              )}
            </div>

            {/* Stage 1: What was spoken (ASR output) */}
            <div style={stageStyle}>
              <span style={stageLabelStyle}>ASR Output</span>
              <div style={stageContentStyle}>
                <span style={langBadge}>{event.language?.toUpperCase()}</span>
                {event.text || "(silence)"}
              </div>
              {event.debug && (
                <div style={metaRowStyle}>
                  <span>Latency: {event.debug.asr_latency_ms}ms</span>
                  <span>Confidence: {(event.debug.asr_confidence * 100).toFixed(0)}%</span>
                </div>
              )}
            </div>

            {/* Stage 1.5: Sliding window context */}
            {event.debug && event.debug.analysis_source && (
              <div style={stageStyle}>
                <span style={{ ...stageLabelStyle, color: "#a78bfa" }}>
                  Analysis Source: {event.debug.analysis_source.toUpperCase()}
                </span>
                <div style={metaRowStyle}>
                  <span>Chunk score: {Math.round((event.debug.chunk_score ?? 0) * 100)}%</span>
                  <span>Window score: {Math.round((event.debug.window_score ?? 0) * 100)}%</span>
                </div>
                {event.debug.window_text && (
                  <div style={{ ...stageContentStyle, fontSize: "0.72rem", opacity: 0.6, marginTop: 4 }}>
                    Window: {event.debug.window_text.slice(0, 300)}
                  </div>
                )}
              </div>
            )}

            {/* Stage 2: Pattern matches */}
            {event.debug && event.debug.pattern_hits.length > 0 && (
              <div style={stageStyle}>
                <span style={{ ...stageLabelStyle, color: "#f97316" }}>
                  Pattern Hits ({event.debug.pattern_hits.length})
                </span>
                <div style={hitsContainerStyle}>
                  {event.debug.pattern_hits.map((hit, j) => (
                    <div key={j} style={hitStyle}>{hit}</div>
                  ))}
                </div>
                <div style={metaRowStyle}>
                  <span>Detect latency: {event.debug.detect_latency_ms}ms</span>
                </div>
              </div>
            )}

            {/* Stage 3: Verdict */}
            {event.scam_analysis && (
              <div style={stageStyle}>
                <span
                  style={{
                    ...stageLabelStyle,
                    color: event.scam_analysis.is_scam
                      ? "#ef4444"
                      : event.scam_analysis.risk_score > 0
                        ? "#eab308"
                        : "#22c55e",
                  }}
                >
                  Verdict
                </span>
                <div style={stageContentStyle}>
                  <strong>
                    {event.scam_analysis.is_scam
                      ? "SCAM"
                      : event.scam_analysis.risk_score > 0
                        ? "SUSPICIOUS"
                        : "CLEAN"}
                  </strong>
                  {" — "}
                  Score: {Math.round(event.scam_analysis.risk_score * 100)}%
                </div>
                <div style={{ ...stageContentStyle, opacity: 0.7 }}>
                  {event.scam_analysis.explanation}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const containerStyle: React.CSSProperties = {
  background: "#0c1222",
  border: "1px solid #1e293b",
  borderRadius: 10,
  padding: 14,
  fontSize: "0.8rem",
  fontFamily: "'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace",
};

const headerStyle: React.CSSProperties = {
  fontWeight: 700,
  color: "#94a3b8",
  fontSize: "0.85rem",
  marginBottom: 12,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
};

const scrollStyle: React.CSSProperties = {
  maxHeight: "50vh",
  overflowY: "auto",
  display: "flex",
  flexDirection: "column",
  gap: 12,
};

const chunkStyle: React.CSSProperties = {
  background: "#111827",
  borderRadius: 8,
  padding: 10,
  border: "1px solid #1e293b",
};

const chunkHeaderStyle: React.CSSProperties = {
  fontWeight: 600,
  color: "#60a5fa",
  marginBottom: 8,
  display: "flex",
  justifyContent: "space-between",
};

const stageStyle: React.CSSProperties = {
  marginBottom: 8,
  paddingLeft: 10,
  borderLeft: "2px solid #334155",
};

const stageLabelStyle: React.CSSProperties = {
  fontSize: "0.7rem",
  fontWeight: 700,
  color: "#60a5fa",
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  display: "block",
  marginBottom: 2,
};

const stageContentStyle: React.CSSProperties = {
  color: "#cbd5e1",
  lineHeight: 1.5,
  wordBreak: "break-word",
};

const metaRowStyle: React.CSSProperties = {
  display: "flex",
  gap: 16,
  color: "#64748b",
  fontSize: "0.72rem",
  marginTop: 2,
};

const metaStyle: React.CSSProperties = {
  color: "#64748b",
  fontSize: "0.72rem",
};

const langBadge: React.CSSProperties = {
  background: "#334155",
  padding: "1px 6px",
  borderRadius: 4,
  fontSize: "0.65rem",
  fontWeight: 600,
  marginRight: 6,
};

const hitsContainerStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 2,
};

const hitStyle: React.CSSProperties = {
  color: "#fb923c",
  fontSize: "0.75rem",
};
