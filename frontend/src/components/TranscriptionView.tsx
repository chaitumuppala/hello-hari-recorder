import type { TranscriptionEvent } from "../types";
import { ScamAlert } from "./ScamAlert";

export function TranscriptionView({
  events,
}: {
  events: TranscriptionEvent[];
}) {
  if (events.length === 0) {
    return (
      <div style={emptyStyle}>
        <p style={{ fontSize: "1.2rem", opacity: 0.6 }}>
          🎙️ Start recording to see live transcription and scam analysis
        </p>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      {events.map((event, i) => (
        <div key={i}>
          {event.scam_analysis && (
            <ScamAlert analysis={event.scam_analysis} />
          )}
          <div style={transcriptStyle}>
            <span style={langBadge}>{event.language?.toUpperCase()}</span>
            <span>{event.text}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

const containerStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 8,
  maxHeight: "60vh",
  overflowY: "auto",
  padding: "8px 0",
};

const emptyStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  minHeight: 200,
  textAlign: "center",
};

const transcriptStyle: React.CSSProperties = {
  padding: "10px 16px",
  background: "#1e293b",
  borderRadius: 8,
  display: "flex",
  alignItems: "baseline",
  gap: 10,
  lineHeight: 1.5,
};

const langBadge: React.CSSProperties = {
  background: "#334155",
  padding: "2px 8px",
  borderRadius: 4,
  fontSize: "0.7rem",
  fontWeight: 600,
  flexShrink: 0,
};
