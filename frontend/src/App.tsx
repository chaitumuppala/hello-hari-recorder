import { useState } from "react";
import { AudioRecorder } from "./components/AudioRecorder";
import TestWorkbench from "./components/TestWorkbench";
import ContributePage from "./components/ContributePage";

export function App() {
  const [tab, setTab] = useState<"recorder" | "workbench" | "contribute">("recorder");

  return (
    <div>
      {/* Tab bar */}
      <div style={{
        display: "flex", gap: "0", borderBottom: "1px solid #334155",
        background: "#0f172a", padding: "0 16px",
      }}>
        {(["recorder", "workbench", "contribute"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: "12px 20px", border: "none", cursor: "pointer",
              background: "transparent", fontSize: "14px", fontWeight: 500,
              color: tab === t ? "#3b82f6" : "#64748b",
              borderBottom: tab === t ? "2px solid #3b82f6" : "2px solid transparent",
            }}
          >
            {t === "recorder" ? "Recorder" : t === "workbench" ? "Test Workbench" : "Contribute"}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "recorder" && <AudioRecorder />}
      {tab === "workbench" && <TestWorkbench />}
      {tab === "contribute" && <ContributePage />}
    </div>
  );
}
