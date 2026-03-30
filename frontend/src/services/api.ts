const API_BASE = "/api";

export async function checkHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function transcribeFile(
  file: Blob,
  language: string = "hi"
): Promise<unknown> {
  const form = new FormData();
  form.append("file", file, "audio.wav");
  const res = await fetch(
    `${API_BASE}/transcribe?language=${encodeURIComponent(language)}`,
    { method: "POST", body: form }
  );
  if (!res.ok) throw new Error(`Transcription failed: ${res.status}`);
  return res.json();
}

export async function analyzeText(text: string) {
  const res = await fetch(
    `${API_BASE}/analyze-text?text=${encodeURIComponent(text)}`,
    { method: "POST" }
  );
  return res.json();
}

export async function getHistory(limit = 50) {
  const res = await fetch(`${API_BASE}/history?limit=${limit}`);
  return res.json();
}

export function createStreamSocket(language: string = "hi") {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${window.location.host}${API_BASE}/ws/stream`);

  ws.addEventListener("open", () => {
    ws.send(JSON.stringify({ language }));
  });

  return ws;
}
