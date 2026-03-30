export interface ScamAnalysis {
  is_scam: boolean;
  risk_score: number;
  matched_patterns: string[];
  explanation: string;
  debug_details: string[];
}

export interface DebugInfo {
  asr_latency_ms: number;
  detect_latency_ms: number;
  asr_confidence: number;
  pattern_hits: string[];
  analysis_source?: string;
  window_text?: string;
  window_score?: number;
  chunk_score?: number;
}

export interface TranscriptionEvent {
  type: "transcription" | "silence";
  text: string;
  language?: string;
  scam_analysis?: ScamAnalysis;
  audio_duration?: number;
  debug?: DebugInfo;
}

export interface CallRecord {
  id: number;
  timestamp: string;
  transcription: string;
  language: string;
  scam_analysis: ScamAnalysis;
  audio_duration: number;
}

export type StreamStatus =
  | "idle"
  | "connecting"
  | "streaming"
  | "error";

export const LANGUAGES = [
  { code: "te", name: "Telugu", native: "తెలుగు" },
  { code: "hi", name: "Hindi", native: "हिन्दी" },
  { code: "en", name: "English", native: "English" },
  { code: "ta", name: "Tamil", native: "தமிழ்" },
  { code: "bn", name: "Bengali", native: "বাংলা" },
  { code: "mr", name: "Marathi", native: "मराठी" },
  { code: "gu", name: "Gujarati", native: "ગુજરાતી" },
  { code: "kn", name: "Kannada", native: "ಕನ್ನಡ" },
  { code: "ml", name: "Malayalam", native: "മലയാളം" },
  { code: "pa", name: "Punjabi", native: "ਪੰਜਾਬੀ" },
  { code: "or", name: "Odia", native: "ଓଡ଼ିଆ" },
] as const;
