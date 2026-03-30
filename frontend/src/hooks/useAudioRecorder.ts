import { useCallback, useRef, useState } from "react";
import type { StreamStatus, TranscriptionEvent } from "../types";
import { createStreamSocket } from "../services/api";

const SAMPLE_RATE = 16000;

export function useAudioRecorder(language: string) {
  const [status, setStatus] = useState<StreamStatus>("idle");
  const [events, setEvents] = useState<TranscriptionEvent[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const processorRef = useRef<ScriptProcessorNode | null>(null);
  const contextRef = useRef<AudioContext | null>(null);

  const start = useCallback(async () => {
    try {
      setStatus("connecting");
      setEvents([]);

      // Get mic access
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          sampleRate: SAMPLE_RATE,
          channelCount: 1,
          echoCancellation: true,
          noiseSuppression: true,
        },
      });
      mediaStreamRef.current = stream;

      // Set up audio processing
      const audioCtx = new AudioContext({ sampleRate: SAMPLE_RATE });
      contextRef.current = audioCtx;
      const source = audioCtx.createMediaStreamSource(stream);

      // ScriptProcessorNode: 4096 samples per buffer, mono
      const processor = audioCtx.createScriptProcessor(4096, 1, 1);
      processorRef.current = processor;

      // Connect WebSocket
      const ws = createStreamSocket(language);
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus("streaming");
      };

      ws.onmessage = (msg) => {
        const event: TranscriptionEvent = JSON.parse(msg.data);
        if (event.type === "transcription" && event.text) {
          setEvents((prev) => [...prev, event]);
        }
      };

      ws.onerror = () => {
        setStatus("error");
      };

      ws.onclose = () => {
        wsRef.current = null;
        setStatus("idle");
      };

      // Send audio chunks to WebSocket
      processor.onaudioprocess = (e) => {
        if (ws.readyState !== WebSocket.OPEN) return;

        const float32 = e.inputBuffer.getChannelData(0);
        // Convert float32 [-1, 1] to int16 PCM
        const int16 = new Int16Array(float32.length);
        for (let i = 0; i < float32.length; i++) {
          const s = Math.max(-1, Math.min(1, float32[i]));
          int16[i] = s < 0 ? s * 0x8000 : s * 0x7fff;
        }
        ws.send(int16.buffer);
      };

      source.connect(processor);
      processor.connect(audioCtx.destination);
    } catch (err) {
      console.error("Failed to start recording:", err);
      setStatus("error");
    }
  }, [language, status]);

  const stop = useCallback(() => {
    // Stop audio processing first (stop sending new audio)
    if (processorRef.current) {
      processorRef.current.disconnect();
      processorRef.current = null;
    }
    if (contextRef.current) {
      contextRef.current.close();
      contextRef.current = null;
    }
    // Stop mic
    if (mediaStreamRef.current) {
      mediaStreamRef.current.getTracks().forEach((t) => t.stop());
      mediaStreamRef.current = null;
    }
    // Send stop signal — backend will drain remaining queued chunks
    // and close the WebSocket when done
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "stop" }));
      // Keep WS open — backend will close it after draining
    } else {
      wsRef.current = null;
      setStatus("idle");
    }
  }, []);

  return { status, events, start, stop };
}
