# ---- Stage 1: Build React frontend ----
FROM node:20-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Python backend + serve built frontend ----
FROM python:3.11-slim AS runtime
WORKDIR /app

# System deps for numpy / onnxruntime / ctranslate2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install torch CPU (separate to keep layer cache)
RUN pip install --no-cache-dir \
    torch torchaudio --index-url https://download.pytorch.org/whl/cpu

# Copy backend source
COPY backend/ ./

# Copy built frontend into backend/static (served by FastAPI)
COPY --from=frontend-build /app/frontend/dist ./static

# Create data dir for SQLite
RUN mkdir -p /app/data

# HuggingFace cache dir — models download on first start
ENV HF_HOME=/app/hf_cache
RUN mkdir -p /app/hf_cache

# Runtime config
ENV SCAM_ASR_ENGINE=hybrid
ENV SCAM_WHISPER_MODEL=distil-small.en
ENV SCAM_DEBUG=false

EXPOSE 7860

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
