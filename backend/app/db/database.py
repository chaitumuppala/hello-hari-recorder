import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from app.config import settings
from app.models.schemas import CallRecord, ScamAnalysis


def _ensure_db() -> None:
    db_dir = settings.db_path.parent
    db_dir.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(settings.db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS call_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TEXT NOT NULL,
                transcription TEXT NOT NULL,
                language TEXT NOT NULL,
                is_scam INTEGER NOT NULL,
                risk_score REAL NOT NULL,
                matched_patterns TEXT NOT NULL,
                explanation TEXT NOT NULL,
                audio_duration REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                language TEXT NOT NULL,
                total_chunks INTEGER DEFAULT 0,
                total_audio_seconds REAL DEFAULT 0,
                final_risk_score REAL DEFAULT 0,
                final_is_scam INTEGER DEFAULT 0,
                final_matched_patterns TEXT DEFAULT '[]',
                full_transcript TEXT DEFAULT '',
                user_agent TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_records_session
            ON call_records(session_id)
        """)
        # Migrate: add session_id column to existing call_records tables
        try:
            conn.execute("ALTER TABLE call_records ADD COLUMN session_id TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        conn.commit()


@contextmanager
def _get_conn():
    _ensure_db()
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_record(record: CallRecord, session_id: str | None = None) -> int:
    with _get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO call_records
                (session_id, timestamp, transcription, language, is_scam, risk_score,
                 matched_patterns, explanation, audio_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                record.timestamp.isoformat(),
                record.transcription,
                record.language,
                int(record.scam_analysis.is_scam),
                record.scam_analysis.risk_score,
                json.dumps(record.scam_analysis.matched_patterns),
                record.scam_analysis.explanation,
                record.audio_duration,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def create_session(session_id: str, language: str, user_agent: str = "") -> None:
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO sessions (id, started_at, language, user_agent)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, datetime.now().isoformat(), language, user_agent),
        )
        conn.commit()


def end_session(
    session_id: str,
    *,
    total_chunks: int,
    total_audio_seconds: float,
    final_risk_score: float,
    final_is_scam: bool,
    final_matched_patterns: list[str],
    full_transcript: str,
) -> None:
    with _get_conn() as conn:
        conn.execute(
            """
            UPDATE sessions SET
                ended_at = ?,
                total_chunks = ?,
                total_audio_seconds = ?,
                final_risk_score = ?,
                final_is_scam = ?,
                final_matched_patterns = ?,
                full_transcript = ?
            WHERE id = ?
            """,
            (
                datetime.now().isoformat(),
                total_chunks,
                total_audio_seconds,
                final_risk_score,
                int(final_is_scam),
                json.dumps(final_matched_patterns),
                full_transcript,
                session_id,
            ),
        )
        conn.commit()


def get_recent_records(limit: int = 50) -> list[CallRecord]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM call_records ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    records = []
    for row in rows:
        records.append(
            CallRecord(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                transcription=row["transcription"],
                language=row["language"],
                scam_analysis=ScamAnalysis(
                    is_scam=bool(row["is_scam"]),
                    risk_score=row["risk_score"],
                    matched_patterns=json.loads(row["matched_patterns"]),
                    explanation=row["explanation"],
                ),
                audio_duration=row["audio_duration"],
            )
        )
    return records
