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


def save_record(record: CallRecord) -> int:
    with _get_conn() as conn:
        cursor = conn.execute(
            """
            INSERT INTO call_records
                (timestamp, transcription, language, is_scam, risk_score,
                 matched_patterns, explanation, audio_duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
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
