"""Lightweight TF-IDF + Logistic Regression scam classifier.

This module provides a secondary confidence layer on top of the
keyword-based detection engine.  While the keyword engine catches
known phrases and co-occurrence patterns, this classifier learns
the *intent* behind sentences — distinguishing "share your card
number" (scam) from "your card has been dispatched" (legitimate)
even though both contain "card".

Architecture:
  - TF-IDF vectorizer with unigrams + bigrams + trigrams
  - Logistic Regression classifier (fast, interpretable)
  - Trained on ~300 labeled examples (expandable)
  - Serialized to ~50KB model file via joblib
  - <1ms inference per sentence

Usage:
  classifier = ScamClassifier.load("models/scam_classifier.joblib")
  result = classifier.predict("give me your otp")
  # result.is_scam = True, result.confidence = 0.94

Integration:
  Used by analyze_session() to suppress false positives — when the
  keyword engine says "scam" but the classifier says "not scam" with
  high confidence, the alert is suppressed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)


@dataclass
class ClassifierResult:
    """Result from the scam classifier."""
    is_scam: bool
    confidence: float  # 0.0 - 1.0, probability of scam class
    label: str  # "scam" or "legitimate"


class ScamClassifier:
    """TF-IDF + Logistic Regression scam text classifier."""

    MODEL_FILENAME = "scam_classifier.joblib"

    def __init__(self, pipeline: Pipeline) -> None:
        self._pipeline = pipeline

    @classmethod
    def train(
        cls,
        texts: list[str],
        labels: list[int],
        ngram_range: tuple[int, int] = (1, 3),
        max_features: int = 10000,
        C: float = 1.0,
    ) -> "ScamClassifier":
        """Train a new classifier from labeled data.

        Args:
            texts: List of text samples.
            labels: List of labels (1=scam, 0=legitimate).
            ngram_range: TF-IDF n-gram range (default unigrams to trigrams).
            max_features: Maximum vocabulary size.
            C: Logistic regression regularization (lower = more regularized).
        """
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=ngram_range,
                max_features=max_features,
                lowercase=True,
                strip_accents="unicode",
                sublinear_tf=True,  # log(1 + tf) — reduces impact of repeated words
            )),
            ("clf", LogisticRegression(
                C=C,
                class_weight="balanced",  # handles imbalanced classes
                max_iter=1000,
                solver="lbfgs",
            )),
        ])
        pipeline.fit(texts, labels)

        n_scam = sum(labels)
        n_legit = len(labels) - n_scam
        logger.info(
            "Trained scam classifier: %d samples (%d scam, %d legit), "
            "%d features",
            len(texts), n_scam, n_legit,
            pipeline.named_steps["tfidf"].vocabulary_.__len__(),
        )

        return cls(pipeline)

    def predict(self, text: str) -> ClassifierResult:
        """Classify a single text."""
        proba = self._pipeline.predict_proba([text])[0]
        # Classes are [0=legit, 1=scam]
        scam_prob = float(proba[1])
        return ClassifierResult(
            is_scam=scam_prob >= 0.5,
            confidence=scam_prob,
            label="scam" if scam_prob >= 0.5 else "legitimate",
        )

    def predict_batch(self, texts: list[str]) -> list[ClassifierResult]:
        """Classify multiple texts at once."""
        probas = self._pipeline.predict_proba(texts)
        results = []
        for proba in probas:
            scam_prob = float(proba[1])
            results.append(ClassifierResult(
                is_scam=scam_prob >= 0.5,
                confidence=scam_prob,
                label="scam" if scam_prob >= 0.5 else "legitimate",
            ))
        return results

    def save(self, path: str | Path) -> None:
        """Save trained model to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._pipeline, path)
        # Also save model size for reference
        size_kb = path.stat().st_size / 1024
        logger.info("Saved classifier to %s (%.1f KB)", path, size_kb)

    @classmethod
    def load(cls, path: str | Path) -> "ScamClassifier":
        """Load a trained model from disk."""
        pipeline = joblib.load(path)
        return cls(pipeline)

    def get_top_features(self, n: int = 20) -> dict[str, list[str]]:
        """Get the most important features for each class."""
        tfidf = self._pipeline.named_steps["tfidf"]
        clf = self._pipeline.named_steps["clf"]
        feature_names = tfidf.get_feature_names_out()
        coefs = clf.coef_[0]

        # Top scam features (highest positive coefficients)
        scam_idx = coefs.argsort()[-n:][::-1]
        scam_features = [feature_names[i] for i in scam_idx]

        # Top legit features (most negative coefficients)
        legit_idx = coefs.argsort()[:n]
        legit_features = [feature_names[i] for i in legit_idx]

        return {"scam": scam_features, "legitimate": legit_features}
