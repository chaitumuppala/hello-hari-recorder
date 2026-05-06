"""Train the scam classifier and save the model.

Run: python scripts/train_classifier.py

Outputs:
  - backend/app/detection/models/scam_classifier.joblib
  - Prints cross-validation accuracy and top features
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from sklearn.model_selection import cross_val_score, StratifiedKFold
import numpy as np

from app.detection.classifier import ScamClassifier
from app.detection.training_data import TRAINING_DATA


def main():
    texts = [t for t, _ in TRAINING_DATA]
    labels = [l for _, l in TRAINING_DATA]

    n_scam = sum(labels)
    n_legit = len(labels) - n_scam
    print(f"Training data: {len(texts)} samples ({n_scam} scam, {n_legit} legit)")
    print()

    # Train the classifier
    classifier = ScamClassifier.train(texts, labels)

    # Cross-validation (5-fold stratified)
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=10000,
            lowercase=True,
            strip_accents="unicode",
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=1000,
            solver="lbfgs",
        )),
    ])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(pipeline, texts, labels, cv=cv, scoring="accuracy")
    print(f"Cross-validation accuracy: {scores.mean():.3f} (+/- {scores.std():.3f})")
    print(f"  Per-fold: {', '.join(f'{s:.3f}' for s in scores)}")
    print()

    # Precision/Recall via cross-val
    from sklearn.model_selection import cross_val_predict
    from sklearn.metrics import classification_report

    pipeline2 = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 3), max_features=10000,
            lowercase=True, strip_accents="unicode", sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            C=1.0, class_weight="balanced", max_iter=1000, solver="lbfgs",
        )),
    ])
    y_pred = cross_val_predict(pipeline2, texts, labels, cv=cv)
    print("Classification Report (cross-validated):")
    print(classification_report(labels, y_pred, target_names=["legitimate", "scam"]))

    # Top features
    features = classifier.get_top_features(15)
    print("Top SCAM features:")
    for f in features["scam"]:
        print(f"  + {f}")
    print()
    print("Top LEGITIMATE features:")
    for f in features["legitimate"]:
        print(f"  - {f}")
    print()

    # Test on the specific false-positive cases from our eval
    print("=== False Positive Test Cases ===")
    test_cases = [
        ("your credit card application has been approved", False),
        ("give me your credit card number", True),
        ("complete the verification report have a good day", False),
        ("complete your kyc or account will be closed", True),
        ("policy renewal is due on 15th of this month", False),
        ("policy will lapse pay premium immediately", True),
        ("I need to transfer money for dinner booking", False),
        ("transfer money now or you will be arrested", True),
        ("constable calling for passport verification", False),
        ("you will be arrested within 24 hours", True),
        ("your new card will be sent to your address", False),
        ("share your card details for verification", True),
        ("scheduled power cut tomorrow 10 am to 2 pm", False),
        ("electricity will be disconnected pay now", True),
        ("we will send confirmation email with directions", False),
        ("send money immediately to avoid arrest", True),
    ]

    correct = 0
    for text, expected_scam in test_cases:
        result = classifier.predict(text)
        status = "OK" if result.is_scam == expected_scam else "WRONG"
        if status == "WRONG":
            print(f"  {status} [{result.confidence:.2f}] \"{text[:60]}\" => {result.label} (expected {'scam' if expected_scam else 'legit'})")
        correct += 1 if result.is_scam == expected_scam else 0

    print(f"  False positive test: {correct}/{len(test_cases)} correct ({correct/len(test_cases)*100:.0f}%)")
    print()

    # Save the model
    model_path = os.path.join(
        os.path.dirname(__file__), '..', 'backend', 'app', 'detection',
        'models', 'scam_classifier.joblib'
    )
    classifier.save(model_path)
    size_kb = os.path.getsize(model_path) / 1024
    print(f"Model saved to {model_path} ({size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
