"""
evaluate_model.py
=================
Phase 8 — Evaluate the trained anomaly detection model.

Since Isolation Forest is unsupervised, meaningful precision/recall
metrics require a LABELLED evaluation dataset.

This module:
  1. Loads the trained model.
  2. Scores events and returns anomaly predictions.
  3. Compares ML predictions against rule-based findings.
  4. Generates a simple comparison report.
  5. Reports precision/recall/F1 only when a labelled dataset is provided.

Full implementation: Phase 8.
Stub created in: Phase 1 (project scaffold).
"""

import logging
import json
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import numpy as np
    import joblib
    from sklearn.metrics import classification_report, confusion_matrix
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


def load_model(model_path: str | None = None) -> tuple:
    """Load a saved Isolation Forest model and scaler."""
    if not ML_AVAILABLE:
        raise ImportError("scikit-learn and joblib are required.")

    if model_path is None:
        root = Path(__file__).resolve().parent.parent
        model_path = root / "ml" / "models" / "isolation_forest.pkl"

    if not Path(model_path).exists():
        raise FileNotFoundError(
            f"No model found at {model_path}. "
            f"Run ml/train_model.py first."
        )

    artifact = joblib.load(model_path)
    return artifact["model"], artifact["scaler"]


def score_events(events: list[dict], model_path: str | None = None) -> list[dict]:
    """
    Score normalised events and return those flagged as anomalies.

    Isolation Forest returns:
      +1  → inlier  (normal)
      -1  → outlier (anomaly)

    Args:
        events:     Normalised event dicts.
        model_path: Path to saved model. Defaults to ml/models/isolation_forest.pkl.

    Returns:
        List of event dicts with added 'mlAnomalyScore' and 'mlIsAnomaly' fields.
    """
    if not ML_AVAILABLE:
        raise ImportError("scikit-learn and numpy are required.")

    from ml.train_model import extract_features

    model, scaler = load_model(model_path)
    X = extract_features(events)
    X_scaled = scaler.transform(X)

    predictions = model.predict(X_scaled)           # +1 or -1
    scores = model.score_samples(X_scaled)          # lower = more anomalous

    scored = []
    for event, pred, score in zip(events, predictions, scores):
        scored_event = dict(event)
        scored_event["mlAnomalyScore"] = float(score)
        scored_event["mlIsAnomaly"]    = bool(pred == -1)
        scored.append(scored_event)

    anomalies = sum(1 for e in scored if e["mlIsAnomaly"])
    log.info("ML scoring: %d / %d events flagged as anomalies.", anomalies, len(scored))
    return scored


def compare_with_rules(
    scored_events: list[dict],
    rule_findings: list[dict],
) -> dict:
    """
    Compare ML anomaly flags with rule-based findings.

    Returns a comparison summary showing overlap and discrepancies.
    This is useful for evaluating whether ML adds value over rules alone.
    """
    rule_event_ids = {f.get("eventId") for f in rule_findings if f.get("eventId")}
    ml_anomaly_ids = {e.get("eventId") for e in scored_events if e.get("mlIsAnomaly")}

    both     = rule_event_ids & ml_anomaly_ids
    rules_only = rule_event_ids - ml_anomaly_ids
    ml_only  = ml_anomaly_ids - rule_event_ids

    summary = {
        "detectedByBoth":      len(both),
        "detectedByRulesOnly": len(rules_only),
        "detectedByMLOnly":    len(ml_only),
        "totalRuleFindings":   len(rule_findings),
        "totalMLAnomalies":    len(ml_anomaly_ids),
        "note": (
            "Events with no eventId (e.g., brute-force findings) "
            "are not included in the overlap count."
        ),
    }
    log.info("Comparison: both=%d, rules-only=%d, ml-only=%d",
             len(both), len(rules_only), len(ml_only))
    return summary


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.collect_events   import load_sample_events
    from src.parse_events     import parse_events
    from src.normalize_events import normalize_events
    from src.detect_anomalies import detect_anomalies

    logging.basicConfig(level=logging.INFO)

    if not ML_AVAILABLE:
        print("scikit-learn not installed. Run: pip install scikit-learn numpy")
        sys.exit(1)

    raw      = load_sample_events()
    parsed   = parse_events(raw)
    norm     = normalize_events(parsed)
    findings = detect_anomalies(norm)

    try:
        scored  = score_events(norm)
        summary = compare_with_rules(scored, findings)
        print(json.dumps(summary, indent=2))
    except FileNotFoundError as e:
        print(f"Model not found: {e}")
        print("Run ml/train_model.py first.")
