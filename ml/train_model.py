"""
train_model.py
==============
Phase 8 — Train an Isolation Forest anomaly detection model.

This module is intentionally kept separate from the rule-based pipeline
so that the project works end-to-end even if scikit-learn is not installed.

IMPORTANT CAVEATS (read before using ML in production)
-------------------------------------------------------
  1. An anomaly score is NOT a confirmed security incident.
  2. Never automatically block users based solely on an ML prediction.
  3. Always investigate findings manually before taking action.
  4. Do NOT train on real account data unless you have explicit authorisation.
  5. This model is unsupervised — it has no ground-truth labels.
     Precision / recall metrics require a labelled evaluation set.

Full implementation: Phase 8.
Stub created in: Phase 1 (project scaffold).
"""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

# Guard against missing scikit-learn
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    log.warning(
        "scikit-learn / numpy not installed. "
        "ML features disabled. Run: pip install scikit-learn numpy"
    )


# ─────────────────────────────────────────────────────────────────────────── #
# Feature engineering
# ─────────────────────────────────────────────────────────────────────────── #

def extract_features(events: list[dict]) -> "np.ndarray":
    """
    Convert normalised events to a numeric feature matrix.

    Features per event:
      0. eventHour            — hour of day (0–23)
      1. isOffHours           — 1 if off-hours, 0 otherwise
      2. isFailed             — 1 if errorCode present
      3. isRootActivity       — 1 if root account used
      4. severityScore        — info=0, medium=1, high=2
      5. isReadOnly           — 1 if readOnly event

    Full implementation (Phase 8) will add:
      - API calls per principal per hour
      - Distinct source IPs per principal
      - Ratio of failed to total calls
    """
    if not ML_AVAILABLE:
        raise ImportError("scikit-learn and numpy are required.")

    severity_map = {"info": 0, "medium": 1, "high": 2}
    rows = []
    for e in events:
        rows.append([
            e.get("eventHour", 0) or 0,
            int(bool(e.get("isOffHours"))),
            int(bool(e.get("isFailed"))),
            int(bool(e.get("isRootActivity"))),
            severity_map.get(e.get("severity", "info"), 0),
            int(bool(e.get("readOnly"))),
        ])
    return np.array(rows, dtype=float)


# ─────────────────────────────────────────────────────────────────────────── #
# Model training (Phase 8 placeholder)
# ─────────────────────────────────────────────────────────────────────────── #

def train(
    events: list[dict],
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
    model_path: str | None = None,
) -> tuple:
    """
    Train an Isolation Forest on normalised events.

    Args:
        events:        Normalised event dicts.
        contamination: Expected fraction of anomalies (0 < x < 0.5).
        n_estimators:  Number of trees.
        random_state:  Reproducibility seed.
        model_path:    Where to save the trained model (.pkl).
                       Defaults to ml/models/isolation_forest.pkl.

    Returns:
        (model, scaler) tuple.

    Full implementation: Phase 8.
    """
    if not ML_AVAILABLE:
        raise ImportError("scikit-learn and numpy are required for ML training.")

    log.info("Extracting features from %d events...", len(events))
    X = extract_features(events)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    log.info(
        "Training Isolation Forest (n_estimators=%d, contamination=%.2f)...",
        n_estimators, contamination
    )
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X_scaled)

    if model_path is None:
        root = Path(__file__).resolve().parent.parent
        model_path = root / "ml" / "models" / "isolation_forest.pkl"

    Path(model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler}, model_path)
    log.info("Model saved to: %s", model_path)

    return model, scaler


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.collect_events   import load_sample_events
    from src.parse_events     import parse_events
    from src.normalize_events import normalize_events

    logging.basicConfig(level=logging.INFO)

    if not ML_AVAILABLE:
        print("scikit-learn not installed. Run: pip install scikit-learn numpy")
        sys.exit(1)

    raw    = load_sample_events()
    parsed = parse_events(raw)
    norm   = normalize_events(parsed)

    model, scaler = train(norm)
    print(f"Training complete. Model saved.")
