"""Offline model-validation entry point for the hackathon's reported metrics."""
from __future__ import annotations

from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from backend.models import InferenceEngine, _dga_vector


def main() -> None:
    engine = InferenceEngine.bootstrap()
    X = [_dga_vector(2.2, 12, .8), _dga_vector(2.8, 15, .6), _dga_vector(4.3, 29, 0, 1), _dga_vector(4.1, 25, .05, 1)] * 50
    y = [0, 0, 1, 1] * 50
    _, X_test, _, y_test = train_test_split(X, y, test_size=.25, random_state=42, stratify=y)
    print(classification_report(y_test, engine.dga_model.predict(X_test), target_names=["benign", "DGA"]))


if __name__ == "__main__":
    main()
