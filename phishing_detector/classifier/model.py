"""Optional scikit-learn phishing URL classifier."""

import pickle
from pathlib import Path
from dataclasses import dataclass

import numpy as np

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from phishing_detector.url_analyzer.feature_extractor import URLFeatureExtractor, URLFeatures

MODEL_PATH = Path(__file__).parent / "phishing_model.pkl"


@dataclass
class ClassificationResult:
    prediction: str = "unknown"
    probability_phishing: float = 0.0
    probability_legit: float = 0.0

    def to_dict(self) -> dict:
        return {
            "prediction": self.prediction,
            "probability_phishing": round(self.probability_phishing, 4),
            "probability_legit": round(self.probability_legit, 4),
        }


def _features_to_vector(f: URLFeatures) -> list[float]:
    return [
        f.length,
        int(f.has_ip_address),
        f.num_special_chars,
        f.num_subdomains,
        int(f.has_https),
        f.num_hyphens,
        f.num_digits,
        f.num_at_symbols,
        int(f.has_suspicious_tld),
        len(f.typosquatting_matches),
        int(f.has_shortening_service),
        f.path_depth,
        int(f.has_double_slash_redirect),
    ]


class PhishingClassifier:
    """Train and predict using a gradient boosting classifier on URL features."""

    FEATURE_NAMES = [
        "length", "has_ip", "special_chars", "subdomains", "has_https",
        "hyphens", "digits", "at_symbols", "suspicious_tld",
        "typosquat_matches", "shortening_svc", "path_depth",
        "double_slash_redirect",
    ]

    def __init__(self):
        if not HAS_SKLEARN:
            raise ImportError(
                "scikit-learn is required. Install with: pip install scikit-learn"
            )
        self.model = None
        self.extractor = URLFeatureExtractor()

    def train(self, urls: list[str], labels: list[int]) -> dict:
        """Train the model. labels: 1=phishing, 0=legitimate."""
        X = []
        for url in urls:
            features = self.extractor.extract(url)
            X.append(_features_to_vector(features))

        X = np.array(X)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model = GradientBoostingClassifier(
            n_estimators=100, max_depth=5, random_state=42
        )
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)

        self.save_model()
        return report

    def predict(self, url: str) -> ClassificationResult:
        if self.model is None:
            self.load_model()

        features = self.extractor.extract(url)
        vector = np.array([_features_to_vector(features)])

        prediction = self.model.predict(vector)[0]
        probabilities = self.model.predict_proba(vector)[0]

        result = ClassificationResult()
        result.predition = "phishing" if prediction == 1 else "legitimate"
        result.probability_phishing = float(probabilities[1])
        result.probability_legit = float(probabilities[0])

        return result

    def save_model(self, path: Path | None = None):
        path = path or MODEL_PATH
        with open(path, "wb") as f:
            pickle.dump(self.model, f)

    def load_model(self, path: Path | None = None):
        path = path or MODEL_PATH
        if not path.exists():
            raise FileNotFoundError(f"Model not found at {path}. Train first.")
        with open(path, "rb") as f:
            self.model = pickle.load(f)
