import joblib

from pathlib import Path


# ============================================================
# MODEL PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "vulnerability_model.pkl"


# ============================================================
# ML PREDICTOR
# ============================================================

class MLPredictor:

    def __init__(self):

        if not MODEL_PATH.exists():

            raise FileNotFoundError(
                "\nML model not found.\n"
                "Please run:\n"
                "python ml\\train_model.py\n"
            )

        print("\nLoading ML model...")

        self.model = joblib.load(
            MODEL_PATH
        )

        print("ML model loaded successfully.")


    # ========================================================
    # PREDICT
    # ========================================================

    def predict(self, code):

        if not code or not code.strip():

            return {
                "vulnerability": "SAFE",
                "confidence": 0.0
            }


        # Predict vulnerability
        prediction = self.model.predict(
            [code]
        )[0]


        # Get probability
        probabilities = self.model.predict_proba(
            [code]
        )[0]


        # Highest probability
        confidence = max(probabilities) * 100


        return {
            "vulnerability": prediction,
            "confidence": round(
                confidence,
                2
            )
        }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("       SafePyScript ML Vulnerability Tester")
    print("=" * 60)


    predictor = MLPredictor()


    # --------------------------------------------------------
    # TEST CODE
    # --------------------------------------------------------

    test_code = """
import os

command = input("Enter command: ")

os.system(command)
"""


    print("\nTest Python Code:")
    print("-" * 60)
    print(test_code)
    print("-" * 60)


    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    result = predictor.predict(
        test_code
    )


    print("\nML Prediction")
    print("-" * 60)

    print(
        "Vulnerability:",
        result["vulnerability"]
    )

    print(
        "Confidence:",
        str(result["confidence"]) + "%"
    )

    print("-" * 60)