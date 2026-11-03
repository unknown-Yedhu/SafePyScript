from analyzer.security_analyzer import SecurityAnalyzer
from ml.predict import MLPredictor


class HybridAnalyzer:

    def __init__(self, code):
        self.code = code

        # Existing rule-based analyzer
        self.rule_analyzer = SecurityAnalyzer(code)

        # ML analyzer
        self.ml_predictor = MLPredictor()

    def analyze(self):

        # ==========================================
        # RULE-BASED ANALYSIS
        # ==========================================

        rule_results = self.rule_analyzer.analyze()

        # ==========================================
        # ML ANALYSIS
        # ==========================================

        ml_result = self.ml_predictor.predict(self.code)

        # ==========================================
        # COMBINE RESULTS
        # ==========================================

        return {
            "rule_based": rule_results,
            "ml_based": ml_result
        }


# ==============================================
# TEST HYBRID ANALYZER
# ==============================================

if __name__ == "__main__":

    print("=" * 60)
    print("       SafePyScript Hybrid Security Analyzer")
    print("=" * 60)

    test_code = """
import os

command = input("Enter command: ")

os.system(command)
"""

    analyzer = HybridAnalyzer(test_code)

    results = analyzer.analyze()

    print("\n")
    print("=" * 60)
    print("RULE-BASED RESULTS")
    print("=" * 60)

    for issue in results["rule_based"]:
        print(issue)

    print("\n")
    print("=" * 60)
    print("ML RESULTS")
    print("=" * 60)

    print(
        "Vulnerability:",
        results["ml_based"]["vulnerability"]
    )

    print(
        "Confidence:",
        str(results["ml_based"]["confidence"]) + "%"
    )