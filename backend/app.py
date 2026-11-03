
from flask import Flask, request, jsonify
from flask_cors import CORS

from analyzer.hybrid_analyzer import HybridAnalyzer

app = Flask(__name__)
CORS(app)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "SafePyScript Security Analyzer API is running"
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        code = ""

        # Accept JSON requests
        if request.is_json:
            data = request.get_json(silent=True) or {}
            code = data.get("code", "")

        # Accept pasted code or an uploaded file
        else:
            code = request.form.get("code", "")

            uploaded_file = (
                request.files.get("file")
                or request.files.get("pythonFile")
            )

            if uploaded_file:
                code = uploaded_file.read().decode(
                    "utf-8",
                    errors="replace"
                )

        # Validate the submitted code
        if not isinstance(code, str) or not code.strip():
            return jsonify({
                "success": False,
                "message": (
                    "Please provide Python code or upload a Python file."
                ),
                "issues_found": 0,
                "rule_based_results": [],
                "ml_result": None,
                "ai_result": None
            }), 400

        print("\n" + "=" * 60)
        print("SafePyScript - Python Security Analysis")
        print("=" * 60)

        # Run existing rule-based and ML analyzers
        analyzer = HybridAnalyzer(code)
        analysis_results = analyzer.analyze()

        rule_results = analysis_results.get("rule_based", [])
        ml_result = analysis_results.get("ml_based")

        # Convert confidence to a regular Python float if present
        if isinstance(ml_result, dict):
            ml_result = dict(ml_result)

            if ml_result.get("confidence") is not None:
                ml_result["confidence"] = float(
                    ml_result["confidence"]
                )

        print("Rule-based issues:", len(rule_results))
        print("ML result:", ml_result)

        # Run AI separately so an AI failure does not discard
        # successful rule-based and ML results.
        ai_result = None
        ai_error = None

        try:
            from ai.ai_analyzer import AIAnalyzer

            ai_analyzer = AIAnalyzer()

            ai_result = ai_analyzer.analyze(
                code,
                rule_results
            )

            print("AI analysis completed.")

        except Exception as error:
            # Keep technical details in the backend terminal only
            print("AI analysis failed:", str(error))

            ai_error = (
                "AI analysis is temporarily unavailable. "
                "Check the backend terminal and API configuration."
            )

        print("Analysis completed.")

        response_data = {
            "success": True,
            "message": "Analysis completed successfully.",
            "issues_found": len(rule_results),
            "rule_based_results": rule_results,
            "ml_result": ml_result,
            "ai_result": ai_result
        }

        if ai_error:
            response_data["ai_error"] = ai_error

        return jsonify(response_data), 200

    except Exception:
        import traceback
        traceback.print_exc()

        return jsonify({
            "success": False,
            "message": (
                "An error occurred while analyzing the code. "
                "Check the backend terminal for details."
            ),
            "issues_found": 0,
            "rule_based_results": [],
            "ml_result": None,
            "ai_result": None
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
