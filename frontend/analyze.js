
const codeInput = document.getElementById("codeInput");
const pythonFile = document.getElementById("pythonFile");
const statusMessage = document.getElementById("statusMessage");

function analyzeCode() {
    const code = codeInput.value.trim();

    // Check whether code or file was provided
    if (code === "" && pythonFile.files.length === 0) {
        statusMessage.textContent =
            "⚠️ Please paste Python code or upload a Python file.";
        return;
    }

    statusMessage.textContent = "🔎 Analyzing your Python code...";

    const formData = new FormData();

    // If code was pasted, send it
    if (code !== "") {
        formData.append("code", code);
    }

    // If a Python file was selected, send it
    if (pythonFile.files.length > 0) {
        formData.append("file", pythonFile.files[0]);
    }

    fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        body: formData
    })
        .then(async response => {
            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.message || "Backend returned an error."
                );
            }

            return data;
        })
        .then(data => {
            console.log("Backend response:", data);

            if (!data.success) {
                statusMessage.textContent =
                    "❌ " + (data.message || "Analysis failed.");
                return;
            }

            displayResults(
                data.rule_based_results || [],
                data.ml_result
            );
        })
        .catch(error => {
            console.error("Analysis error:", error);

            statusMessage.textContent =
                "❌ " + error.message +
                " Make sure the Flask backend is running.";
        });
}


// ---------------------------------------------------------
// Display rule-based and ML analysis results
// ---------------------------------------------------------
function displayResults(results, mlResult) {
    let html = `
        <div class="analysis-success">
            ✅ Analysis completed successfully!
        </div>

        <h2>🔐 Security Analysis Results</h2>

        <p>
            <strong>${results.length}</strong>
            rule-based security issue(s) detected.
        </p>
    `;

    // Rule-based findings
    html += `<h3>1. Rule-Based Analysis</h3>`;

    if (results.length === 0) {
        html += `
            <div class="security-result">
                ✅ No vulnerabilities detected by the current rules.
            </div>
        `;
    } else {
        html += `<div class="results-container">`;

        results.forEach((issue, index) => {
            html += `
                <div class="security-result">
                    <h3>
                        ${index + 1}.
                        ${escapeHtml(issue.vulnerability)}
                    </h3>

                    <p>
                        <strong>Severity:</strong>
                        <span class="severity">
                            ${escapeHtml(issue.severity)}
                        </span>
                    </p>

                    <p>
                        <strong>Line:</strong>
                        ${escapeHtml(String(issue.line))}
                    </p>

                    <p>
                        <strong>Description:</strong><br>
                        ${escapeHtml(issue.description)}
                    </p>

                    <p>
                        <strong>Recommendation:</strong><br>
                        ${escapeHtml(issue.recommendation)}
                    </p>
                </div>
            `;
        });

        html += `</div>`;
    }

    // Machine-learning prediction
    html += `<h3>2. Machine Learning Prediction</h3>`;

    if (mlResult && mlResult.vulnerability) {
        const confidence = Number(mlResult.confidence);
        const validConfidence = Number.isFinite(confidence);

        html += `
            <div class="security-result">
                <p>
                    <strong>Predicted category:</strong>
                    ${escapeHtml(mlResult.vulnerability)}
                </p>

                <p>
                    <strong>Model confidence:</strong>
                    ${
                        validConfidence
                            ? escapeHtml(confidence.toFixed(2)) + "%"
                            : "Not available"
                    }
                </p>

                <p>
                    <strong>Important:</strong>
                    This is a machine-learning prediction, not confirmation
                    that the code is vulnerable or safe.
                    Review the code and rule-based findings before drawing
                    a conclusion.
                </p>
            </div>
        `;
    } else {
        html += `
            <div class="security-result">
                ML prediction is not available for this analysis.
            </div>
        `;
    }

    statusMessage.innerHTML = html;
}


// ---------------------------------------------------------
// Escape output before inserting it into HTML
// ---------------------------------------------------------
function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = String(value ?? "");
    return div.innerHTML;
}
