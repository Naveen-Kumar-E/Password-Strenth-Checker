"""
Flask web server for the Password Strength Analyzer
Run: python app.py  →  open http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify
from analyzer import analyze_password
import dataclasses
import math

app = Flask(__name__)


def to_dict(obj):
    """Recursively convert dataclasses to dicts, handle inf/nan."""
    if dataclasses.is_dataclass(obj):
        return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, float):
        if math.isinf(obj):
            return "infinity"
        if math.isnan(obj):
            return 0
    return obj


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided"}), 400

    if len(password) > 128:
        return jsonify({"error": "Password too long (max 128 chars)"}), 400

    result = analyze_password(password)
    return jsonify(to_dict(result))


@app.route("/batch", methods=["POST"])
def batch():
    """Analyze multiple passwords at once."""
    data = request.get_json()
    passwords = data.get("passwords", [])

    if not isinstance(passwords, list) or len(passwords) > 20:
        return jsonify({"error": "Provide a list of up to 20 passwords"}), 400

    results = []
    for pw in passwords:
        r = analyze_password(str(pw)[:128])
        results.append({
            "password_masked": "*" * len(pw),
            "score": r.score,
            "level": r.level,
            "entropy_bits": r.entropy_bits,
            "crack_estimates": [to_dict(e) for e in r.crack_estimates],
        })

    return jsonify(results)


if __name__ == "__main__":
    print("\n🔐 Password Analyzer running at http://localhost:5000\n")
    app.run(debug=True, port=5000)
