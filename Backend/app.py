from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from urllib.parse import urlparse
from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)

model = joblib.load("model/url_model_4.pkl")
features_list = joblib.load("model/features.pkl")

TRUSTED_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "microsoft.com", "www.microsoft.com",
    "adoptium.net", "www.adoptium.net",
    "youtube.com", "www.youtube.com",
    "stackoverflow.com", "www.stackoverflow.com",
    "wikipedia.org", "www.wikipedia.org",
}

@app.route("/")
def home():
    return jsonify({"message": "Phishing Detection API Running 🚀"})

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON body received"}), 400

        url = data.get("url")
        if not url:
            return jsonify({"error": "URL is required"}), 400

        domain = urlparse(url).netloc.lower()
        if domain in TRUSTED_DOMAINS:
            return jsonify({
                "url": url,
                "prediction": "Legitimate",
                "probability": 2.0
            })

        feats = extract_features(url)
        input_data = [feats.get(f, 0) for f in features_list]

        prediction = model.predict([input_data])[0]
        proba = model.predict_proba([input_data])[0]
        phishing_probability = float(proba[1]) * 100

        return jsonify({
            "url": url,
            "prediction": "Phishing" if prediction == 1 else "Legitimate",
            "probability": round(phishing_probability, 2)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)