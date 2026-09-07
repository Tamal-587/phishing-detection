import joblib
from feature_extractor import extract_features, FEATURES
import pandas as pd


# Load trained model
data = joblib.load("phishing_model.pkl")
model = data["model"]


while True:

    url = input("\nEnter URL (or type 'exit' to quit): ").strip()

    if url.lower() == "exit":
        print("Program closed.")
        break

    # Extract URL features
    values = extract_features(url)

    # Create DataFrame
    X = pd.DataFrame([values], columns=FEATURES)

    # Prediction
    prediction = model.predict(X)[0]

    # Probability
    probabilities = model.predict_proba(X)[0]
    confidence = max(probabilities) * 100

    print("\n------------------------------")

    if prediction == 1:
        print("⚠️ RESULT: PHISHING")
    else:
        print("✅ RESULT: LEGITIMATE")

    print(f"Confidence: {confidence:.2f}%")
    print("------------------------------")