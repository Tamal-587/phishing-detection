from flask import Flask, render_template, request, send_file
import joblib
import pandas as pd
import os

from feature_extractor import (
    extract_features,
    analyze_url,
    FEATURES
)

from report_generator import generate_security_report


app = Flask(__name__)


# =========================================================
# LOAD MODEL
# =========================================================

data = joblib.load("phishing_model.pkl")

model = data["model"]


# =========================================================
# MODEL INFORMATION
# =========================================================

MODEL_NAME = "Random Forest Classifier"

MODEL_ACCURACY = 99.73

MODEL_FEATURES = len(FEATURES)


# =========================================================
# CONFUSION MATRIX VALUES
# =========================================================

TN = 20082
FP = 107
FN = 21
TP = 26949

TOTAL = TN + FP + FN + TP


# =========================================================
# CALCULATE METRICS
# =========================================================

accuracy = (TP + TN) / TOTAL

precision = TP / (TP + FP)

recall = TP / (TP + FN)

f1_score = (
    2 * precision * recall
    / (precision + recall)
)


# =========================================================
# HOME / SCANNER
# =========================================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    confidence = None
    url = None
    analysis = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()


        if url:

            # -------------------------------------------------
            # EXTRACT ML FEATURES
            # -------------------------------------------------

            values = extract_features(url)

            X = pd.DataFrame(
                [values],
                columns=FEATURES
            )


            # -------------------------------------------------
            # ML PREDICTION
            # -------------------------------------------------

            prediction = model.predict(X)[0]

            probabilities = model.predict_proba(X)[0]

            confidence = round(
                max(probabilities) * 100,
                2
            )


            # -------------------------------------------------
            # ML RESULT
            # -------------------------------------------------

            if prediction == 1:

                ml_result = "PHISHING"

            else:

                ml_result = "LEGITIMATE"


            # -------------------------------------------------
            # SECURITY ANALYSIS
            # -------------------------------------------------

            analysis = analyze_url(url)


            # -------------------------------------------------
            # HYBRID DECISION
            # -------------------------------------------------

            if analysis["risk_score"] >= 40:

                result = "PHISHING"

            else:

                result = ml_result


    return render_template(
        "index.html",

        result=result,

        confidence=confidence,

        url=url,

        analysis=analysis,

        model_name=MODEL_NAME,

        model_accuracy=MODEL_ACCURACY,

        model_features=MODEL_FEATURES,

        accuracy=round(
            accuracy * 100,
            2
        ),

        precision=round(
            precision * 100,
            2
        ),

        recall=round(
            recall * 100,
            2
        ),

        f1_score=round(
            f1_score * 100,
            2
        ),

        tn=TN,

        fp=FP,

        fn=FN,

        tp=TP
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    return render_template(
        "dashboard.html",

        model_name=MODEL_NAME,

        model_accuracy=MODEL_ACCURACY,

        model_features=MODEL_FEATURES,

        accuracy=round(
            accuracy * 100,
            2
        ),

        precision=round(
            precision * 100,
            2
        ),

        recall=round(
            recall * 100,
            2
        ),

        f1_score=round(
            f1_score * 100,
            2
        ),

        tn=TN,

        fp=FP,

        fn=FN,

        tp=TP
    )


# =========================================================
# PDF SECURITY REPORT
# =========================================================

@app.route("/download-report", methods=["POST"])
def download_report():

    url = request.form.get(
        "url",
        ""
    ).strip()


    if not url:

        return "URL is required.", 400


    # ---------------------------------------------------------
    # ANALYZE URL
    # ---------------------------------------------------------

    values = extract_features(url)

    X = pd.DataFrame(
        [values],
        columns=FEATURES
    )


    # ---------------------------------------------------------
    # ML PREDICTION
    # ---------------------------------------------------------

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    confidence = round(
        max(probabilities) * 100,
        2
    )


    if prediction == 1:

        ml_result = "PHISHING"

    else:

        ml_result = "LEGITIMATE"


    # ---------------------------------------------------------
    # SECURITY ANALYSIS
    # ---------------------------------------------------------

    analysis = analyze_url(url)


    # ---------------------------------------------------------
    # HYBRID RESULT
    # ---------------------------------------------------------

    if analysis["risk_score"] >= 40:

        result = "PHISHING"

    else:

        result = ml_result


    # ---------------------------------------------------------
    # REPORT PATH
    # ---------------------------------------------------------

    report_path = os.path.join(
        os.getcwd(),
        "phishing_security_report.pdf"
    )


    # ---------------------------------------------------------
    # GENERATE REPORT
    # ---------------------------------------------------------

    generate_security_report(

        filepath=report_path,

        url=url,

        result=result,

        confidence=confidence,

        analysis=analysis,

        model_name=MODEL_NAME,

        model_accuracy=MODEL_ACCURACY,

        model_features=MODEL_FEATURES,

        accuracy=round(
            accuracy * 100,
            2
        ),

        precision=round(
            precision * 100,
            2
        ),

        recall=round(
            recall * 100,
            2
        ),

        f1_score=round(
            f1_score * 100,
            2
        ),

        tn=TN,

        fp=FP,

        fn=FN,

        tp=TP
    )


    # ---------------------------------------------------------
    # SEND PDF TO USER
    # ---------------------------------------------------------

    return send_file(
        report_path,
        as_attachment=True,
        download_name="phishing_security_report.pdf",
        mimetype="application/pdf"
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )