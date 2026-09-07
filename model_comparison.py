import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

# Load dataset
df = pd.read_csv("dataset.csv")

# Same features used for Random Forest
features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]

X = df[features]
y = df["label"]

# Remove missing values
X = X.dropna()
y = y.loc[X.index]

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# -----------------------------
# Random Forest
# -----------------------------
data = joblib.load("phishing_model.pkl")
rf_model = data["model"]

rf_pred = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_pred)

# -----------------------------
# Logistic Regression
# -----------------------------
lr_model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

lr_model.fit(X_train, y_train)

lr_pred = lr_model.predict(X_test)
lr_accuracy = accuracy_score(y_test, lr_pred)

# Print results
print("\n==============================")
print("MODEL COMPARISON")
print("==============================")

print(f"Random Forest Accuracy      : {rf_accuracy * 100:.2f}%")
print(f"Logistic Regression Accuracy: {lr_accuracy * 100:.2f}%")

# -----------------------------
# Comparison Graph
# -----------------------------
models = ["Random Forest", "Logistic Regression"]
accuracies = [rf_accuracy * 100, lr_accuracy * 100]

plt.figure(figsize=(8, 5))

bars = plt.bar(models, accuracies)

plt.ylabel("Accuracy (%)")
plt.xlabel("Machine Learning Model")
plt.title("Model Accuracy Comparison")

plt.ylim(0, 100)

# Add accuracy values above bars
for bar, accuracy in zip(bars, accuracies):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height() + 0.5,
        f"{accuracy:.2f}%",
        ha="center"
    )

plt.tight_layout()

# Save graph
plt.savefig("model_comparison.png", dpi=300)

plt.show()

print("\nComparison graph saved as model_comparison.png")