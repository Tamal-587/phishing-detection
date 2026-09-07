import joblib
import matplotlib.pyplot as plt
import pandas as pd

# Load trained model
data = joblib.load("phishing_model.pkl")
model = data["model"]
features = data["features"]

# Get feature importance
importance = model.feature_importances_

# Create DataFrame
importance_df = pd.DataFrame({
    "Feature": features,
    "Importance": importance
})

# Sort by importance
importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

# Show top 10
print("\nTop 10 Important Features:")
print(importance_df.head(10).to_string(index=False))

# Plot
top10 = importance_df.head(10).sort_values(
    by="Importance"
)

plt.figure(figsize=(10, 6))

plt.barh(
    top10["Feature"],
    top10["Importance"]
)

plt.xlabel("Importance")
plt.ylabel("Feature")
plt.title("Top 10 Features - Phishing URL Detection")

plt.tight_layout()

# Save graph
plt.savefig("feature_importance.png", dpi=300)

plt.show()

print("\nFeature importance graph saved as feature_importance.png")