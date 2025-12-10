import pandas as pd
import joblib

# Load model and scaler
model = joblib.load("threat_model.pkl")
scaler = joblib.load("scaler.pkl")

# Load a few rows
df = pd.read_csv("kdd_train.csv").head(10)
X = df.drop(columns=["labels"])

# Encode categorical columns exactly like in training
cat_cols = X.select_dtypes(include=["object"]).columns
for col in cat_cols:
    X[col] = X[col].astype("category").cat.codes

X_scaled = scaler.transform(X)

# Predict: 1 = normal, -1 = anomaly
preds = model.predict(X_scaled)
print("Predictions for first 10 rows:", preds)
print("Raw labels:", df["labels"].values)
