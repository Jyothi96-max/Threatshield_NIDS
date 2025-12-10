import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# 1) Load the dataset
# Make sure the CSV name matches exactly
df = pd.read_csv("kdd_train.csv")

# 2) Separate features (X) and label (y)
# In your file the label column is named "labels"
y = df["labels"]          # not used for training Isolation Forest, but kept for reference
X = df.drop(columns=["labels"])

# 3) Convert text (categorical) columns to numbers
# Columns like protocol_type, service, flag are strings → need numeric codes
cat_cols = X.select_dtypes(include=["object"]).columns

for col in cat_cols:
    X[col] = X[col].astype("category").cat.codes

# 4) Scale the numeric features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5) Train Isolation Forest (unsupervised anomaly detection model)
# contamination = expected proportion of anomalies in data
model = IsolationForest(
    n_estimators=100,
    contamination=0.3,
    random_state=42
)
model.fit(X_scaled)

# 6) Save model and scaler so you can use them later in sniffer/dashboard
joblib.dump(model, "threat_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("✅ Training complete!")
print("Saved files: threat_model.pkl, scaler.pkl")
print("Shape of X_scaled:", X_scaled.shape)
print("Categorical columns encoded as:", list(cat_cols))
