import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import gc

print("=== Training Isolation Forest Only ===")

# Load dataset
print("Loading dataset...")
df = pd.read_csv(
    '/home/lingkong/NAIDS_Project/dataset/cicids2017_cleaned.csv'
)
print(f"Dataset loaded: {df.shape[0]} rows")

# Extract normal traffic sample only
print("Extracting 200,000 normal traffic records...")
normal_traffic = df[df['Attack Type'] == 'Normal Traffic']
X_normal = normal_traffic.sample(
    n=200000, random_state=42
).drop('Attack Type', axis=1)
print(f"Sample ready: {X_normal.shape[0]} records")

# Free full dataset from memory
del df
gc.collect()
print("Memory freed successfully")

# Train Isolation Forest
print("\nTraining Isolation Forest...")
print("Please wait 2-4 minutes...")
isolation_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    max_samples=10000,
    random_state=42,
    n_jobs=-1,
    verbose=0
)
isolation_forest.fit(X_normal)
print("Training complete!")

# Test it
print("\nTesting model...")
test_sample = X_normal.sample(n=500, random_state=99)
scores = isolation_forest.decision_function(test_sample)
predictions = isolation_forest.predict(test_sample)
normal_count = (predictions == 1).sum()
anomaly_count = (predictions == -1).sum()
print(f"Normal predictions:  {normal_count}/500")
print(f"Anomaly predictions: {anomaly_count}/500")
print(f"Average score: {scores.mean():.4f}")

# Save
print("\nSaving model...")
joblib.dump(
    isolation_forest,
    '/home/lingkong/NAIDS_Project/model/isolation_forest.pkl'
)
print("✅ Isolation Forest saved successfully!")
print("✅ Ready for dual engine detection!")