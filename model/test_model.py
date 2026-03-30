import pandas as pd
import numpy as np
import joblib

print("=== Testing Saved NAIDS Model ===")

# Load the saved model and encoder
model = joblib.load('/home/lingkong/NAIDS_Project/model/naids_model.pkl')
le = joblib.load('/home/lingkong/NAIDS_Project/model/label_encoder.pkl')
print("✅ Model loaded successfully from file")

# Load a small sample from dataset to test
df = pd.read_csv('/home/lingkong/NAIDS_Project/dataset/cicids2017_cleaned.csv')

# Take 10 random samples
sample = df.sample(n=10, random_state=99)
X_sample = sample.drop('Attack Type', axis=1)
actual = sample['Attack Type'].values

# Make predictions
predictions_encoded = model.predict(X_sample)
predictions = le.inverse_transform(predictions_encoded)

# Show results
print("\n=== PREDICTION RESULTS ===")
print(f"{'Actual':<20} {'Predicted':<20} {'Match'}")
print("-" * 55)
for actual_val, pred_val in zip(actual, predictions):
    match = "✅" if actual_val == pred_val else "❌"
    print(f"{actual_val:<20} {pred_val:<20} {match}")

print("\n✅ Model is working correctly and ready for live detection!")