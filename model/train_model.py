import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

print("=== NAIDS - AI Model Training ===")
print("Step 1: Loading dataset...")

# Load the dataset
df = pd.read_csv('/home/lingkong/NAIDS_Project/dataset/cicids2017_cleaned.csv')
print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

# Step 2: Check for missing values
print("\nStep 2: Checking for missing values...")
missing = df.isnull().sum().sum()
print(f"Total missing values: {missing}")

# Drop rows with missing values if any
df = df.dropna()
print(f"Rows after cleaning: {df.shape[0]}")

# Step 3: Remove infinite values
print("\nStep 3: Removing infinite values...")
df = df.replace([np.inf, -np.inf], np.nan).dropna()
print(f"Rows after removing infinites: {df.shape[0]}")

# Step 4: Show attack type distribution
print("\nStep 4: Attack type distribution:")
print(df['Attack Type'].value_counts())

# Step 5: Prepare features and labels
print("\nStep 5: Preparing features and labels...")

# Separate features (X) and labels (y)
# X = all columns except Attack Type (what the AI studies)
# y = Attack Type column only (what the AI learns to predict)
X = df.drop('Attack Type', axis=1)
y = df['Attack Type']

print(f"Features shape: {X.shape}")
print(f"Labels shape: {y.shape}")

# Step 6: Encode labels into numbers
# AI cannot read words - we convert attack names to numbers
# Normal Traffic=0, DoS=1, DDoS=2 etc.
print("\nStep 6: Encoding attack type labels...")
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print("Label encoding complete:")
for i, label in enumerate(le.classes_):
    print(f"  {i} = {label}")

# Step 7: Split into training and testing sets
# 80% of data trains the model, 20% tests it
print("\nStep 7: Splitting data - 80% train, 20% test...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"Training samples: {X_train.shape[0]}")
print(f"Testing samples: {X_test.shape[0]}")

# Step 8: Train the Random Forest model
print("\nStep 8: Training Random Forest model...")
print("This will take 3-10 minutes. Please wait...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    verbose=1
)
model.fit(X_train, y_train)
print("Training complete!")

# Step 9: Test the model
print("\nStep 9: Testing model accuracy...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n✅ MODEL ACCURACY: {accuracy * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# Step 10: Save the model and label encoder
print("\nStep 10: Saving model to file...")
os.makedirs('/home/lingkong/NAIDS_Project/model', exist_ok=True)
joblib.dump(model, '/home/lingkong/NAIDS_Project/model/naids_model.pkl')
joblib.dump(le, '/home/lingkong/NAIDS_Project/model/label_encoder.pkl')
print("✅ Model saved: model/naids_model.pkl")
print("✅ Label encoder saved: model/label_encoder.pkl")
print("\n=== TRAINING COMPLETE ===")