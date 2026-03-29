import pandas as pd

# Load the dataset
df = pd.read_csv('/home/lingkong/NAIDS_Project/dataset/cicids2017_cleaned.csv')

# Show basic information
print("=== DATASET SHAPE ===")
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])

print("\n=== FIRST 3 ROWS ===")
print(df.head(3))

print("\n=== COLUMN NAMES ===")
print(df.columns.tolist())

print("\n=== ATTACK TYPES IN DATASET ===")
print(df['Label'].value_counts())