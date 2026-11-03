import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "dataset" / "vulnerability_dataset.csv"
MODEL_PATH = BASE_DIR / "vulnerability_model.pkl"


# ============================================================
# START
# ============================================================

print("=" * 60)
print("       SafePyScript ML Model Training")
print("=" * 60)


# ============================================================
# LOAD DATASET
# ============================================================

if not DATASET_PATH.exists():
    print("\nERROR: Dataset not found!")
    print(DATASET_PATH)
    exit()


df = pd.read_csv(DATASET_PATH)

print(f"\nDataset loaded: {len(df)} samples")


# Remove empty rows
df = df.dropna(subset=["code", "vulnerability"])


print("\nVulnerability classes:")
print(df["vulnerability"].value_counts())


# ============================================================
# INPUT AND OUTPUT
# ============================================================

X = df["code"]
y = df["vulnerability"]


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# ============================================================
# MACHINE LEARNING PIPELINE
# ============================================================

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            min_df=1
        )
    ),

    (
        "classifier",
        LogisticRegression(
            max_iter=3000
        )
    )
])


# ============================================================
# TRAIN
# ============================================================

print("\nTraining ML model...")

model.fit(X_train, y_train)

print("Training completed successfully.")


# ============================================================
# TEST MODEL
# ============================================================

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)


print("\n" + "=" * 60)
print("              MODEL PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy: {accuracy:.2%}")

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

joblib.dump(
    model,
    MODEL_PATH
)


print("=" * 60)
print("MODEL SAVED SUCCESSFULLY")
print("=" * 60)

print("\nModel location:")
print(MODEL_PATH)

print("\nSafePyScript ML training completed.")