"""
Standalone entry point to (re)train the ML phishing classifier.

Usage:
    python train_model.py
"""
from detection.ml_model import train_and_save

if __name__ == "__main__":
    accuracy = train_and_save()
    print(f"Model trained and saved to detection/model.json")
    print(f"Training-set accuracy: {accuracy:.2%}")
