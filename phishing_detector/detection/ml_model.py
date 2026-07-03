"""
Pure-Python Multinomial Naive Bayes text classifier.

Deliberately has ZERO dependency on numpy / scipy / scikit-learn. Those
packages ship compiled DLL (.pyd) files which get blocked by some
locked-down Windows machines (school/corporate Application Control /
WDAC policies). This implementation only uses the Python standard
library, so it runs anywhere Python itself runs.

The model (word counts + priors) is persisted as plain JSON. Class
labels are always stored/looked-up as the strings "0" (legit) and "1"
(phishing) so behaviour is identical whether the model was just trained
in-memory or reloaded from JSON.
"""

import os
import json
import math
import re
from collections import Counter

from .dataset import SAMPLES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.json")

_TOKEN_RE = re.compile(r"[a-zA-Z]{2,}")

# small stopword list, same spirit as sklearn's 'english' stop_words
_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "is", "are", "was", "were", "be",
    "been", "being", "to", "of", "in", "on", "at", "for", "with", "as",
    "by", "this", "that", "these", "those", "it", "its", "you", "your",
    "we", "our", "i", "will", "can", "has", "have", "had", "not", "if",
    "from", "so", "please", "thank", "thanks",
}

_model = None  # lazy-loaded singleton: dict with priors + word_log_probs


def _tokenize(text):
    words = _TOKEN_RE.findall(text.lower())
    return [w for w in words if w not in _STOPWORDS]


def train_and_save():
    """Train the Naive Bayes model on the sample dataset and persist it as JSON."""
    class_word_counts = {"0": Counter(), "1": Counter()}
    class_doc_counts = {"0": 0, "1": 0}
    vocab = set()

    for text, label in SAMPLES:
        key = str(label)
        tokens = _tokenize(text)
        class_word_counts[key].update(tokens)
        class_doc_counts[key] += 1
        vocab.update(tokens)

    vocab = sorted(vocab)
    vocab_size = len(vocab)
    total_docs = sum(class_doc_counts.values())

    priors = {c: class_doc_counts[c] / total_docs for c in ("0", "1")}
    total_words = {c: sum(class_word_counts[c].values()) for c in ("0", "1")}

    # Laplace-smoothed log P(word | class) for every vocab word
    word_log_probs = {"0": {}, "1": {}}
    for c in ("0", "1"):
        denom = total_words[c] + vocab_size  # +1 smoothing per vocab word
        for word in vocab:
            count = class_word_counts[c].get(word, 0)
            word_log_probs[c][word] = math.log((count + 1) / denom)
        # probability mass reserved for unseen words at prediction time
        word_log_probs[c]["__unseen__"] = math.log(1 / denom)

    model = {
        "priors": priors,
        "word_log_probs": word_log_probs,
        "vocab_size": vocab_size,
    }

    with open(MODEL_PATH, "w", encoding="utf-8") as f:
        json.dump(model, f)

    # quick self-check accuracy on the training set (just for the console message)
    correct = 0
    for text, label in SAMPLES:
        _, pred = _predict_with_model(model, text)
        if pred == label:
            correct += 1
    accuracy = correct / len(SAMPLES)

    return accuracy


def _ensure_loaded():
    global _model
    if _model is not None:
        return
    if not os.path.exists(MODEL_PATH):
        train_and_save()
    with open(MODEL_PATH, "r", encoding="utf-8") as f:
        _model = json.load(f)


def _predict_with_model(model, text):
    tokens = _tokenize(text)
    log_scores = {}
    for c in ("0", "1"):
        log_scores[c] = math.log(model["priors"][c])
        wlp = model["word_log_probs"][c]
        unseen = wlp["__unseen__"]
        for token in tokens:
            log_scores[c] += wlp.get(token, unseen)

    # convert log scores to a normalized probability for class "1" (phishing)
    max_log = max(log_scores.values())
    exp_scores = {c: math.exp(v - max_log) for c, v in log_scores.items()}
    total = sum(exp_scores.values())
    phishing_proba = exp_scores["1"] / total

    prediction = int(phishing_proba >= 0.5)
    return phishing_proba, prediction


def ml_predict(text):
    """
    Returns (probability_of_phishing 0-1, predicted_label 0/1)
    """
    _ensure_loaded()
    return _predict_with_model(_model, text)


if __name__ == "__main__":
    accuracy = train_and_save()
    print(f"Model trained. Training-set accuracy: {accuracy:.2f}")
