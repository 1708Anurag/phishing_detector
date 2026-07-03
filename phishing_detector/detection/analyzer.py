from .heuristics import heuristic_score
from .ml_model import ml_predict


def analyze_email(sender, subject, body):
    """
    Combines rule-based heuristics with the ML text classifier.

    Final risk score (0-100) = 55% heuristic score + 45% ML probability*100.
    Verdict thresholds:
        >= 65  -> phishing
        35-64  -> suspicious
        < 35   -> safe
    """
    heur_score, reasons, urls = heuristic_score(sender, subject, body)

    full_text = f"{subject or ''} {body or ''}".strip()
    ml_proba, ml_label = ml_predict(full_text) if full_text else (0.0, 0)

    final_score = round(0.55 * heur_score + 0.45 * (ml_proba * 100), 1)

    if final_score >= 65:
        verdict = "phishing"
    elif final_score >= 35:
        verdict = "suspicious"
    else:
        verdict = "safe"

    if ml_label == 1:
        reasons = [f"ML classifier flagged this text as phishing-like ({ml_proba*100:.0f}% confidence)"] + reasons
    else:
        reasons = reasons + [f"ML classifier estimates {ml_proba*100:.0f}% phishing probability from wording/style"]

    return {
        "verdict": verdict,
        "score": final_score,
        "heuristic_score": heur_score,
        "ml_probability": round(ml_proba * 100, 1),
        "reasons": reasons,
        "urls": urls,
    }
