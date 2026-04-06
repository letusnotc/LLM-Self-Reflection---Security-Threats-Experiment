"""
Evaluation Metrics — Compute and compare performance across reflection levels.
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
try:
    from scipy.stats import mcnemar as _mcnemar
except ImportError:
    _mcnemar = None


def compute_metrics(y_true: list, y_pred: list, y_prob: list = None) -> dict:
    """
    Compute comprehensive evaluation metrics.

    Args:
        y_true: Ground truth labels (0=benign, 1=malicious)
        y_pred: Predicted labels
        y_prob: Predicted probabilities (confidence scores) for ROC-AUC

    Returns:
        dict with all computed metrics
    """
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1_score": f1_score(y_true, y_pred, zero_division=0),
        "false_positive_rate": fp / (fp + tn) if (fp + tn) > 0 else 0.0,
        "false_negative_rate": fn / (fn + tp) if (fn + tp) > 0 else 0.0,
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "total_samples": len(y_true),
        "confusion_matrix": cm.tolist(),
    }

    if y_prob is not None:
        try:
            metrics["roc_auc"] = roc_auc_score(y_true, y_prob)
        except ValueError:
            metrics["roc_auc"] = None

    return metrics


def compare_levels(results_by_level: dict) -> pd.DataFrame:
    """
    Compare metrics across reflection levels.

    Args:
        results_by_level: dict mapping level (0, 1, 2) to metrics dict

    Returns:
        DataFrame with levels as rows and metrics as columns
    """
    rows = []
    for level, metrics in sorted(results_by_level.items()):
        row = {"level": level}
        for key in ["accuracy", "precision", "recall", "f1_score",
                     "false_positive_rate", "false_negative_rate", "roc_auc"]:
            row[key] = metrics.get(key, None)
        rows.append(row)

    return pd.DataFrame(rows).set_index("level")


def mcnemar_test(y_true: list, y_pred_a: list, y_pred_b: list) -> dict:
    """
    McNemar's test to check if two classifiers have significantly different error rates.

    Args:
        y_true: Ground truth labels
        y_pred_a: Predictions from model A (e.g., Level 0)
        y_pred_b: Predictions from model B (e.g., Level 2)

    Returns:
        dict with test statistic, p-value, and significance
    """
    y_true = np.array(y_true)
    y_pred_a = np.array(y_pred_a)
    y_pred_b = np.array(y_pred_b)

    correct_a = (y_pred_a == y_true)
    correct_b = (y_pred_b == y_true)

    # Build contingency table
    # b_wrong_a_right = both A correct and B wrong
    b01 = np.sum(correct_a & ~correct_b)  # A right, B wrong
    b10 = np.sum(~correct_a & correct_b)  # A wrong, B right

    contingency = np.array([[0, b01], [b10, 0]])

    if b01 + b10 == 0:
        return {"statistic": 0.0, "p_value": 1.0, "significant": False,
                "note": "No discordant pairs — models have identical predictions"}

    if _mcnemar is not None:
        result = _mcnemar(contingency, exact=True if (b01 + b10) < 25 else False)
        statistic, p_value = result.statistic, result.pvalue
    else:
        # Manual McNemar's test fallback
        n = b01 + b10
        if n < 25:
            from scipy.stats import binom
            p_value = 2 * binom.cdf(min(b01, b10), n, 0.5)
            p_value = min(p_value, 1.0)
            statistic = float(min(b01, b10))
        else:
            statistic = (abs(b01 - b10) - 1) ** 2 / (b01 + b10)
            from scipy.stats import chi2
            p_value = 1 - chi2.cdf(statistic, df=1)

    return {
        "statistic": statistic,
        "p_value": p_value,
        "significant": p_value < 0.05,
        "a_right_b_wrong": int(b01),
        "a_wrong_b_right": int(b10),
    }
