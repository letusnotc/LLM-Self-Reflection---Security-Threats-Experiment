"""
Visualizations — Charts and plots for experiment analysis.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, auc
from typing import Optional


# Style configuration
sns.set_theme(style="whitegrid", palette="Set2")
LEVEL_NAMES = {0: "Level 0\n(No Reflection)", 1: "Level 1\n(Single Reflection)", 2: "Level 2\n(Iterative)"}
LEVEL_COLORS = {0: "#e74c3c", 1: "#f39c12", 2: "#27ae60"}


def plot_comparison(metrics_by_level: dict, domain: str = "All Domains",
                    save_path: Optional[str] = None) -> plt.Figure:
    """
    Bar chart comparing key metrics across reflection levels.

    Args:
        metrics_by_level: dict mapping level (0,1,2) to metrics dict
        domain: Domain name for the title
        save_path: Optional path to save the figure
    """
    metric_names = ["accuracy", "precision", "recall", "f1_score"]
    display_names = ["Accuracy", "Precision", "Recall", "F1 Score"]

    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(metric_names))
    width = 0.25

    for i, (level, metrics) in enumerate(sorted(metrics_by_level.items())):
        values = [metrics.get(m, 0) for m in metric_names]
        bars = ax.bar(x + i * width, values, width,
                      label=LEVEL_NAMES.get(level, f"Level {level}"),
                      color=LEVEL_COLORS.get(level, f"C{i}"),
                      edgecolor="white", linewidth=0.5)
        # Add value labels on bars
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f'{val:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.set_ylabel("Score", fontsize=12)
    ax.set_title(f"Performance Comparison Across Reflection Levels\n{domain}", fontsize=14, fontweight='bold')
    ax.set_xticks(x + width)
    ax.set_xticklabels(display_names, fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10, loc="upper right")
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig


def plot_confusion_matrix(y_true: list, y_pred: list, level: int = 0,
                          domain: str = "", save_path: Optional[str] = None) -> plt.Figure:
    """
    Plot a confusion matrix heatmap.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Benign", "Malicious"],
                yticklabels=["Benign", "Malicious"],
                ax=ax, cbar_kws={"label": "Count"})
    ax.set_xlabel("Predicted", fontsize=12)
    ax.set_ylabel("Actual", fontsize=12)
    level_name = LEVEL_NAMES.get(level, f"Level {level}").replace("\n", " ")
    ax.set_title(f"Confusion Matrix — {level_name}\n{domain}", fontsize=13, fontweight='bold')

    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig


def plot_roc_curve(y_true_by_level: dict, y_prob_by_level: dict,
                   domain: str = "", save_path: Optional[str] = None) -> plt.Figure:
    """
    Plot ROC curves for all reflection levels on the same chart.

    Args:
        y_true_by_level: dict mapping level to true labels
        y_prob_by_level: dict mapping level to predicted probabilities
    """
    fig, ax = plt.subplots(figsize=(8, 6))

    for level in sorted(y_true_by_level.keys()):
        y_true = y_true_by_level[level]
        y_prob = y_prob_by_level[level]

        if y_prob is None:
            continue

        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)

        level_name = LEVEL_NAMES.get(level, f"Level {level}").replace("\n", " ")
        ax.plot(fpr, tpr, color=LEVEL_COLORS.get(level, f"C{level}"),
                linewidth=2, label=f"{level_name} (AUC = {roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], "k--", linewidth=1, alpha=0.5, label="Random")
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title(f"ROC Curves — Reflection Level Comparison\n{domain}", fontsize=13, fontweight='bold')
    ax.legend(fontsize=10, loc="lower right")
    ax.grid(alpha=0.3)

    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig


def plot_cost_vs_performance(cost_data: dict, metrics_data: dict,
                             save_path: Optional[str] = None) -> plt.Figure:
    """
    Scatter plot showing the trade-off between cost (tokens/latency) and performance (F1).
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Plot 1: Tokens vs F1
    ax = axes[0]
    for level in sorted(cost_data.keys()):
        cost = cost_data[level]
        metrics = metrics_data[level]
        ax.scatter(cost.get("avg_tokens_per_sample", 0), metrics.get("f1_score", 0),
                   s=200, color=LEVEL_COLORS.get(level, f"C{level}"),
                   edgecolors="black", linewidth=1, zorder=5,
                   label=LEVEL_NAMES.get(level, f"Level {level}").replace("\n", " "))
    ax.set_xlabel("Avg Tokens per Sample", fontsize=12)
    ax.set_ylabel("F1 Score", fontsize=12)
    ax.set_title("Token Cost vs Performance", fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)

    # Plot 2: Latency vs F1
    ax = axes[1]
    for level in sorted(cost_data.keys()):
        cost = cost_data[level]
        metrics = metrics_data[level]
        ax.scatter(cost.get("avg_wall_time_seconds", 0), metrics.get("f1_score", 0),
                   s=200, color=LEVEL_COLORS.get(level, f"C{level}"),
                   edgecolors="black", linewidth=1, zorder=5,
                   label=LEVEL_NAMES.get(level, f"Level {level}").replace("\n", " "))
    ax.set_xlabel("Avg Latency per Sample (seconds)", fontsize=12)
    ax.set_ylabel("F1 Score", fontsize=12)
    ax.set_title("Latency vs Performance", fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)

    plt.suptitle("Cost-Performance Trade-off Analysis", fontsize=15, fontweight='bold', y=1.02)
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig


def plot_domain_comparison(domain_metrics: dict, save_path: Optional[str] = None) -> plt.Figure:
    """
    Grouped bar chart comparing F1 scores across domains and levels.

    Args:
        domain_metrics: nested dict {domain: {level: metrics_dict}}
    """
    domains = sorted(domain_metrics.keys())
    levels = [0, 1, 2]

    fig, ax = plt.subplots(figsize=(12, 6))

    x = np.arange(len(domains))
    width = 0.25

    for i, level in enumerate(levels):
        values = []
        for domain in domains:
            if level in domain_metrics[domain]:
                values.append(domain_metrics[domain][level].get("f1_score", 0))
            else:
                values.append(0)
        bars = ax.bar(x + i * width, values, width,
                      label=LEVEL_NAMES.get(level, f"Level {level}"),
                      color=LEVEL_COLORS.get(level, f"C{i}"),
                      edgecolor="white", linewidth=0.5)
        for bar, val in zip(bars, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        f'{val:.2f}', ha='center', va='bottom', fontsize=9, fontweight='bold')

    domain_labels = [d.replace("_", "\n").title() for d in domains]
    ax.set_ylabel("F1 Score", fontsize=12)
    ax.set_title("F1 Score by Domain and Reflection Level", fontsize=14, fontweight='bold')
    ax.set_xticks(x + width)
    ax.set_xticklabels(domain_labels, fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    return fig
