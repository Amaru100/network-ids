"""
evaluate.py - Model Evaluation and Report Generation
======================================================
This script generates detailed evaluation reports and visualisations
for the trained machine learning models.

Outputs:
- Classification reports for each model
- Confusion matrices (heatmaps)
- Model comparison bar charts (Accuracy, F1-Score, FPR, Inference Time)
- Summary report text file

Author: University of Botswana - Final Year Project
"""

import os
import sys
import numpy as np
import joblib
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving plots
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, ConfusionMatrixDisplay
)


def load_evaluation_data(model_dir):
    """
    Load saved evaluation data from the training pipeline.

    Args:
        model_dir (str): Path to the model directory.

    Returns:
        dict: Evaluation data including test labels, predictions, and metrics.
    """
    eval_path = os.path.join(model_dir, 'eval_data.pkl')
    if not os.path.exists(eval_path):
        print("[!] Error: eval_data.pkl not found. Run train_model.py first.")
        sys.exit(1)

    data = joblib.load(eval_path)
    print("[+] Loaded evaluation data successfully")
    return data


def generate_classification_reports(results, y_test, label_encoder, output_dir):
    """
    Generate and save detailed classification reports for each model.

    Args:
        results (list): Training results with predictions.
        y_test (np.ndarray): True test labels.
        label_encoder: Fitted LabelEncoder.
        output_dir (str): Directory to save reports.
    """
    print("\n[*] Generating classification reports...")
    report_text = ""

    for r in results:
        report = classification_report(
            y_test, r['y_pred'],
            target_names=label_encoder.classes_,
            zero_division=0
        )
        report_text += f"\n{'=' * 60}\n"
        report_text += f"Classification Report: {r['name']}\n"
        report_text += f"{'=' * 60}\n"
        report_text += report
        report_text += f"\nFalse Positive Rate: {r['fpr']:.4f} ({r['fpr']*100:.2f}%)\n"
        report_text += f"Training Time: {r['train_time']:.2f}s\n"
        report_text += f"Avg Inference Time: {r['avg_inference_ms']:.4f}ms per sample\n"

        print(f"  [{r['name']}] Report generated")

    # Save combined report
    report_path = os.path.join(output_dir, 'classification_reports.txt')
    with open(report_path, 'w') as f:
        f.write("NETWORK INTRUSION DETECTION SYSTEM\n")
        f.write("Model Evaluation Reports\n")
        f.write("=" * 60 + "\n")
        f.write(report_text)

    print(f"  Saved to: {report_path}")


def plot_confusion_matrices(results, y_test, label_encoder, output_dir):
    """
    Generate and save confusion matrix heatmaps for each model.

    Args:
        results (list): Training results with predictions.
        y_test (np.ndarray): True test labels.
        label_encoder: Fitted LabelEncoder.
        output_dir (str): Directory to save plots.
    """
    print("\n[*] Generating confusion matrices...")

    fig, axes = plt.subplots(2, 2, figsize=(16, 14))
    fig.suptitle('Confusion Matrices - All Models', fontsize=16, fontweight='bold')

    for idx, r in enumerate(results):
        ax = axes[idx // 2, idx % 2]
        cm = confusion_matrix(y_test, r['y_pred'])
        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Blues', ax=ax,
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_
        )
        ax.set_title(f"{r['name']}\n(Accuracy: {r['accuracy']:.4f}, F1: {r['f1_score']:.4f})")
        ax.set_xlabel('Predicted')
        ax.set_ylabel('Actual')

    plt.tight_layout()
    cm_path = os.path.join(output_dir, 'confusion_matrices.png')
    plt.savefig(cm_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved to: {cm_path}")


def plot_model_comparison(results, output_dir):
    """
    Generate bar charts comparing all models across key metrics.

    Args:
        results (list): Training results with metrics.
        output_dir (str): Directory to save plots.
    """
    print("\n[*] Generating model comparison charts...")

    model_names = [r['name'] for r in results]
    metrics = {
        'Accuracy': [r['accuracy'] for r in results],
        'Precision': [r['precision'] for r in results],
        'Recall': [r['recall'] for r in results],
        'F1-Score': [r['f1_score'] for r in results],
    }

    # Plot 1: Performance metrics comparison
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Model Performance Comparison', fontsize=16, fontweight='bold')
    colors = ['#2196F3', '#4CAF50', '#FF9800', '#F44336']

    for idx, (metric_name, values) in enumerate(metrics.items()):
        ax = axes[idx // 2, idx % 2]
        bars = ax.bar(model_names, values, color=colors, edgecolor='black', linewidth=0.5)
        ax.set_title(metric_name, fontsize=13)
        ax.set_ylim(0, 1.05)
        ax.axhline(y=0.85 if metric_name == 'Accuracy' else 0.80,
                    color='red', linestyle='--', alpha=0.7, label='Target')
        ax.legend()

        # Add value labels on bars
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f'{val:.3f}', ha='center', va='bottom', fontsize=10)

        ax.tick_params(axis='x', rotation=15)

    plt.tight_layout()
    perf_path = os.path.join(output_dir, 'model_comparison_performance.png')
    plt.savefig(perf_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Performance chart saved to: {perf_path}")

    # Plot 2: FPR and Inference Time comparison
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('False Positive Rate & Inference Time', fontsize=16, fontweight='bold')

    # FPR
    fpr_values = [r['fpr'] * 100 for r in results]
    bars1 = ax1.bar(model_names, fpr_values, color=colors, edgecolor='black', linewidth=0.5)
    ax1.set_title('False Positive Rate (%)')
    ax1.set_ylabel('FPR (%)')
    ax1.axhline(y=10, color='red', linestyle='--', alpha=0.7, label='Target (<10%)')
    ax1.legend()
    for bar, val in zip(bars1, fpr_values):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                 f'{val:.2f}%', ha='center', va='bottom', fontsize=10)
    ax1.tick_params(axis='x', rotation=15)

    # Inference time
    inf_values = [r['avg_inference_ms'] for r in results]
    bars2 = ax2.bar(model_names, inf_values, color=colors, edgecolor='black', linewidth=0.5)
    ax2.set_title('Average Inference Time per Sample')
    ax2.set_ylabel('Time (ms)')
    for bar, val in zip(bars2, inf_values):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.001,
                 f'{val:.4f}ms', ha='center', va='bottom', fontsize=10)
    ax2.tick_params(axis='x', rotation=15)

    plt.tight_layout()
    fpr_path = os.path.join(output_dir, 'model_comparison_fpr_inference.png')
    plt.savefig(fpr_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  FPR/Inference chart saved to: {fpr_path}")


def generate_summary_report(results, output_dir):
    """
    Generate a text summary report of all model evaluations.

    Args:
        results (list): Training results with metrics.
        output_dir (str): Directory to save report.
    """
    print("\n[*] Generating summary report...")

    # Find best model
    best = sorted(results, key=lambda x: (-x['f1_score'], x['inference_time']))[0]

    lines = []
    lines.append("=" * 70)
    lines.append("NETWORK INTRUSION DETECTION SYSTEM - MODEL EVALUATION SUMMARY")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"{'Model':<22} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8} {'FPR':>8} {'Inf(ms)':>10}")
    lines.append("─" * 70)

    for r in results:
        star = " ★" if r['name'] == best['name'] else ""
        lines.append(
            f"{r['name']:<22} {r['accuracy']:>8.4f} {r['precision']:>8.4f} "
            f"{r['recall']:>8.4f} {r['f1_score']:>8.4f} {r['fpr']:>8.4f} "
            f"{r['avg_inference_ms']:>10.4f}{star}"
        )

    lines.append("─" * 70)
    lines.append("")
    lines.append(f"BEST MODEL: {best['name']}")
    lines.append(f"  Accuracy:        {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)")
    lines.append(f"  Precision:       {best['precision']:.4f}")
    lines.append(f"  Recall:          {best['recall']:.4f}")
    lines.append(f"  F1-Score:        {best['f1_score']:.4f}")
    lines.append(f"  FPR:             {best['fpr']:.4f} ({best['fpr']*100:.2f}%)")
    lines.append(f"  Inference Time:  {best['avg_inference_ms']:.4f}ms per sample")
    lines.append(f"  Training Time:   {best['train_time']:.2f}s")
    lines.append("")
    lines.append("TARGET ACHIEVEMENT:")
    lines.append(f"  Accuracy >= 85%:    {'PASS' if best['accuracy'] >= 0.85 else 'FAIL'}")
    lines.append(f"  F1-Score >= 0.80:   {'PASS' if best['f1_score'] >= 0.80 else 'FAIL'}")
    lines.append(f"  FPR < 10%:          {'PASS' if best['fpr'] < 0.10 else 'FAIL'}")
    lines.append("=" * 70)

    report = "\n".join(lines)
    report_path = os.path.join(output_dir, 'evaluation_summary.txt')
    with open(report_path, 'w') as f:
        f.write(report)

    print(report)
    print(f"\n  Saved to: {report_path}")


def main():
    """Main evaluation pipeline."""
    print("=" * 60)
    print("NETWORK INTRUSION DETECTION SYSTEM")
    print("Model Evaluation Pipeline")
    print("=" * 60)

    # Setup paths
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model')
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    os.makedirs(output_dir, exist_ok=True)

    # Load evaluation data
    data = load_evaluation_data(model_dir)
    y_test = data['y_test']
    label_encoder = data['label_encoder']
    results = data['results']

    # Generate all reports and plots
    generate_classification_reports(results, y_test, label_encoder, output_dir)
    plot_confusion_matrices(results, y_test, label_encoder, output_dir)
    plot_model_comparison(results, output_dir)
    generate_summary_report(results, output_dir)

    print(f"\n{'=' * 60}")
    print("Evaluation Complete!")
    print(f"All reports saved to: {output_dir}")
    print(f"{'=' * 60}")


if __name__ == '__main__':
    main()
