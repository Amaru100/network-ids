"""
train_model.py - Train and Compare ML Models for Network Intrusion Detection
==============================================================================
This script trains four machine learning algorithms on the NSL-KDD dataset,
compares their performance, and saves the best model for real-time classification.

Algorithms:
1. Random Forest
2. Decision Tree
3. K-Nearest Neighbours (KNN)
4. Gradient Boosting

Selection Criteria:
- Primary: Highest F1-Score (weighted)
- Secondary: Fastest inference time
- Targets: Accuracy >= 85%, F1-Score >= 0.80, False Positive Rate < 10%

Author: University of Botswana - Final Year Project
"""

import os
import sys
import time
import warnings
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from preprocess import preprocess_data

warnings.filterwarnings('ignore')


def calculate_false_positive_rate(y_true, y_pred, label_encoder):
    """
    Calculate the False Positive Rate for an IDS context.
    FPR = (Normal traffic incorrectly flagged as attack) / (Total Normal traffic)
    This measures false alarms - how often the system cries wolf on benign traffic.

    Args:
        y_true (np.ndarray): True labels.
        y_pred (np.ndarray): Predicted labels.
        label_encoder: Fitted LabelEncoder.

    Returns:
        float: False Positive Rate (false alarm rate for normal traffic).
    """
    normal_idx = list(label_encoder.classes_).index('Normal')

    # Find all samples that are truly Normal
    truly_normal_mask = (y_true == normal_idx)
    total_normal = truly_normal_mask.sum()

    if total_normal == 0:
        return 0.0

    # Of those truly Normal samples, how many were misclassified as attacks?
    false_alarms = (y_pred[truly_normal_mask] != normal_idx).sum()

    fpr = false_alarms / total_normal
    return fpr


def train_and_evaluate_model(name, model, X_train, y_train, X_test, y_test, label_encoder):
    """
    Train a single model, measure training and inference times, and evaluate performance.

    Args:
        name (str): Model name for display.
        model: scikit-learn classifier instance.
        X_train, y_train: Training data.
        X_test, y_test: Test data.
        label_encoder: Fitted LabelEncoder for class names.

    Returns:
        dict: Performance metrics including accuracy, precision, recall, F1, FPR,
              training time, inference time, and the trained model.
    """
    print(f"\n{'─' * 50}")
    print(f"Training: {name}")
    print(f"{'─' * 50}")

    # Train the model
    start_train = time.time()
    model.fit(X_train, y_train)
    train_time = time.time() - start_train
    print(f"  Training time: {train_time:.2f}s")

    # Make predictions and measure inference time
    start_inference = time.time()
    y_pred = model.predict(X_test)
    inference_time = time.time() - start_inference
    avg_inference_per_sample = (inference_time / len(X_test)) * 1000  # ms per sample
    print(f"  Total inference time: {inference_time:.4f}s ({avg_inference_per_sample:.4f}ms per sample)")

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    fpr = calculate_false_positive_rate(y_test, y_pred, label_encoder)

    print(f"  Accuracy:             {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"  Precision (weighted): {precision:.4f}")
    print(f"  Recall (weighted):    {recall:.4f}")
    print(f"  F1-Score (weighted):  {f1:.4f}")
    print(f"  False Positive Rate:  {fpr:.4f} ({fpr*100:.2f}%)")

    # Check against targets
    targets_met = []
    if accuracy >= 0.85:
        targets_met.append("Accuracy >= 85%")
    if f1 >= 0.80:
        targets_met.append("F1 >= 0.80")
    if fpr < 0.10:
        targets_met.append("FPR < 10%")

    print(f"  Targets met: {len(targets_met)}/3 - {', '.join(targets_met) if targets_met else 'None'}")

    return {
        'name': name,
        'model': model,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'fpr': fpr,
        'train_time': train_time,
        'inference_time': inference_time,
        'avg_inference_ms': avg_inference_per_sample,
        'y_pred': y_pred,
        'targets_met': len(targets_met),
    }


def select_best_model(results):
    """
    Select the best model based on F1-Score (primary) and inference time (secondary).

    Args:
        results (list): List of result dictionaries from train_and_evaluate_model.

    Returns:
        dict: The result dictionary of the best model.
    """
    # Sort by F1-Score descending, then by inference time ascending
    sorted_results = sorted(results, key=lambda x: (-x['f1_score'], x['inference_time']))
    return sorted_results[0]


def print_comparison_table(results, best_name):
    """
    Print a formatted comparison table of all models.

    Args:
        results (list): List of result dictionaries.
        best_name (str): Name of the best model.
    """
    print(f"\n{'=' * 90}")
    print("MODEL COMPARISON TABLE")
    print(f"{'=' * 90}")
    print(f"{'Model':<22} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1-Score':>10} {'FPR':>8} {'Inf(ms)':>10} {'Best':>6}")
    print(f"{'─' * 90}")

    for r in results:
        is_best = "  ★" if r['name'] == best_name else ""
        print(f"{r['name']:<22} {r['accuracy']:>10.4f} {r['precision']:>10.4f} "
              f"{r['recall']:>10.4f} {r['f1_score']:>10.4f} {r['fpr']:>8.4f} "
              f"{r['avg_inference_ms']:>10.4f} {is_best}")

    print(f"{'─' * 90}")
    print(f"★ = Selected best model (highest F1-Score, fastest inference)")
    print(f"{'=' * 90}")


def main():
    """Main training pipeline."""
    print("=" * 60)
    print("NETWORK INTRUSION DETECTION SYSTEM")
    print("ML Model Training Pipeline")
    print("=" * 60)

    # Step 1: Preprocess data
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
    data = preprocess_data(data_dir)

    X_train = data['X_train']
    X_test = data['X_test']
    y_train = data['y_train']
    y_test = data['y_test']
    label_encoder = data['label_encoder']

    print(f"\n{'=' * 60}")
    print("Training 4 Machine Learning Models")
    print(f"{'=' * 60}")

    # Step 2: Define models with optimised hyperparameters
    # class_weight='balanced' helps handle the imbalanced dataset (U2R and R2L are rare)
    models = {
        'Random Forest': RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            n_jobs=-1,
            random_state=42
        ),
        'Decision Tree': DecisionTreeClassifier(
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42
        ),
        'KNN (k=3)': KNeighborsClassifier(
            n_neighbors=3,
            weights='distance',
            n_jobs=-1
        ),
        'Gradient Boosting': GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=7,
            min_samples_split=5,
            subsample=0.8,
            random_state=42
        ),
    }

    # Step 3: Train and evaluate each model
    results = []
    for name, model in models.items():
        result = train_and_evaluate_model(
            name, model, X_train, y_train, X_test, y_test, label_encoder
        )
        results.append(result)

    # Step 4: Select best model
    best = select_best_model(results)

    # Step 5: Print comparison table
    print_comparison_table(results, best['name'])

    # Step 6: Save the best model
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model')
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'best_model.pkl')

    joblib.dump(best['model'], model_path)
    print(f"\n[+] Best model saved to: {model_path}")
    print(f"    Model: {best['name']}")
    print(f"    Accuracy: {best['accuracy']:.4f} ({best['accuracy']*100:.2f}%)")
    print(f"    F1-Score: {best['f1_score']:.4f}")
    print(f"    FPR: {best['fpr']:.4f} ({best['fpr']*100:.2f}%)")
    print(f"    Avg inference: {best['avg_inference_ms']:.4f}ms per sample")

    # Save all results for evaluation script
    results_path = os.path.join(model_dir, 'training_results.pkl')
    # Remove model objects from results to reduce file size
    results_to_save = []
    for r in results:
        r_copy = {k: v for k, v in r.items() if k != 'model'}
        results_to_save.append(r_copy)
    joblib.dump(results_to_save, results_path)
    print(f"[+] Training results saved to: {results_path}")

    # Save test data info for evaluation
    eval_data = {
        'y_test': y_test,
        'label_encoder': label_encoder,
        'results': results_to_save,
    }
    eval_path = os.path.join(model_dir, 'eval_data.pkl')
    joblib.dump(eval_data, eval_path)
    print(f"[+] Evaluation data saved to: {eval_path}")

    print(f"\n{'=' * 60}")
    print("Training Pipeline Complete!")
    print(f"{'=' * 60}")

    return results, best


if __name__ == '__main__':
    results, best = main()
