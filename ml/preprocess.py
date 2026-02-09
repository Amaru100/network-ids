"""
preprocess.py - Data Preprocessing for NSL-KDD Dataset
========================================================
This module handles loading, cleaning, encoding, and normalising the NSL-KDD
dataset so it is ready for machine learning model training.

Features:
- Loads raw NSL-KDD .txt files (no headers)
- Assigns proper column names based on the NSL-KDD specification
- Maps specific attack labels to their 5-class categories (Normal, DoS, Probe, R2L, U2R)
- One-hot encodes categorical features (protocol_type, service, flag)
- Normalises numerical features using Min-Max scaling
- Aligns train and test feature columns to ensure consistency

Author: University of Botswana - Final Year Project
"""

import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import joblib


# ============================================================================
# NSL-KDD Column Names (41 features + label + difficulty)
# ============================================================================
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# ============================================================================
# Attack Type to Category Mapping
# ============================================================================
ATTACK_CATEGORY_MAP = {
    # Normal
    'normal': 'Normal',

    # DoS attacks
    'neptune': 'DoS', 'smurf': 'DoS', 'pod': 'DoS', 'teardrop': 'DoS',
    'land': 'DoS', 'back': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS',

    # Probe attacks
    'portsweep': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',

    # R2L attacks (Remote to Local)
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L',
    'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'worm': 'R2L',

    # U2R attacks (User to Root)
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
}


def load_dataset(filepath):
    """
    Load an NSL-KDD dataset file and assign proper column names.

    Args:
        filepath (str): Path to the .txt dataset file.

    Returns:
        pd.DataFrame: Loaded dataset with proper column names.
    """
    print(f"[*] Loading dataset from: {filepath}")
    df = pd.read_csv(filepath, header=None, names=COLUMN_NAMES)
    print(f"    Loaded {len(df)} records with {len(df.columns)} columns")
    return df


def map_attack_categories(df):
    """
    Map specific attack type labels to their 5-class category.
    Unknown attack types are mapped to the most likely category or 'Unknown'.

    Args:
        df (pd.DataFrame): Dataset with 'label' column containing specific attack types.

    Returns:
        pd.DataFrame: Dataset with added 'attack_category' column and original
                       'label' renamed to 'attack_type'.
    """
    print("[*] Mapping attack types to categories...")

    # Store the original specific attack type
    df['attack_type'] = df['label'].str.strip().str.lower()

    # Map to 5-class categories
    df['attack_category'] = df['attack_type'].map(ATTACK_CATEGORY_MAP)

    # Handle any unmapped attack types (assign to closest category or Unknown)
    unmapped = df[df['attack_category'].isna()]['attack_type'].unique()
    if len(unmapped) > 0:
        print(f"    [!] Warning: Unmapped attack types found: {unmapped}")
        print("    [!] Assigning unmapped types to 'Unknown' category")
        df['attack_category'] = df['attack_category'].fillna('Unknown')

    # Print category distribution
    print("    Category distribution:")
    for cat, count in df['attack_category'].value_counts().items():
        print(f"      {cat}: {count} ({count/len(df)*100:.1f}%)")

    return df


def encode_categorical_features(df_train, df_test):
    """
    One-hot encode categorical features (protocol_type, service, flag).
    Ensures both train and test sets have the same columns after encoding.

    Args:
        df_train (pd.DataFrame): Training dataset.
        df_test (pd.DataFrame): Test dataset.

    Returns:
        tuple: (encoded_train, encoded_test) DataFrames with aligned columns.
    """
    print("[*] One-hot encoding categorical features...")

    categorical_cols = ['protocol_type', 'service', 'flag']

    # One-hot encode both datasets
    df_train_encoded = pd.get_dummies(df_train, columns=categorical_cols, dtype=int)
    df_test_encoded = pd.get_dummies(df_test, columns=categorical_cols, dtype=int)

    # Align columns - ensure both have the same features
    # Add missing columns with 0s
    train_cols = set(df_train_encoded.columns)
    test_cols = set(df_test_encoded.columns)

    for col in train_cols - test_cols:
        df_test_encoded[col] = 0
    for col in test_cols - train_cols:
        df_train_encoded[col] = 0

    # Ensure same column order
    df_test_encoded = df_test_encoded[df_train_encoded.columns]

    print(f"    Train features: {len(df_train_encoded.columns)} columns")
    print(f"    Test features: {len(df_test_encoded.columns)} columns")

    return df_train_encoded, df_test_encoded


def normalise_features(X_train, X_test):
    """
    Apply Min-Max normalisation to scale all numerical features to [0, 1].
    The scaler is fitted on training data only to prevent data leakage.

    Args:
        X_train (np.ndarray): Training feature matrix.
        X_test (np.ndarray): Test feature matrix.

    Returns:
        tuple: (X_train_scaled, X_test_scaled, scaler) normalised arrays and fitted scaler.
    """
    print("[*] Normalising features using Min-Max scaling...")

    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print(f"    Feature range after scaling: [{X_train_scaled.min():.2f}, {X_train_scaled.max():.2f}]")

    return X_train_scaled, X_test_scaled, scaler


def encode_labels(y_train, y_test):
    """
    Encode attack category labels as integers for model training.

    Args:
        y_train (pd.Series): Training labels (attack categories).
        y_test (pd.Series): Test labels (attack categories).

    Returns:
        tuple: (y_train_encoded, y_test_encoded, label_encoder)
    """
    print("[*] Encoding labels...")

    le = LabelEncoder()
    y_train_encoded = le.fit_transform(y_train)
    y_test_encoded = le.transform(y_test)

    print(f"    Label classes: {list(le.classes_)}")
    print(f"    Encoding: {dict(zip(le.classes_, le.transform(le.classes_)))}")

    return y_train_encoded, y_test_encoded, le


def preprocess_data(data_dir):
    """
    Complete preprocessing pipeline for the NSL-KDD dataset.

    Steps:
    1. Load train and test datasets
    2. Map attack types to 5-class categories
    3. One-hot encode categorical features
    4. Normalise numerical features
    5. Encode labels
    6. Save the scaler and label encoder for later use

    Args:
        data_dir (str): Path to directory containing KDDTrain+.txt and KDDTest+.txt

    Returns:
        dict: Dictionary containing all preprocessed data and fitted transformers.
    """
    print("=" * 60)
    print("NSL-KDD Dataset Preprocessing Pipeline")
    print("=" * 60)

    # Step 1: Load datasets
    train_path = os.path.join(data_dir, 'KDDTrain+.txt')
    test_path = os.path.join(data_dir, 'KDDTest+.txt')

    df_train = load_dataset(train_path)
    df_test = load_dataset(test_path)

    # Step 2: Map attack categories
    df_train = map_attack_categories(df_train)
    df_test = map_attack_categories(df_test)

    # Remove the difficulty column (not a feature) and original label column
    cols_to_drop = ['difficulty', 'label']
    df_train = df_train.drop(columns=cols_to_drop)
    df_test = df_test.drop(columns=cols_to_drop)

    # Separate labels before encoding features
    y_train_category = df_train['attack_category']
    y_test_category = df_test['attack_category']
    y_train_type = df_train['attack_type']
    y_test_type = df_test['attack_type']

    df_train = df_train.drop(columns=['attack_category', 'attack_type'])
    df_test = df_test.drop(columns=['attack_category', 'attack_type'])

    # Step 3: One-hot encode categorical features
    df_train, df_test = encode_categorical_features(df_train, df_test)

    # Save feature names before converting to numpy
    feature_names = list(df_train.columns)

    # Step 4: Normalise features
    X_train = df_train.values.astype(np.float64)
    X_test = df_test.values.astype(np.float64)
    X_train, X_test, scaler = normalise_features(X_train, X_test)

    # Step 5: Encode labels
    y_train, y_test, label_encoder = encode_labels(y_train_category, y_test_category)

    # Step 6: Save transformers
    model_dir = os.path.join(os.path.dirname(data_dir), 'ml', 'model')
    os.makedirs(model_dir, exist_ok=True)

    scaler_path = os.path.join(model_dir, 'scaler.pkl')
    encoder_path = os.path.join(model_dir, 'label_encoder.pkl')
    features_path = os.path.join(model_dir, 'feature_names.pkl')

    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    joblib.dump(feature_names, features_path)

    print(f"\n[*] Saved scaler to: {scaler_path}")
    print(f"[*] Saved label encoder to: {encoder_path}")
    print(f"[*] Saved feature names to: {features_path}")

    print(f"\n{'=' * 60}")
    print(f"Preprocessing Complete")
    print(f"{'=' * 60}")
    print(f"  Training samples:  {X_train.shape[0]}")
    print(f"  Test samples:      {X_test.shape[0]}")
    print(f"  Features:          {X_train.shape[1]}")
    print(f"  Classes:           {list(label_encoder.classes_)}")

    return {
        'X_train': X_train,
        'X_test': X_test,
        'y_train': y_train,
        'y_test': y_test,
        'y_train_category': y_train_category,
        'y_test_category': y_test_category,
        'y_train_type': y_train_type,
        'y_test_type': y_test_type,
        'scaler': scaler,
        'label_encoder': label_encoder,
        'feature_names': feature_names,
    }


if __name__ == '__main__':
    # Run preprocessing pipeline
    data_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data')
    result = preprocess_data(data_directory)
    print("\n[+] Preprocessing completed successfully!")
