"""
classifier.py - Real-Time Traffic Classification and Alert Dispatch
=====================================================================
This module loads the trained ML model and preprocessors, classifies
incoming network traffic features, and sends alerts to the backend API.

Responsibilities:
- Load the trained model, scaler, label encoder, and feature names
- Transform raw feature dictionaries into model-ready input vectors
- Classify traffic and compute confidence scores
- Determine alert severity based on confidence thresholds
- Send alerts to the backend API via HTTP POST

Confidence Thresholds:
- Above 80%: Clear alert with classification + email notification
- 50-80%: Suspicious activity flag (no email)
- Below 50%: Flagged for review (no email)

Author: University of Botswana - Final Year Project
"""

import os
import json
import time
import logging
import numpy as np
import pandas as pd
import joblib
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('NIDS-Classifier')


class TrafficClassifier:
    """
    Classifies network traffic features using the trained ML model.
    Handles feature transformation, prediction, and alert dispatching.
    """

    def __init__(self, model_dir, api_url=None, agent_name=None):
        """
        Initialise the classifier by loading all required artifacts.

        Args:
            model_dir (str): Path to the ml/model directory containing:
                             best_model.pkl, scaler.pkl, label_encoder.pkl, feature_names.pkl
            api_url (str): Backend API URL for sending alerts. If None, alerts are logged only.
            agent_name (str): Name of this agent for identifying the monitored machine.
        """
        self.api_url = api_url
        self.model_dir = model_dir
        self.agent_name = agent_name

        # Load trained model and preprocessors
        logger.info("Loading ML model and preprocessors...")
        self.model = joblib.load(os.path.join(model_dir, 'best_model.pkl'))
        self.scaler = joblib.load(os.path.join(model_dir, 'scaler.pkl'))
        self.label_encoder = joblib.load(os.path.join(model_dir, 'label_encoder.pkl'))
        self.feature_names = joblib.load(os.path.join(model_dir, 'feature_names.pkl'))

        logger.info(f"Model loaded: {type(self.model).__name__}")
        logger.info(f"Classes: {list(self.label_encoder.classes_)}")
        logger.info(f"Expected features: {len(self.feature_names)}")

        # Statistics tracking
        self.stats = {
            'total_classified': 0,
            'normal_count': 0,
            'attack_count': 0,
            'alerts_sent': 0,
            'errors': 0,
        }

    def _prepare_features(self, raw_features):
        """
        Transform raw feature dictionary into a model-ready input vector.
        Handles one-hot encoding and scaling to match the training format.

        Args:
            raw_features (dict): Raw features from feature_extractor.

        Returns:
            np.ndarray: Scaled feature vector ready for prediction.
        """
        # Extract metadata (prefixed with _) before creating DataFrame
        metadata = {k: v for k, v in raw_features.items() if k.startswith('_')}
        features = {k: v for k, v in raw_features.items() if not k.startswith('_')}

        # Create a single-row DataFrame
        df = pd.DataFrame([features])

        # One-hot encode categorical columns
        categorical_cols = ['protocol_type', 'service', 'flag']
        df = pd.get_dummies(df, columns=categorical_cols, dtype=int)

        # Align with training feature columns
        # Add missing columns with 0, drop extra columns
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0

        # Keep only the expected columns in the correct order
        df = df[self.feature_names]

        # Scale features
        X = self.scaler.transform(df.values.astype(np.float64))

        return X, metadata

    def classify(self, raw_features):
        """
        Classify a single network connection.

        Args:
            raw_features (dict): Raw features from feature_extractor.

        Returns:
            dict: Classification result with category, confidence, and metadata.
        """
        start_time = time.time()

        try:
            # Prepare features for the model
            X, metadata = self._prepare_features(raw_features)

            # Get prediction and probability scores
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]

            # Decode prediction
            category = self.label_encoder.inverse_transform([prediction])[0]
            confidence = float(probabilities[prediction]) * 100  # Convert to percentage

            # Determine specific attack type hint based on traffic patterns
            attack_type = self._infer_attack_type(raw_features, category)

            # Determine severity based on confidence
            severity = self._get_severity(confidence, category)

            # Calculate classification time
            classification_time_ms = (time.time() - start_time) * 1000

            # Update statistics
            self.stats['total_classified'] += 1
            if category == 'Normal':
                self.stats['normal_count'] += 1
            else:
                self.stats['attack_count'] += 1

            result = {
                'category': category,
                'attack_type': attack_type,
                'confidence': round(confidence, 2),
                'severity': severity,
                'src_ip': metadata.get('_src_ip', 'unknown'),
                'dst_ip': metadata.get('_dst_ip', 'unknown'),
                'dst_port': metadata.get('_dst_port', 0),
                'src_port': metadata.get('_src_port', 0),
                'protocol': metadata.get('_protocol', 'unknown'),
                'classification_time_ms': round(classification_time_ms, 2),
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                'probabilities': {
                    self.label_encoder.inverse_transform([i])[0]: round(float(p) * 100, 2)
                    for i, p in enumerate(probabilities)
                },
            }

            return result

        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Classification error: {e}")
            return None

    def _infer_attack_type(self, features, category):
        """
        Infer the specific attack type based on traffic patterns and the predicted category.
        Since the model predicts categories (not specific types), this provides a best-guess
        based on observable network characteristics.

        Args:
            features (dict): Raw network features.
            category (str): Predicted attack category.

        Returns:
            str: Best-guess specific attack type.
        """
        if category == 'Normal':
            return 'normal'

        service = features.get('service', 'other')
        flag = features.get('flag', 'SF')
        src_bytes = features.get('src_bytes', 0)
        count = features.get('count', 0)

        if category == 'DoS':
            if flag in ['S0', 'S1']:
                return 'SYN Flood (Neptune)'
            elif src_bytes > 1000 and count > 50:
                return 'Smurf'
            elif features.get('wrong_fragment', 0) > 0:
                return 'Teardrop'
            elif features.get('land', 0) == 1:
                return 'Land'
            else:
                return 'DoS Attack'

        elif category == 'Probe':
            if count > 20 or features.get('srv_count', 0) > 20:
                return 'Port Scan (Nmap)'
            elif features.get('dst_host_diff_srv_rate', 0) > 0.5:
                return 'Port Sweep'
            elif features.get('dst_host_same_src_port_rate', 0) > 0.5:
                return 'IP Sweep'
            else:
                return 'Network Probe'

        elif category == 'R2L':
            if service in ['ssh', 'telnet', 'ftp']:
                return 'Brute Force (Guess Password)'
            elif service == 'imap4':
                return 'IMAP Attack'
            elif service == 'http':
                return 'HTTP Tunnel'
            else:
                return 'Remote to Local Attack'

        elif category == 'U2R':
            return 'Privilege Escalation (Buffer Overflow)'

        return 'Unknown Attack'

    def _get_severity(self, confidence, category):
        """
        Determine alert severity based on confidence threshold.

        Args:
            confidence (float): Classification confidence percentage.
            category (str): Predicted category.

        Returns:
            str: Severity level ('high', 'medium', 'low').
        """
        if category == 'Normal':
            return 'none'

        if confidence > 80:
            return 'high'      # Clear alert + email
        elif confidence >= 50:
            return 'medium'    # Suspicious activity flag
        else:
            return 'low'       # Flagged for review

    def send_alert(self, result):
        """
        Send a classification result to the backend API.
        Only sends alerts for detected attacks (not normal traffic).

        Args:
            result (dict): Classification result from classify().

        Returns:
            bool: True if alert was sent successfully.
        """
        if result is None or result['category'] == 'Normal':
            return False

        if self.api_url is None:
            # Log-only mode
            severity_colors = {'high': 'RED', 'medium': 'ORANGE', 'low': 'YELLOW'}
            color = severity_colors.get(result['severity'], 'WHITE')
            logger.warning(
                f"[{color}] ALERT: {result['category']} - {result['attack_type']} | "
                f"From: {result['src_ip']} -> {result['dst_ip']}:{result['dst_port']} | "
                f"Confidence: {result['confidence']}% | Severity: {result['severity']}"
            )
            return True

        try:
            # Send alert to backend API
            response = requests.post(
                f"{self.api_url}/api/alerts",
                json={
                    'category': result['category'],
                    'attack_type': result['attack_type'],
                    'confidence': result['confidence'],
                    'severity': result['severity'],
                    'src_ip': result['src_ip'],
                    'dst_ip': result['dst_ip'],
                    'dst_port': result['dst_port'],
                    'src_port': result['src_port'],
                    'protocol': result['protocol'],
                    'timestamp': result['timestamp'],
                    'agent_name': self.agent_name,
                },
                timeout=15
            )

            if response.status_code in [200, 201]:
                self.stats['alerts_sent'] += 1
                logger.info(f"Alert sent: {result['category']} ({result['confidence']}%)")
                return True
            else:
                logger.error(f"Failed to send alert: HTTP {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to send alert: {e}")
            return False

    def send_normal(self, result):
        """Send a Normal classification to the backend so the normal counter updates."""
        if result is None or self.api_url is None:
            return
        try:
            requests.post(
                f"{self.api_url}/api/alerts",
                json={
                    'category': 'Normal',
                    'attack_type': 'normal',
                    'confidence': result['confidence'],
                    'severity': 'none',
                    'src_ip': result['src_ip'],
                    'dst_ip': result['dst_ip'],
                    'dst_port': result['dst_port'],
                    'src_port': result['src_port'],
                    'protocol': result['protocol'],
                    'timestamp': result['timestamp'],
                    'agent_name': self.agent_name,
                },
                timeout=5
            )
        except requests.exceptions.RequestException:
            pass  # Don't log errors for normal traffic updates

    def send_normal_batch(self, count):
        """Send a batch normal traffic count to the backend (one HTTP call for many packets)."""
        if self.api_url is None or count <= 0:
            return
        try:
            requests.post(
                f"{self.api_url}/api/alerts",
                json={
                    'category': 'Normal',
                    'attack_type': 'normal',
                    'confidence': 99.0,
                    'severity': 'none',
                    'src_ip': '0.0.0.0',
                    'dst_ip': '0.0.0.0',
                    'dst_port': 0,
                    'src_port': 0,
                    'protocol': 'tcp',
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
                    'agent_name': self.agent_name,
                    'normal_count': count,
                },
                timeout=5
            )
            self.stats['normal_count'] += count
        except requests.exceptions.RequestException:
            pass

    def get_stats(self):
        """Return current classification statistics."""
        total = self.stats['total_classified']
        return {
            **self.stats,
            'attack_percentage': round(
                (self.stats['attack_count'] / total * 100) if total > 0 else 0, 2
            ),
        }
