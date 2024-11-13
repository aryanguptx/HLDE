# models/confidence_calculator.py
import numpy as np


def calculate_rf_confidence(rf_model, input_features, class_labels=['bruteforce', 'benign', 'ddos', 'botnet']):
    """
    Calculate confidence score for Random Forest predictions based on class probability.

    Parameters:
        rf_model (RandomForestClassifier): The pre-trained random forest model.
        input_features (numpy array): Scaled input features.
        class_labels (list): List of class labels in the model.

    Returns:
        tuple: Predicted labels and confidence scores.
    """
    probabilities = rf_model.predict_proba(input_features)
    max_prob_indices = np.argmax(probabilities, axis=1)
    labels = [class_labels[i] for i in max_prob_indices]
    max_probs = probabilities[np.arange(len(probabilities)), max_prob_indices]
    return labels, max_probs


def calculate_autoencoder_confidence(autoencoder_model, input_features, threshold=0.6):
    """
    Calculate confidence score for the autoencoder based on reconstruction error.

    Parameters:
        autoencoder_model (keras Model): The pre-trained autoencoder model.
        input_features (numpy array): Scaled input features.
        threshold (float): Threshold for anomaly detection.

    Returns:
        tuple: Anomaly labels and confidence scores.
    """
    reconstructed = autoencoder_model.predict(input_features)
    reconstruction_error = np.mean((input_features - reconstructed) ** 2, axis=1)
    labels = np.where(reconstruction_error > threshold, "malicious", "benign")
    confidence_scores = np.clip(1 - (reconstruction_error / threshold), 0, 1)
    return labels, confidence_scores
