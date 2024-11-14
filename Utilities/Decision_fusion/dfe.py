import numpy as np


def decision_fusion(metrics_df, ae_weight=0.6, rf_weight=0.4):
    """
    Perform decision fusion to determine the final verdict for each entry in metrics_df
    based on weighted confidence scores from the autoencoder and Random Forest.

    Parameters:
    - metrics_df (pd.DataFrame): DataFrame containing 'predicted_class_rf', 'autoencoder_confidence',
                                 'rf_confidence', and 'anomaly_label' columns.
    - ae_weight (float): Weight for the autoencoder confidence score.
    - rf_weight (float): Weight for the Random Forest confidence score.

    Returns:
    - pd.DataFrame: Updated DataFrame with 'final_verdict' column indicating the final classification.
    """
    # Convert Random Forest prediction to a binary label (benign/malicious)
    metrics_df['rf_binary'] = metrics_df['predicted_class_rf'].apply(
        lambda x: 'benign' if x == 'benign' else 'malicious'
    )

    # Calculate weighted confidence scores
    metrics_df['weighted_ae_confidence'] = metrics_df['autoencoder_confidence'] * ae_weight
    metrics_df['weighted_rf_confidence'] = metrics_df['rf_confidence'] * rf_weight

    # Determine the final verdict based on the highest weighted confidence score
    metrics_df['final_verdict'] = np.where(
        metrics_df['weighted_ae_confidence'] > metrics_df['weighted_rf_confidence'],
        np.where(metrics_df['anomaly_label'] == 'malicious', 'malicious', 'benign'),
        metrics_df['rf_binary']
    )

    malicious_df = metrics_df[metrics_df['final_verdict'] == 'malicious']

    return malicious_df
