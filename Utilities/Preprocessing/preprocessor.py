# metrics/preprocessor.py
import pandas as pd
from sklearn.preprocessing import MinMaxScaler


def prepare_feature_dataframe(feature_columns, metrics_list):
    """
    Convert a list of metric dictionaries to a DataFrame and scale features.

    Parameters:
        metrics_list (list): List of dictionaries with metrics for each TEID.

    Returns:
        pd.DataFrame: Scaled feature DataFrame ready for model input.
        :param feature_columns:
    """

    # Convert to DataFrame
    metrics_df = pd.DataFrame(metrics_list)

    # Ensure DataFrame has the correct columns
    X = metrics_df[feature_columns]

    # Scale features using MinMaxScaler
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    metrics_df[feature_columns] = X_scaled
    return metrics_df

