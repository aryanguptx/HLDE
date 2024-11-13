import joblib
import tensorflow as tf
from Utilities.Preprocessing.packet_parser import parse_pcap_files
from Utilities.Preprocessing.metrics_calculator import calculate_metrics_for_all_teids
from Utilities.Preprocessing.preprocessor import prepare_feature_dataframe
from Utilities.Inference.confidence_calculators import calculate_rf_confidence, calculate_autoencoder_confidence
from Utilities.Decision_fusion.dfe import decision_fusion
from Utilities.Rule_generation.rule_generator import generate_snort_rules


def main():
    feature_columns = [
        'Avg Packet Size', 'Packet Length Mean', 'Bwd Packet Length Std',
        'Packet Length Variance', 'Bwd Packet Length Max', 'Packet Length Max',
        'Packet Length Std', 'Fwd Packet Length Mean', 'Flow Bytes/s',
        'Bwd Packet Length Mean', 'Fwd Packets/s', 'Flow Packets/s',
        'Subflow Fwd Bytes', 'Fwd Packets Length Total', 'Total Fwd Packets',
        'Subflow Fwd Packets'
    ]

    teid_dict = parse_pcap_files("Data/Pcaps")
    metric_list = calculate_metrics_for_all_teids(teid_dict)
    metric_dataframe = prepare_feature_dataframe(feature_columns, metric_list)
    print(metric_dataframe.columns)

    autoencoder = tf.keras.models.load_model('Models/autoencoder_model.keras')
    model = joblib.load('Models/random_forest_classifier2.joblib')

    feature_column_scaled = metric_dataframe[feature_columns]

    rf_labels, rf_probs = calculate_rf_confidence(model, feature_column_scaled)
    metric_dataframe['predicted_class_rf'] = rf_labels
    metric_dataframe['rf_confidence'] = rf_probs

    anomaly_labels, autoencoder_confidences = calculate_autoencoder_confidence(autoencoder, feature_column_scaled)
    metric_dataframe['anomaly_label'] = anomaly_labels
    metric_dataframe['autoencoder_confidence'] = autoencoder_confidences

    print(metric_dataframe.head())
    malicious_df = decision_fusion(metric_dataframe)
    print(malicious_df.head())
    generate_snort_rules(malicious_df)


if __name__ == "__main__":
    main()
