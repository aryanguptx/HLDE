import numpy as np


def calculate_metrics(teid, teid_packets):
    """
    Calculate flow metrics for packets with the same TEID.

    Parameters:
        teid_packets (list): List of packet information dictionaries for a specific TEID.

    Returns:
        dict: Calculated metrics for the flow.
    """
    fwd_packet_lengths = [p['length'] for p in teid_packets if p['direction'] == "fwd"]
    bwd_packet_lengths = [p['length'] for p in teid_packets if p['direction'] == "bwd"]
    all_packet_lengths = [p['length'] for p in teid_packets]
    total_duration = teid_packets[-1]["timestamp"] - teid_packets[0]["timestamp"]

    metrics = {
        "Avg Packet Size": np.mean(all_packet_lengths) if all_packet_lengths else 0,
        "Packet Length Mean": np.mean(all_packet_lengths) if all_packet_lengths else 0,
        "Bwd Packet Length Std": np.std(bwd_packet_lengths) if bwd_packet_lengths else 0,
        "Packet Length Variance": np.var(all_packet_lengths) if all_packet_lengths else 0,
        "Bwd Packet Length Max": max(bwd_packet_lengths) if bwd_packet_lengths else 0,
        "Packet Length Max": max(all_packet_lengths) if all_packet_lengths else 0,
        "Packet Length Std": np.std(all_packet_lengths) if all_packet_lengths else 0,
        "Fwd Packet Length Mean": np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0,
        "Flow Bytes/s": sum(all_packet_lengths) / total_duration if total_duration > 0 else 0,
        "Bwd Packet Length Mean": np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
        "Fwd Packets/s": len(fwd_packet_lengths) / total_duration if total_duration > 0 else 0,
        "Flow Packets/s": len(all_packet_lengths) / total_duration if total_duration > 0 else 0,
        "Subflow Fwd Bytes": sum(fwd_packet_lengths),
        "Fwd Packets Length Total": sum(fwd_packet_lengths),
        "Total Fwd Packets": len(fwd_packet_lengths),
        "Subflow Fwd Packets": len(fwd_packet_lengths),
        "Src IP": teid_packets[0]['src_ip'],
        "Dst IP": teid_packets[0]['dst_ip'],
        "TEID": teid
    }
    return metrics


def calculate_metrics_for_all_teids(teid_dict):
    """
    Calculate metrics for each TEID in the given dictionary.

    Parameters:
        teid_dict (dict): Dictionary with TEID as keys and lists of packet information as values.

    Returns:
        list: List of dictionaries with metrics for each TEID.
    """
    metrics_list = []
    for teid, packets in teid_dict.items():
        metrics = calculate_metrics(teid, packets)
        metrics_list.append(metrics)
    print(metrics_list[0])
    print(len(metrics_list[0]))
    return metrics_list
