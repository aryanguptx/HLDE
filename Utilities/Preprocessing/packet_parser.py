import os
from scapy.all import rdpcap, IP
from scapy.contrib.gtp import GTP_U_Header


def parse_pcap_files(directory_path):
    """
    Parse multiple PCAP files in a specified directory and extract packet data by TEID.

    Parameters:
        directory_path (str): Path to the directory containing PCAP files.

    Returns:
        dict: Dictionary where each TEID maps to a list of packet information.
    """
    teid_dict = {}

    # Loop over each file in the directory
    for filename in os.listdir(directory_path):
        if filename.endswith(".pcap") or filename.endswith(".pcapng"):
            file_path = os.path.join(directory_path, filename)
            print(f"Processing file: {file_path}")

            try:
                packets = rdpcap(file_path)

                for packet in packets:
                    # Check if packet has a GTP layer
                    if packet.haslayer(GTP_U_Header):
                        gtp_layer = packet[GTP_U_Header]
                        teid = gtp_layer.teid

                        # Extract relevant details for each packet
                        packet_info = {
                            "timestamp": packet.time,
                            "size": len(packet),
                            "direction": "bwd" if packet[IP].dst == "10.53.1.1" else "fwd",
                            "length": gtp_layer.length,
                            "src_ip": packet[IP].src,
                            "dst_ip": packet[IP].dst
                        }

                        # Append packet to the context dictionary by TEID
                        if teid in teid_dict:
                            teid_dict[teid].append(packet_info)
                        else:
                            teid_dict[teid] = [packet_info]

            except Exception as e:
                print(f"Error processing {file_path}: {e}")
    print(teid_dict.keys())
    return teid_dict
