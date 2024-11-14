import os
from scapy.all import rdpcap, IP, UDP
from scapy.contrib.gtp import GTP_U_Header


def parse_pcap_files(directory_path):
    """
    Parse multiple PCAP files in a specified directory and extract packet data by TEID, 
    including the first inner source and destination IP addresses.

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

                        # Check if the GTP layer contains a UDP layer (GTP is often over UDP)
                        if packet.haslayer(UDP):
                            udp_layer = packet[UDP]
                            # Look for the inner IP layer inside the UDP payload
                            if udp_layer.payload.haslayer(IP):
                                inner_ip = udp_layer.payload[IP]

                                # Extract relevant details for each packet
                                packet_info = {
                                    "timestamp": packet.time,
                                    "size": len(packet),
                                    "direction": "bwd" if packet[IP].dst == "10.53.1.1" else "fwd",
                                    "length": inner_ip.len,  # length of the inner IP layer
                                    "src_ip": inner_ip.src,
                                    "dst_ip": inner_ip.dst
                                }

                                # Append packet information to the TEID dictionary by TEID
                                if teid in teid_dict:
                                    teid_dict[teid].append(packet_info)
                                else:
                                    teid_dict[teid] = [packet_info]

            except Exception as e:
                print(f"Error processing {file_path}: {e}")

    print(teid_dict.keys())  # Optional: To print the TEIDs that were found
    return teid_dict
