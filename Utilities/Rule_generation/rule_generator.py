import os
import hashlib
import tarfile
import socket
import struct


def generate_sid(teid, src_ip, dst_ip):
    """
    Generates a hash-based unique SID from TEID, src_ip, and dst_ip.

    Args:
        teid (str): TEID value.
        src_ip (str): Source IP address.
        dst_ip (str): Destination IP address.

    Returns:
        int: A 6-digit unique SID.
    """
    hash_input = f"{teid}{src_ip}{dst_ip}".encode('utf-8')
    sid_hash = int(hashlib.md5(hash_input).hexdigest(), 16) % (10 ** 6)  # 6-digit SID
    return sid_hash


def ip_to_hex(ip_address):
    """
    Converts an IP address to its hexadecimal representation.

    Args:
        ip_address (str): The IP address to convert.

    Returns:
        str: Hexadecimal representation of the IP address.
    """
    packed_ip = socket.inet_aton(ip_address)
    return struct.unpack("!I", packed_ip)[0]


def make_tarfile(output_filename, source_dir):
    """
    Creates a compressed tar.gz file of the specified directory.

    Args:
        output_filename (str): The path for the tar.gz file to create.
        source_dir (str): The directory to compress.
    """
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
    print(f"Directory '{source_dir}' has been compressed into '{output_filename}'")


def generate_snort_rules(malicious_df, rules_dir="Data/Rules", snort_rules_dir="Data/Rules/snort_rules/snort_rules"):
    """
    Generates Snort rules to block specific TEIDs, appends them to `rulefile.rules`,
    and zips the snort_rules directory.

    Args:
        malicious_df (DataFrame): DataFrame containing rows with malicious TEIDs.
        rules_dir (str): The parent directory for Snort rules and the zipped file.
        snort_rules_dir (str): The directory where the Snort rules file will be saved.
    """
    # Ensure the snort_rules directory exists
    os.makedirs(snort_rules_dir, exist_ok=True)

    # Define the path for the persistent rule file
    rule_file_path = os.path.join(snort_rules_dir, "rulefile.rules")

    # Open file in append mode to add new rules
    with open(rule_file_path, "a") as file:
        for _, row in malicious_df.iterrows():
            # Extract TEID, Src IP, and Dst IP
            teid = row['TEID']
            src_ip = row['Src IP']
            dst_ip = row['Dst IP']

            # Generate a unique SID using the generate_sid function
            sid = generate_sid(teid, src_ip, dst_ip)

            # Convert IPs to hexadecimal
            src_ip_hex = f"{ip_to_hex(src_ip):08x}"
            dst_ip_hex = f"{ip_to_hex(dst_ip):08x}"

            # Generate Snort rule using the new template
            rule = (
                f"alert udp any 2152 -> any any (msg:\"Block malicious TEID {teid}\"; "
                f"gtp_type:255; "
                f"byte_test:4,=,0x{src_ip_hex},28; "
                f"byte_test:4,=,0x{dst_ip_hex},32; "
                f"sid:{sid}; rev:1; "
                f"classification:attempted-admin; priority:1; metadata:service http;)"
            )

            # Write the rule to file
            file.write(rule + "\n")

    print(f"New rules have been appended to {rule_file_path}")

    # Zip the snort_rules directory and save the archive in the rules directory
    zip_file_path = os.path.join(rules_dir, "snort_rules.tar.gz")
    make_tarfile(zip_file_path, rules_dir + "/snort_rules")
    print(f"snort_rules directory has been zipped to {zip_file_path}")
