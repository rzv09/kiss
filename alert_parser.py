import csv
import re
from utils import match_signatures_with_ids
from query_attackcti import find_mitigations

def parse_snort_alerts(file_path):
    """
    Parses a Snort alert file and extracts information about each alert.

    Args:
    file_path (str): The path to the Snort alert file.

    Returns:
    list of dicts: A list containing information about each alert.
    """
    alerts = []
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('[**]'):
                try:
                    # Start of a new alert
                    alert = {}
                    match = re.search(r'\[\*\*\] \[[^\]]+\] ([^\[]+)', line)
                    if match:
                        alert['type'] = match.group(1).strip()

                    # skip one line
                    next_line = next(file)

                    # Read the next line for timestamp and IP details
                    next_line = next(file).strip()
                    parts = next_line.split(' ')
                    alert['timestamp'] = parts[0]
                    alert['src_ip'] = parts[1]
                    alert['dst_ip'] = parts[3]
                    alerts.append(alert)
                except:
                    pass
    return alerts

def save_alerts_to_csv(alerts, output_file):
    """
    Saves a list of alert dictionaries to a CSV file.

    Args:
    alerts (list of dicts): The list of alert dictionaries.
    output_file (str): The path to the output CSV file.
    """
    keys = alerts[0].keys()  # Assuming all dictionaries have the same keys
    with open(output_file, 'w', newline='') as file:
        dict_writer = csv.DictWriter(file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(alerts)

def parse_new_logs(file_path, output_filename):
    # Define the regular expression pattern to extract the needed data
    pattern = re.compile(r"""
        (?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6})   # timestamp
        \s+\[\*\*\]\s+\[\d+:\d+:\d+\]\s+                       # ignore rule details
        (?P<type>[\w\s]+)                               # attack type
        \s+\[\*\*\]\s+                                         # ignore marker
        (?:\[.*?\]\s+)?                                        # ignore optional parts like classification
        \{(?P<protocol>\w+)\}\s+                               # protocol
        (?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)\s+    # source IP and port
        -+\s*>\s*
        (?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)       # destination IP and port
        """, re.VERBOSE)
    
    # Parse the content
    parsed_data = []
    # for line in log_content.strip().split('\n'):
    with open(file_path, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                parsed_data.append(match.groupdict())

    # Write to CSV file
    # with open(output_filename, 'a', newline='') as csvfile:
    #     fieldnames = ['timestamp', 'attack_type', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port']
    #     writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    #     writer.writeheader()
    #     for entry in parsed_data:
    #         writer.writerow(entry)
    return parsed_data

# Usage
if __name__ == '__main__':
    alert_file_path = './snort_alerts/SnortAlert.txt'
    output_csv_path = 'parsed_snort_alerts.csv'
    alerts = parse_new_logs(alert_file_path, output_csv_path)
    print(alerts)  # Optionally print the alerts to see the output

    save_alerts_to_csv(alerts, output_csv_path)

    pattern_ids_matched = match_signatures_with_ids(output_csv_path)
    for pattern_id in pattern_ids_matched:
        find_mitigations(pattern_id)