import csv

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
                # Start of a new alert
                alert = {}
                header = line.strip().split('] [')
                alert['sid'] = header[1].split(':')[1]
                alert['rev'] = header[1].split(':')[2]
                
                # Read the next line for classification and priority
                next_line = next(file).strip()
                classification_part = next_line.split('] [')
                alert['classification'] = classification_part[0].split(': ')[1]

                # Read the next line for timestamp and IP details
                next_line = next(file).strip()
                parts = next_line.split(' ')
                alert['timestamp'] = parts[0]
                alert['src_ip'] = parts[1].split(':')[0]
                alert['src_port'] = parts[1].split(':')[1]
                alert['dst_ip'] = parts[3].split(':')[0]
                alert['dst_port'] = parts[3].split(':')[1]
                alerts.append(alert)
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

# Usage
# alert_file_path = './snort_alerts/alert.1'
# alerts = parse_snort_alerts(alert_file_path)
# print(alerts)  # Optionally print the alerts to see the output

# output_csv_path = 'parsed_snort_alerts.csv'
# save_alerts_to_csv(alerts, output_csv_path)
