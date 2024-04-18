"""
Knowledge Integration System Service
Collects detection logs as well as IPS/IDS logs
provides a security recommendation based on 
knowledge integrated from the logs

"""
from detection_log_parser import find_low_scores, file_checksum
from alert_parser import parse_snort_alerts, save_alerts_to_csv
from utils import match_signatures_with_ids
from query_attackcti import find_mitigations

output_csv_path = 'parsed_snort_alerts.csv'

class KISS:
    def __init__(self) -> None:
        # store low conf scores from inference
        self.lowScores = []
        self.recordsRead = 0
        self.numAlerts = 0

    def parseInferenceLogs(self, log_filepath='detections_logs.json'):
        """Parse the inference logs to find 
        low detection scores

        Args:
            log_filepath (str): file path of the log
        """
        print(f"File checksum: {file_checksum(log_filepath)}")
        self.recordsRead, self.lowScores = find_low_scores()
        return
    
    def parseIDSAlerts(self, alert_file_path='./snort_alerts/alert.1', printAlerts=False):
        alerts = parse_snort_alerts(alert_file_path)
        self.numAlerts = len(alerts)
        if (printAlerts):
            print(alerts)  # Optionally print the alerts to see the output
        save_alerts_to_csv(alerts, output_csv_path)
    
    def aggregate_knowledge(self):
        # first, see if any potential adversarial attacks
        if (len(self.lowScores) > 0):
            self.display_results(self.recordsRead, len(self.lowScores), 'adversarial')
        
        if (self.numAlerts > 0):
            pattern_ids_matched = match_signatures_with_ids(output_csv_path)
            for pattern_id in pattern_ids_matched:
                find_mitigations(pattern_id)
        

    def display_results(self, records_read, attacks_detected, attack_type):
    # Using formatted strings to create a clean and readable message
        print("\n")
        print("="*40)  # prints a line to separate the message for clarity
        print("Summary of the Security Analysis")
        print("="*40)
        print(f"Total records read: {records_read}")
        print(f"Potential {attack_type} attacks detected: {attacks_detected}")
        print("="*40)
        print("\n")  


    # first, scan the detection file
    # second, scan the IDS/IPS file
    # then, provide recommendations based on that
    # (finally) implement multithreaded file reading
    


