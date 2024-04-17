"""
Knowledge Integration System Service
Collects detection logs as well as IPS/IDS logs
provides a security recommendation based on 
knowledge integrated from the logs

"""
from detection_log_parser import find_low_scores, file_checksum
from alert_parser import parse_snort_alerts, save_alerts_to_csv

class KISS:
    def __init__(self) -> None:
        # store low conf scores from inference
        self.lowScores = []
        # self.networkLogs = []


    def parseInferenceLogs(self, log_filepath):
        """Parse the inference logs to find 
        low detection scores

        Args:
            log_filepath (str): file path of the log
        """
        print(f"File checksum: {file_checksum(log_filepath)}")
        self.lowScores = find_low_scores()
        return
    
    def parseIDSAlerts(self, alert_filepath, printAlerts=False):
        alert_file_path = './snort_alerts/alert.1'
        alerts = parse_snort_alerts(alert_file_path)
        if (printAlerts):
            print(alerts)  # Optionally print the alerts to see the output
        output_csv_path = 'parsed_snort_alerts.csv'
        save_alerts_to_csv(alerts, output_csv_path)
    
    
    


