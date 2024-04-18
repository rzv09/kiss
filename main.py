import sys
from inference_logger import InferenceLogger
from kiss import KISS

def main():
    inf_logger = InferenceLogger('./model/best.pt')
    try:
        image_dir = sys.argv[1]
        ids_alerts_file=sys.argv[2]
        inf_logger.detect(image_dir)
        
        kiss = KISS()
        kiss.parseInferenceLogs()
        kiss.parseIDSAlerts(alert_file_path=ids_alerts_file)
        kiss.aggregate_knowledge()

    except Exception as e:
        print(e)

def print_usage():
    usage_message = (
        "Usage: python3 main.py <image set directory> <IDS alerts file>\n"
        "\n"
        "Arguments:\n"
        "  <image set directory>   Directory containing the image sets to be processed.\n"
        "  <IDS alerts file>       File containing IDS alerts for analysis.\n"
        "\n"
        "Example:\n"
        "  python main.py /path/to/images /path/to/alerts\n"
        "\n"
        "This command starts the Knowledge Integration System Service (KISS), processing\n"
        "images from the specified image directory and analyzing IDS alerts from the\n"
        "specified alerts directory."
    )
    
    print(usage_message)

if __name__ == "__main__":
    main()