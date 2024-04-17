import sys
from inference_logger import InferenceLogger
from detection_log_parser import find_low_scores

def main():
    inf_logger = InferenceLogger('./model/best.pt')
    image_dir = sys.argv[1]
    inf_logger.detect(image_dir)
    find_low_scores()

if __name__ == "__main__":
    main()