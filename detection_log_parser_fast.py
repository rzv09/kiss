import orjson
from utils import time_function, file_checksum
import hashlib

# log_file = 'large_detection_log.json'
log_file = 'detections_logs.json'

image = 0
# confidence = 

@time_function
def find_low_scores(print_alerts=False):
    low_conf_scores = []
    with open(log_file, 'r') as file:
        for n, line in enumerate(file):
            # print(line)
            d = orjson.loads(line)
            print(d[0])
            try:
                if (d['confidence'] < 0.5):
                    record = {
                        'file_name': d['image'],
                        'class': d['class'],
                        'confidence': d['confidence']
                    }
                    low_conf_scores.append(record)
            except:
                # print(d)
                pass
     


    # low_conf_scores = []
    # print(len(data))
    # for item in data:
    #     if item['confidence'] < 0.5:
    #         record = {
    #             'file_name': item['image'],
    #             'class': item['class'],
    #             'confidence': item['confidence']
    #         }
    #         low_conf_scores.append(record)
    
    if (print_alerts):
        print('##########################################')
        print(f"Potential attacks:{len(low_conf_scores)}")
        print('##########################################')
    return low_conf_scores


if __name__=='__main__':

    print(f"File checksum: {file_checksum(log_file)}")
    find_low_scores(print_alerts=True)