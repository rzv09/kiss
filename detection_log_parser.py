import json
from utils import time_function, file_checksum
import concurrent.futures

# log_file = 'large_detection_log.json'
log_file = 'detections_logs.json'

@time_function
def find_low_scores(print_alerts=False):
    with open(log_file, 'r') as file:
        data = json.load(file)

    low_conf_scores = []
    print(len(data))
    for item in data:
        if item['confidence'] < 0.5:
            record = {
                'file_name': item['image'],
                'class': item['class'],
                'confidence': item['confidence']
            }
            low_conf_scores.append(record)
    
    if (print_alerts):
        print('##########################################')
        print(f"Potential attacks:{len(low_conf_scores)}")
        print('##########################################')
    return low_conf_scores

def process_chunk(chunk):
    low_conf_rec = []
    for item in chunk:
        if item['confidence'] < 0.5:
            record = {
                'file_name': item['image'],
                'class': item['class'],
                'confidence': item['confidence']
            }
            low_conf_rec.append(record)
    return low_conf_rec

@time_function
def find_low_scores_parallel(print_alerts=False):
    with open(log_file, 'r') as file:
        data = json.load(file)
    
    num_workers = 8
    chunk_size = len(data) // num_workers

    # split data into chunks chunks
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    results = []
    # process chunks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_chunk = {executor.submit(process_chunk, chunk): chunk for chunk in chunks}
        for future in concurrent.futures.as_completed(future_to_chunk):
            results.extend(future.result())        

    print('##########################################')
    print(f"Potential attacks:{len(results)}")
    print('##########################################')

def read_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content

if __name__=='__main__':

    print(f"File checksum: {file_checksum(log_file)}")
    find_low_scores(print_alerts=True)
    # find_low_scores_parallel()