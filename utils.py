import time
import json
import random
import os
import hashlib


def file_checksum(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def time_function(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        print(f"{func.__name__} took {elapsed_time} seconds")
        return result
    return wrapper


def generate_entry(index):
    classes = [("Speed Limit 80", 12), ("Red Light", 1)]
    chosen_class = random.choice(classes)
    entry = {
        "image": f"test_set/{index:05d}_image.jpg",
        "class_num": chosen_class[1],
        "confidence": random.uniform(0.0, 1.0),
        "class": chosen_class[0]
    }
    return entry

def generate_large_json_file(file_path, target_size_mb):
    # Open the file in write mode
    with open(file_path, 'w') as file:
        file.write('[')  # Start of JSON array
        size = 0
        index = 0
        # Keep generating entries until the file is large enough
        while size < target_size_mb * 1024 * 1024:
            entry = generate_entry(index)
            json_entry = json.dumps(entry)
            if index > 0:
                file.write(',\n')  # JSON array element separator
            file.write(json_entry)
            size = os.path.getsize(file_path)
            index += 1
        file.write(']')  # End of JSON array

# Usage
# generate_large_json_file('large_detection_log.json', 500)  # 500 MB
if __name__ == '__main__':
    generate_large_json_file('large_detection_log.json', 1)
    # generate_large_json_file('large_detection_log.json', 5000)