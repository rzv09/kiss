import time
import json
import random
import os
import hashlib
import csv
from attack_types_ids import KNOWN_ATTACKS_AND_MITIGATIONS

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

def normalize_text(text):
    return text.lower().strip()

def match_signatures_with_ids(csvfile_path):
    normalized_keys = {normalize_text(key): key for key in KNOWN_ATTACKS_AND_MITIGATIONS.keys()}
    pattern_ids_matched = []

    with open(csvfile_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            normalized_type = normalize_text(row['type'])
    
            # Check if any normalized key is a substring of the normalized type
            matches = [key for key, original_key in normalized_keys.items() if key in normalized_type]
            if matches:
                for match in matches:
                    print(f"Match found: Original Type: {row['type']}, Dictionary Key: {normalized_keys[match]}, Pattern ID: {KNOWN_ATTACKS_AND_MITIGATIONS[normalized_keys[match]]}")
                    pattern_ids_matched.append(KNOWN_ATTACKS_AND_MITIGATIONS[normalized_keys[match]])
            else:
                print(f"No matches found for type: {row['type']}")

    return pattern_ids_matched
# Usage
# generate_large_json_file('large_detection_log.json', 500)  # 500 MB
if __name__ == '__main__':
    generate_large_json_file('large_detection_log.json', 1)
    # generate_large_json_file('large_detection_log.json', 5000)