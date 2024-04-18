import csv
# looking up by keywords is hard and slow,
# so for now just hard code relevant attacks

KNOWN_ATTACKS_AND_MITIGATIONS = {
    'UDP FLOOD': 'attack-pattern--0bda01d5-4c1d-4062-8ee2-6872334383c3',
    'TCP SYN FLOOD' : '',
    'ICMP FLOOD' : '',
    'ICMP ECHO REQUEST SCAN': '',
    'TCP SYN SCAN': '',
    'UDP SCAN': ''
}

def normalize_text(text):
    return text.lower().strip()

# Normalize the dictionary keys
normalized_keys = {normalize_text(key): key for key in KNOWN_ATTACKS_AND_MITIGATIONS.keys()}

# Read and process the CSV
# reader = csv.DictReader('parsed_snort_alerts.csv', newline='', encoding='utf-8') 
with open('parsed_snort_alerts.csv', newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        normalized_type = normalize_text(row['type'])
    
        # Check if any normalized key is a substring of the normalized type
        matches = [key for key, original_key in normalized_keys.items() if key in normalized_type]
        if matches:
            for match in matches:
                print(f"Match found: Original Type: {row['type']}, Dictionary Key: {normalized_keys[match]}, Pattern ID: {KNOWN_ATTACKS_AND_MITIGATIONS[normalized_keys[match]]}")
        else:
            print(f"No matches found for type: {row['type']}")