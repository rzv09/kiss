from attackcti import attack_client
from mitreattack.stix20 import MitreAttackData
import logging
import pandas as pd
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)

# looking up by keywords is hard and slow,
# so for now just hard code relevant attacks


def get_mitigations_for_technique(technique_id):
    # Initialize the client
    lift = attack_client()

    # Get all mitigations from the ATT&CK knowledge base
    all_mitigations = lift.get_mitigations()

    # Get relationships to find which mitigations apply to the given technique
    all_relationships = lift.get_relationships()
    related_mitigations = [
        relation['target_ref']
        for relation in all_relationships
        if relation['source_ref'] == technique_id and relation['relationship_type'] == 'mitigates'
    ]

    # Find and print mitigation details
    for mitigation_id in related_mitigations:
        mitigation = next((mit for mit in all_mitigations if mit['id'] == mitigation_id), None)
        if mitigation:
            print(f"Mitigation: {mitigation['name']}")
            print(f"Description: {mitigation['description']}\n")

# Example use case

def get_attack_data():
    # Initialize the client
    lift = attack_client()

    # Retrieve all techniques from the ATT&CK knowledge base
    # all_techniques = lift.get_techniques()
    # print(all_techniques[0])

    # Filter for techniques that involve UDP flood (e.g., by keyword search)
    # udp_flood_techniques = [tech for tech in all_techniques if 'UDP' in tech['name']] #and 'flood' in tech['description'].lower()]

    # Print out relevant techniques and their mitigations
    # for tech in udp_flood_techniques:
    #     print(f"Technique: {tech['name']}")
    #     print(f"Description: {tech['description']}")
    #     if 'mitigations' in tech:
    #         for mit in tech['mitigations']:
    #             print(f"Mitigation: {mit['description']}")
    #     else:
    #         print("No specific mitigations provided.")
    #     print("\n")

    tech = lift.get_object_by_attack_id('attack-pattern', 'T1498.001')
    tech = tech[0]

    # print(tech)
    print(f"Technique: {tech['name']}")
    print(f"Description: {tech['description']}")
    # print(f"mitigations: {tech['mitigations']}")
    # if 'mitigations' in tech:
    #     for mit in tech['mitigations']:
    #         print(f"Mitigation: {mit['description']}")
    # else:
    #     print("No specific mitigations provided.")
    print("\n")    
    return tech['id']

def load_alerts(csv_path):
    """
    Load alerts from a CSV file into a pandas DataFrame.
    """
    return pd.read_csv(csv_path)

def search_mitre_techniques(alerts):
    """
    Search for MITRE ATT&CK techniques based on alert descriptions.
    
    Args:
    alerts (DataFrame): DataFrame containing the alerts.

    Returns:
    dict: A dictionary mapping alerts to potential MITRE ATT&CK techniques.
    """
    lift = attack_client()
    alert_techniques = {}

    for index, row in alerts.iterrows():
        # Assuming 'message' contains the descriptive part of the alert
        message = row['classification']
        # Search for techniques by keywords extracted from the message
        keywords = message.split()  # Simple split, can be refined
        techniques_found = []

        for keyword in keywords:
            # Get techniques that match the keyword
            techniques = lift.get_techniques_by_content(keyword)
            for tech in techniques:
                techniques_found.append(tech['name'])

        # Store unique techniques for this alert
        alert_techniques[row['sid']] = list(set(techniques_found))

    return alert_techniques


# Usage with snort log
# csv_path = 'parsed_snort_alerts.csv'
# alerts = load_alerts(csv_path)
# mitre_techniques = search_mitre_techniques(alerts)
# print(mitre_techniques)




# Execute the function
id = get_attack_data()
# print(id)
mitre_attack_data = MitreAttackData("enterprise-attack.json")
# get_mitigations_mitigating_technique('attack-pattern--0bda01d5-4c1d-4062-8ee2-6872334383c3')
technique_stix_id = "attack-pattern--0bda01d5-4c1d-4062-8ee2-6872334383c3"
mitigations_mitigating = mitre_attack_data.get_mitigations_mitigating_technique(technique_stix_id)

print(f"Mitigations mitigating T1014 ({len(mitigations_mitigating)}):")
for m in mitigations_mitigating:
    mitigation = m["object"]
    print(f"* {mitigation.name} ({mitre_attack_data.get_attack_id(mitigation.id)})")