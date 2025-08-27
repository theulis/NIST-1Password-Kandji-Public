import requests
import os # For enviromental variables
import json
import csv

# To use environmental values for the API and Kandji Domain
# echo 'export kandji_api_token="your_client_id_here"' >> ~/.zshrc
# echo 'kandji_domain="your_kandji_domain"' >> ~/.zshrc

kandji_api_token = os.environ.get("kandji_api_token")
kandji_domain=os.environ.get("kandji_domain")
authorisation_value = str('Bearer ') + kandji_api_token

with open("Kandji_1password_export.csv", "w") as csv_file:
    print(f'Device name,User,User Email,1Password Version, 1Password Version (long)', file=csv_file)

urls = [
    "https://"+kandji_domain+".api.kandji.io/api/v1/prism/apps?device_families=Mac&filter={\"name\":{\"in\":[\"1Password\"]}}&limit=300",
    "https://"+kandji_domain+".api.kandji.io/api/v1/prism/apps?device_families=Mac&filter={\"name\":{\"in\":[\"1Password\"]}}&limit=300&offset=300"
]

payload = {}
headers = {
  'Authorization': authorisation_value
}



for url in urls:
    response = requests.request("GET", url, headers=headers, data=payload)
# Parse JSON directly
    json_response = response.json()

    for device in range(len(json_response["data"])):
        if json_response["data"][device]["path"]== "/Applications/1Password.app":
            short_version = ".".join(json_response["data"][device]["short_version"].split(".")[:3])
            with open("Kandji_1password_export.csv", "a") as csv_file:
                print(f'{json_response["data"][device]["device__name"]}',end=',',file=csv_file)
                print(f'{json_response["data"][device]["device__user_name"]}',end=',',file=csv_file)
                print(f'{json_response["data"][device]["device__user_email"]}',end=',',file=csv_file)
                print(f'{short_version}',end=',',file=csv_file)
                print(f'{json_response["data"][device]["short_version"]}',file=csv_file)

            

csv_column="1Password Version"
csv_column_data = []

### Exports all the CSV Colums to a List - 1Password Version
### This 1Password version will be used for Vulnertabilities

with open('Kandji_1password_export.csv',newline='') as csvfile:
    reader = csv.DictReader(csvfile)  # Use DictReader to access by column name
    for row in reader:
        csv_column_data.append(row[csv_column])

version_list = csv_column_data
# Remove Duplicates and Sorts the List version_list=sorted(dict.fromkeys(version_list))
# Remove duplicates and Sort numerically
version_list = sorted(set(version_list), key=lambda s: [int(part) for part in s.split('.')])

# Set to track CVE IDs we've already processed in this run
processed_cve_ids = set()

### Print Header
with open("1Password-Vulnerabilities.csv", "w") as csvfile:
    print(f'CVE,Base Score,Severity,Min Affected Version,None Affected Version,Description', file=csvfile)

for version in version_list:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:1password:1password:"+version+":*:*:*:*:macos:*:*"
    payload = {}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)
    
    json_response = response.json()


##  print(f'Version:{version}') # Check that versions are added
    if response.status_code == 200:
        for vuln in range(len(json_response["vulnerabilities"])):

            # Get the CVE IDs
            cve_id = json_response["vulnerabilities"][vuln]['cve']['id']

            # Only add if we haven't already processed this CVE ID in this run
            if cve_id not in processed_cve_ids:
                with open("1Password-Vulnerabilities.csv", "a") as csvfile:
                    print(f'{json_response["vulnerabilities"][vuln]['cve']['id']}',end=',',file=csvfile)
                    print(f'{json_response["vulnerabilities"][vuln]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']}',end=',',file=csvfile)
                    print(f'{json_response["vulnerabilities"][vuln]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']}',end=',',file=csvfile)
                    print(f'{json_response["vulnerabilities"][vuln]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0]['versionStartIncluding']}',end=',',file=csvfile)
                    print(f'{json_response["vulnerabilities"][vuln]['cve']['configurations'][0]['nodes'][0]['cpeMatch'][0]['versionEndExcluding']}',end=',',file=csvfile)
                    print(f'{json_response["vulnerabilities"][vuln]['cve']['descriptions'][0]['value']}',end='\n',file=csvfile)

                # Add CVE ID to the set of processed CVE IDs
                processed_cve_ids.add(cve_id)

import csv

# We will use out existing exporting files to check the active vulnerabilities
vuln_file = "1Password-Vulnerabilities.csv"
device_file = "Kandji_1password_export.csv"

# Helper: parse "8.11.4" or "8.11.4.360922" → (8,11,4)
def parse_version(v):
    parts = v.split(".")
    return tuple(int(x) for x in parts[:3] if x.isdigit())

# Load vulnerabilities
vulns = []
with open(vuln_file, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        vulns.append({
            "CVE": row["CVE"],
            "min_ver": parse_version(row["Min Affected Version"]),
            "max_ver": parse_version(row["None Affected Version"]),
        })

# Read Kandji file into memory
# Adds two more Rows
vulnerabilities_found = 0  # Add this counter
with open(device_file, "r") as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames + ["Vulnerability Status", "Vulnerability Count"]
    rows = []

    for row in reader:
        user_ver = parse_version(row["1Password Version"])  # << using short version
        matches = 0
        vulnerable_cves = []

        for vuln in vulns:
            if vuln["min_ver"] <= user_ver < vuln["max_ver"]:
                matches += 1
                vulnerable_cves.append(vuln["CVE"])

        if matches > 0:
            row["Vulnerability Status"] = "Active"
            device_name = row.get("Device name", "Unknown Device")
            user_name = row.get("User", "Unknown User")
            version = row.get("1Password Version", "Unknown Version")
            print(f"🚨 VULNERABILITY FOUND: {user_name} ({device_name}) (1Password {version}) - {matches} vulnerability(s): {', '.join(vulnerable_cves)}")
            vulnerabilities_found += 1  # Increment counter
        else:
            row["Vulnerability Status"] = "No Vulnerabilities"

        row["Vulnerability Count"] = matches
        rows.append(row)

# Overwrite the same Kandji CSV with updated data
with open(device_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

# Add this check before the final success message
if vulnerabilities_found == 0:
    print("✅ No 1Passwordvulnerabilities found!")

print(f"✅ Vulnerability Report for 1Password has been completed - Check the 📁 \033[91mKandji_1password_export.csv\033[0m file for the results")
if vulnerabilities_found != 0:
    print(f"👉 For a full list of the\033[91m current Active Vulnerabilities\033[0m, including CVSS score, check the 📁 \033[91m1Password-Vulnerabilities.csv\033[0m file")
