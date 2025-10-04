# NIST-1Password-Kandji-Public
Get 1Password version per MacOS device via Kandji and check if there are any Vulnerabilities

## Information
This Script will grab all the current 1Password versions running on all macOS devices.
For those versions, it will contactthe  NIST Database and find if there are any Active Vulnerabilities, which will be added to the file: **1Password-Vulnerabilities.csv**

```bash
CVE,Base Score,Severity,Min Affected Version,None Affected Version,Description
CVE-2024-42218,4.7,MEDIUM,8.0,8.10.38,1Password 8 before 8.10.38 for macOS allows local attackers to exfiltrate vault items by bypassing macOS-specific security mechanisms.
CVE-2024-42219,7.8,HIGH,8.0,8.10.36,1Password 8 before 8.10.36 for macOS allows local attackers to exfiltrate vault items because XPC inter-process communication validation is insufficient.
```


Finally, we will get a full report Kandji_1password_export.csv

```bash
Device name,User,User Email,1Password Version,1Password Version (long),Vulnerability Status,Vulnerability Count
G479R42V90,John Doe,john.doe@fictionalcorp.com,8.11.4,8.11.4.360922,No Vulnerabilities,0
W25CY32DL0,Alice Martinez,alice.martinez@fictionalcorp.com,8.11.4,8.11.4.360922,No Vulnerabilities,0
K212NT9XDC,Rahul Patel,rahul.patel@fictionalcorp.com,8.11.4,8.11.4.360922,No Vulnerabilities,0
FX9TW12LPJ,Carla Lopez,carla.lopez@fictionalcorp.com,8.11.4,8.11.4.360922,No Vulnerabilities,0
G7VNWQDKVK,Michael Murphy,michael.murphy@fictionalcorp.com,8.11.8,8.11.8.367424,No Vulnerabilities,0
C02H3060Q6LT,Thomas Hughes,thomas.hughes@fictionalcorp.com,8.11.8,8.11.8.367424,No Vulnerabilities,0
J265WW5TG7,Emily Brown,emily.brown@fictionalcorp.com,8.11.4,8.11.4.360922,No Vulnerabilities,0
FVFH92LEQ6LT,Henry Wilson,henry.wilson@fictionalcorp.com,8.10.30,8.10.30.218949,Active,1
C1FY1W1M94,Karen Nguyen,karen.nguyen@fictionalcorp.com,8.11.8,8.11.8.367424,No Vulnerabilities,0
G5G4W6YXGY,David Peters,david.peters@fictionalcorp.com,8.11.8,8.11.8.367424,No Vulnerabilities,0
HVXCK0G2LQ,Susan Roberts,susan.roberts@fictionalcorp.com,8.11.6,8.11.6.364665,No Vulnerabilities,0
W4V2RQMQFM,Linda Chen,linda.chen@fictionalcorp.com,8.11.4,8.11.4.360922,No Vulnerabilities,0
```

*The Terminal output will be*

```
🚨 VULNERABILITY FOUND: Henry Wilson (FVFH92LEQ6LT) (1Password 8.10.30) - 2 vulnerability(s): CVE-2024-42218, CVE-2024-42219
✅ Vulnerability Report for 1Password has been completed - Check the 📁 Kandji_1password_export.csv file for the results
✅ For a full list of the Active Vulnerabilities, including CVSS score, check the 📁 1Password-Vulnerabilities.csv file
```
