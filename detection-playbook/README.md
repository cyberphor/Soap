## Detection Playbook

| ID  | Incident Category | Tactic | Technique | Sub-Technique | Data Source |
| --- | ----------------- | ------ | --------- | ------------- | ----------- |
| 01 | CAT 7 | Execution | n/a | n/a | Windows Event Logs | 
| 01 | CAT 7 | Execution | Command and Scripting Interpreter | PowerShell | Windows Event Logs | 
| 02 | CAT 3 | Credential Access | Brute Force | Password Guessing | Windows Event Logs |
| 03 | CAT 5 | Exfiltration | Exfiltration Over Physical Medium | Exfiltration Over USB | Windows Event Logs | 
| 04 | CAT 8 | Persistence | Scheduled Task/Job | Scheduled Task | Windows Event Logs | 

**CJCSM 6501.01B Incident Categories (By Precedence)**  
* CAT 1 - Root-Level Intrusion
* CAT 2 - User-Level Intrusion
* CAT 4 - Denial of Service
* CAT 7 - Malicious Logic
* CAT 3 - Unsuccessful Activity Attempt
* CAT 5 - Non-Compliance Activity
* CAT 6 - Reconnaissance
* CAT 8 - Investigation

**Detection Playbook Coverage of the MITRE ATT&CK Framework**  
* [ ] Reconnaissance
* [ ] Resource Development
* [ ] Initial Access
* [x] Execution
  * [x] Command and Scripting Interpreter
    * [x] PowerShell 
* [x] Persistence
  * [x] Scheduled Task/Job
    * [x] Scheduled Task  
* [ ] Privilege Escalation
* [ ] Defense Evasion
* [x] Credential Access
  * [x] Brute Force
    * [x] Password Guessing  
* [ ] Discovery
* [ ] Lateral Movement
* [ ] Collection
* [ ] Command and Control
* [x] Exfiltration
  * [x] Exfiltration Over Physical Medium
    * [x] Exfiltration Over USB 
* [ ] Impact
