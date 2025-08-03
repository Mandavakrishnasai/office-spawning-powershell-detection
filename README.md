#  Office ➝ PowerShell Detection (MITRE T1059.001)

##  Overview
This detection identifies when Microsoft Office applications like Word, Excel, or PowerPoint launch PowerShell. This is a common technique used in phishing attacks, where an attacker tricks a user into opening a document that triggers malicious PowerShell activity via macros or embedded scripts.

---

##  Detection Purpose
Office ➝ PowerShell behavior is not normal in most environments. This detection helps:
- Catch early-stage malware execution.
- Surface suspicious activity from trusted applications.
- Correlate events with MITRE ATT&CK tactics and techniques.

---

##  Detection Logic (SPL)
The following SPL query looks for process creation events where the parent process is an Office application and the child is PowerShell. It also adds MITRE context and assigns a static risk score.

```spl
index="office_spawning" 
| eval parent_image=lower(parent_process_name), child_image=lower(process_name)
| search parent_image IN ("winword.exe", "excel.exe", "powerpnt.exe")
| search child_image="powershell.exe"
| eval Tactic="Execution", Technique_ID="T1059.001", Technique_Name="PowerShell"
| eval risk_score=80
| table _time, host, user, parent_image, child_image, CommandLine, ParentCommandLine, Tactic, Technique_ID, Technique_Name, risk_score
| sort - _time
```
##  MITRE ATT&CK Mapping
- **Tactic**: Execution
- **Technique ID**: T1059.001
- **Technique Name**: PowerShell

  ```
 ##  Notes
- This detection assumes access to process lineage logs (e.g., normalized fields like `parent_process_name` and `process_name`).
- It can be enhanced by checking command-line arguments or adding frequency-based baselining for known Office behavior.

---
