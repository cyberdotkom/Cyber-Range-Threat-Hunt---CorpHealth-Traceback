# Cyber-Range-Threat-Hunt---CorpHealth-Traceback
This is a threat hunt project using tools such as Azure, KQL , etc 
# 📚 Table of Contents

- [Threat Hunt: "Remote Assistance"](#%EF%B8%8F%E2%80%8D%EF%B8%8F-threat-hunt-remote-assistance)
- [Platforms and Tools](#-platforms-and-tools)
- [Summary of Findings (Flags)](#-summary-of-findings-flags)
  [ Flags]  0-31 
- [MITRE ATT&CK Technique Mapping](#-mitre-attck-technique-mapping)
- [Conclusion](#-conclusion)
- [Lessons Learned](#-lessons-learned)
- [Recommendations for Remediation](#%EF%B8%8F-recommendations-for-remediation)

---

# 🕵️‍♂️ Threat Hunt: *"Remote Assistance"*

## Scenario

Your organization recently completed a phased deployment of an internal platform known as CorpHealth — a lightweight system monitoring and maintenance framework designed to: 
 
Track endpoint stability and performance
Run automated post-patch health checks
Collect system diagnostics during maintenance windows
Reduce manual workload for operations teams 

CorpHealth operates using a mix of scheduled tasks, background services, and diagnostic scripts deployed across operational workstations.

To support this, IT provisioned a dedicated operational account.

This account was granted local administrator privileges on specific systems in order to: 

Register scheduled maintenance tasks
Install and remove system services
Write diagnostic and configuration data to protected system locations
Perform controlled cleanup and telemetry operations 

It was designed to be used only through approved automation frameworks, not through interactive sign-ins.

 Anomalous Activity 

In mid-November, routine monitoring began surfacing unusual activity tied to a workstation in the operations environment.

At first glance, the activity appeared consistent with normal system maintenance tasks:
 health checks, scheduled runs, configuration updates, and inventory synchronization.

However, closer review raised concerns:

Activity occurred outside normal maintenance windows
Script execution patterns deviated from approved baselines
Diagnostic processes were launched manually rather than through automation
Some actions resembled behaviors often associated with credential compromise or script misuse

Much of this activity was associated with an account that normally runs silently in the background.

 Your Role 

You are taking over as the lead analyst assigned to review historical telemetry captured by: 

Microsoft Defender for Endpoint
Azure diagnostic and device logs
Supporting endpoint event artifacts 

You will not have live access to the machine — only its recorded activity.

Your task is to determine: 

What system was affected
When suspicious activity occurred
How the activity progressed across different stages
Whether the behavior represents authorized automation or misuse of a privileged account

The incident is not labeled as a confirmed breach.

It has been formally categorized as:

“An Operations Activity Review”
Your investigation will determine whether it remains just that — or escalates into something more.



This report includes:

- 📅 Timeline reconstruction of auditing, reconnaissance, and attempted exfiltration of data on the device **`ch-ops-wks02`**
- 📜 Detailed queries using Microsoft Defender Advanced Hunting (KQL)
- 🎯 MITRE ATT&CK mapping to understand TTP alignment
- 🧪 Evidence-based summaries supporting each flag and behavior discovered

---

## 🧰 Platforms and Tools

**Analysis Environment:**
- Microsoft Defender for Endpoint
- Log Analytics Workspace
- Azure

**Techniques Used:**
- Kusto Query Language (KQL)
- Behavioral analysis of endpoint logs (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents)

---

## 📔 Summary of Findings (Flags)

| Flag | Objective | Finding | TimeStamp |
|------|------------------------|---------|-----------|
| 0 | Starting Point: suspicious events originated from a single endpoint active during an off-hours window in the middle of November. | `ch-ops-wks02` was the endpoint| `2025-10-09T12:22:27.6514901Z` |
| 1 | Unique Maintenance File |"powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1" was the strange file found | `2025-11-24T19:14:06.925Z |
| 2 | Outbound beacon indicator | The beacon was first initiated on 2025-11-23T03:46:08.400686Z| 2025-11-23T03:46:08.400686Z |
| 3 | Identify the Beacon Destination | The beacon was coming from IP 127.0.01:8080 |2025-11-23T03:46:08.400686Z |
| 4 | Confirm the Successful Beacon Timestamp | A successful beacon occurred at 2025-11-30T01:03:17.6985973Z | 2025-11-30T01:03:17.6985973Z |
| 5 | Unexpected Staging activity detected |C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_tmp_6ECFD4DF.csv | 2025-11-25T04:15:02.4575635Z|
| 6 | Confirm staged files integrity | The SHA 256 hash is “7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8” |2025-11-25T04:15:02.4575635Z |
| 7 | Identify the duplicate staged artifact | C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv| 2025-11-30T01:03:17.6985973Z |
| 8 | Suspicious Registry Activity | HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent| 2025-11-25T04:14:40.9857945Z|
|9| Scheduled Task Persistence | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64 |2025-11-25T04:15:26.9010509Z| 
|10| Registry-Based Persistence | The value name is Maintenance Runner | 2025-11-25T04:24:48.8957038Z  
|11| Privilege Escalation Event Timestamp | The time stamp was 2025-11-23T03:47:21.8529749Z |2025-11-23T03:47:21.8529749Z  
|12| Identify the AV exclusion Attempt | the full folder path is C:\ProgramData\Corp\Ops\staging -Force | 2025-11-23T03:46:37.92301Z  
|13| PowerShell Encoded Command Execution | the PS command that was executed first is write-Output "token-6D5E4EE08227"  | 2025-11-23T03:46:25.5148956Z
|14| Privilege Token Modification | The initiating ProcessID was 4888 | 2025-11-25T04:14:07.0587586Z
|15| Whose token was Modified | The security identifier of the modified token is S-1-5-21-1605642021-30596605-784192815-1000 | 2025-11-25T04:14:07.0587586Z
|16| Ingress Tool Transfer from External Dynamic Tunnel | the name of the executable file is revshell.exe | 2025-12-02T12:17:07.718921Z
|17| Identify the External Download Source | The URL the workstation connected to when retrieving the file is unresuscitating-donnette-smothery.ngrok-free.dev| 2025-12-02T12:17:07.718921Z
|18| Execution of the Staged Unsigned Binary | The process that executed the downloaded binary on CH-OPS-WKS02 is explorer.exe | 2025-12-02T23:55:50.2184423Z
|19| Identify the External IP Contacted by the Executable | what external IP address did the executable attempt to contact after execution is 13.228.171.119 | 2025-12-02T12:57:50.9507802Z
|20| Persistence via Startup Folder Placement| the folder path the attacker used to establish persistence is C:PrgramData\Microsoft\Windows\Start\Menu\Programs\Startup\revshell.exe |2025-12-02T12:28:26.871006Z
|21| Identify the Remote Session Source Device | 对手 | 2025-12-02T12:28:26.871006Z
|22| Identify the Remote Session IP Address | The Ip address that appears as the source of the remote session tied to the attacker is 100.64.100.6 | 2025-12-02T12:28:26.871006Z
|23| Identify the Internal pivot Host used by the Attacker | The internal IP address that appears on the attackers remote session metadata is 10.168.0.7 | 2025-12-02T12:17:07.718921Z
|24| Identify the first suspicious Logon Event | The earliest timestamp showing a suspicious logon was 2025-11-23T03:08:31.1849379Z | 2025-11-23T03:08:31.1849379Z 
|25| IP Address Used During the First suspicious logon | The IP address that is associated with the earliest suspicious logon timestamp is 104.164.168.17 | 2025-11-23T03:08:31.1849379Z 
|26| Account used during the first suspicious logon | The account name that appears in the earliest suspicious logon event |chadmin | 2025-11-23T03:08:31.1849379Z
|27| Determine the attackers geographic region | The country or region the attackers IP originated from was Vietnam | 2025-11-23T03:30:27.5983652Z
|28| First Process launched after the attacker logged in | The first process launched by the attacker immediately after logging in is explorer.exe |  2025-11-23T03:11:00.6981995Z
|29| Identify the first file the attacker accessed | The file the attacker opened first after the previous flag is CH-OPS-WKS02 user-pass.txt | 2025-11-23T03:11:00.6981995Z
|30| Determine the attackers next action after reading the file | the attacker read the ipconfig.exe file | 2025-11-23T03:11:45.1631084Z
|31| Identify the Next Account Accessed after Recon  | The user account the attacker accessed immediately after enumeration activity  is ops.maintenance | 2025-11-23T03:08:00Z


### 🚩 Flag 0: Starting Point - Suspicious Processes Spawning in Downloads

**Objective:**
Your first step is confirming which workstation generated the unusual telemetry.
Initial log clustering shows that all suspicious events originated from a single endpoint active during an off-hours window in the middle of November.  
During your initial sweep, look for a workstation that shows:

A small cluster of events during an unusual maintenance window 

Activity between Mid November to Early December.

**Flag Value:** 
`ch-ops-wks02` 
`2025-10-09T12:22:27.6514901Z


**Detection Strategy:**
The detection strategy focuses on identifying the workstation responsible for generating unusual telemetry by analyzing endpoint logs within a defined timeframe. Analysts  should filter activity occurring between mid-November and early December, paying particular attention to events generated during off-hours or unusual maintenance windows. By grouping and clustering logs by device name, investigators can identify endpoints producing a concentrated set of suspicious events during these periods. Systems showing short bursts of activity outside normal operating hours should be prioritized, as this behavior often indicates potential malicious activity. Once the cluster is identified, the associated endpoint hostname and event timestamps can be used to confirm the workstation responsible and establish the starting point for deeper investigation.

**KQLQuery:**
```kql

DeviceProcessEvents
| where DeviceName has 'ch-'      


**Evidence:**
<img width="1902" height="359" alt="image" src="https://github.com/cyberdotkom/assets-for-github-/raw/main/screenshot%20for%20hunt%20corpshealth.png">

The initial query showed suspicious files that were downloaded with the keywords in the alert. The affected device was identified as `ch-ops-wks02`.












### 🚩 Flag 1: Initial Execution Detection

**Objective:**

ch-ops-wks02   is the workstation of interest and narrowed your timeframe to the mid-November maintenance window. 
CorpHealth uses a mix of scheduled scripts and diagnostic utilities across multiple endpoints. Most of them are standard, repeated across many machines. But one script on CH-OPS-WKS02 appears to be unique to this host, tied to recent maintenance work.


As an analyst, you want to know which “maintenance” file stands out here before treating any behavior as normal.

**Flag Value:**
"powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\ProgramData\Corp\Ops\MaintenanceRunner_Distributed.ps1"

**Detection Strategy:** 
The detection strategy focuses on identifying unusual maintenance activity originating from the workstation CH-OPS-WKS02 during the mid-November maintenance window. Analysts should begin by filtering endpoint telemetry for this device and examining scripts and diagnostic utilities executed during that timeframe. Because the CorpHealth environment uses many standard maintenance scripts across multiple endpoints, the investigation should compare scripts executed on CH-OPS-WKS02 against those commonly observed across other systems. Any script that appears unique to this host or executed only once during the maintenance period should be flagged for further review. By isolating maintenance files that deviate from the normal baseline, analysts can identify potentially malicious scripts masquerading as legitimate maintenance tasks and determine whether the activity represents unauthorized execution or persistence mechanisms.


**KQLQuery:**
DeviceProcessEvents
    | where ProcessCommandLine has_any (".ps1")
    | project ProcessCommandLine, SHA256, DeviceName, DeviceId, FileName, Timestamp 
    | order by Timestamp desc


**Evidence:**
<img width="1699" height="220" alt="image" src= xx/>





### 🚩 Flag 2: Outbound beacon indicator

**Objective:**
After identifying the unique maintenance script, you now pivot into other queries to determine what this script actually did when executed.

CorpHealth agents often phone home to internal listeners or update servers — but the behavior from CH-OPS-WKS02 feels different. 
Determine when the maintenance script first initiated outbound communication.

**Flag Value:**
“2025-11-23T03:46:08.400686Z”
“2025-11-23T03:46:08.400686Z” 

**Detection Strategy:**
The detection strategy focuses on determining when the identified maintenance script on CH-OPS-WKS02 first initiated outbound communication. Analysts should review network and process telemetry associated with the script execution and filter for connections originating from the workstation during the mid-November maintenance window. Because CorpHealth agents commonly communicate with internal update servers or listeners, the investigation should compare normal agent communication patterns against the network activity generated by the maintenance script. Any outbound connection that appears unusual in timing, destination, or frequency should be examined closely to determine whether it represents beaconing behavior or unauthorized command-and-control communication initiated after the script was executed.


**KQLQuery:**

 DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed"
| summarize FirstExecution = min(Timestamp)




**Evidence:**
<img width="2083" height="492" alt="image" src= xx />






### 🚩 Flag 3: Identify the Beacon Destination

**Objective:**
Where was the workstation trying to beacon to?

**Flag Value:**
127.0.0.1:8080

**Detection Strategy:**
The detection strategy focuses on identifying the destination that CH-OPS-WKS02 attempted to contact following the execution of the suspicious PowerShell maintenance script. Analysts should review network telemetry associated with the script execution and filter for outbound connections originating from the workstation during the investigation timeframe. Since CorpHealth systems normally communicate with known internal update or management servers, analysts should compare the observed network activity against expected communication patterns to identify any unusual destinations. Particular attention should be given to connection attempts, even if unsuccessful, as they can reveal potential command-and-control infrastructure, data exfiltration staging points, or attempts at lateral movement within the network. Extracting the destination IP address or port will help determine the intent of the activity and guide further investigation.


**KQLQuery:**
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed"
| project TimeGenerated, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort


**Evidence:**
<img width="1217" height="218" alt="image" src= />



### 🚩 Flag 4: Confirm the Successful Beacon Timestamp

**Objective:**
What is the most recent (latest) timestamp where CH-OPS-WKS02 successfully connected (ConnectionSuccess) to the beacon IP and port?

**Flag Value:**
2025-11-30T01:03:17.6985973Z

**Detection Strategy:**
The detection strategy focuses on identifying the most recent successful outbound connection from CH-OPS-WKS02 associated with the suspicious maintenance script. Analysts should review network telemetry and filter for ConnectionSuccess events tied to the script’s execution during the investigation timeframe. While earlier connection attempts may have failed, a confirmed successful connection indicates the earliest point at which the attacker could have received commands or exchanged data with the host. By isolating the latest successful connection event, including the associated remote IP address and port, investigators can establish a reliable anchor point in the attack timeline. This timestamp provides a critical reference for correlating subsequent activity and reconstructing the sequence of malicious events on the compromised workstation.


**KQLQuery:** 
DeviceNetworkEvents
| where DeviceName has "CH-OPS-WKS02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed"
| where RemoteIP has "127.0.0.1"
| project TimeGenerated, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort 


```
**Evidence:**
<img width="1266" height="251" alt="image" src= />




### 🚩 Flag 5: Storage Surface Mapping

**Objective:**
Determine how exactly the attack was staged 

**Flag Value:**
C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv




**Detection Strategy:**
The detection strategy focuses on identifying the artifacts staged by the attacker on the compromised workstation CH-OPS-WKS02. Analysts should review file creation and endpoint telemetry during the investigation timeframe to locate files that were generated or staged shortly after the suspicious script execution. By filtering for newly created files within system or temporary directories and correlating them with the attacker’s activity timeline, investigators can identify the first primary staging artifact created during the attack. Determining the full file path of this artifact helps reveal what data the attacker intended to collect, stage, or modify and provides additional indicators for tracking further malicious activity across the system.
**KQLQuery:**
DeviceFileEvents
| where DeviceName has  "CH-OPS-WKS02"
| where ActionType in ("FileCreated")
| where FolderPath has "CorpHealth" 
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc


```

**Evidence:**
<img width="1378" height="279" alt="image" src= xx  />



### 🚩 Flag 6: Confirm the Staged File’s Integrity

**Objective:**
verify the file’s cryptographic fingerprint.

**Flag Value:**
7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8 


**Detection Strategy:**
The detection strategy focuses on validating the integrity and identity of the suspicious artifact discovered in the attacker’s staging location on CH-OPS-WKS02. After identifying the staged file within the system’s diagnostic directory, analysts should calculate the SHA-256 cryptographic hash of the file to establish a unique fingerprint. This hash can then be compared against threat intelligence databases, malware repositories, and internal security tools to determine whether the artifact matches any known malicious files. Hash verification also ensures evidence integrity during the investigation and helps maintain proper chain-of-custody for forensic analysis. By confirming the SHA-256 value of the staged artifact, analysts can accurately classify the file and support further investigation into the attacker’s actions.


**KQLQuery:**
DeviceFileEvents
| where DeviceName has  "CH-OPS-WKS02"
| where ActionType in ("FileCreated")
| where FolderPath has "CorpHealth" 
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc  


**Evidence:**
<img width="1858" height="321" alt="image" src= xx />



### 🚩 Flag 7: Identify the Duplicate Staged Artifact

**Objective:**
What is the full file path of the second file?

**Flag Value:**
C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv

**Detection Strategy:**
The detection strategy focuses on identifying potential duplicate or alternate staging artifacts created by the attacker on CH-OPS-WKS02. After confirming the SHA-256 hash of the primary staged file, analysts should expand the investigation by reviewing file creation events across the system during the same timeframe. The goal is to detect files that share similar naming patterns, comparable file sizes, and closely aligned write timestamps with the original artifact but appear in different directories and possess a different SHA-256 hash. Such patterns often indicate an attacker working copy, intermediary version, or secondary staging location used during the intrusion. By correlating file metadata and hash values across directories, analysts can identify these redundant artifacts and gain deeper insight into how the attacker prepared or modified data during the attack.




**KQLQuery:**  

DeviceFileEvents
| where DeviceName has  "CH-OPS-WKS02"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has "inventory" 
| project TimeGenerated, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc




**Evidence:**
<img width="2104" height="348" alt="image" src= >


### 🚩 Flag 8: Suspicious Registry Activity

**Objective:**
Which exact registry key was created or touched during this activity?

**Flag Value:**
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent

**Detection Strategy:**
The detection strategy focuses on identifying suspicious registry activity associated with the attacker’s credential harvesting stage on CH-OPS-WKS02. Analysts should review registry modification events occurring within the investigation timeframe, particularly those initiated by PowerShell or other scripting processes. Because attackers often modify or inspect registry keys to gather credentials, establish persistence, or manipulate system logging, investigators should filter for newly created or modified registry entries that deviate from normal system behavior. Special attention should be given to keys accessed during the same timeframe as the suspicious script execution. By correlating registry activity with the attacker’s timeline, analysts can identify the exact registry key that was created or modified and determine how it may have supported credential harvesting or further system compromise.






**KQLQuery:**
DeviceRegistryEvents
| where DeviceName has  "CH-OPS-WKS02"
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| where InitiatingProcessCommandLine has "corp"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine 



**Evidence:**
<img width="2101" height="356" alt="image" src= xx/>



### 🚩 Flag 9: 

**Objective:**
Scheduled Task Persistence

**Flag Value:**
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64

**Detection Strategy:**
The detection strategy focuses on identifying **unauthorized persistence mechanisms** created on **CH-OPS-WKS02** following the earlier credential-related registry anomaly. Analysts should review Windows scheduled task telemetry during the investigation timeframe and filter for **new task creation events**, particularly those occurring shortly after suspicious PowerShell or registry activity. Since CorpHealth maintains a baseline of approved scheduled tasks, investigators should compare newly created tasks against this baseline to identify any entries that do not match standard configurations. Special attention should be given to scheduled tasks created within the **TaskCache registry path**, as attackers often use these entries to maintain persistence even after reboots. By isolating newly created tasks that deviate from normal system behavior, analysts can determine the exact scheduled task used by the attacker to establish persistence.








**KQLQuery:** 
DeviceRegistryEvents
| where DeviceName has  "CH-OPS-WKS02"
| where RegistryKey has "schedule"
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine



**Evidence:**
<img width="2088" height="362" alt="image" src=" />


### 🚩 Flag 10: Registry-based Persistence

**Objective:**
What Registry Value Name Was Added to the Run Key?

**Flag Value:**
MaintenanceRunner

**Detection Strategy:**
The detection strategy focuses on identifying **temporary registry-based persistence mechanisms** used by the attacker on **CH-OPS-WKS02**. Analysts should examine registry telemetry for events involving the Windows **Run key**, particularly those showing the creation, modification, and deletion of registry values within a short timeframe. Attackers sometimes use **ephemeral persistence**, where a Run key value is briefly created to execute a script during the next login or reboot and then removed to reduce forensic evidence. Investigators should filter registry activity for events such as **RegistryKeyCreated, RegistryValueSet, and RegistryKeyDeleted**, and correlate them with PowerShell execution events. By identifying the specific registry value that was created and then removed, analysts can determine the value name used by the attacker to trigger the malicious script and confirm the persistence technique employed during the intrusion.


**KQLQuery:** 
DeviceRegistryEvents
| where DeviceName has  "CH-OPS-WKS02"
| where ActionType in ("RegistryKeyCreated","RegistryValueSet","RegistryKeyDeleted","RegistryValueDeleted")
| where RegistryKey has "Run"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine



**Evidence:**
<img width="2080" height="212" alt="image" src= xx />



### 🚩 Flag 11: Privilege Escalation Event Timestamp

**Objective:**
Locate the exact Timestamp (UTC) of the FIRST ConfigAdjust privilege-escalation event.

**Flag Value:**
2025-11-23T03:47:21.8529749Z

**Detection Strategy:**
The detection strategy focuses on identifying the **initial privilege-escalation activity** performed by the attacker during the **MaintenanceRunner execution sequence** on **CH-OPS-WKS02**. Analysts should review **Application log telemetry** and filter for events associated with configuration adjustment actions, specifically those containing indicators of a **ConfigAdjust privilege-escalation event**. Because these events include relevant details within the **AdditionalFields payload**, investigators should examine this field to confirm the configuration change and determine whether it reflects unauthorized privilege modification. By isolating the **first occurrence of this event in the timeline**, analysts can identify the exact **UTC timestamp** when the privilege escalation attempt began, helping establish a key milestone in reconstructing the attacker’s activity during the intrusion.


**KQLQuery:**
DeviceEvents
| where DeviceName has "CH-OPS-WKS02"
| where AdditionalFields  has ( "ConfigAdjust")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine

**Evidence:**
<img width="1348" height="314" alt="image" src= />







### 🚩 Flag 12: Identify the AV Exclusion Attempt

**Objective:**
What folder path did the attacker attempt to add as an exclusion in Windows Defender?

**Flag Value:**
C:\ProgramData\Corp\Ops\staging -Force

**Detection Strategy:**
The detection strategy focuses on identifying attempts by the attacker to **bypass security controls by modifying Windows Defender settings** on **CH-OPS-WKS02**. Analysts should review endpoint security telemetry and PowerShell activity for events related to **Defender configuration changes**, particularly those involving the addition of new exclusion paths. Attackers commonly add folders to the Defender exclusion list to prevent security tools from scanning malicious files stored in those locations. Investigators should filter for events that reference **Defender preference changes or ExclusionPath modifications** and correlate them with the attacker’s activity timeline. By isolating these configuration changes, analysts can determine the exact folder path the attacker attempted to exclude from real-time scanning and identify the location where malicious files were likely staged or executed.


**KQLQuery:**
DeviceProcessEvents
| where DeviceName has "CH-OPS-WKS02"
| where ProcessCommandLine has "-ExclusionPath"
| project Timestamp, ProcessCommandLine
| order by Timestamp as

**Evidence:**
<img width="2082" height="586" alt="image" src= xx />



### 🚩 Flag 13: PowerShell Encoded Command Execution

**Objective:**
What decoded PowerShell command was executed First?

**Flag Value:**
Write-Output 'token-6D5E4EE08227'

**Detection Strategy:**
The detection strategy focuses on identifying **suspicious PowerShell execution using encoded commands** on **CH-OPS-WKS02**. Analysts should review **DeviceProcessEvents** and filter for processes where the **ProcessCommandLine contains the `-EncodedCommand` flag**, as attackers commonly use encoded PowerShell commands to obfuscate malicious activity and bypass detection. To reduce noise, investigators should also filter by the relevant **AccountName** and exclude system or legitimate background processes. Once these events are isolated, analysts should extract the Base64-encoded string from the command line and decode it to reveal the **plaintext PowerShell command** that was executed. By identifying the first decoded command in the timeline, investigators can determine the attacker’s initial scripted action and gain insight into the intent of the encoded PowerShell activity during the intrusion.


**KQLQuery:**
DeviceProcessEvents
| where DeviceName =~ "ch-ops-wks02"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "-EncodedCommand"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = replace_string(base64_decode_tostring(Enc), "\u0000", "")
| project Timestamp, AccountName, InitiatingProcessCommandLine, Decoded
| order by Timestamp asc
| take 50


**Evidence:**
<img width="2082" height="587" alt="image" src= />



### 🚩 Flag 14: Privilege Token Modification

**Objective:**
What is the "InitiatingProcessId" of the process whose token privileges were modified?

**Flag Value:**
4888

**Detection Strategy:**
The detection strategy focuses on identifying **token manipulation activity** associated with the suspicious PowerShell execution chain on **CH-OPS-WKS02**. Analysts should review **DeviceEvents** for entries indicating a **ProcessPrimaryTokenModified** action, as this behavior can signal privilege escalation or attempts to make a process appear more trusted by adjusting its security token. Investigators should filter for events where the **AdditionalFields** contain indicators such as **`tokenChangeDescription`** or **“Privileges were added”**, then correlate those events with the earlier PowerShell, registry, and persistence activity. By isolating the first relevant token modification event and identifying its **InitiatingProcessId**, analysts can determine which process performed the privilege change and better understand how the attacker attempted to elevate access or evade detection.


**KQLQuery:**
DeviceEvents
| where DeviceName has "CH-OPS-WKS02" 
| where ActionType has "ProcessPrimaryTokenModified" 
| project TimeGenerated, InitiatingProcessId, ActionType, AdditionalFields
| order by TimeGenerated asc


**Evidence:**
<img width="1840" height="214" alt="image" src=  />




### 🚩 Flag 15: Whose Token Was Modified?

**Objective:**
Which security identifier (SID) did the modified token belong to?

**Flag Value:**
S-1-5-21-1605642021-30596605-784192815-1000

**Detection Strategy:**
The detection strategy focuses on identifying the **security principal associated with the modified access token** during the privilege escalation activity on **CH-OPS-WKS02**. After confirming that a process modified its own token privileges, analysts should examine the **DeviceEvents** telemetry related to the same **ProcessPrimaryTokenModified** event. Investigators should review the **AdditionalFields** section of the event details to extract the **Security Identifier (SID)** tied to the modified token. Determining the SID allows analysts to identify whether the affected token belongs to a **standard user, domain account, or a privileged administrator account**, which helps assess the severity and potential impact of the privilege escalation attempt. By correlating the token modification event with the associated SID, investigators can better understand the level of access the attacker attempted to manipulate and evaluate the risk of subsequent actions taken on the compromised system.






**KQLQuery:**


let PrivEscPid = 4888;  // <-- replace with your Flag 14 InitiatingProcessId
DeviceEvents
| where DeviceName =~ "ch-ops-wks02"
| where ActionType == "ProcessPrimaryTokenModified"
| where InitiatingProcessId == PrivEscPid
| extend AF = tostring(AdditionalFields)
| extend OriginalTokenUserSid = extract(@"""OriginalTokenUserSid"":\s*""([^""]+)""", 1, AF)
| extend CurrentTokenUserSid  = extract(@"""CurrentTokenUserSid"":\s*""([^""]+)""", 1, AF)
| extend OriginalTokenUserSid = trim(@" ""\t\r\n", OriginalTokenUserSid)
| extend CurrentTokenUserSid  = trim(@" ""\t\r\n", CurrentTokenUserSid)
| project Timestamp, InitiatingProcessId, OriginalTokenUserSid, CurrentTokenUserSid, AdditionalFields
| order by Timestamp asc

**Evidence:**
<img width="1524" height="313" alt="image" src= />

### 🚩 Flag 16 Ingress Tool Transfer from External Dynamic Tunnel
 
Objective  What is the name of the executable that was written to disk after the outbound request? 

**Flag Value** 
revshell.exe    

**Detection Strategy**
The detection strategy focuses on identifying the **malicious executable introduced onto CH-OPS-WKS02 following the attacker’s privilege escalation and outbound network activity**. Analysts should review file creation and endpoint telemetry occurring shortly after the outbound request to determine whether a new executable was written to disk. Investigators should filter for file write events involving **.exe files** during this timeframe and correlate them with the attacker’s activity sequence. Because attackers often download or drop payloads after establishing communication with external infrastructure, special attention should be given to files created in temporary, staging, or user-accessible directories. By isolating the first executable written to disk after the outbound request, analysts can identify the payload introduced by the attacker and better understand the next phase of the intrusion.





**KQL value** 

DeviceFileEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| where Timestamp between (CurlTime .. CurlTime + 30m)
| where FolderPath !has @"\AppData\Local\Microsoft\WindowsApps\"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc 



### 🚩 Flag 17 Identify the External Download Source 

**Objective** 
What URL did the workstation connect to when retrieving the file? 

**Flag Value**  
Unresuscitating-donnette-smothery.ngrok-free.dev 

**Detection Strategy** 
The detection strategy focuses on identifying the **external source used to deliver the malicious executable** to **CH-OPS-WKS02**. Analysts should review network and process telemetry to locate outbound requests initiated by **curl.exe** during the timeframe preceding the appearance of the suspicious file on disk. Because attackers often use dynamic tunneling services to host or deliver payloads, investigators should filter for external connections made by curl.exe and examine the **ProcessCommandLine and network destination fields** to extract the full remote URL. By correlating this outbound request with the subsequent file creation event, analysts can determine the exact source from which the executable was retrieved and better understand how the attacker delivered the payload to the compromised workstation.

**KQL Query**  

DeviceNetworkEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where InitiatingProcessFileName =~ "curl.exe"
| where TimeGenerated  between (CurlTime - 10m .. CurlTime + 10m)
| where RemotePort == 443 or tostring(RemoteUrl) startswith "https://"
| where tostring(RemoteUrl) has "-"   // long hyphenated domain hint
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by TimeGenerated asc 


### 🚩 Flag 18 Execution of the Staged Unsigned Binary 

**Objective**  
Which process executed the downloaded binary on CH-OPS-WKS02? 

**Flag Value**  
Explorer.exe   

**Detection Strategy**  
The detection strategy focuses on identifying the **process responsible for executing the downloaded binary** on **CH-OPS-WKS02** following its retrieval from the external tunnel. Analysts should review **DeviceProcessEvents** and correlate process execution telemetry with the timeframe immediately after the file was written to disk. Because the binary originated from a user profile directory and not from a trusted software distribution source, investigators should filter for processes that launched executables from **non-standard or user-accessible directories**. By examining the parent-child process relationships and execution logs associated with the suspicious file, analysts can determine which process initiated the binary and confirm the point at which the attacker transitioned from staging the payload to actively running their tooling.

**KQL value** 
DeviceProcessEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where FileName =~ "revshell.exe"
| project TimeGenerated,
          FileName,
          FolderPath,
          InitiatingProcessFileName,
          InitiatingProcessParentFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated asc


### 🚩 Flag 19 Identify the External IP Contacted by the Executable

**Objective**   
What external IP address did the executable attempt to contact after execution?  

**Flag Value**  

13.228.171.119  


**Detection Strategy**   

The detection strategy focuses on identifying the **process responsible for executing the downloaded binary** on **CH-OPS-WKS02** following its retrieval from the external tunnel. Analysts should review **DeviceProcessEvents** and correlate process execution telemetry with the timeframe immediately after the file was written to disk. Because the binary originated from a user profile directory and not from a trusted software distribution source, investigators should filter for processes that launched executables from **non-standard or user-accessible directories**. By examining the parent-child process relationships and execution logs associated with the suspicious file, analysts can determine which process initiated the binary and confirm the point at which the attacker transitioned from staging the payload to actively running their tooling.

**KQL Value**  
DeviceNetworkEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where RemotePort == 11746
| project TimeGenerated,
          InitiatingProcessFileName,
          InitiatingProcessParentFileName,
          RemoteIP,
          InitiatingProcessCommandLine
| order by TimeGenerated asc 




### 🚩 Flag 20 Persistence via Startup Folder Placement 

**Objective**   
Which folder path did the attacker use to establish persistence for the executable? 

**Flag Value**  
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe 

**Detection Strategy**  

The detection strategy focuses on identifying **persistence attempts involving the malicious executable** on **CH-OPS-WKS02** after it was executed and initiated outbound communication. Analysts should review file system telemetry for events showing the executable being **copied or written to new locations** shortly after its initial execution. Particular attention should be given to directories commonly abused for persistence, such as **Windows Startup folders**, where files automatically execute during user logon. By filtering file events for activity involving the same executable and examining the destination paths, investigators can determine the exact folder where the attacker attempted to establish persistence and confirm how the malware was configured to relaunch automatically on the compromised system.  

**KQL Value** 
DeviceFileEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where FileName =~ "revshell.exe"
| where ActionType in ("FileCreated","FileCopied","FileRenamed")
| where FolderPath startswith @"C:\ProgramData"
| where FolderPath has "Start"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by TimeGenerated asc  


### 🚩 Flag 21 Identify the Remote Session Source Device 

**Objective**  
What is the remote session device name associated with the attacker’s activity? 

**Flag Value** 
对手 

**Detection Strategy** 
The detection strategy focuses on identifying the remote session source device associated with the attacker’s activity on CH-OPS-WKS02. Analysts should review endpoint telemetry tied to suspicious events such as file creation, process execution, and network connections, paying particular attention to remote session metadata fields recorded in the logs. Because these events share the same session attributes, investigators can correlate them to determine whether the activity originated from a remote interactive session rather than direct physical access to the workstation. By isolating the device name listed as the remote session origin across these events, analysts can identify the system used by the attacker to access CH-OPS-WKS02 and better understand the access path used during the intrusion.
**KQL value** 
DeviceProcessEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where isnotempty(InitiatingProcessRemoteSessionDeviceName) or isnotempty(ProcessRemoteSessionDeviceName)
| extend RemoteSessionDeviceName = coalesce(InitiatingProcessRemoteSessionDeviceName, ProcessRemoteSessionDeviceName)
| summarize Hits=count() by RemoteSessionDeviceName
| order by Hits desc  


### 🚩 Flag 22 Identify the Remote Session IP Address 

    **Objective** 
 What IP address appears as the source of the remote session tied to the attacker’s activity? 

**Flag Value**  
100.64.100.6

**Detection strategy** 
The detection strategy focuses on identifying the **originating IP address associated with the attacker’s remote session** on **CH-OPS-WKS02**. Analysts should review endpoint and session telemetry linked to suspicious events such as file creation, process execution, and network activity, and examine the **remote session metadata fields** included in those records. Because multiple events share the same session information, investigators can correlate these logs to isolate the **consistent source IP address** used during the attacker’s interaction with the system. Identifying this IP address helps analysts determine the adversary’s network entry point and enables further correlation with authentication logs, potential lateral movement, and other external access patterns across the environment.

**KQL Value** 
DeviceNetworkEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where InitiatingProcessFileName =~ "revshell.exe"
| extend RemoteSessionIP = coalesce(InitiatingProcessRemoteSessionIP, RemoteIP)
| where isnotempty(RemoteSessionIP)
| where RemoteSessionIP !startswith "10."
| project TimeGenerated, RemoteIP, RemotePort, RemoteSessionIP
| order by TimeGenerated asc 

 
### 🚩 Flag 23 Identify the Internal Pivot Host Used by the Attacker 

**Objective** 
Which internal IP address (non–100.64.x.x) appears as part of the attacker’s remote session metadata? 

**Flag Value** 
10.168.0.7 






**Detection strategy** 
The detection strategy focuses on identifying a potential **internal pivot point used by the attacker within the Azure environment** during the intrusion on **CH-OPS-WKS02**. Analysts should review the **remote session metadata** attached to suspicious events and examine the IP addresses associated with those sessions. Because attackers often move laterally through compromised systems, investigators should differentiate between **external session addresses and internal virtual network addresses**. By filtering for IPs that belong to the **internal Azure virtual network range (excluding 100.64.x.x addresses)**, analysts can identify the internal system likely used as a hop or staging point before accessing CH-OPS-WKS02. Determining this internal IP helps reconstruct the attacker’s path through the environment and may reveal additional compromised systems involved in the intrusion.

**KQL Value** 
DeviceProcessEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where isnotempty(InitiatingProcessRemoteSessionIP)
| where InitiatingProcessRemoteSessionIP startswith "10."
| where not(ipv4_is_in_range(InitiatingProcessRemoteSessionIP, "100.64.0.0/10"))
| distinct InitiatingProcessRemoteSessionIP  



### 🚩 Flag 24 Identify the First Suspicious Logon Event 

**Objective** 
What is the earliest timestamp showing a suspicious logon to CH-OPS-WKS02? 

**Flag Value** 
2025-11-23T03:08:31.1849379Z 

**Detection Strategy** 

To determine when the adversary first accessed the system, we need to look at the earliest logon event tied to their activity. This marks the true beginning of their presence on CH-OPS-WKS02. Multiple remote session IPs appear later in the attack timeline, but only one timestamp reflects the very first successful logon.

What is the earliest timestamp showing a suspicious logon to CH-OPS-WKS02?  

**KQL Value** 
DeviceLogonEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where ActionType == "LogonSuccess"
| where LogonType has_any ("Remote","Network","RDP")
| where AccountName in~ ("ops.maintenance","chadmin","analyst.user")
| order by Timestamp asc
| project Timestamp, RemoteDeviceName,RemotePort,DeviceName,InitiatingProcessCommandLine
| take 25


### 🚩 Flag 25   IP Address Used During the First Suspicious Logon 

**Objective**  
What IP address is associated with the earliest suspicious logon timestamp?

**Flag Value** 
104.164.168.17 

**Detection Strategy**   
The detection strategy focuses on identifying the **earliest suspicious logon event associated with the attacker’s activity on CH-OPS-WKS02**. Analysts should review authentication and logon telemetry to locate the **first successful login tied to the attacker’s session metadata**. Although multiple remote session IP addresses may appear later in the timeline, investigators should prioritize identifying the **earliest timestamp** that indicates a successful logon to the workstation. By filtering authentication logs for suspicious accounts, unusual login times, or unfamiliar source IP addresses, analysts can determine when the adversary first gained access to the system. Establishing this initial logon timestamp is critical for reconstructing the attack timeline and understanding how the intrusion began.

**KQL Value**  
DeviceLogonEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where ActionType == "LogonSuccess"
| where LogonType has_any ("Remote","Network","RDP")
| where AccountName in~ ("ops.maintenance","chadmin","analyst.user")
| order by Timestamp asc
| project Timestamp, RemoteDeviceName,RemotePort,DeviceName,InitiatingProcessCommandLine,RemoteIP
| take 25



### 🚩 Flag 26 Account Used During the First Suspicious Logon 

**Objective** 

Which account name appears in the earliest suspicious logon event?
**Flag Value**
Chadmin  

**Detection Strategy** 
The detection strategy focuses on identifying the **compromised account used during the earliest suspicious logon to CH-OPS-WKS02**. After determining the initial logon timestamp and source IP, analysts should review authentication telemetry to identify the **AccountName associated with that event**. Investigators should correlate the logon record with session metadata and examine whether the account belongs to a **local user, domain account, or administrative account**, as this helps determine how the attacker authenticated to the system. By isolating the account tied to the first suspicious login, analysts can identify the credentials leveraged by the adversary and assess whether the access resulted from stolen credentials, credential reuse, or misuse of a privileged account.

**KQL value** 
DeviceLogonEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where ActionType == "LogonSuccess"
| where LogonType has_any ("Remote","Network","RDP")
| where AccountName in~ ("ops.maintenance","chadmin","analyst.user")
| order by Timestamp asc
| project Timestamp, RemoteDeviceName,RemotePort,DeviceName,InitiatingProcessCommandLine,RemoteIP, AccountName
| take 25 




### 🚩 Flag 27 Determine the Attacker’s Geographic Region

**Objective** 

According to Defender geolocation enrichment, what country or region do the attacker’s IPs originate from?

**Flag Value** 
Vietnam  






**Detection Strategy** 
The detection strategy focuses on identifying the **geographic origin of the attacker’s remote access activity** targeting **CH-OPS-WKS02**. Analysts should review authentication and session telemetry associated with the suspicious remote device and extract the public IP addresses used during the attacker’s logons. Because the attacker utilized multiple IPs within a similar range, investigators should enrich these addresses using the **`geo_info_from_ip_address()`** function in KQL to derive location details such as **country, region, and city**. By correlating the enriched geolocation data with the suspicious login events, analysts can determine the likely geographic source of the attacker’s activity and gain additional context for tracking external access patterns and potential threat actor origins. 

**KQL value** 
DeviceLogonEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where ActionType == "LogonSuccess"
| where LogonType has_any ("Remote","Network","RDP")
| where AccountName in~ ("ops.maintenance","chadmin","analyst.user")
| order by Timestamp asc
| project Timestamp, RemoteDeviceName,RemotePort,DeviceName,InitiatingProcessCommandLine,RemoteIP, AccountName
| take 2 


### 🚩 Flag 28 First Process Launched After the Attacker Logged In 

**Objective** 
What was the first process launched by the attacker immediately after logging in?

**Flag Value** 
Explorer.exe 

**Detection Strategy** 
The detection strategy focuses on identifying the **first action performed by the attacker immediately after their initial logon to CH-OPS-WKS02**. Analysts should review **process execution telemetry** associated with the same logon session as the suspicious authentication event. Because Microsoft Defender records each new process launch along with its related session information, investigators can filter **DeviceProcessEvents** for processes started shortly after the login timestamp. By correlating these events with the attacker’s session metadata, analysts can determine the **first process executed after access was obtained**, revealing whether the adversary began with system exploration, privilege escalation attempts, or the deployment of additional tools.



**KQL Value** 
DeviceLogonEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where isnotempty(RemoteIP)
| extend Geo = geo_info_from_ip_address(RemoteIP)
| extend Country = Geo.country
| project Timestamp, AccountName, RemoteIP, Country 





### 🚩 Flag 29 Identify the First File the Attacker Accessed

**Objective** 
What file did the attacker open first after the previous flag?

**Flag Value**
CH-OPS-WKS02 user-pass.txt

**Detection Strategy**
The detection strategy focuses on identifying the **first file accessed by the attacker immediately after authenticating to CH-OPS-WKS02**. Analysts should review file activity telemetry associated with the attacker’s logon session and filter for the earliest **file open or read events** occurring shortly after the login timestamp. Because early file access often reveals an attacker’s intent, investigators should correlate these events with the same session metadata used during the suspicious authentication. By isolating the first file accessed during the session, analysts can determine whether the adversary was searching for **credentials, configuration files, or operational information**, providing insight into their initial objectives after gaining access to the system. 

**KQL Value** 
DeviceProcessEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where TimeGenerated > datetime(2025-11-23T03:08:59Z)   // <- replace
| where InitiatingProcessFileName =~ "explorer.exe"
| where ProcessCommandLine has @":\"
| project TimeGenerated, ProcessCommandLine,InitiatingProcessId,FileName
| order by TimeGenerated asc
| take 50   




### 🚩 Flag 30 Determine the Attacker’s Next Action After Reading the File

**Objective** 

What did the attacker do next after reading the file? 

**Flag Value** 
Ipconfig.exe 

**Detection Strategy**  

The detection strategy focuses on identifying the **next process executed by the attacker after accessing the initial file on CH-OPS-WKS02**. Analysts should review **process execution telemetry** tied to the attacker’s logon session and filter for processes launched immediately after the file access event. By correlating these events with the same session metadata and timestamps, investigators can determine the attacker’s next action in the intrusion chain. This analysis helps reveal whether the adversary used the information obtained from the file to perform **system reconnaissance, credential use, privilege escalation, or preparation for lateral movement**, providing deeper insight into the attacker’s operational intent and progression through the system.

**KQL Value** 
DeviceProcessEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where AccountName =~ "chadmin" or InitiatingProcessAccountName =~ "chadmin"
| project TimeGenerated, AccountName, ProcessCommandLine,InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc  


### 🚩 Flag 31 Identify the Next Account Accessed After Recon 

**Objective** 
Which user account did the attacker access immediately after their initial enumeration activity? 

**Flag Value**
Ops.maintenance 






** Detection Strategy** 

The detection strategy focuses on identifying the **next user account accessed by the attacker after completing initial reconnaissance on CH-OPS-WKS02**. Analysts should review authentication and logon telemetry occurring immediately after the enumeration activity and correlate these events with the attacker’s session metadata. By filtering for new logon events or account interactions during this timeframe, investigators can determine whether the adversary attempted to **test stolen credentials, access another user profile, or pivot to a higher-privileged account**. Identifying the account involved in this transition helps defenders understand the attacker’s intent, trace potential privilege escalation attempts, and map how the adversary began interacting with additional user accounts during the intrusion.

**KQL Value** 
DeviceLogonEvents
| where DeviceName =~ "CH-OPS-WKS02"
| where ActionType == "LogonSuccess"
| where TimeGenerated > datetime(2025-11-23T03:08:00Z)   // <- your anchor time
| order by TimeGenerated asc
| project AccountName,TimeGenerated,InitiatingProcessCommandLine

























## 🎯 MITRE ATT&CK Technique Mapping

| Flag | Description | MITRE ATT&CK Technique(s) |
|------|-------------|---------------------------|


#
MITRE Technique
Key Artifact
Timestamp
0
Valid Accounts (T1078)
Suspicious activity on ch-ops-wks02
2025-10-09
1
PowerShell Execution (T1059.001)
MaintenanceRunner_Distributed.ps1
2025-11-24
2
C2 Beaconing (T1071)
Initial outbound beacon
2025-11-23
3
C2 Communication (T1071)
127.0.0.1:8080
2025-11-23
4
C2 Established (T1071)
Successful beacon
2025-11-30
5
Data Staging (T1074)
inventory_tmp_6ECFD4DF.csv
2025-11-25
6
Artifact Validation
SHA256 7f6393...f12d8
2025-11-25
7
Staged File Copy (T1074)
Temp artifact duplicate
2025-11-30
8
Registry Persistence (T1547.001)
CorpHealthAgent registry entry
2025-11-25
9
Scheduled Task Persistence (T1053.005)
CorpHealth_A65E64 task
2025-11-25
10
Registry Run Key (T1547.001)
Value: Maintenance Runner
2025-11-25
11
Privilege Escalation (T1548)
Elevated privileges detected
2025-11-23
12
AV Exclusion (T1562.001)
C:\ProgramData\Corp\Ops\staging
2025-11-23
13
Encoded PowerShell (T1059.001)
write-output token
2025-11-23
14
Token Manipulation (T1134)
ProcessID 4888
2025-11-25
15
Token Impersonation (T1134.001)
SID S-1-5-21-...-1000
2025-11-25
16
Ingress Tool Transfer (T1105)
revshell.exe
2025-12-02
17
External Tunnel (T1572)
ngrok-free.dev
2025-12-02
18
User Execution (T1204)
explorer.exe launched payload
2025-12-02
19
External C2 IP (T1071)
13.228.171.119
2025-12-02
20
Startup Persistence (T1547.001)
Startup folder revshell.exe
2025-12-02
21
Remote Session (T1021)
Attacker remote session
2025-12-02
22
Remote IP (T1021)
100.64.100.6
2025-12-02
23
Internal Pivot (T1021)
10.168.0.7
2025-12-02
24
Suspicious Logon (T1078)
Earliest login event
2025-11-23
25
External Login IP (T1078)
104.164.168.17
2025-11-23
26
Compromised Account (T1078)
chadmin
2025-11-23
27
Attacker Location
Vietnam
2025-11-23
28
Process Launch (T1059)
explorer.exe
2025-11-23
29
Credential File Access (T1552)
user-pass.txt
2025-11-23
30
Network Discovery (T1016)
ipconfig.exe
2025-11-23
31
Account Pivot (T1078)
ops.maintenance
2025-11-23



---

## 🧾 Conclusion


Logical Flow & Analyst Reasoning

0 → 1 🔍
A suspicious activity window is identified on CH-OPS-WKS02. Analysts anchor the starting point by validating host identity and establishing the timeframe of abnormal behavior.

1 → 2 🔍
Unusual maintenance activity and script execution stand out. Analysts question whether this was legitimate IT work or the beginning of attacker tooling.

2 → 3 🔍
Outbound connectivity attempts expose a nonstandard external destination. This raises concern that the script is beaconing rather than performing diagnostics.

3 → 4 🔍
Successful outbound traffic confirms a live connection. Analysts pivot to identify the destination and whether this aligns with corporate endpoints — it does not.

4 → 5 🔍
Disk activity follows shortly after beaconing. A new file appears, suggesting staging or tool transfer. Analysts catalog file properties and hashes.



5 → 6 🔍
Hash mismatch comparisons reveal differing versions of staged files. This raises suspicion of modification or deception during upload.

6 → 7 🔍
Additional staging artifacts appear in multiple directories. The attacker seems to be preparing the environment for future operations.

7 → 8 🔍
Registry queries indicate that the attacker is exploring credential or privilege-related keys. Analysts question whether escalation is being attempted.

8 → 9 🔍
Privilege manipulation events, including token modifications, confirm the attacker probed escalation pathways. This validates the earlier registry activity.

9 → 10 🔍
Shortly after escalation attempts, the attacker reaches out externally to download a new payload. This establishes the transition from recon to tool deployment.

10 → 11 🔍
Execution of the downloaded file marks a significant shift. Analysts inspect command-line arguments to determine purpose.

11 → 12 🔍
Network events reveal that the binary establishes outbound connectivity via an ngrok TCP tunnel. This confirms external control infrastructure.

12 → 13 🔍
Persistence emerges: the file is placed in the Startup folder. This ensures automatic execution on future logons and confirms foothold intent.

13 → 14 🔍
Analysts backtrack the origin of execution. Remote session metadata identifies the suspicious device name used for initial access.

14 → 15 🔍
That device name is tied to several internal IPs, hinting at pivoting or multiple session attempts. Analysts extract all related IPs for correlation.

15 → 16 🔍
Sorting by timestamp reveals which internal IP connected first. This establishes the earliest footprint inside the network.

16 → 17 🔍
Pivoting to logon events, analysts identify the earliest suspicious logon timestamp linked to the malicious device or IP.

17 → 18 🔍
The RemoteIP associated with the first logon reveals the attacker’s initial entry vector.

18 → 19 🔍
The corresponding account used during this logon surfaces the credentials the attacker leveraged to enter the environment.

19 → 20 🔍
Analysts correlate all accounts used across the attacker’s activity. This helps identify lateral movement or credential testing.

20 → 21 🔍
The first process launched immediately after logon exposes the attacker’s priority — reconnaissance, validation, or environment orientation.

21 → 22 🔍
Following that, the attacker opens a file containing credentials. Analysts understand this as targeted harvesting behavior.

22 → 23 🔍
The subsequent action reveals whether the attacker attempted to use those credentials or continued recon — showcasing tactical decision-making.

23 → 24 🔍
Events around remote IP geolocation help determine the attacker’s likely region or hosting provider, adding intelligence context.

24 → 25 🔍
Outbound HTTP/TCP attempts show whether the attacker established control channels beyond the ngrok tunnel.

25 → 26 🔍
Analysts review session lifecycles to identify active persistence channels and whether any were redundant or contingency mechanisms.

26 → 27 🔍
Registry-based Run keys or startup file placements point toward deliberate re-entry capability — the attacker prepared for repeated access.

27 → 28 🔍
Subtle cleanup behaviors appear. Analysts determine whether the attacker attempted to blend into system logs or overwrite artifacts.

28 → 29 🔍
File modification timestamps and process sequences help analysts reconstruct staging order and validate whether exfiltration occurred.

29 → 30 🔍
Outbound DNS or HTTP queries reveal whether the attacker validated external reachability for future exfil movements.

30 → 31 🔍
Analysts confirm whether compression or aggregation behavior occurred — attackers often bundle evidence before exfil attempts.

31 → 32 🔍
Finally, analysts correlate all elements — recon, credential access, payload deployment, persistence, and outbound C2 — closing out the narrative and reconstructing the full attack chain.

---
##Conclusion 

The investigation established **CH-OPS-WKS02** as the compromised endpoint and showed that the intrusion was not normal maintenance activity, but a coordinated attack that unfolded between late November and early December. The attacker used a suspicious PowerShell script, `MaintenanceRunner_Distributed.ps1`, to initiate outbound communications, stage files in multiple directories, modify registry keys, create scheduled task and Run key persistence, and attempt to weaken Windows Defender by adding an exclusion path. Additional evidence of privilege escalation was uncovered through token modification events, encoded PowerShell execution, and the creation of a malicious payload, `revshell.exe`, which was later executed and copied into the Startup folder for persistence. Together, these findings demonstrate a deliberate sequence of execution, defense evasion, persistence, and command-and-control activity on the host.

The timeline also revealed how the attacker gained and expanded access. The earliest suspicious logon to **CH-OPS-WKS02** originated from public IP **104.164.168.17**, which geolocation data linked to **Vietnam**, and used the **chadmin** account before moving into additional account activity involving **ops.maintenance**. Remote session metadata tied the activity to the device name **对手**, with evidence of both an external session IP and an internal pivot host, suggesting the attacker may have moved through the Azure environment before or during the compromise. Early post-logon actions, including opening `user-pass.txt` and launching `ipconfig.exe`, indicate the attacker quickly shifted from access to reconnaissance and credential-focused activity. Overall, the evidence shows a full intrusion chain involving initial access, reconnaissance, privilege escalation, payload delivery, persistence, and likely preparation for exfiltration or further lateral movement.

## Lessons Learned 


This investigation highlighted how quickly legitimate administrative tools and maintenance processes can be abused to conceal malicious activity. The attacker leveraged what appeared to be a normal maintenance script, **MaintenanceRunner_Distributed.ps1**, to initiate command execution, outbound communication, and staging behavior on **CH-OPS-WKS02**. Because environments like CorpHealth rely heavily on scheduled scripts and diagnostic utilities, it becomes critical for defenders to maintain a **baseline of expected administrative activity**. Without this baseline, malicious scripts that mimic maintenance tasks can easily blend into routine operations. Monitoring for unusual execution parameters, off-hours activity, encoded PowerShell commands, and deviations from standard script distribution across endpoints is essential for detecting this type of abuse early.

The investigation also demonstrated the importance of **correlating multiple telemetry sources to reconstruct an attacker’s full intrusion chain**. No single log source revealed the complete story. Instead, analysts had to combine process telemetry, network events, registry modifications, file creation events, authentication logs, and remote session metadata to uncover the progression of the attack. This multi-layer correlation revealed how the adversary gained access, performed reconnaissance, escalated privileges, deployed tooling, and established persistence. The lab reinforces that effective threat detection relies on **cross-data correlation, timeline reconstruction, and contextual analysis**, allowing defenders to move beyond isolated alerts and instead understand attacker intent, movement, and objectives within the environment. 


### Recommendations for Remediation

To reduce the likelihood of similar intrusions, CorpHealth should strengthen monitoring and control over **administrative scripting and PowerShell usage**. Because the attacker abused a maintenance script to execute commands and initiate network communication, organizations should implement **PowerShell logging and restriction controls**, such as Script Block Logging, Module Logging, and Constrained Language Mode where appropriate. Additionally, encoded PowerShell commands and scripts executed with bypassed execution policies should trigger alerts in the security monitoring platform. Establishing a baseline of approved maintenance scripts and verifying their integrity through hashing or digital signatures can also help detect unauthorized or modified scripts running within the environment.

Another key remediation step is improving **endpoint hardening and persistence monitoring**. The attacker created registry Run keys, scheduled tasks, and placed a malicious executable in the Windows Startup directory to maintain persistence. Security teams should regularly audit these persistence locations and deploy automated detection rules that alert when new scheduled tasks, Run key entries, or startup folder files are created outside of approved change windows. Furthermore, organizations should restrict the ability to modify **Windows Defender exclusions**, as this tactic is commonly used to hide malicious files from security tools. Administrative privileges should be limited to only necessary accounts, and all privilege escalation events should be logged and monitored.

Finally, CorpHealth should strengthen **network and authentication monitoring** to detect suspicious remote access activity earlier. The intrusion began with a remote login from an external IP address originating outside the organization’s normal geographic region. Implementing controls such as **conditional access policies, geolocation alerts, and multi-factor authentication (MFA)** for privileged accounts can significantly reduce the risk of unauthorized logins. Security teams should also monitor outbound connections to suspicious domains, tunneling services, and unusual ports that may indicate command-and-control communication. By combining improved endpoint visibility, tighter privilege management, and stronger network monitoring, the organization can significantly reduce its attack surface and detect malicious activity earlier in the intrusion lifecycle.

