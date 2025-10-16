---
title: 'Revil Walkthrough - CyberDefenders Labs'
date: 2025-10-16 18:00:00 +0530
categories: [threat-hunting]
tags:
- Cyber-Defenders
- Splunk
---

## Scenario

*You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users have reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.*

## Walkthrough

There are around **1,153 events** captured by the lab SIEM. All events were collected from a single source: `winlog.ndjson`.

![image.png]({{ '/assets/img/Revil/image.png' | relative_url }})

## Identifying host environment

From the event metadata I identified the host details:

```jsx
host.ip   = 192.168.19.129
host.name = win-2fosvi01scf
```

**Users on the machine**
The top accounts that appear in the `winlog.event_data.User` field are:

![image.png]({{ '/assets/img/Revil/image%201.png' | relative_url }})

Alerts/Rules triggered on the machine

## Alerts / Rules triggered on the machine

I enumerated alerts by rule name to understand what detections already fired:

```c
index=Revil
| stats count by winlog.event_data.RuleName
```

**RuleName**

| Technique ID | Technique Name                         |
| ------------ | -------------------------------------- |
| T1574.010    | Services File Permissions Weakness     |
| T1574.002    | DLL Side-Loading                       |
| T1571        | Non-Standard Port                      |
| T1204        | User Execution                         |
| T1197        | BITS                                   |
| T1083        | File and Directory Discovery           |
| T1070.001    | Clear Windows Event Logs               |
| T1059.001    | PowerShell                             |
| T1055.001    | Dynamic-link Library Injection         |
| T1055        | Process Injection                      |
| T1053        | Scheduled Task                         |
| T1047        | Windows Management Instrumentation     |
| T1047        | File System Permissions Weakness       |
| T1016        | System Network Configuration Discovery |
| T1053.002    | At                                     |


## Investigation Notes

Since we already have rules triggered on this activity, I started by identifying when the first alert occurred and which rule was the earliest indicator.

```c
index=revil
| table @timestamp, winlog.event_data.RuleName
| sort +@timestamp
```

![image.png]({{ '/assets/img/Revil/image%202.png' | relative_url }})


The timeline shows the earliest suspicious activity beginning on **2023-09-07** after 15:00 (UTC). I adjusted the time filter in the SIEM to narrow the window and locate the first IOC.

![image.png]({{ '/assets/img/Revil/image%203.png' | relative_url }})

To focus on genuine suspicious executions, I filtered out common benign or background processes using the following query:

```c
index=revil
| rex field=winlog.event_data.CommandLine "(?<cmd>[^\"']+)"
| where isnotnull(cmd) AND NOT like(cmd, "%Microsoft-Windows%") and NOT like (cmd,"%wevtutil.exe%")
| table @timestamp, winlog.event_data.RuleName, cmd
| sort +@timestamp
```

This yielded some interesting file executions, as shown below.

![image.png]({{ '/assets/img/Revil/image%204.png' | relative_url }})


From the above table, **“facebook assistant”** stood out as a suspicious entry. To investigate further, I decided to enumerate more information about this executable.

## Enumerating details about `facebook assistant`

To identify *when* and *where* the process executed:

```c
index=revil event.code=1 "facebook assistant.exe"
| table @timestamp, winlog.event_data.Image, wionlog.event_data.CommandLine, winlog.event_data.ProcessId, winlog.event_data.ParentProcessId
| sort @timestamp+
```

![image.png]({{ '/assets/img/Revil/image%205.png' | relative_url }})


From the query above, we can derive that the **PID** of `facebook assistant.exe` is **5348**, which later spawned a **PowerShell** process with PID **1860**.
Next, I looked for the parent process that launched `facebook assistant.exe`:

```c
index=revil event.code=1  winlog.event_data.ProcessId="5348"
| table @timestamp, winlog.event_data.Image, winlog.event_data.CommandLine, winlog.event_data.ProcessId, winlog.event_data.ParentProcessId
| sort +@timestamp
```

![image.png]({{ '/assets/img/Revil/image%206.png' | relative_url }})


As shown, there are two events recorded — each process gets a unique PID when created. Once a process exits, Windows can **recycle** that PID and assign it to a new one over time.

### Fetching child processes of `facebook assistant.exe`

To find all child processes spawned by the same PID (5348):

```c
index=revil event.code=1  winlog.event_data.ParentProcessId="5348"
| table @timestamp, winlog.event_data.Image, winlog.event_data.CommandLine, winlog.event_data.ProcessId, winlog.event_data.ParentProcessId
| sort +@timestamp
```

![image.png]({{ '/assets/img/Revil/image%207.png' | relative_url }})


Decoding the B64 data translates to 

```c
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```

Now that we have the **process ID** of `facebook assistant.exe`, I examined which **event codes** it generated during execution:

| **EventCode** | **Event Name** | **Description** |
| --- | --- | --- |
| **5** | Process Terminated | Logs when a process ends (PID termination). |
| **7** | Image Loaded | Logs when a process loads a DLL or image file into memory (useful for detecting DLL injection or side-loading). |
| **11** | File Create | Logs when a file is created or overwritten by a process. |
| **13** | Registry Value Set | Logs when a registry value is modified (used for persistence or configuration changes). |

Finally, I projected key telemetry values for process **5348**:

```c
index=revil winlog.event_data.ProcessId="5348"
| table @timestamp, winlog.event_data.Image, winlog.event_data.CommandLine, event.code, winlog.event_data.ProcessId, winlog.event_data.ParentProcessId,  winlog.event_data.TargetFilename, winlog.event_data.TargetObject
| sort +@timestamp
```

![image.png]({{ '/assets/img/Revil/image%208.png' | relative_url }})


The ransomware encrypted multiple files, terminated itself, and spawned a child process that deleted shadow copies.

### IOCs

```
B8D7FB4488C0556385498271AB9FFFD0EB38BB2A330265D9852E3A6288092AA - facebook assistant.exe

```