---
title: "Piggy Walkthrough - BTLO Labs"
date: 2025-07-10 19:00:00 +0530
categories: [Capture the Flags, Windows]
tags: [BTLO,wireshark,MITRE, forensics]   
description: "Walkthrough of PIGGY invesigation"
---


### PCAP One: SSH Data Exfiltration

**Question:**  
What remote IP address was used to transfer data over SSH? *(Format: X.X.X.X — 3 points)*  
How much data was transferred in total? *(Format: XXXX M — 3 points)*

PCAP One is quite large—over **1GB** in size—so I filtered only the **outbound SSH traffic** using the Wireshark filter:

```wireshark
tcp.dstport == 22
```

From there, I navigated to `Statistics > Conversations`, checked **“Limit to display filter”**, and found the remote IP `35.211.33.16`. The total bytes transferred to this IP from the internal machine was approximately **1123M** — a clear indicator of potential data exfiltration over SSH.

![image.png](assets/img/Piggy/image%201.png)


### PCAP Two: OSINT-Based Malware Attribution

**Question:**  
Review the IPs the infected system has communicated with. Perform OSINT searches to identify the malware family tied to this infrastructure. *(Format: MalwareName — 3 points)*

Here are the IPs observed in the PCAP conversations:

```plaintext
10.0.9.171      ← internal
82.2.64.107
34.110.209.165
188.120.241.27
195.161.41.93
92.53.67.7
31.184.253.37
78.155.206.172
```

Excluding the internal IP, I started investigating the others using tools like **Scamalytics**, **VirusTotal**, and **Google**.

The IP `31.184.253.37` caught my attention. Scamalytics flagged it with a **"Medium Risk"** reputation, and after digging deeper, I found that it had been associated with **Trickbot loader** campaigns in the past.
![image.png](assets/img/Piggy/image%203.png)

Reference:  
[Malicious Activity Linked to Trickbot Loader - ANY.RUN](https://any.run/report/387682995c339dd34e1b7943d7bcb84a7c1a3b538ffa10cf5a1555361a40a0fd/c066e0e9-2a69-4927-9d24-11e2888ffbf9#Network)



### PCAP Three: Unusual Ports & Mining Activity

**Question 1:**  
Review the two IPs communicating on unusual ports. What are the two ASN numbers these IPs belong to? *(Format: ASN, ASN — 3 points)*

By checking `Statistics > Conversations`, I identified two suspicious external IPs:

- `194.233.171.171`
- `104.236.57.24`

These stood out due to communication over non-standard ports. Using `whois.domaintools.com`, I mapped them to the following ASNs:

- `194.233.171.171` → **AS63949**
- `104.236.57.24` → **AS14061**

![image.png](assets/img/Piggy/image%204.png)

**Question 2:**  
What malware category have these IPs been historically linked to? *(Format: MalwareType — 3 points)*

VirusTotal analysis revealed that both IPs were previously reported as involved in **cryptocurrency mining**:

- [104.236.57.24 - VirusTotal](https://www.virustotal.com/gui/ip-address/104.236.57.24)
- [194.233.171.171 - VirusTotal](https://www.virustotal.com/gui/ip-address/194.233.171.171)

**Question 3:**  
What ATT&CK technique is most closely related to this activity? *(Format: TXXXX — 3 points)*

This behavior corresponds to ATT&CK technique **T1496 – Resource Hijacking**.

> *Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks such as cryptocurrency mining, which may impact system performance and service availability.*


###  PCAP Four: DNS TXT Queries & C2 Communication

**Question 1:**  
Go to `View > Time Display Format > Seconds Since Beginning of Capture`.  
How long into the capture was the first TXT record query made? *(Format: X.xxxxxx — 3 points)*

After switching the time format to **Seconds Since Beginning of Capture**, I applied the display filter:

```wireshark
dns.qry.type == 16
```

This filter isolates DNS TXT record queries — often used for exfiltration or C2 signaling.

![image.png](assets/img/Piggy/image%205.png)

The first TXT request was observed at:

```
8.527712 seconds
```

![image.png](assets/img/Piggy/image%206.png)

**Question 2:**  
Change the display format to `UTC Date and Time of Day`.  
What is the date and timestamp of the first TXT record? *(Format: YYYY-MM-DD HH:MM:SS — 3 points)*

Switching to UTC format clearly shows the time of the first TXT query:

**Timestamp:**  
(Refer to screenshot below)

![image.png](assets/img/Piggy/image%207.png)


**Question 3:**  
What is the ATT&CK subtechnique relating to this activity? *(Format: TXXXX.xxx — 1 point)*

This activity — where the attacker uses **DNS TXT records for C2 communication** — aligns with:

**MITRE ATT&CK:**  
**T1071.004 – Application Layer Protocol: DNS**

Adversaries may communicate using application layer protocols such as DNS to bypass traditional network defenses.

🔗 [MITRE ATT&CK - T1071.004](https://attack.mitre.org/techniques/T1071/004/)

### Disclaimer
This walkthrough is intended for educational and ethical purposes only. All analysis was performed in a controlled environment using simulated traffic provided by **BlueTeam Labs Online**.  
No part of this content should be used to target or attack real-world systems without proper authorization.  
Some investigative steps and insights reference official documentation, threat intel platforms, and community research to ensure accuracy. Full credit goes to the original authors and tool creators.