

I wish i could have given this more time. 

###PHASE1###

nmap is a tool used to enumerate networks/ports/services. 

Found three host on the 10.0.0.0/24 subnet. Initially I did not use the -Pn switch which would have revealed the d-link page.

```
nmap -Pn -sT 10.0.0.0/24 -T5
 -Pn assumes all hosts are up and enumerates the ports anyways isntead of skipping them. *slow*
-Pn assume host is up
-sT use TCP
-T5 thread 5
```

```
nmap -T4 -sC -sV -p- -oA nmap/RenLin-total 10.0.0.1   
-sC Default scripts
-sV Determine which port is open

Nmap scan report for 10.0.0.1
Host is up (0.050s latency).
Not shown: 65532 filtered ports
PORT    STATE SERVICE  VERSION
53/tcp  open  domain   (generic dns response: NOTIMP)
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp  open  http     nginx
|_http-server-header: nginx
|_http-title: Did not follow redirect to https://10.0.0.1/
443/tcp open  ssl/http nginx
|_http-title: 400 The plain HTTP request was sent to HTTPS port
| ssl-cert: Subject: commonName=pfSense-5cdd6132d61e9/organizationName=pfSense webConfigurator Self-Signed Certificate                                       
| Subject Alternative Name: DNS:pfSense-5cdd6132d61e9
| Not valid before: 2019-05-16T13:10:11
|_Not valid after:  2024-11-05T13:10:11
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
| tls-nextprotoneg:
|   h2
|_  http/1.1
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.70%I=7%D=6/10%Time=5CFECA7E%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x85\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03")%r(DNSStatusRequestTCP,E,"\0\x0c\0\0\x90\x04\0\0
SF:\0\0\0\0\0\0");
```

2)d-link![d-link](C:\Users\charl\OneDrive\Pictures\hackthebox\rendition\d-link.PNG)

###PHASE2### Enumerating Hosts

The first 10.0.0.1 is an instance of pfsense(firewall) with ports 53, 80, 443. Http is redirected to Https. Default credentials for pfsense are admin, pfsense. The default credentials don't work,  ran hydra(Brute Forcing Passwords) against Admin as user.

I used hydra and a handful of credentials to try and guess the password. I ran through msfconsole and tried to get command injection, Buffer overflow attacks to work to. 



The second
phase1) 10.0.0.2  My initial finding using Nmap were quite misleading. I thought because I saw SMB was up, it was a windows host, also seeing port 8080. Skipping further enumeration I rushed off to enumerate the website. Quickly discovering that image upload was an option. that none of the filters in place prevent uploading malware. Uploaded a PHP file that allowed me to run system commands. This the moment i released the host was Linux based. Ping is disabled wasn't able to use that while nmap did its full scan.  Because of permission, limited to traversal. Found out the user's name was David I guessed the password was David quickly gaining access. 

initially when i gained access i used nc to enumerate the subnet. 

```
for i in {1..254}; do nc -v -n -z -w 1 10.100.10.$i 22; done | grep -v 'timed'
```

Nmap Results this will ad an additional 3 host

```
                   
                                                                                       Nmap scan report for 10.100.10.15                                                      
Host is up (0.00028s latency).                                                         
Not shown: 1198 filtered ports
PORT    STATE SERVICE
53/tcp  open  domain
88/tcp  open  kerberos
135/tcp open  loc-srv
139/tcp open  netbios-ssn
389/tcp open  ldap
445/tcp open  microsoft-ds
464/tcp open  kpasswd
593/tcp open  unknown
636/tcp open  ldaps
MAC Address: 00:0C:29:B3:3F:FA (Unknown)

Nmap scan report for 10.100.10.25
Host is up (0.00034s latency).
Not shown: 1204 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https
MAC Address: 00:0C:29:3D:DC:C4 (Unknown)

Nmap scan report for 10.100.10.139
Host is up (0.00019s latency).
Not shown: 1205 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
MAC Address: 00:0C:29:3E:DB:19 (Unknown)
```

system 15 Domain Controller



**SYSTEM** 25	4/5	 web server or rhel-2394-11922 

user = root , pass = AllMyBas3srBELONGt0m3 # MAY ALSO USE RSA KEY FOUND /var/www/back_ups

webpage creds admin/admin. I had hoped since this logs into a personal account there might be saved creds in the mozilla folder. The server is using 

![webpage-dog](C:\Users\charl\OneDrive\Pictures\hackthebox\rendition\webpage-dog.PNG)

1) Found /home/sthompson/ftp_check.sh which contained credentials to host 139

```
#!/bin/sh
HOST='10.100.10.139'
USER='sthompson'
PASSWD='hackersW4ntT0Bm3'
```

2) Found a **FLAG** in BASH HISTORY

  192  cd /var/www/html/                                                               
  193  ssh-keygen -t rsa -C "sara@global.scb" 

```
I_H3@RT_bash_history

192  cd /var/www/html/                                                               
  193  ssh-keygen -t rsa -C "sara@global.scb" 
```

3) Hard Coded Credentials **FLAG** The login Credentials for the webpage are admin, admin. so lucky xD

```
2c00l4_security_
```

![hard-coded-creds](C:\Users\charl\OneDrive\Pictures\hackthebox\rendition\hard-coded-creds.PNG)



**SYSTEM** 4/4 139  	NAME = file server / aob8q

user = sthompson , pass = hackersW4ntT0Bm3

user =  t7dqohu8n7wq , pass = abc123!@# **FLAG**

1) Found some stored credentials & a flag. 

![tp](C:\Users\charl\OneDrive\Pictures\hackthebox\rendition\ftp.PNG)

![creds](C:\Users\charl\OneDrive\Pictures\hackthebox\rendition\creds.PNG)

2) Found another user ***t7dqohu8n7wq***(sudo user), i tried all the cred i had saved and a whim tried the decrypted ntlm hash and it worked. you may access all the files in home directory but not golden_ponyboy.txt

```
P0n3y_uP_and_GRAB_d1$_K3Y
# For debugging the web server, we can just add our hash to the MariaDB.               
65af2bf5f5c7d6802d01bf967917e0cd  == abc123!@#
yOu4_S1lver_n_MY_B00ks
```

![t7dqohu8n7wq](C:\Users\charl\OneDrive\Pictures\hackthebox\rendition\t7dqohu8n7wq.PNG)

3).python_history found encrypting the string. 

```
cat .python_history
import hashlib
haslib.md5("abc123!@#").hexdigest()
hashlib.md5("abc123!@#").hexdigest()
hashlib.md5(str("abc123!@#")).hexdigest()
hashlib.md5(str("abc123!@#").encode("utf-8")).hexdigest()                              
'65af2bf5f5c7d6802d01bf967917e0cd'
quit
quit()
```

