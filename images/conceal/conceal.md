nmap 

I would like to take a momment ang go into --min-rate . so the target might have some kind of firewall emplave effecting rate limit. Whats this garbage well i can't even scan the target most likely blocked xD

1) Nmap failed me. 

![fail-nmap](C:\Hugo\sites\blog\static\images\conceal\fail-nmap.PNG)

2) nmap failed me again. 

```
nmap -sU -p 160-165 10.10.10.116 -T5                                               
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-26 01:51 EDT                                                       
Nmap scan report for 10.10.10.116
Host is up (0.041s latency).

PORT    STATE         SERVICE
160/udp open|filtered sgmp-traps
161/udp open|filtered snmp
162/udp open|filtered snmptrap
163/udp open|filtered cmip-man
164/udp open|filtered smip-agent
165/udp open|filtered xns-courier

Nmap done: 1 IP address (1 host up) scanned in 1.56 seconds   
```

3) going to try and and see if all the port return like that. 

```
nmap -sU 10.10.10.116 -T5
```

4) nmap -sU -sC --top-ports 20 -oA nmap/udp-top20-scripts 10.10.10.116



SNMP

snmpwalk

apt install snmp-mibs-downloader  

UDP PORT 500 ike internet key excahnge used in a ipsec 

```
ike-scan -M 10.10.10.116
ike-scan -M --ikev2 10.10.10.116
```

```
9C8B1A372B1878851BE2C097031B6E43
Dudecake1!
```



VPN

use strongswan as the vpn client



```
nmap -sC -sV -p21,80,135,139,445,49664,49665,49666,49667,49668,49669,49670 --min-rate 10000 -oA nmap/golden-pie 10.10.10.116
```

```
 nmap -sT -sC -sV -p21,80,135,139,445,49664,49665,49666,49667,49668,49669,49670 --min
-rate 10000 -oA nmap/golden-pie 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-26 04:30 EDT
Nmap scan report for 10.10.10.116
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-26-19  09:29AM                    0 jp.exe
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 10s, deviation: 0s, median: 10s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-05-26 04:31:40
|_  start_date: 2019-05-25 16:50:54

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.87 seconds

```

```
gobuster -u http://10.10.10.116 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 100 
```

web 

there is no php it reads .htm files check asp

