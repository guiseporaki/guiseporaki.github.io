---
title: Enumeración de Servicios
author: guiseporaki
date: 2023-09-20
categories: [Linux, Cajón de Arriba]
tags: [FTP, SSH, SMB]
---

Parte de la información la he recogido de la academia de Marcelo Vázquez también conocido como S4vitar. La recomiendo totalmente para aprender. Esta es su academia; [Hack4u](https://hack4u.io/).

## FTP

Para conectarte a un servicio ftp simplemente es usar el comando ftp y la ip:
```
> ftp IP
```
Si está activada la entrada para el usuario invitado podrás entrar con estas credenciales:  
user: anonymous  
passwd:(vacía)

### Docker con servicio FTP y práctica.

Para probar la enumeración FTP recomiendo instalarte estos dos dockers de github:  
https://github.com/garethflowers/docker-ftp-server  
https://github.com/metabrainz/docker-anon-ftp (ejemplo con usuario anonymous)

Por ejemplo, en la primera página solo hay que ejectuar esto:
```
docker run \
	--detach \
	--env FTP_PASS=1234 \
	--env FTP_USER=guise \
	--name my-ftp-server \
	--publish 20-21:20-21/tcp \
	--publish 40000-40009:40000-40009/tcp \
	--volume /data:/home/user \
	garethflowers/ftp-server
```
Puedes cambiar el user y el pass si quieres, como probaremos fuerza bruta puedes poner alguna passwd de algún archivo que te crees con unas cuantas palabras o usar el rockyou.txt( o algumo más pequeño).   
Si haces un `docker ps` saldrá, está corriendo, y puedes ver los puertos por donde corre ese servicio ftp, puerto 21 seguramente. Nos conectamos:
```
> ftp localhost
```
Si está en el puerto 21 no hay que indicar puertos porque es el de por defecto, si es otro valdría con añadir el puerto así:
```
> ftp localhost PUERTO
```
Nos pedirá usuario y contraseña que hayamos agregrado antes.

Recuerda que antes de llegar aquí ya hemos realiado la fase de reconocimiento donde se escanean los puertos de la máquina objetivo, son estos dos comandos, por ejemplo para la ip `10.10.11.144`:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.144 -oG allPorts
(Descubre abierto el puerto 21)

❯ nmap -p21 -sC -sV 10.10.11.166 -oN targeted
```
Este último comando te indicaría la versión del ftp y si está habilitado el acceso para anonymous.

### Fuerza bruta a servicio FTP

Supondremos que sabemos el usuario. Vamos a emplear la herramienta **hydra** para realizar un ataque de fuerza bruta y averiguar la contraseña.
```
> hydra -l guise -P DICCIONARIO ftp://127.0.0.1 -t 10
```
Si usas diccionario la letra de opción en mayúsculas, si ya sabes user/passwd en minúsculas. t: número de hilos.

Te tendría que descubrir la password.

**Comandos típicos una vez dentro:**

help: lista de comandos.  
cd: movimiento entre directorios.  
ls: listar contenido.  
pwd: directorio actual.  
get: descarga de archivo del servidor remoto, desde el que te conectaste.  
mget: lo mismo que get pero para varias descargas.  
put: sube arhivo al servidor remoto.  
mput: sube varios archivos.  
delete: eliminar archivo.  
quit o bye: Para salir.

- - - 

## SSH

Voy a estructurarlo como en el FTP; primero nos montamos un docker con el servicio y luego mientras practicamos vemos un poco de enumeración.

### Docker con servicio ssh y práctica.

Vamos a utlizar una página para montarlo. Baja hasta **docker cli** copia el código y pegalo en consola.  
https://hub.docker.com/r/linuxserver/openssh-server

Las opcionales puedes quitarlas o cambiarlas. En PASSWORD_ACCESS tienes que poner true. USER_PASSWORD y USER_NAME la que tu quieras, PASSWORD_FILE quitalo.

Una vez lanzado el código en la consola nos conectamos:
```
> ssh USER@127.0.0.1 -p PUERTO
```

### Fuerza Bruta a servicio SSH

Usaremos hydra de nuevo, muy similar a ftp:
```
> hydra -l USER -P DICCIONARIO ssh://127.0.0.1 -s PUERTO -t 10
```
La opción -s es para indicar el puerto si no es el puerto por defecto, que es el puerto 22.

Si está en el diccionario te lo encontrará.

- - - 

## SMB

Montaremos un docker con este servicio para practicar con él.

### Docker con servicio SMB y práctica

Usaremos este repo: https://github.com/vulhub/vulhub/tree/master/samba/CVE-2017-7494

```
> svn checkout https://github.com/vulhub/vulhub/trunk/samba/CVE-2017-7494

> cd CVE-2017-7494

> docker-compose up -d

> docker ps (veriamos el puerto que esta usando, 445 será.)
```
La enumeración que realizaremos se puede utilizar tanto para linux como para windows.
```
> smbclient -L 127.0.0.1 -N
Este comando listaria "-L" los servicios compartidos de esa ip. Opción "-N" es de conectarnos mediante Null Session porque no disponemos de credenciales.

> smbmap -H 127.0.0.1
Igual que el anterior comando pero este además te muestra los permisos de cada archivo o carpeta.
```
Para conectarnos a esos recursos que hay dentro:
```
> smbclient //127.0.0.1/RECURSO -N
Una vez dentro, podemos usar comandos:
dir: para listar
put: para subir contenido
get: para descargar contenido
```
Puede que la carpeta compartida sea muy amplia y profunda, no es fácil moverse desde dentro del servicio. En local, por ejemplo, podríamos hacer un comando "tree" para visualizar el árbol de carpetas. ¿Solución?. Jugar con **monturas**.
```
> apt install cifs-utils

> mount -t cifs //127.0.0.1/RECURSO DIRECTORIOLOCAL
Ese directorio local es un directorio que tu has tenido que crear previamente. Es ahí donde se alojará la montura. Opción "-t" es de tipo.
Te pedirá contraseña, si no pones nada jugarás con Null Session y ya está.
```
Toda estructura y contenido del recurso compartido estará en ese directorio local. Todo lo que modifiques en local también se modificará en el recurso remoto, así que ¡¡cuidadin!!.

Para desmontar la montura:
```
> umount DIRECTORIOLOCAL
```

Otra herramienta muy potene es **crackmapexec**. Pero la usaré para Windows para máquinas Linux suele fallar.