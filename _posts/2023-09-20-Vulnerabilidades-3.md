---
title: Vulnerabilidades 3
date: 2023-09-20
categories: [Hacking Web, Abrir con cuidado]
tags: [Inyecciones XPath, IDORs, CORS, SQL Truncation Attack, JWT]
image:
  path: ../../assets/img/HackingWeb/AbrirConCuidado/vulns3.jpg
  width: 528
  height: 340
  alt: Banner Vulns3
---

Y vengo con más vulnerabilidades. Todas ellas hermosas. Agradecimientos a Marcelo Vázquez conocido también como s4vitar. Parte de los conocimientos los he recogido de sus videos y academia.

- - - 

## Inyecciones XPath

### ¿Qué es?

Es un lenguaje de consulta utilizado en XML. Las vulnerabilidades XPath son las que se aprovechan de un fallo en la implementación de consultas XPath.

Se parece bastante a las SQLi pero aquí no hay una base da datos por detrás, hay una estructura XML.

### ¿Cómo nos damos cuenta?

Mientras probamos una SQLi por ejemplo;
```
'
' or 1=1-- -
' or '1'='1  # Esta es una forma de no tener que poner comentarios, la comilla que resta te cerraría el 1.
' and 1=1-- -
```
Imagina que el XML por detrás contiene algo así:
```c
FindUserXPath = "//Employee[UserName/text()='" + Request("Username") + "' And
        Password/text()='" + Request("Password") + "']";
```
Una de esas inyecciones puede que funcione. Posiblemente pensarás que estas ante un SQLi. Llegarías a la conclusión de que se puede tratar de una inyección XPath cuando después de que haya funcionado alguna inyección anterior sigas con el ataque y no te funcione ni el order by, ni el union, ni los time, ni el NoSQLi.

Como no en hacktricks tienes más información de este ataque.

El lenguaje XML va por etiquetas, la inyección consistirá en averiguar etiquetas principales -las primeras-, los nombres de estas, etiquetas secundarías -las que están dentro de las principales-. E ir averiguando así toda la estructura XML. Para ello es aconsejable usar fuerza bruta, por ejemplo creandonos un script en python. La forma de hacerlo es muy similiar a otras hechas para SQLi. Usando la inyección vulnerable encontrada y jugando con la respuesta iremos sacando letra por letra. Jugaremos con la función substring, string-lenght, etc.
```sh
# Desde burpsuite, en la data:

search=1' and count(/*)='1&submit=
# Para averiguar número de etiqueas principales, se iría brute forceando en el 1.
search=1' and count(/*[1]/*)='1&submit=
# Averiguar número de etiquetas dentro de la primera eiqueta principal.

# Para averiguar el nombre de la etiqueta primera podríamos averiguar el número de caracteres:
search=1' and string-lenght(name(/*[1]))='5&submit=
# También se puede jugar con mayor o menor.
# Una vez descubierto podríamos hacer un bucle hasta ese número, si no ponemos un número alto y ya.
```
```py
# Y ya desde un script en python formar una data como esta para averiguar el nombre de la etiquea:
post_data = {

    'search' = "1' and substring(name(/*[1],%d,1)='%s" % (position, character),
    'submit' = ''
}
# Si quisieras sacar el nombre de las etiquetas de dentro:
post_data = {

    'search' = "1' and substring(name(/*[1]/*[1],%d,1)='%s" % (position, character),
    'submit' = ''
}
# En el if para sacar las respuestas que nos interesan podríamos descartar por la longitud de la respuesta; print(len(r.text)).
```
Y de esta manera, mediante estas solicitudes, ir sacando las etiquetas. Si quiero ver el valor de las eiquetas sacadas:
```py
# Estraída la etiqueta Secret averiguamos su valor:
post_data = {

    'search' = "1' and substring(Secret,%d,1)='%s" % (position, character),
    'submit' = ''
}
```

- - - 

## IDORs

### ¿Qué es?

El IDOR -Insecure Direct Object Reference- es un tipo de vulnerabilidad que ocurre cuando una aplicación le permite a un usuario acceder directamente a objetos (como recursos, funciones o archivos) en función de la consulta que este realice, sin realizar el debido control de acceso.

### Explotación

Con un ejemplo se me mejor, imagina la siguiente url:
```sh
htp://maquinota.htb/index.php?producto=1
# Ese 1 lo puedes cambiar por otros números que corresponderían a otros productos, incluso productos que no tendrían que estar visibles.
```
Y poco más. Es ir cambiando los valores (lógicamente) a ver que encuentras.

- - - 

## CORS

### ¿Qué es?

Información recogida de esta [página](https://developer.mozilla.org/es/docs/Web/HTTP/CORS).
El intercambio de recursos de origen cruzado (CORS, por sus siglas en inglés), es un mecanismo basado en cabeceras HTTP que permite a un servidor indicar cualquier dominio, esquema o puerto con un origen (en-US) distinto del suyo desde el que un navegador debería permitir la carga de recursos. CORS también se basa en un mecanismo por el cual los navegadores realizan una solicitud de "verificación previa" al servidor que aloja el recurso de origen cruzado, con el fin de comprobar que el servidor permitirá la solicitud real.

Un ejemplo de solicitud de origen cruzado: el código JavaScript del front-end servido desde https://domain-a.com utiliza XMLHttpRequest para realizar una solicitud a https://domain-b.com/data.json .

Por razones de seguridad, los navegadores restringen las peticiones HTTP de origen cruzado iniciadas desde scripts. Por ejemplo, XMLHttpRequest y la API Fetch siguen la Política Same-origin. Esto significa que una aplicación web que utilice esas API solo puede solicitar recursos del mismo origen desde el que se cargó la aplicación, a menos que la respuesta de otros orígenes incluya las cabeceras CORS adecuadas.

En el caso típico de un XSS, donde se carga la cookie desde el navegador a través de las instrucciones de un JS si que funciona porque es el mismo origen digamos. Es la web víctima el origen , la que solicita mi recurso js y nos carga directamente la cookie via url.

El estándar para recursos compartidos de origen cruzado funciona añadiendo nuevas Cabeceras HTTP que permiten a los servidores describir qué orígenes tienen permiso para leer esa información de un navegador web. Es aquí donde se puede intentar vulnerar y añadir nuevos origenes con permiso.

- - - 

## SQL Truncation

### ¿Qué es?

La vulnerabilidad de truncamiento de SQL ocurre cuando una base de datos trunca la entrada del usuario debido a una restricción en la longitud.  
Podríamos pensar en este tipo de ataque siempre que la aplicación nos acorte lo que pongamos.

### Explotación

Imagina que tienes un limite de 15 caracteres en el registro de cualquier usuario. Es un limite de la base de datos SQL que corre por detrás, pero a la hora de hacer el registro tu puedes meter más ya sea desde la consola del navegador modificando el campo de longitud o desde burpsuite que no vas a tener límites. Si añado más de 15 lo que pasará es que cuando la base de datos maneje la data introducida la acortará a 15.

Imagina que conoces el login del administrador, digamos  que es SuperAdmin. En esta vulnerabilidad atacaremos el registro. Si intentamos registrar ese usuario nos saldrá que ya está en uso, pero si añadimos espacios hasta pasarnos del límite **y un carácter** lo insertaría en la base de datos, es decir, **en la comparativa tiene en cuenta esos espacios y el carácter y lo toma como un usuario diferente, pero una vez dentro de la base de datos esta elimina lo que sobrepasa del límite(el cáracter) y los espacios los quita** y nos quedamos con que hemos registrado al usuario SuperAdmin con la contraseña deseada. Hemos cambiado la contraseña a SuperAdmin.

Repaso:
```sh
# Máximo 15 caracteres. Conocemos usuario SuperAdmin
# Pasamos la petición por bursuite y en el registro:
User: SuperAdmin     a  # Llegamos a 15 incluido con los espacios y añadimos un carácter.
Password: hackiiadoo
```
- - - 

## Jason Web Token

### Explotación

Parte de que es no la pongo porqe es básicamente un token, dentro de este se asignan campos mediante una clave.

El onjetivo es cambiar los campos y sus valores contenidos en el token por otro usuario que nos convega.  

**¿Cómo se ve?**. Suele dividirse en tres partes separadas por un punto. La primera parte, hasta el primer punto, suele corresponder a la cabecera, la segunda al payload (user, password, etc) y la tercera a la firma digital que se encarga de verificar la intregridad del token y utliza un hash criptográfico que usa por detrás un clave secreta. Esas tres partes normalmente las encuentro en base64.

En posesión del token podemos irnos a la super página para jwt; [jwt.io](https://jwt.io). Si pegamos nuestra cookie podríamos ver los valores a la derecha. Si supieramos el secreto lo añadiriamos en el campo "your-256-bit-secret". Si lo conocieras puedes meter a la derecha el usuario que quieras y se generará un token válido para él.

Hay alguno jwt que no requieren de la tercera parte, de la firma, y es porque en el campo **alg** de algoritmo, o similiar, tienen como valor **NONE**. En estos casos puedes convertir a base 64 la data que quieras hasta el segundo punto incluido, el resto se omite y no se manda.

El segundo caso más probable es que esté la firma por detrás y que haya que averiguarla para alterar los campos y que sea válidos. Si el secreto -la clave- no es díficil quizás podramos averiguarla.

Recomiendo ver algunas máquinas usadas con este tipo de ataque. Puedes usar esta [página](https://machines-javiermolines.vercel.app/) para filtrar por tipo de ataque en las máquinas realizadas por S4vitar. Una de las máquinas se llama **Secret**.

- - - 

