---
title: Tratamiento de la TTY
author: guiseporaki
date: 2023-02-24
categories: [Linux, Cajón Verde]
tags: [Linux, Tratamiento TTY]
---
## Tratamiento de la tty
Cuando ingresas a la máquina objetivo a través de una reverse shell, en la mayoría de los casos que realizo es asi, tenemos que hacer lo que se llama un tratamiento de la tty/consola para poder trabajar con ella como si fuera la consola normal a la que estamos acostumbrados. Gracias a este tratamiento podremos hacer:
+ `Ctrl + C`  
Sin miedo a que nos salga de la consola y por consiguiente de la máquina objetivo.
+ `Ctrl + L`  
Para borrar la consola de manera rápida.
+ Uso del nano y demás editores de texto en las proporciones adecuadas.

Y esto son los comandos que suelo realizar para este tratamiento:

```
> script /dev/null -c bash
```
Y ahora hago un `Ctrl + Z` para dejar la consola en segundo plano y luego volver a ella.
```
> stty raw -echo; fg
> reset xterm
```
Ahora ya estaremos de vuelta en la consola remota.
```
> export TERM=xterm
> export SHELL=bash
En tu consola local haces un stty size y añades esos valores en:
> stty rows NUMERO columns NUMERO
```

---

### Pwncat

Otra forma es con pwncat, visto máquina VENOM, DARKHOLE de Vulnhub, SHURIKEN de Vulnhub. Que además tiene opción de hacer reconocimiento de la máquina y descubre vulnerabilidades tipo linpeas o winpeas.
Para instalar busca pwncat-cs en github: pip install pwncat-cs.

---
### Consideraciones Varias

Si al hacer el "script /dev/null -c bash" no te da mensaje de darte consola(atento), mira si tiene python:  
```
> which python
```
Y si tiene;
```
> python -c 'import pty;pty.spawn("/bin/bash")'
```
Esto ya sería una pseudo-consola, vamos a mejorarla:
```
Ctrl + Z
> stty raw -echo; fg
> reset xterm
> y ahora los export y el size visto antes.
```
Visto KOTARAK.
