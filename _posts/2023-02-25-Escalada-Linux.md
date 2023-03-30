---
title: Escalada en Linux
author: guiseporaki
date: 2023-02-24
categories: [Linux, Cajón de Arriba]
tags: [Linux, Escalada]
---
## Escalada

Una vez accedido al sistema objetivo y teniendo la consola en condiciones, después del tratamiento de la tty(en el cajón verde), empiezo a buscar formas de escalar priviligios.

Esta es la estructura o **método** que suelo usar:
```
> id  
> sudo -l  
> find \-perm -4000 2>/dev/null
> getcap -r / 2>/dev/null  
> uname -a   
> lsb_release -a   (también vale cat /etc/os-release)    
> crontab -l  (ó cat /etc/crontab -visto máquina Time-)
> systemctl list-timers  
```
[gtfobins]: https://gtfobins.github.io/ 
En cuanto a permiso de sudo o suid me apoyo en la página [GTFObins][gtfobins]

No todas las tareas programadas están en el crontab, hay otras rutas. Esta por ejemplo el systemctl de antes. Visto Time.  

Si no encontramos nada de momento en cuanto a tareas programadas podremos usar pspy(en github lo encontrarás) o crearnos un script rápido que las detecte, comunmente lo llamo **procmon** porque así lo llama S4vitar y así se quedo -visto en máquina Meta y Time por ejemplo). Pero antes de esto prefiero echar un vistazo por otro lado, por ejemplo buscando strings interesantes(config, password, passwd) en determinadas rutas como la de alojamiento de la web:

En `var/www/html` hacer un:
```
> grep -riE "passwords|username"
```
Si en vez del contenido quisieras sacar los nombres de archivos donde se encuentran ese contenido grepeado añades **opción l**  
**less -S** para leer poco a poco, en formato paginate.
```
> find . -name \*config\* | xargs cat | grep -iE "user|pass|key|database"  
```
Suelo añadir un wc -l para saber cuan grande es. Y si lo es quitar alguna palabra o añadir un less.

Ahora me gusta buscar archivos de los que yo tenga control por si pudiera aprovechar esto de alguna manera:
```
> find . -type f -user <usuarioactual> 2>/dev/null  
```
O sin opción type. Puedes quitar rutas que no te interesen, por ejemplo:  
```
> find . -type f -user <useractual> 2>/dev/null | grep -v -E "proc|var"   
```

¡ Ah!. Podrías hacer lo mismo con otros usuarios:  
`grep "sh$" /etc/passwd`  (y ahora lo mismo de antes pero cambiando de user).  
También prueba esto:  
```
> find \-writeable 2>/dev/null
```

Retomamos ahora la búsqueda de tareas cron/procesos programados, dos maneras:

1- Tirando de pspy, lo transfieres a la máquina víctima, le das permiso de ejecución y lo ejecutas. El programa buscará procesos ejecutandose.

2- Te creas/copias el script que pongo abajo, al que llamaré procmon.sh, recuerda darle permiso de ejecución:
``` bash
#!/bin/bash
function ctrl_c(){
     echo -e "\n\n[!] Saliendo...\n"
}
# Ctrl+C
trap ctrl_c INT

old_process=$(ps -eo command)
while true;  do
    new_process=$(ps -eo command)
    diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\]" | grep -vE "procmon|command|kworker"
    old_process=$new_process
done
```

Y si nada uso la herramienta **linpeas** de Carlos ¡Polopo!, en github está. Esta herramienta se encarga de detectar vías para escalar privilegios. Se puede usar para la OSCP y otros porque no te automatiza la escalada, solo es un reconocimento.
