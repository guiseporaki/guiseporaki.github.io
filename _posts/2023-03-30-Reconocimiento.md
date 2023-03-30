---
title: Trick WriteUp
date: 2023-03-30
categories: [Linux, Cajón de Arriba]
tags: [nmap]
---

¿Qué tal gente?. En este post escribiré los comandos que suelo realizar para reconocimiento inicial de puertos de la máquina. También añadiré el método de algunos players que hacen WriteUps y que sirven de gran ayuda a la comunidad como es el caso de 0xdf, byte-mind y jarrodrizor. A mi el que más me ha ayudado es S4vitar, y es a este a quién debo el método que yo uso para el reconocimiento inicial de la máquina a realizar.

## Método S4vitar y el que yo uso

Usaré para los ejemplos la ip `10.10.11.166`.

Primero de todo suelo comprobar que esa ip me devuelve señal, que tengo conectividad con ella, y para ello le envio un ping.
```
❯ ping -c 1 10.10.11.166
PING 10.10.11.166 (10.10.11.166) 56(84) bytes of data.
64 bytes from 10.10.11.166: icmp_seq=1 ttl=63 time=39.6 ms

--- 10.10.11.166 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 39.625/39.625/39.625/0.000 ms
```
Como podéis ver arriba; 1 packets transmitted, 1 received. Todo bien.  
Si no fuera así, tendréis que comprobar que tenéis encendida la máquina y estáis conectadas a la VPN.

**Escaneo de puertos:**

Ejecuto dos comandos de escaneo de puertos. El primero es este y es para encontrar todos los puertos abiertos con un poca de información de estos.

```
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.166 -oG allPorts
```

Las opciones significan lo siguiente:  

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos.
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan.
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo.
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo.
* -n : Para no aplicar resolución DNS.
* -Pn : Para que no aplique el protocolo ARP.
* 10.10.11.166 : Dirección IP objetivo, la cual quiero escanear.
* -oG allPorts -> Exportará el output a un fichero grepeable que llamaremos "allPorts".

Después del anterior y primer comando uso un segundo y último. Este enfocado en sacar más información de los puertos obtenidos en la primera búsqueda. Imagina que los puertos conseguidos en el anterior comando son 22 y 80, entonces:
```
❯ nmap -p22,80 -sC -sV 10.10.11.166 -oN targeted
```
* -p  : Indica los puertos que quieres escanear.  
* -sC : Lanza una serie de scripts básicos de reconocimiento.
* -sV : Lanza script que descubre la servicio y la versión que corren en esos puertos. 
* -oN : Guarda el output en formato nmap a un fichero que llamaremos targeted.

----

## Método 0xdf

```
> nmap -p- --min-rate 10000 -oA alltcp 10.10.11.166
```
* -p- : Escanea todos los puertos.
* --min-rate 10000 : Para enviar paquetes no más lentos que 10000 paquetes por segundo.
* -oA : Te guarda la salida en los 3 formatos principales a la vez. Elige llamarlo alltcp.

```
> nmap -p22,80 -sCV -oA tcpScripts 10.10.11.160
```
* p : Indica los puertos que quieres escanear.
* sCV : Unifica las opciones -sC y -sV, explicados más arriba.
* oA : Te guarda la salida en los 3 formatos principales a la vez. Elige llamarlo tcpScripts.

---

## Método Jarrodrizor

```
> nmap -p- -sV -Pn -v 10.10.11.166
```
* -p- : Escanea todos los puertos.
* -sV : Lanza una serie de script básicos de reconocimiento.
* -Pn : Para que no aplique el protocola ARP. Tardaría un buen rato de hacerlo.
* -v : Muestra la información en pantalla mientras se realizar el escaneo.

---

## Método byte-mind

```
> nmap -sC -sV -oA allPorts 10.10.11.166
```
Instrucción más corta que las anteriores. Las opciones ya las he explicado en anteriores métodos.

De momento hasta que no modifique o añada algo más, eso es todo amigxs. Un saludito




