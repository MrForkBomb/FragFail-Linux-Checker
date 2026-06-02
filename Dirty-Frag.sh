#!/usr/bin/env bash
set -u

VERSION="1.0"

ROJO="\033[31m"
AMAR="\033[33m"
VERDE="\033[32m"
AZUL="\033[34m"
CIAN="\033[36m"
GRIS="\033[90m"
MAGENTA="\033[35m"
BLANCO="\033[37m"
NC="\033[0m"

ROJO_BOLD="\033[1;31m"
AMAR_BOLD="\033[1;33m"
VERDE_BOLD="\033[1;32m"
CIAN_BOLD="\033[1;36m"
GRIS_BOLD="\033[1;90m"
MAGENTA_BOLD="\033[1;35m"
BLANCO_BOLD="\033[1;37m"

KERNEL="$(uname -r)"
CONFIG="/boot/config-$KERNEL"
START_TIME=$(date +%s)

ok()   { echo -e "${VERDE}[OK]${NC} $*"; }
warn() { echo -e "${AMAR}[!]${NC} $*"; }
bad()  { echo -e "${ROJO}[VULNERABLE/POSIBLE]${NC} $*"; }
vuln() { echo -e "${ROJO_BOLD}[VULNERABLE]${NC} $*"; }
info() { echo -e "${AZUL}[*]${NC} $*"; }

good_item() { echo -e "  ${VERDE}- $*${NC}"; }
warn_item() { echo -e "  ${AMAR}- $*${NC}"; }
bad_item()  { echo -e "  ${ROJO}- $*${NC}"; }

copy_reasons=()
copy_mitigations=()
dirty_reasons=()
dirty_mitigations=()
fragnesia_reasons=()
fragnesia_mitigations=()

COPY_AEAD_AVAILABLE=0
COPY_AEAD_LOADED=0
COPY_AEAD_BLOCKED=0

DIRTY_ESP4_AVAILABLE=0
DIRTY_ESP6_AVAILABLE=0
DIRTY_RXRPC_AVAILABLE=0
DIRTY_ESP4_LOADED=0
DIRTY_ESP6_LOADED=0
DIRTY_RXRPC_LOADED=0
DIRTY_USERNS_ENABLED=0
DIRTY_USERNS_WORKS=0
DIRTY_NETNS_WORKS=0
DIRTY_ANY_BLOCKED=0

FRAG_ESPINTCP_PRESENT=0
FRAG_ESPINTCP_RUNTIME=0
FRAG_XFRM_SURFACE=0
FRAG_NS_USABLE=0
FRAG_ESP4_AVAILABLE=0
FRAG_ESP6_AVAILABLE=0
FRAG_ESP4_LOADED=0
FRAG_ESP6_LOADED=0
FRAG_XFRM_USER=0
FRAG_USER_NS=0
FRAG_NET_NS=0
FRAG_USERNS_ENABLED=0

banner() {
  echo -e "${CIAN_BOLD}"
  cat << "EOF"
   ______                 ______    _ _
  |  ____|               |  ____|  (_) |
  | |__ _ __ __ _  __ _  | |__ __ _ _| |
  |  __| '__/ _` |/ _` | |  __/ _` | | |
  | |  | | | (_| | (_| | | | | (_| | | |
  |_|  |_|  \__,_|\__, | |_|  \__,_|_|_|
                   __/ |
                  |___/

EOF
  echo -e "${MAGENTA_BOLD}   Copy-Fail | Dirty Frag | Fragnesia${NC}"

  echo
  echo -e "${CIAN_BOLD}             FragFail Linux Checker v${VERSION}${NC}"
  echo -e "${CIAN_BOLD}              Linux LPE Exposure Checker${NC}"
  echo -e "                    ${MAGENTA_BOLD}by MrForkBomb${NC}"
  echo -e ""
  echo -e ""
}

add_copy_factor() { copy_reasons+=("$1"); }
add_copy_mitigation() { copy_mitigations+=("$1"); }
add_dirty_factor() { dirty_reasons+=("$1"); }
add_dirty_mitigation() { dirty_mitigations+=("$1"); }
add_frag_factor() { fragnesia_reasons+=("$1"); }
add_frag_mitigation() { fragnesia_mitigations+=("$1"); }

print_section() {
  echo
  echo
  echo -e "${CIAN_BOLD}========== $1 ==========${NC}"
}

vuln_block() {
  echo
  echo -e "${CIAN_BOLD}══════════════════════════════════════════════${NC}"
  echo -e "${CIAN_BOLD}                $1${NC}"
  echo -e "${CIAN_BOLD}══════════════════════════════════════════════${NC}"
}

print_list() {
  local title="$1"
  local mode="$2"
  shift 2
  local arr=("$@")

  echo
  echo -e "${BLANCO_BOLD}${title}${NC}"

  if [ "${#arr[@]}" -eq 0 ]; then
    good_item "Ninguna"
    return
  fi

  for item in "${arr[@]}"; do
    case "$mode" in
      bad) bad_item "$item" ;;
      warn) warn_item "$item" ;;
      good) good_item "$item" ;;
      *) echo "  - $item" ;;
    esac
  done
}

cfg() {
  local key="$1"

  if [ -r "$CONFIG" ]; then
      grep -E "^${key}=" "$CONFIG" && return
      echo "${key}= no definido"
      return
  fi

  if [ -r /proc/config.gz ] && command -v zgrep >/dev/null 2>&1; then
      zgrep -E "^${key}=" /proc/config.gz 2>/dev/null && return
      echo "${key}= no definido"
      return
  fi

  echo "${key}= desconocido"
}

cfg_enabled() {
  local key="$1"

  if [ -r "$CONFIG" ]; then
    grep -Eq "^${key}=(m|y)" "$CONFIG" && return 0
  fi

  if [ -r /proc/config.gz ] && command -v zgrep >/dev/null 2>&1; then
    zgrep -Eq "^${key}=(m|y)" /proc/config.gz 2>/dev/null && return 0
  fi

  return 1
}

mod_exists() {
  modinfo "$1" >/dev/null 2>&1
}

mod_loaded() {
  lsmod | awk '{print $1}' | grep -qx "$1"
}

blocked() {
  grep -RhsE "^(install|blacklist)[[:space:]]+$1([[:space:]]|$)" \
    /etc/modprobe.d /lib/modprobe.d 2>/dev/null
}

detect_platform() {
  PLATFORM="Linux nativo"
  PLATFORM_DETAIL=""

  if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null || echo "$KERNEL" | grep -qiE "microsoft|wsl"; then
    PLATFORM="WSL2"
    PLATFORM_DETAIL="Kernel Microsoft WSL2 detectado. Algunos módulos y rutas del kernel pueden comportarse de forma diferente a un Linux nativo."
    return
  fi

  if [ -f /.dockerenv ]; then
    PLATFORM="Docker"
    PLATFORM_DETAIL="Contenedor Docker detectado. El resultado puede depender del host real."
    return
  fi

  if grep -qaE "docker|containerd|kubepods" /proc/1/cgroup 2>/dev/null; then
    PLATFORM="Contenedor"
    PLATFORM_DETAIL="Entorno containerizado detectado por cgroup. El kernel real pertenece al host."
    return
  fi

  if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt="$(systemd-detect-virt 2>/dev/null || true)"
    if [ -n "$virt" ] && [ "$virt" != "none" ]; then
      PLATFORM="$virt"
      PLATFORM_DETAIL="Virtualización detectada mediante systemd-detect-virt."
      return
    fi
  fi
}

clear 2>/dev/null || true
banner

sleep 0.25
echo -e "${CIAN_BOLD}Inicializando motor de análisis...${NC}"
echo -e "${CIAN_BOLD}Comprobando componentes del sistema...${NC}"
echo

echo -e "${MAGENTA_BOLD}[*]${NC} ${BLANCO_BOLD}Fecha :  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${MAGENTA_BOLD}[*]${NC} ${BLANCO_BOLD}Host  :  $(hostname)${NC}"
echo -e "${MAGENTA_BOLD}[*]${NC} ${BLANCO_BOLD}Kernel:  $KERNEL${NC}"
echo -e "${MAGENTA_BOLD}[*]${NC} ${BLANCO_BOLD}Modo  :  Análisis pasivo / sin PoC / solo lectura${NC}"
[ -r /etc/os-release ] && . /etc/os-release && echo -e "${MAGENTA_BOLD}[*]${NC} ${BLANCO_BOLD}Sistema: ${PRETTY_NAME:-desconocido}${NC}"
detect_platform
echo -e "${MAGENTA_BOLD}[*]${NC} ${BLANCO_BOLD}Plataforma: $PLATFORM${NC}"

if [ -n "$PLATFORM_DETAIL" ]; then
  warn "$PLATFORM_DETAIL"
fi
echo
sleep 1.5

print_section "Copy-Fail / CVE-2026-31431"

echo
echo -e "${CIAN_BOLD}Configuración relevante:${NC}"
cfg CONFIG_CRYPTO_USER_API_AEAD
cfg CONFIG_CRYPTO_AUTHENC
cfg CONFIG_CRYPTO_AUTHENCESN
echo

if cfg_enabled CONFIG_CRYPTO_USER_API_AEAD || mod_exists algif_aead; then
  COPY_AEAD_AVAILABLE=1
  bad "La superficie AF_ALG AEAD está disponible."
  add_copy_factor "AF_ALG AEAD disponible"
else
  ok "No se ve disponible la superficie AF_ALG AEAD."
  add_copy_mitigation "AF_ALG AEAD no disponible"
fi

if mod_loaded algif_aead; then
  COPY_AEAD_LOADED=1
  bad "El módulo algif_aead está cargado actualmente."
  add_copy_factor "algif_aead cargado actualmente"
else
  info "algif_aead no está cargado ahora."
fi

if blocked algif_aead >/dev/null; then
  COPY_AEAD_BLOCKED=1
  ok "algif_aead tiene bloqueo persistente en modprobe:"
  blocked algif_aead | sed 's/^/    /'
  add_copy_mitigation "algif_aead bloqueado por modprobe"
else
  warn "No hay bloqueo persistente para algif_aead."
fi

print_section "Dirty Frag / CVE-2026-43284"

echo
echo -e "${CIAN_BOLD}Configuración relevante:${NC}"
cfg CONFIG_INET_ESP
cfg CONFIG_INET6_ESP
cfg CONFIG_AF_RXRPC
cfg CONFIG_XFRM_USER
cfg CONFIG_USER_NS
cfg CONFIG_NET_NS
echo

for mod in esp4 esp6 rxrpc; do
  if mod_exists "$mod"; then
    bad "El módulo $mod existe en el sistema."
    add_dirty_factor "módulo $mod disponible"

    case "$mod" in
      esp4) DIRTY_ESP4_AVAILABLE=1 ;;
      esp6) DIRTY_ESP6_AVAILABLE=1 ;;
      rxrpc) DIRTY_RXRPC_AVAILABLE=1 ;;
    esac
  else
    ok "El módulo $mod no aparece disponible."
    add_dirty_mitigation "módulo $mod no disponible"
  fi

  if mod_loaded "$mod"; then
    bad "El módulo $mod está cargado actualmente."
    add_dirty_factor "módulo $mod cargado actualmente"

    case "$mod" in
      esp4) DIRTY_ESP4_LOADED=1 ;;
      esp6) DIRTY_ESP6_LOADED=1 ;;
      rxrpc) DIRTY_RXRPC_LOADED=1 ;;
    esac
  fi

  if blocked "$mod" >/dev/null; then
    DIRTY_ANY_BLOCKED=1
    ok "$mod tiene bloqueo persistente en modprobe:"
    blocked "$mod" | sed 's/^/    /'
    add_dirty_mitigation "$mod bloqueado por modprobe"
  else
    warn "No hay bloqueo persistente para $mod."
  fi

  echo
done

if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
  userns="$(cat /proc/sys/kernel/unprivileged_userns_clone)"
  info "kernel.unprivileged_userns_clone=$userns"

  if [ "$userns" = "1" ]; then
    DIRTY_USERNS_ENABLED=1
    bad "Los namespaces sin privilegios están habilitados."
    add_dirty_factor "user namespaces sin privilegios habilitados"
  else
    ok "Los namespaces sin privilegios están deshabilitados."
    add_dirty_mitigation "kernel.unprivileged_userns_clone=0"
  fi
else
  info "No existe /proc/sys/kernel/unprivileged_userns_clone."
fi

if command -v unshare >/dev/null 2>&1; then
  if unshare -Ur true >/dev/null 2>&1; then
    DIRTY_USERNS_WORKS=1
    warn "Prueba real: unshare -Ur funciona."
    add_dirty_factor "user namespace realmente usable"
  else
    ok "Prueba real: unshare -Ur no funciona."
    add_dirty_mitigation "user namespace no usable"
  fi

  if unshare -Urn true >/dev/null 2>&1; then
    DIRTY_NETNS_WORKS=1
    warn "Prueba real: unshare -Urn funciona."
    add_dirty_factor "user+network namespace realmente usable"
  else
    ok "Prueba real: unshare -Urn no funciona."
    add_dirty_mitigation "user+network namespace no usable"
  fi
fi

print_section "Fragnesia / XFRM ESP-in-TCP"

echo
echo -e "${CIAN_BOLD}Configuración relevante:${NC}"
cfg CONFIG_XFRM_ESPINTCP
cfg CONFIG_INET_ESPINTCP
cfg CONFIG_INET6_ESPINTCP
cfg CONFIG_INET_ESP
cfg CONFIG_INET6_ESP
cfg CONFIG_XFRM_USER
cfg CONFIG_USER_NS
cfg CONFIG_NET_NS
cfg CONFIG_CRYPTO_GCM
cfg CONFIG_CRYPTO_AES
cfg CONFIG_CRYPTO_USER_API_SKCIPHER
cfg CONFIG_CRYPTO_USER_API_AEAD
echo

if cfg_enabled CONFIG_XFRM_ESPINTCP || cfg_enabled CONFIG_INET_ESPINTCP || cfg_enabled CONFIG_INET6_ESPINTCP; then
  FRAG_ESPINTCP_PRESENT=1
  bad "Soporte ESP-in-TCP habilitado en configuración de kernel."
  add_frag_factor "CONFIG ESP-in-TCP habilitado"
else
  ok "No se observa CONFIG ESP-in-TCP en /boot/config."
  add_frag_mitigation "CONFIG ESP-in-TCP no detectado"
fi

if mod_exists espintcp; then
  FRAG_ESPINTCP_PRESENT=1
  bad "El módulo espintcp existe en el sistema."
  add_frag_factor "módulo espintcp disponible"
else
  ok "El módulo espintcp no aparece disponible."
  add_frag_mitigation "módulo espintcp no disponible"
fi

if mod_loaded espintcp; then
  FRAG_ESPINTCP_RUNTIME=1
  bad "El módulo espintcp está cargado actualmente."
  add_frag_factor "módulo espintcp cargado"
else
  info "espintcp no está cargado ahora."
fi

if blocked espintcp >/dev/null; then
  ok "espintcp tiene bloqueo persistente en modprobe:"
  blocked espintcp | sed 's/^/    /'
  add_frag_mitigation "espintcp bloqueado por modprobe"
else
  warn "No hay bloqueo persistente para espintcp."
fi

echo

if [ -r /proc/sys/net/ipv4/tcp_available_ulp ]; then
  ulp="$(cat /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null)"
  info "tcp_available_ulp=$ulp"

  if echo "$ulp" | grep -qw "espintcp"; then
    FRAG_ESPINTCP_PRESENT=1
    FRAG_ESPINTCP_RUNTIME=1
    bad "espintcp aparece como TCP ULP disponible en runtime."
    add_frag_factor "espintcp listado en tcp_available_ulp"
  else
    ok "espintcp no aparece listado como TCP ULP disponible."
    add_frag_mitigation "espintcp no listado en tcp_available_ulp"
  fi
else
  info "No existe /proc/sys/net/ipv4/tcp_available_ulp."
fi

echo

for mod in esp4 esp6; do
  if mod_exists "$mod"; then
    warn "Superficie XFRM/ESP relacionada: $mod existe."
    add_frag_factor "módulo $mod disponible"
    FRAG_XFRM_SURFACE=1

    case "$mod" in
      esp4) FRAG_ESP4_AVAILABLE=1 ;;
      esp6) FRAG_ESP6_AVAILABLE=1 ;;
    esac
  else
    ok "Módulo $mod no disponible para Fragnesia."
    add_frag_mitigation "módulo $mod no disponible"
  fi

  if mod_loaded "$mod"; then
    bad "$mod está cargado actualmente."
    add_frag_factor "módulo $mod cargado"
    FRAG_XFRM_SURFACE=1

    case "$mod" in
      esp4) FRAG_ESP4_LOADED=1 ;;
      esp6) FRAG_ESP6_LOADED=1 ;;
    esac
  fi

  if blocked "$mod" >/dev/null; then
    ok "$mod tiene bloqueo persistente en modprobe:"
    blocked "$mod" | sed 's/^/    /'
    add_frag_mitigation "$mod bloqueado por modprobe"
  fi
done

echo

if cfg_enabled CONFIG_XFRM_USER; then
  FRAG_XFRM_USER=1
  FRAG_XFRM_SURFACE=1
  warn "CONFIG_XFRM_USER habilitado: permite gestión XFRM desde userland."
  add_frag_factor "CONFIG_XFRM_USER habilitado"
else
  ok "CONFIG_XFRM_USER no detectado."
  add_frag_mitigation "CONFIG_XFRM_USER no detectado"
fi

if cfg_enabled CONFIG_USER_NS; then
  FRAG_USER_NS=1
  warn "CONFIG_USER_NS habilitado."
  add_frag_factor "CONFIG_USER_NS habilitado"
else
  ok "CONFIG_USER_NS no detectado."
  add_frag_mitigation "CONFIG_USER_NS no detectado"
fi

if cfg_enabled CONFIG_NET_NS; then
  FRAG_NET_NS=1
  warn "CONFIG_NET_NS habilitado."
  add_frag_factor "CONFIG_NET_NS habilitado"
else
  ok "CONFIG_NET_NS no detectado."
  add_frag_mitigation "CONFIG_NET_NS no detectado"
fi

if [ -r /proc/sys/kernel/unprivileged_userns_clone ]; then
  userns="$(cat /proc/sys/kernel/unprivileged_userns_clone)"
  info "kernel.unprivileged_userns_clone=$userns"

  if [ "$userns" = "1" ]; then
    FRAG_USERNS_ENABLED=1
    bad "Namespaces de usuario sin privilegios habilitados."
    add_frag_factor "unprivileged_userns_clone habilitado"
  else
    ok "Namespaces de usuario sin privilegios deshabilitados."
    add_frag_mitigation "unprivileged_userns_clone deshabilitado"
  fi
fi

if command -v unshare >/dev/null 2>&1; then
  if unshare -Urn true >/dev/null 2>&1; then
    FRAG_NS_USABLE=1
    warn "Prueba real: unshare -Urn funciona."
    add_frag_factor "user+network namespace realmente usable"
  else
    ok "Prueba real: unshare -Urn no funciona."
    add_frag_mitigation "user+network namespace no usable"
  fi
fi

if [ -r /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
  aa_userns="$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)"
  info "kernel.apparmor_restrict_unprivileged_userns=$aa_userns"

  if [ "$aa_userns" = "1" ]; then
    ok "AppArmor restringe user namespaces sin privilegios."
    add_frag_mitigation "AppArmor restringe unprivileged user namespaces"
  else
    warn "AppArmor no restringe user namespaces sin privilegios."
    add_frag_factor "AppArmor no restringe unprivileged user namespaces"
  fi
else
  info "No existe kernel.apparmor_restrict_unprivileged_userns."
fi

print_section "Resumen"

vuln_block "COPY-FAIL"
if [ "$COPY_AEAD_AVAILABLE" -eq 1 ]; then bad_item "AF_ALG AEAD disponible"; else good_item "AF_ALG AEAD no disponible"; fi
if [ "$COPY_AEAD_LOADED" -eq 1 ]; then bad_item "algif_aead cargado"; else good_item "algif_aead no cargado"; fi
if [ "$COPY_AEAD_BLOCKED" -eq 1 ]; then good_item "algif_aead bloqueado por modprobe"; else warn_item "algif_aead no bloqueado por modprobe"; fi
print_list "Factores detectados:" bad "${copy_reasons[@]}"
print_list "Mitigaciones detectadas:" good "${copy_mitigations[@]}"

vuln_block "DIRTY FRAG"
if [ "$DIRTY_ESP4_AVAILABLE" -eq 1 ]; then bad_item "esp4 disponible"; else good_item "esp4 no disponible"; fi
if [ "$DIRTY_ESP6_AVAILABLE" -eq 1 ]; then bad_item "esp6 disponible"; else good_item "esp6 no disponible"; fi
if [ "$DIRTY_RXRPC_AVAILABLE" -eq 1 ]; then bad_item "rxrpc disponible"; else good_item "rxrpc no disponible"; fi
if [ "$DIRTY_ESP4_LOADED" -eq 1 ]; then bad_item "esp4 cargado"; else good_item "esp4 no cargado"; fi
if [ "$DIRTY_ESP6_LOADED" -eq 1 ]; then bad_item "esp6 cargado"; else good_item "esp6 no cargado"; fi
if [ "$DIRTY_RXRPC_LOADED" -eq 1 ]; then bad_item "rxrpc cargado"; else good_item "rxrpc no cargado"; fi
if [ "$DIRTY_USERNS_ENABLED" -eq 1 ]; then bad_item "user namespaces habilitados"; else good_item "user namespaces deshabilitados/no detectados"; fi
if [ "$DIRTY_NETNS_WORKS" -eq 1 ]; then bad_item "user+network namespace funcional"; else good_item "user+network namespace no funcional"; fi
print_list "Factores detectados:" bad "${dirty_reasons[@]}"
print_list "Mitigaciones detectadas:" good "${dirty_mitigations[@]}"

vuln_block "FRAGNESIA"
if [ "$FRAG_ESPINTCP_PRESENT" -eq 1 ]; then bad_item "espintcp presente/disponible"; else good_item "espintcp no disponible"; fi
if [ "$FRAG_ESPINTCP_RUNTIME" -eq 1 ]; then bad_item "espintcp activo en runtime"; else good_item "espintcp no activo en runtime"; fi
if [ "$FRAG_XFRM_SURFACE" -eq 1 ]; then warn_item "superficie XFRM/ESP presente"; else good_item "superficie XFRM/ESP no detectada"; fi
if [ "$FRAG_NS_USABLE" -eq 1 ]; then bad_item "user+network namespace funcional"; else good_item "user+network namespace no funcional"; fi
print_list "Factores detectados:" bad "${fragnesia_reasons[@]}"
print_list "Mitigaciones detectadas:" good "${fragnesia_mitigations[@]}"

print_section "Diagnóstico"

echo
if [ "$COPY_AEAD_BLOCKED" -eq 1 ]; then
  COPY_VERDICT="NO VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Copy-Fail: ${VERDE_BOLD}NO VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} algif_aead está bloqueado por modprobe."
elif [ "$COPY_AEAD_AVAILABLE" -eq 1 ]; then
  COPY_VERDICT="VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Copy-Fail:${NC} ${ROJO_BOLD}VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} AF_ALG AEAD / algif_aead está disponible."
else
  COPY_VERDICT="NO VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Copy-Fail:${NC} ${VERDE_BOLD}NO VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} no se observa la superficie AF_ALG AEAD."
fi

echo

if { [ "$DIRTY_ESP4_AVAILABLE" -eq 1 ] || [ "$DIRTY_ESP6_AVAILABLE" -eq 1 ] || [ "$DIRTY_RXRPC_AVAILABLE" -eq 1 ]; } && \
   { [ "$DIRTY_USERNS_ENABLED" -eq 1 ] || [ "$DIRTY_NETNS_WORKS" -eq 1 ]; }; then
  DIRTY_VERDICT="VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Dirty Frag:${NC} ${ROJO_BOLD}VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} ESP/RXRPC y user namespaces están disponibles."
elif [ "$DIRTY_ESP4_AVAILABLE" -eq 1 ] || [ "$DIRTY_ESP6_AVAILABLE" -eq 1 ] || [ "$DIRTY_RXRPC_AVAILABLE" -eq 1 ]; then
  DIRTY_VERDICT="POSIBLEMENTE VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Dirty Frag:${NC} ${AMAR_BOLD}POSIBLEMENTE VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} hay módulos relacionados disponibles, pero faltan condiciones para confirmar la cadena."
else
  DIRTY_VERDICT="NO VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Dirty Frag:${NC} ${VERDE_BOLD}NO VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} no se observa superficie ESP/RXRPC relevante."
fi

echo

if [ "$FRAG_ESPINTCP_PRESENT" -eq 1 ] && [ "$FRAG_NS_USABLE" -eq 1 ] && [ "$FRAG_XFRM_SURFACE" -eq 1 ]; then
  FRAG_VERDICT="VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Fragnesia:${NC} ${ROJO_BOLD}VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} ESP-in-TCP, XFRM/ESP y namespaces están disponibles."
elif [ "$FRAG_ESPINTCP_PRESENT" -eq 0 ] && [ "$FRAG_XFRM_SURFACE" -eq 1 ]; then
  FRAG_VERDICT="NO VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Fragnesia:${NC} ${VERDE_BOLD}NO VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} hay XFRM/ESP/namespaces, pero no hay evidencia de ESP-in-TCP/espintcp."
elif [ "$FRAG_XFRM_SURFACE" -eq 1 ] && [ "$FRAG_NS_USABLE" -eq 1 ]; then
  FRAG_VERDICT="POSIBLEMENTE VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Fragnesia:${NC} ${AMAR_BOLD}POSIBLEMENTE VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} hay superficie XFRM/ESP y namespaces, pero no se confirma ESP-in-TCP."
else
  FRAG_VERDICT="NO VULNERABLE"
  echo -e "${MAGENTA_BOLD}[!] Fragnesia:${NC} ${VERDE_BOLD}NO VULNERABLE${NC}"
  echo -e "${CIAN_BOLD} Motivo:${NC} no se observa la cadena mínima necesaria."
fi

echo
echo
echo -e "${CIAN_BOLD}Recomendaciones:${NC}"
echo -e "${BLANCO_BOLD}  1. Si el kernel es vulnerable, actualizar kernel y reiniciar.${NC}"
echo -e "${BLANCO_BOLD}  2. Si no puedes actualizar todavía, aplicar mitigación temporal:${NC}"
echo -e "${BLANCO_BOLD}       install algif_aead /bin/false${NC}"
echo -e "${BLANCO_BOLD}       install esp4 /bin/false${NC}"
echo -e "${BLANCO_BOLD}       install esp6 /bin/false${NC}"
echo -e "${BLANCO_BOLD}       install rxrpc /bin/false${NC}"
echo -e "${BLANCO_BOLD}       install espintcp /bin/false${NC}"
echo -e "${BLANCO_BOLD}  3. Guardarlas en: /etc/modprobe.d/mitigacion-lpe-2026.conf${NC}"
echo -e "${BLANCO_BOLD}  4. Si usas IPsec/VPN/RXRPC, validar impacto antes de bloquear módulos.${NC}"
echo -e "${BLANCO_BOLD}  5. Reiniciar y volver a ejecutar este checker.${NC}"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME-START_TIME))

echo
echo
echo -e "${CIAN_BOLD}========== Resultado final ==========${NC}"
echo

print_verdict() {
  local name="$1"
  local verdict="$2"

  case "$verdict" in
    VULNERABLE)
      echo -e "${MAGENTA_BOLD}[*]${NC} ${CIAN_BOLD}$name:${NC} ${ROJO_BOLD}${verdict}${NC}"
      ;;
    POSIBLEMENTE\ VULNERABLE)
      echo -e "${MAGENTA_BOLD}[*]${NC} ${CIAN_BOLD}$name:${NC} ${AMAR_BOLD}${verdict}${NC}"
      ;;
    NO\ VULNERABLE)
      echo -e "${MAGENTA_BOLD}[*]${NC} ${CIAN_BOLD}$name:${NC} ${VERDE_BOLD}${verdict}${NC}"
      ;;
    *)
      echo -e "${MAGENTA_BOLD}[*]${NC} ${CIAN_BOLD}$name:${NC} $verdict"
      ;;
  esac
}

print_verdict "Copy-Fail " "$COPY_VERDICT"
print_verdict "Dirty Frag" "$DIRTY_VERDICT"
print_verdict "Fragnesia " "$FRAG_VERDICT"

echo -e "${MAGENTA_BOLD}[*]${NC} ${CIAN_BOLD}Tiempo de ejecución:${NC} ${VERDE_BOLD}${ELAPSED}s${NC}"
echo
