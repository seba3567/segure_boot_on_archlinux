#!/usr/bin/env bash
# secure-boot-manager.sh
# Gestor minimalista y seguro para Secure Boot (generar claves, auto-firma, limpieza).
# Hecho para UEFI + coexistencia con Windows e ISOs firmadas por Microsoft si sus certificados están presentes.
# v5: Instala automáticamente secureboot-db para máxima compatibilidad y mejora la lógica de instalación.
set -euo pipefail

# ---- Configuración ----
KEY_DIR="/usr/share/secureboot/keys"
EFI_DIR="/boot/efi"
SIGN_SCRIPT="/usr/local/bin/secboot-sign-kernel"
PACMAN_HOOK_DIR="/etc/pacman.d/hooks"
PACMAN_HOOK_FILE="$PACMAN_HOOK_DIR/99-secureboot-sign-kernel.hook"
BACKUP_DIR="/var/lib/secureboot-manager/backup-$(date +%Y%m%d%H%M%S)"
MS_KEYS_DIR_CANDIDATES=(
  "/usr/share/secureboot/keys/microsoft" # Ruta que usa el paquete secureboot-db
  "/usr/share/efitools/keys"
  "/usr/share/secureboot/microsoft"
)

# Nombres de certificados de Microsoft
MS_KEK_CRT_NAMES=("MicrosoftKEKCA.crt" "Microsoft Corporation KEK CA 2011.crt")
MS_DB_CRT_NAMES=("MicrosoftUEFICA.crt" "Microsoft Windows Production PCA 2011.crt")

# ---- Helpers ----
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
err() { echo -e "[ERROR] $*" >&2; exit 1; }

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Este script debe correr como root. Usa: sudo $0"
  fi
}

is_arch() { [[ -f /etc/arch-release ]]; }
mkdirp_root() { mkdir -p "$1"; chmod 755 "$1"; }

find_ms_cert() {
  local cert_found=""
  for dir in "${MS_KEYS_DIR_CANDIDATES[@]}"; do
    if [[ ! -d "$dir" ]]; then continue; fi
    # Busca tanto KEK como DB, devuelve el primero que encuentre
    for name in "${MS_KEK_CRT_NAMES[@]}" "${MS_DB_CRT_NAMES[@]}"; do
      if [[ -f "$dir/$name" ]]; then
        cert_found="$dir/$name"
        echo "$cert_found"
        return 0
      fi
    done
  done
  return 1
}

create_and_sign_esl_auth() {
  local cert="$1" outbase="$2" signer_key="$3" signer_cert="$4" signer_label="$5"
  local esl="${outbase}.esl" auth="${outbase}.auth"
  cert-to-efi-sig-list "$cert" "$esl"
  sign-efi-sig-list -k "$signer_key" -c "$signer_cert" "$signer_label" "$esl" "$auth"
  log "Generado $auth a partir de $cert"
}

backup_if_exists() {
  local f="$1"
  if [[ -e "$f" ]]; then
    mkdir -p "$BACKUP_DIR"
    cp -a "$f" "$BACKUP_DIR/"
    log "Backup: $f -> $BACKUP_DIR/"
  fi
}

sbsign_replace() {
  local key="$1" cert="$2" infile="$3" outfile="$4" tmp
  tmp="$(mktemp)"
  sbsign --key "$key" --cert "$cert" --output "$tmp" "$infile"
  mv -f "$tmp" "$outfile"
  log "Firmado: $outfile"
}

# ---- Funciones principales ----
firmar_todo() {
  log "Iniciando proceso de firma..."
  if ! [[ -f "$KEY_DIR/db.key" && -f "$KEY_DIR/db.crt" ]]; then
    err "No se encontraron las claves de firma (db.key, db.crt) en $KEY_DIR."
  fi
  shopt -s nullglob
  log "Buscando y firmando kernels en /boot..."
  for k in /boot/vmlinuz-*; do
    if [[ -f "$k" ]]; then
      backup_if_exists "$k"
      sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$k" "$k"
    fi
  done
  shopt -u nullglob
  if is_arch; then
    log "Detectado Arch Linux. Usando shim-signed."
    pacman -Sy --noconfirm --needed shim-signed >/dev/null || true
    local SHIM_PATH="/usr/share/shim-signed/shimx64.efi"
    local GRUB_PATH="/boot/efi/EFI/arch/grubx64.efi"
    local MOK_MANAGER_PATH="/usr/share/shim-signed/mmx64.efi"
    local BOOT_FALLBACK="/boot/efi/EFI/boot/bootx64.efi"
    local GRUB_FALLBACK="/boot/efi/EFI/boot/grubx64.efi"
    if [[ ! -f "$SHIM_PATH" ]]; then
      err "No se encuentra shimx64.efi. Asegúrate de que 'shim-signed' esté instalado."
    fi
    mkdir -p "$(dirname "$BOOT_FALLBACK")"
    cp -f "$SHIM_PATH" "$BOOT_FALLBACK"
    cp -f "$MOK_MANAGER_PATH" "$(dirname "$BOOT_FALLBACK")/mmx64.efi"
    backup_if_exists "$BOOT_FALLBACK"
    sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$BOOT_FALLBACK" "$BOOT_FALLBACK"
    if [[ -f "$GRUB_PATH" ]]; then
      cp -f "$GRUB_PATH" "$GRUB_FALLBACK"
      backup_if_exists "$GRUB_FALLBACK"
      sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$GRUB_FALLBACK" "$GRUB_FALLBACK"
    else
      warn "No se encontró grubx64.efi en $GRUB_PATH. Esto es normal si usas systemd-boot."
    fi
  else
    log "Firmando cargadores EFI detectados en $EFI_DIR..."
    shopt -s nullglob
    for efi in "$EFI_DIR"/EFI/*/*.efi "$EFI_DIR"/EFI/boot/bootx64.efi; do
      if [[ -f "$efi" ]]; then
        backup_if_exists "$efi"
        sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$efi" "$efi"
      fi
    done
    shopt -u nullglob
  fi
  log "Proceso de firma completado."
}

reinstalar_bootloader() {
  log "Reinstalando gestor de arranque para registrar archivos firmados..."
  if command -v bootctl &> /dev/null && [[ -d /sys/firmware/efi ]]; then
    log "Detectado systemd-boot. Ejecutando 'bootctl install'..."
    bootctl install
  elif command -v grub-install &> /dev/null; then
    log "Detectado GRUB. Ejecutando 'grub-install'..."
    local BOOTLOADER_ID="GRUB"
    if is_arch; then BOOTLOADER_ID="arch"; fi
    grub-install --target=x86_64-efi --efi-directory="$EFI_DIR" --bootloader-id="$BOOTLOADER_ID" --removable
  else
    warn "No se pudo detectar 'bootctl' ni 'grub-install'. Deberás reinstalar tu gestor de arranque manualmente."
  fi
  log "Reinstalación del gestor de arranque finalizada."
}

generar_e_instalar_claves() {
  log "Generando e instalando claves en: $KEY_DIR"
  pacman -Sy --noconfirm --needed efitools sbsigntools secureboot-db >/dev/null || true
  mkdirp_root "$KEY_DIR"; chmod 700 "$KEY_DIR"; cd "$KEY_DIR" || exit 1
  
  # Generación de PK, KEK, DB
  if [[ -f PK.key ]]; then log "PK ya existe. Omitiendo."; else
    log "Generando PK..."; openssl req -new -x509 -newkey rsa:4096 -subj "/CN=Local PK/" -keyout PK.key -out PK.crt -days 3650 -nodes -sha256; cert-to-efi-sig-list PK.crt PK.esl; sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth; chmod 600 PK.*; fi
  if [[ -f KEK.key ]]; then log "KEK ya existe. Omitiendo."; else
    log "Generando KEK..."; openssl req -new -x509 -newkey rsa:4096 -subj "/CN=Local KEK/" -keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256; cert-to-efi-sig-list KEK.crt KEK.esl; sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth; chmod 600 KEK.*; fi
  if [[ -f db.key ]]; then log "DB ya existe. Omitiendo."; else
    log "Generando DB..."; openssl req -new -x509 -newkey rsa:4096 -subj "/CN=Local DB/" -keyout db.key -out db.crt -days 3650 -nodes -sha256; cert-to-efi-sig-list db.crt db.esl; sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth; chmod 600 db.*; fi

  # Integración con claves Microsoft
  log "Buscando certificados de Microsoft para mantener compatibilidad..."
  ms_kek_cert_file=""
  ms_db_cert_file=""
  for dir in "${MS_KEYS_DIR_CANDIDATES[@]}"; do
    if [[ -d "$dir" ]]; then
      for name in "${MS_KEK_CRT_NAMES[@]}"; do
        if [[ -f "$dir/$name" ]]; then ms_kek_cert_file="$dir/$name"; fi
      done
      for name in "${MS_DB_CRT_NAMES[@]}"; do
        if [[ -f "$dir/$name" ]]; then ms_db_cert_file="$dir/$name"; fi
      done
    fi
  done

  if [[ -n "$ms_kek_cert_file" && -n "$ms_db_cert_file" ]]; then
    log "Certificados Microsoft encontrados. Generando claves combinadas..."
    
    # Combinar KEK
    create_and_sign_esl_auth "$ms_kek_cert_file" "MS_KEK_temp" "PK.key" "PK.crt" "KEK"
    cat KEK.esl MS_KEK_temp.esl > KEK_combined.esl
    sign-efi-sig-list -k PK.key -c PK.crt KEK KEK_combined.esl KEK_combined.auth
    log "KEK combinado creado: KEK_combined.auth y KEK_combined.esl"
    
    # Combinar DB
    create_and_sign_esl_auth "$ms_db_cert_file" "MS_db_temp" "KEK.key" "KEK.crt" "db"
    cat db.esl MS_db_temp.esl > db_combined.esl
    sign-efi-sig-list -k KEK.key -c KEK.crt db db_combined.esl db_combined.auth
    log "DB combinado creado: db_combined.auth y db_combined.esl"
  else
    warn "No se encontraron los certificados de Microsoft después de la instalación. La compatibilidad puede ser limitada."
  fi

  reinstalar_bootloader
  firmar_todo
  log "Claves generadas. Cargadores y kernels firmados."
  echo
  echo "PASOS SIGUIENTES EN LA BIOS/UEFI (Key Management):"
  echo "  1) Importa PK.auth -> REEMPLAZA la PK existente."
  if [[ -f "$KEY_DIR/KEK_combined.auth" ]]; then
    echo "  2) Importa KEK_combined.auth -> AÑADE (Append) a las KEK."
    echo "     (Si tu BIOS no soporta .auth para 'append', usa KEK_combined.esl)"
  else
    echo "  2) Importa KEK.auth -> AÑADE (Append) a las KEK."
    echo "     (Si tu BIOS no soporta .auth para 'append', usa KEK.esl)"
  fi
  if [[ -f "$KEY_DIR/db_combined.auth" ]]; then
    echo "  3) Importa db_combined.auth -> AÑADE (Append) a la DB."
    echo "     (Si tu BIOS no soporta .auth para 'append', usa db_combined.esl)"
  else
    echo "  3) Importa db.auth -> AÑADE (Append) a la DB."
    echo "     (Si tu BIOS no soporta .auth para 'append', usa db.esl)"
  fi
  echo "  4) No modifiques 'dbx' (Forbidden Signatures)."
  echo "  5) Activa Secure Boot y guarda los cambios."
}

crear_autofirma_y_hook() {
  log "Creando script de auto-firma: $SIGN_SCRIPT"
  mkdir -p "$(dirname "$SIGN_SCRIPT")"

  cat > "$SIGN_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Script que firma kernels y gestores de arranque con las claves en KEY_DIR.
set -eu
KEY_DIR="/usr/share/secureboot/keys"
LOG_FILE="/var/log/secboot-sign-kernel.log"
# Redirigir stdout y stderr al archivo de log y a la consola
exec > >(tee -a ${LOG_FILE}) 2>&1

sbsign_replace() {
  local key="$1" cert="$2" infile="$3" outfile="$4" tmp
  tmp="$(mktemp)"
  sbsign --key "$key" --cert "$cert" --output "$tmp" "$infile"
  mv -f "$tmp" "$outfile"
  echo "$(date -Iseconds) Signed: $outfile"
}

if [[ ! -f "$KEY_DIR/db.key" ]]; then
    echo "$(date -Iseconds) ERROR: Clave de firma no encontrada en $KEY_DIR/db.key"
    exit 1
fi

echo "--- Hook de Secure Boot ejecutado ---"
# Firmar todos los kernels en /boot
shopt -s nullglob
for k in /boot/vmlinuz-*; do
  if sbverify --list "$k" >/dev/null 2>&1; then
    echo "Kernel ya firmado, omitiendo: $k"
  else
    sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$k" "$k"
  fi
done
shopt -u nullglob

# Re-firmar cargadores EFI
EFI_CANDIDATES=(
  "/boot/efi/EFI/boot/bootx64.efi"
  "/boot/efi/EFI/boot/grubx64.efi"
  "/boot/efi/EFI/arch/grubx64.efi"
  "/boot/efi/EFI/systemd/systemd-bootx64.efi"
)
for efi_file in "${EFI_CANDIDATES[@]}"; do
    if [[ -f "$efi_file" ]] && ! sbverify --list "$efi_file" >/dev/null 2>&1; then
      sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$efi_file" "$efi_file"
    fi
done
echo "--- Fin del hook de Secure Boot ---"
EOF

  chmod 755 "$SIGN_SCRIPT"
  log "Script de firma creado."

  log "Creando hook de pacman para yay/paru en: $PACMAN_HOOK_FILE"
  mkdir -p "$PACMAN_HOOK_DIR"
  cat > "$PACMAN_HOOK_FILE" <<EOF
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
# Vigila los paquetes de kernel más comunes y gestores de arranque
Target = linux
Target = linux-lts
Target = linux-zen
Target = linux-hardened
Target = linux-lqx
Target = grub
Target = shim-signed
Target = systemd

[Action]
Description = Firmando kernels/bootloaders con claves de Secure Boot...
When = PostTransaction
Exec = $SIGN_SCRIPT
EOF

  chmod 644 "$PACMAN_HOOK_FILE"
  log "Hook de pacman creado."
  log "Auto-firma y hook configurados para funcionar con pacman, yay y paru."
}

limpiar_generado() {
  echo "ADVERTENCIA: Esto eliminará los archivos generados por este script (claves, hook, script)."
  read -rp "¿Estás seguro y quieres continuar? (si/no): " confirm
  if [[ "${confirm,,}" != "si" && "${confirm,,}" != "s" ]]; then
    echo "Abortado."; return 0
  fi
  log "Limpiando archivos generados..."
  if [[ -d "$KEY_DIR" && -f "$KEY_DIR/PK.key" ]]; then backup_if_exists "$KEY_DIR"; rm -rf "$KEY_DIR"; log "Eliminado directorio: $KEY_DIR"; else warn "No se eliminará $KEY_DIR por seguridad."; fi
  [[ -f "$SIGN_SCRIPT" ]] && { backup_if_exists "$SIGN_SCRIPT"; rm -f "$SIGN_SCRIPT"; log "Eliminado: $SIGN_SCRIPT"; }
  [[ -f "$PACMAN_HOOK_FILE" ]] && { backup_if_exists "$PACMAN_HOOK_FILE"; rm -f "$PACMAN_HOOK_FILE"; log "Eliminado hook: $PACMAN_HOOK_FILE"; }
  log "Limpieza completa. Las claves en la BIOS/UEFI deben borrarse manualmente."
  log "Backups guardados en: ${BACKUP_DIR:-(no backups)}"
}

# ---- Menú ----
ensure_root
cat <<'EOF'
========================================================================
           Secure Boot Manager - Asistente de configuración
========================================================================
 Este script te ayudará a tomar control de Secure Boot en tu sistema.

 1) Generar claves, firmar todo y reinstalar Bootloader
    (Opción principal. Haz esto primero. Genera PK, KEK, db,
     reinstala tu gestor de arranque y firma kernels y EFI.)

 2) Crear script y hook de auto-firma (Compatible con yay/paru)
    (Crea un hook para `pacman` que firmará automáticamente los
     nuevos kernels/bootloaders después de una actualización.)

 3) Limpiar archivos generados por este script
    (Revierte los cambios en el disco duro, no en el firmware.)

 0) Salir
========================================================================
EOF

read -rp "Elige una opción [0-3]: " opt
case "$opt" in
  1) generar_e_instalar_claves ;;
  2) crear_autofirma_y_hook ;;
  3) limpiar_generado ;;
  0) exit 0 ;;
  *) echo "Opción inválida"; exit 1 ;;
esac

exit 0
