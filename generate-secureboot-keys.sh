#!/usr/bin/env bash
# secure-boot-manager.sh
# Gestor minimalista y seguro para Secure Boot (generar claves, auto-firma, limpieza).
# Hecho para UEFI + coexistencia con Windows e ISOs firmadas por Microsoft si sus certificados están presentes.
set -euo pipefail

# ---- Configuración ----
KEY_DIR="/usr/share/secureboot/keys"
EFI_DIR="/boot/efi"
SIGN_SCRIPT="/usr/local/bin/secboot-sign-kernel"
PACMAN_HOOK_DIR="/etc/pacman.d/hooks"
PACMAN_HOOK_FILE="$PACMAN_HOOK_DIR/99-secureboot-sign-kernel.hook"
BACKUP_DIR="/var/lib/secureboot-manager/backup-$(date +%Y%m%d%H%M%S)"
MS_KEYS_DIR_CANDIDATES=(
  "/usr/share/efitools/keys"
  "/usr/share/secureboot/microsoft"
  "/usr/share/secureboot/keys"
)

# Common Microsoft cert filenames (varies by distro/package)
MS_KEK_CRT_NAMES=("MicrosoftKEKCA.crt" "Microsoft_production_CA_2011.crt" "Microsoft Corporation UEFI CA.crt")
MS_DB_CRT_NAMES=("MicrosoftUEFICA.crt" "Microsoft Windows Production PCA 2011.crt" "Microsoft Corporation UEFI CA.crt")

# ---- Helpers ----
log() { echo -e "[+] $*"; }
warn() { echo -e "[!] $*" >&2; }
err() { echo -e "[ERROR] $*" >&2; exit 1; }

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Este script debe correr como root. Usa: sudo $0"
  fi
}

mkdirp_root() {
  mkdir -p "$1"
  chmod 755 "$1"
}

find_ms_cert() {
  # busca un certificado microsoft (por lista de candidatos) y devuelve ruta o vacío
  local candidate dir name
  for dir in "${MS_KEYS_DIR_CANDIDATES[@]}"; do
    [[ -d "$dir" ]] || continue
    for name in "${MS_KEK_CRT_NAMES[@]}" "${MS_DB_CRT_NAMES[@]}"; do
      candidate="$dir/$name"
      if [[ -f "$candidate" ]]; then
        printf "%s\n" "$candidate"
        return 0
      fi
    done
  done
  return 1
}

# convierte y firma .esl -> .auth seguro con sign-efi-sig-list
create_and_sign_esl_auth() {
  # args: <cert.crt> <out_basename> <signer_key> <signer_cert> <signer_label>
  local cert="$1" outbase="$2" signer_key="$3" signer_cert="$4" signer_label="$5"
  local esl="${outbase}.esl" auth="${outbase}.auth"
  cert-to-efi-sig-list "$cert" "$esl"
  sign-efi-sig-list -k "$signer_key" -c "$signer_cert" "$signer_label" "$esl" "$auth"
  log "Generado $auth"
}

backup_if_exists() {
  local f="$1"
  if [[ -e "$f" ]]; then
    mkdir -p "$BACKUP_DIR"
    cp -a "$f" "$BACKUP_DIR/"
    log "Backup: $f -> $BACKUP_DIR/"
  fi
}

# safe sign: escribe a temp y mv para evitar corrupciones
sbsign_replace() {
  # args: <key> <cert> <input> <output>
  local key="$1" cert="$2" infile="$3" outfile="$4"
  local tmp
  tmp="$(mktemp)"
  sbsign --key "$key" --cert "$cert" --output "$tmp" "$infile"
  mv -f "$tmp" "$outfile"
}

# ---- Funciones principales ----

generar_e_instalar_claves() {
  log "Generando e instalando claves en: $KEY_DIR"
  pacman -Sy --noconfirm --needed efitools sbsigntools >/dev/null || true

  mkdirp_root "$KEY_DIR"
  chmod 700 "$KEY_DIR"

  # Crear claves si no existen
  cd "$KEY_DIR" || exit 1

  # PK
  if [[ -f PK.key && -f PK.crt && -f PK.auth ]]; then
    log "PK ya existe. Omitiendo regeneración."
  else
    log "Generando PK (Platform Key)..."
    openssl req -new -x509 -newkey rsa:4096 -subj "/CN=Local PK/" -keyout PK.key -out PK.crt -days 3650 -nodes -sha256
    cert-to-efi-sig-list PK.crt PK.esl
    sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth
    chmod 600 PK.key PK.crt PK.auth PK.esl
  fi

  # KEK
  if [[ -f KEK.key && -f KEK.crt && -f KEK.auth ]]; then
    log "KEK ya existe. Omitiendo regeneración."
  else
    log "Generando KEK (Key Exchange Key)..."
    openssl req -new -x509 -newkey rsa:4096 -subj "/CN=Local KEK/" -keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256
    cert-to-efi-sig-list KEK.crt KEK.esl
    # firmar KEK.esl con PK
    sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth
    chmod 600 KEK.key KEK.crt KEK.auth KEK.esl
  fi

  # DB
  if [[ -f db.key && -f db.crt && -f db.auth ]]; then
    log "DB ya existe. Omitiendo regeneración."
  else
    log "Generando DB (Allowed Signatures)..."
    openssl req -new -x509 -newkey rsa:4096 -subj "/CN=Local DB/" -keyout db.key -out db.crt -days 3650 -nodes -sha256
    cert-to-efi-sig-list db.crt db.esl
    # firmar db.esl con KEK
    sign-efi-sig-list -k KEK.key -c KEK.crt db db.esl db.auth
    chmod 600 db.key db.crt db.auth db.esl
  fi

  # Integración con claves Microsoft (append) si están disponibles
  log "Buscando certificados de Microsoft para mantener compatibilidad..."
  ms_cert="$(find_ms_cert || true)"
  if [[ -n "$ms_cert" ]]; then
    log "Encontrado certificado Microsoft: $ms_cert"
    # KEK combined
    create_and_sign_esl_auth "$ms_cert" "$KEY_DIR/MS_KEK_temp" "PK.key" "PK.crt" "KEK"
    # Combine KEK.esl + MS KEK esl
    cat KEK.esl "$KEY_DIR/MS_KEK_temp.esl" > KEK_combined.esl
    sign-efi-sig-list -k PK.key -c PK.crt KEK KEK_combined.esl KEK_combined.auth
    log "KEK combinado creado: KEK_combined.auth"

    # DB combined
    create_and_sign_esl_auth "$ms_cert" "$KEY_DIR/MS_db_temp" "KEK.key" "KEK.crt" "db"
    cat db.esl "$KEY_DIR/MS_db_temp.esl" > db_combined.esl
    sign-efi-sig-list -k KEK.key -c KEK.crt db db_combined.esl db_combined.auth
    log "DB combinado creado: db_combined.auth"

    log "NOTA: Para máxima compatibilidad, importa en BIOS: PK.auth (reemplaza), luego KEK_combined.auth (append), db_combined.auth (append)."
  else
    warn "No se encontraron certificados Microsoft en ubicaciones usuales. Si quieres compatibilidad con ISOs firmadas por Microsoft (Ubuntu/Fedora/etc.), instala el paquete con certificados MS o colócalos en /usr/share/efitools/keys y vuelve a ejecutar."
    log "IMPORTANTE: Si decides usar MS keys más tarde, genera KEK/db combinados como se indica."
  fi

  # Firmar cargadores EFI detectados en /boot/efi
  log "Firmando cargadores EFI detectados en $EFI_DIR..."
  shopt -s nullglob
  for efi in "$EFI_DIR"/EFI/*/*.efi "$EFI_DIR"/EFI/boot/bootx64.efi; do
    [[ -f "$efi" ]] || continue
    # hacer backup
    backup_if_exists "$efi"
    log "Firmando: $efi"
    sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$efi" "$efi"
  done
  shopt -u nullglob

  log "Claves generadas y cargadores firmados (si fueron detectados)."
  echo
  echo "PASOS EN BIOS (Key Management):"
  echo "  1) Importa PK.auth -> Reemplaza PK (solo una vez)."
  if [[ -f "$KEY_DIR/KEK_combined.auth" ]]; then
    echo "  2) Importa KEK_combined.auth -> Append (mantén la de Microsoft)."
  else
    echo "  2) Importa KEK.auth -> Append (si quieres mantener Microsoft, usa KEK_combined.auth si está disponible)."
  fi
  if [[ -f "$KEY_DIR/db_combined.auth" ]]; then
    echo "  3) Importa db_combined.auth -> Append (mantén Microsoft)."
  else
    echo "  3) Importa db.auth -> Append (ten en cuenta compatibilidad)."
  fi
  echo "  Deja dbx como viene de fábrica."
}

crear_autofirma_y_hook() {
  log "Creando script de auto-firma: $SIGN_SCRIPT"
  mkdir -p "$(dirname "$SIGN_SCRIPT")"

  cat > "$SIGN_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Script que firma kernels y initramfs (si aplica) con las claves en KEY_DIR.
set -euo pipefail
KEY_DIR="/usr/share/secureboot/keys"
LOG="/var/log/secboot-sign-kernel.log"
exec >>"$LOG" 2>&1
# Firmar kernels en /boot (vmlinuz-*)
shopt -s nullglob
for k in /boot/vmlinuz-*; do
  if [[ ! -f "$k" ]]; then continue; fi
  # Evitamos volver a firmar si ya está firmado (sbverify falla si no lo está).
  if sbverify --list "$k" >/dev/null 2>&1; then
    echo "$(date -Iseconds) Skipping already signed kernel: $k"
    continue
  fi
  tmp="$(mktemp)"
  sbsign --key "$KEY_DIR/db.key" --cert "$KEY_DIR/db.crt" --output "$tmp" "$k"
  mv -f "$tmp" "$k"
  echo "$(date -Iseconds) Signed kernel: $k"
done
shopt -u nullglob
# Intentar firmar grub efi en /boot/efi si existe
EFI_BOOT="/boot/efi/EFI/boot/bootx64.efi"
if [[ -f "$EFI_BOOT" ]]; then
  if ! sbverify --list "$EFI_BOOT" >/dev/null 2>&1; then
    tmp2="$(mktemp)"
    sbsign --key "$KEY_DIR/db.key" --cert "$KEY_DIR/db.crt" --output "$tmp2" "$EFI_BOOT"
    mv -f "$tmp2" "$EFI_BOOT"
    echo "$(date -Iseconds) Signed EFI bootloader: $EFI_BOOT"
  else
    echo "$(date -Iseconds) EFI bootloader already signed: $EFI_BOOT"
  fi
fi
EOF

  chmod 755 "$SIGN_SCRIPT"
  log "Script de firma creado."

  log "Creando hook de pacman en: $PACMAN_HOOK_FILE"
  mkdir -p "$PACMAN_HOOK_DIR"
  cat > "$PACMAN_HOOK_FILE" <<EOF
[Trigger]
Operation = Install
Operation = Upgrade
Type = Path
Target = boot/vmlinuz-*

[Action]
Description = Firmando kernels con Secure Boot keys...
When = PostTransaction
Exec = $SIGN_SCRIPT
EOF

  chmod 644 "$PACMAN_HOOK_FILE"
  log "Hook de pacman creado."

  # Verificar GRUB firmado
  GRUB_CANDIDATES=("$EFI_DIR"/EFI/*/grubx64.efi "$EFI_DIR"/EFI/boot/bootx64.efi)
  for g in "${GRUB_CANDIDATES[@]}"; do
    [[ -f "$g" ]] || continue
    if sbverify --list "$g" >/dev/null 2>&1; then
      log "GRUB/boot EFI ya está firmado: $g"
    else
      log "Firmando GRUB/boot EFI: $g"
      backup_if_exists "$g"
      sbsign_replace "$KEY_DIR/db.key" "$KEY_DIR/db.crt" "$g" "$g"
      log "Firmado: $g"
    fi
  done

  log "Auto-firma y hook configurados."
  log "Nota: El hook funciona en sistemas que usan pacman. Para otras distros, crea un hook equivalente (dnf/apt/etc.)."
}

limpiar_generado() {
  echo "ADVERTENCIA: Esto eliminará sólo los archivos generados por este script (claves en $KEY_DIR, hook y script). No modifica las claves cargadas en firmware."
  read -rp "¿Estás seguro y quieres continuar? (si/no): " confirm
  if [[ "${confirm,,}" != "si" && "${confirm,,}" != "s" && "${confirm,,}" != "yes" ]]; then
    echo "Abortado por usuario."
    return 0
  fi

  log "Limpiando archivos generados..."
  if [[ -d "$KEY_DIR" ]]; then
    # Solo borrar si encontramos un archivo PK.key para evitar borrar cosas ajenas
    if [[ -f "$KEY_DIR/PK.key" ]]; then
      backup_if_exists "$KEY_DIR"
      rm -rf "$KEY_DIR"
      log "Eliminado directorio: $KEY_DIR"
    else
      warn "No se detectó PK.key en $KEY_DIR. No se eliminará el directorio por seguridad."
    fi
  fi

  if [[ -f "$SIGN_SCRIPT" ]]; then
    backup_if_exists "$SIGN_SCRIPT"
    rm -f "$SIGN_SCRIPT"
    log "Eliminado: $SIGN_SCRIPT"
  fi

  if [[ -f "$PACMAN_HOOK_FILE" ]]; then
    backup_if_exists "$PACMAN_HOOK_FILE"
    rm -f "$PACMAN_HOOK_FILE"
    log "Eliminado hook: $PACMAN_HOOK_FILE"
  fi

  log "Limpieza completa. Si ya cargaste claves en la BIOS/UEFI, deberás borrarlas desde el menú Key Management del firmware si quieres volver al estado anterior."
  log "Backups guardados en: ${BACKUP_DIR:-(no backups)}"
}

# ---- Menú ----
ensure_root

cat <<'EOF'
===========================================
   Secure Boot Manager - Menú principal
===========================================
1) Generar e instalar claves (PK, KEK, DB) y firmar cargadores EFI
2) Crear script + hook para auto-firma de kernels y verificar/firmar GRUB
3) Limpiar archivos generados por este script (claves, script, hook)
0) Salir
EOF

read -rp "Elige una opción [0-3]: " opt
case "$opt" in
  1)
    generar_e_instalar_claves
    ;;
  2)
    crear_autofirma_y_hook
    ;;
  3)
    limpiar_generado
    ;;
  0)
    exit 0
    ;;
  *)
    echo "Opción inválida"; exit 1
    ;;
esac

exit 0
