#!/bin/bash
set -euo pipefail

KEY_DIR="/usr/share/secureboot/keys"
EFI_MOUNTPOINT=""
GUID_FILE="$KEY_DIR/GUID.txt"
PACMAN_HOOK_DIR="/etc/pacman.d/hooks"
HOOK_FILE="$PACMAN_HOOK_DIR/secureboot-sign.hook"

echo "=== Instalando herramientas necesarias ==="
sudo pacman -S --noconfirm efitools sbsigntools curl

echo "=== Detectando punto de montaje EFI ==="
for path in /boot/efi /boot/EFI; do
    if [[ -d "$path" ]]; then
        EFI_MOUNTPOINT="$path"
        break
    fi
done

if [[ -z "$EFI_MOUNTPOINT" ]]; then
    echo "❌ No se encontró la partición EFI montada en /boot/efi ni /boot/EFI."
    exit 1
fi
echo "✔️ Usando EFI en: $EFI_MOUNTPOINT"

echo "=== Creando directorio de claves en: $KEY_DIR ==="
sudo mkdir -p "$KEY_DIR"
cd "$KEY_DIR"

if [[ ! -f "$GUID_FILE" ]]; then
    echo "=== Generando GUID aleatorio ==="
    uuidgen --random | tee "$GUID_FILE"
fi
GUID=$(< "$GUID_FILE")

# ---- PK ----
if [[ ! -f PK.key ]]; then
    echo "=== Generando Clave de Plataforma (PK) ==="
    openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 \
        -subj "/CN=Platform Key/" -out PK.crt
    openssl x509 -outform DER -in PK.crt -out PK.cer
    cert-to-efi-sig-list -g "$GUID" PK.crt PK.esl
    sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt PK PK.esl PK.auth
    sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt PK /dev/null rm_PK.auth
else
    echo "✔️ PK ya existe, no se regenera."
fi

# ---- KEK ----
if [[ ! -f KEK.key ]]; then
    echo "=== Generando KEK (Key Exchange Key) ==="
    openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 \
        -subj "/CN=Key Exchange Key/" -out KEK.crt
    openssl x509 -outform DER -in KEK.crt -out KEK.cer
    cert-to-efi-sig-list -g "$GUID" KEK.crt KEK.esl

    # Descargar KEK de Microsoft
    curl -s -o MS_KEK.crt https://www.microsoft.com/pkiops/certs/MicCorKEKCA2011_2011-06-24.crt
    cert-to-efi-sig-list -g "$GUID" MS_KEK.crt MS_KEK.esl

    cat KEK.esl MS_KEK.esl > KEK_combined.esl
    sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt KEK KEK_combined.esl KEK.auth
else
    echo "✔️ KEK ya existe, no se regenera."
fi

# ---- DB ----
if [[ ! -f db.key ]]; then
    echo "=== Generando DB (Signature Database) ==="
    openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 \
        -subj "/CN=Secure Boot DB/" -out db.crt
    openssl x509 -outform DER -in db.crt -out db.cer
    cert-to-efi-sig-list -g "$GUID" db.crt db.esl

    # Descargar DB de Microsoft
    curl -s -o MS_DB.crt https://www.microsoft.com/pkiops/certs/MicWinProPCA2011_2011-10-19.crt
    cert-to-efi-sig-list -g "$GUID" MS_DB.crt MS_DB.esl

    cat db.esl MS_DB.esl > db_combined.esl
    sign-efi-sig-list -g "$GUID" -k KEK.key -c KEK.crt db db_combined.esl db.auth
else
    echo " DB ya existe, no se regenera. ✔️"
fi

# ---- Firmar EFI ----
echo "=== Buscando archivos EFI a firmar ==="
mapfile -t EFI_FILES < <(find "$EFI_MOUNTPOINT" -type f -iname "*.efi" 2>/dev/null)

if [[ ${#EFI_FILES[@]} -gt 0 ]]; then
    for EFI_FILE in "${EFI_FILES[@]}"; do
        if [[ "$EFI_FILE" =~ bootmgfw\.efi$ ]]; then
            echo "⚠️ Saltando Windows Boot Manager: $EFI_FILE"
            continue
        fi
        echo "Firmando: $EFI_FILE"
        sudo sbsign --key db.key --cert db.crt --output "$EFI_FILE" "$EFI_FILE"
    done
else
    echo "❌ No se encontró ningún archivo EFI en $EFI_MOUNTPOINT"
    echo "Instala grub o systemd-boot primero."
fi

echo "=== Copiando claves a la partición EFI ==="
sudo cp "$KEY_DIR"/*.cer "$KEY_DIR"/*.esl "$KEY_DIR"/*.auth "$EFI_MOUNTPOINT"

# ---- Pacman Hook ----
echo "=== Creando hook de pacman para firmar kernels ==="
sudo mkdir -p "$PACMAN_HOOK_DIR"

cat <<EOF | sudo tee "$HOOK_FILE" > /dev/null
[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = vmlinuz-linux
Target = vmlinuz-linux-lts
Target = vmlinuz-*

[Action]
Description = Firmando kernel con Secure Boot...
When = PostTransaction
Exec = /usr/local/bin/sign-kernel
EOF

echo "=== Creando script firmador: /usr/local/bin/sign-kernel ==="
cat <<'EOF' | sudo tee /usr/local/bin/sign-kernel > /dev/null
#!/bin/bash
KEY="/usr/share/secureboot/keys/db.key"
CERT="/usr/share/secureboot/keys/db.crt"
KERNELS=(/boot/vmlinuz-* /boot/efi/*/vmlinuz-* /boot/EFI/*/vmlinuz-*)

for KERNEL_PATH in "${KERNELS[@]}"; do
    if [ -f "$KERNEL_PATH" ]; then
        SIGNED_KERNEL="${KERNEL_PATH}.signed"
        /usr/bin/sbsign --key "$KEY" --cert "$CERT" --output "$SIGNED_KERNEL" "$KERNEL_PATH"
        echo " Kernel firmado: $SIGNED_KERNEL ✔️"
    fi
done
EOF

sudo chmod +x /usr/local/bin/sign-kernel

echo "Script completado."
echo "Ahora entra a la BIOS (Key Management) y carga en este orden:"
echo "  1. PK.auth   (única, no append)"
echo "  2. KEK.auth  (append con Microsoft)"
echo "  3. db.auth   (append con Microsoft)"
echo "Deja dbx como viene de fábrica."
