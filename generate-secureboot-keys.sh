#!/bin/bash

set -euo pipefail

KEY_DIR="/usr/share/secureboot/keys"
EFI_MOUNTPOINT=""
GUID_FILE="$KEY_DIR/GUID.txt"
PACMAN_HOOK_DIR="/etc/pacman.d/hooks"
HOOK_FILE="$PACMAN_HOOK_DIR/secureboot-sign.hook"

echo "=== Instalando herramientas necesarias ==="
sudo pacman -S --noconfirm efitools sbsigntools

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

echo "=== Creando directorio para claves en: $KEY_DIR ==="
sudo mkdir -p "$KEY_DIR"
cd "$KEY_DIR"

if [[ ! -f "$GUID_FILE" ]]; then
    echo "=== Generando GUID aleatorio ==="
    uuidgen --random | tee "$GUID_FILE"
fi
GUID=$(< "$GUID_FILE")

echo "=== Generando Clave de Plataforma (PK) ==="
openssl req -newkey rsa:4096 -nodes -keyout PK.key -new -x509 -sha256 -days 3650 -subj "/CN=my Platform Key/" -out PK.crt
openssl x509 -outform DER -in PK.crt -out PK.cer
cert-to-efi-sig-list -g "$GUID" PK.crt PK.esl
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt PK PK.esl PK.auth
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt PK /dev/null rm_PK.auth

echo "=== Generando Clave de Intercambio de Claves (KEK) ==="
openssl req -newkey rsa:4096 -nodes -keyout KEK.key -new -x509 -sha256 -days 3650 -subj "/CN=my Key Exchange Key/" -out KEK.crt
openssl x509 -outform DER -in KEK.crt -out KEK.cer
cert-to-efi-sig-list -g "$GUID" KEK.crt KEK.esl
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

echo "=== Generando Clave de Base de Datos de Firmas (db) ==="
openssl req -newkey rsa:4096 -nodes -keyout db.key -new -x509 -sha256 -days 3650 -subj "/CN=my Signature Database key/" -out db.crt
openssl x509 -outform DER -in db.crt -out db.cer
cert-to-efi-sig-list -g "$GUID" db.crt db.esl
sign-efi-sig-list -g "$GUID" -k KEK.key -c KEK.crt db db.esl db.auth

echo "=== Buscando archivos EFI a firmar ==="
mapfile -t EFI_FILES < <(find "$EFI_MOUNTPOINT" -type f -iname "*.efi" 2>/dev/null)

if [[ ${#EFI_FILES[@]} -gt 0 ]]; then
    for EFI_FILE in "${EFI_FILES[@]}"; do
        # Evitar romper Windows Boot Manager
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

echo "=== Creando hook de pacman para firmar kernel actualizado ==="
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
        echo "✔️ Kernel firmado: $SIGNED_KERNEL"
    fi
done
EOF

sudo chmod +x /usr/local/bin/sign-kernel

echo "Hook y script de firmado instalados. ✅"

echo "=== Detectando sistema de archivos raíz ==="
ROOT_FS=$(findmnt -n -o FSTYPE /)

if [[ "$ROOT_FS" == "btrfs" ]]; then
    echo "✔️ El sistema raíz usa Btrfs"

    ROOT_DEV=$(findmnt -n -o SOURCE /)
    echo "Dispositivo raíz: $ROOT_DEV"

    echo "=== Listando subvolúmenes existentes ==="
    sudo btrfs subvolume list / || true

    echo "=== Detectando subvolúmenes estándar ==="
    MISSING_SUBVOLS=()
    for sub in @ @home @log @pkg; do
        if ! sudo btrfs subvolume list / | grep -q "path $sub\$"; then
            MISSING_SUBVOLS+=("$sub")
        fi
    done

    if [[ ${#MISSING_SUBVOLS[@]} -gt 0 ]]; then
        echo "⚠️ Faltan los siguientes subvolúmenes: ${MISSING_SUBVOLS[*]}"
        read -rp "¿Quieres que el script los cree automáticamente? [s/N] " ans
        if [[ "$ans" =~ ^[sS]$ ]]; then
            for sub in "${MISSING_SUBVOLS[@]}"; do
                sudo btrfs subvolume create "/$sub"
                echo "✔️ Subvolumen creado: /$sub"
            done
        else
            echo "No se crearán subvolúmenes automáticamente."
        fi
    else
        echo "✔️ Ya existen los subvolúmenes recomendados."
    fi

else
    echo "⚠️ El sistema raíz no usa Btrfs (es $ROOT_FS)."
    echo "Se omite configuración de subvolúmenes."
fi

echo "Todo listo. Reinicia y registra las claves desde la UEFI si no lo has hecho."
