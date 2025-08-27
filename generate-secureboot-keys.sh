#!/bin/bash

set -euo pipefail

KEY_DIR="/usr/share/secureboot/keys"
EFI_DIR="/boot/EFI"
GUID_FILE="$KEY_DIR/GUID.txt"
PACMAN_HOOK_DIR="/etc/pacman.d/hooks"
HOOK_FILE="$PACMAN_HOOK_DIR/secureboot-sign.hook"
BOOTLOADER_EFI="$EFI_DIR/BOOT/BOOTX64.EFI"

echo "=== Instalando herramientas necesarias ==="
sudo pacman -S --noconfirm efitools sbsigntools

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

echo "=== Firmando gestor de arranque (BOOTX64.EFI) ==="
if [[ -f "$BOOTLOADER_EFI" ]]; then
    sudo sbsign --key db.key --cert db.crt --output "$BOOTLOADER_EFI" "$BOOTLOADER_EFI"
else
    echo "❌ Archivo $BOOTLOADER_EFI no encontrado. Asegúrate de instalar systemd-boot primero."
fi

echo "=== Copiando claves a la partición EFI ==="
sudo cp "$KEY_DIR"/*.cer "$KEY_DIR"/*.esl "$KEY_DIR"/*.auth "$EFI_DIR"

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
KERNEL_PATH="/boot/vmlinuz-linux"
SIGNED_KERNEL="/boot/vmlinuz-linux.signed"

if [ -f "$KERNEL_PATH" ]; then
    /usr/bin/sbsign --key "$KEY" --cert "$CERT" --output "$SIGNED_KERNEL" "$KERNEL_PATH"
    echo "Kernel firmado: $SIGNED_KERNEL ✔️"
else
    echo "⚠️ Kernel no encontrado en $KERNEL_PATH ⚠️"
fi
EOF

sudo chmod +x /usr/local/bin/sign-kernel

echo "Hook y script de firmado instalados. ✅"

echo "=== Configuración básica de Btrfs recomendada (manual) ==="
cat <<'EOF'

Puedes usar Btrfs con subvolúmenes para organizar mejor tu sistema:

Ejemplo de creación con subvolúmenes:
  mkfs.btrfs -L archlinux /dev/sdX
  mount /dev/sdX /mnt
  btrfs subvolume create /mnt/@
  btrfs subvolume create /mnt/@home
  btrfs subvolume create /mnt/@log
  btrfs subvolume create /mnt/@pkg
  umount /mnt

Luego montar con:
  mount -o subvol=@ /dev/sdX /mnt
  mkdir -p /mnt/{home,var/log,var/cache/pacman/pkg}
  mount -o subvol=@home /dev/sdX /mnt/home
  mount -o subvol=@log /dev/sdX /mnt/var/log
  mount -o subvol=@pkg /dev/sdX /mnt/var/cache/pacman/pkg

Para usar snapshots con `snapper`, `btrfs-assistant` o `timeshift`.

EOF

echo "Todo listo. Reinicia y registra las claves desde la UEFI si no lo has hecho."