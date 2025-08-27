# Configuración de Secure Boot para Arch Linux (y derivadas)

Este binerio te guiará a través del proceso para configurar Secure Boot en tu sistema con Arch Linux y Windows, basándose en un hilo de Reddit para asegurar un arranque seguro sin conflictos.

---

## 1. Generar las Claves

Primero, necesitas generar tus propias claves criptográficas (`PK`, `KEK`, `db`). Estas claves son necesarias para que el UEFI de tu placa base pueda verificar la firma de tu gestor de arranque.

1.  Dale permisos de ejecución al script:
    ```bash
    chmod +x generate-secureboot-keys.sh
    ```

2.  Ejecuta el script con privilegios de superusuario. Esto creará los archivos de claves directamente en tu partición EFI.
    ```bash
    sudo ./generate-secureboot-keys.sh
    ```
    > **Nota importante:** Este script está diseñado para no borrar el archivo `bootmgfw.efi` de Windows, asegurando que tu arranque dual funcione sin problemas.

---

## 2. Cargar las Claves en el UEFI

Una vez que tengas los archivos de claves, el siguiente paso es cargarlos en la configuración de tu BIOS/UEFI.

1.  **Reinicia** el equipo y entra en el menú de la **BIOS/UEFI**. La tecla para acceder a este menú suele ser `Supr`, `F2`, `F10` o `F12`.

2.  Busca la sección de **Secure Boot**. Generalmente la encontrarás en las opciones de "Boot" o "Security".

3.  Cambia el modo de **Secure Boot** a **"Custom Mode"** (o "Personalizado").

4.  Navega a la opción **"Manage Keys"** o "Key Management". Aquí verás los campos para cargar las diferentes claves.

5.  Carga los archivos `.cer` que el script generó. Los encontrarás en tu partición EFI (normalmente en `/boot/efi/` o `/boot/EFI/`).

    * `PK.cer` → **Platform Key**
    * `KEK.cer` → **Key Exchange Key**
    * `db.cer` → **Database Key** (para los binarios válidos)

6.  Guarda los cambios y, si es necesario, **activa Secure Boot**.

¡Listo! Tu sistema ahora usará las claves que tú controlas para arrancar de forma segura.
