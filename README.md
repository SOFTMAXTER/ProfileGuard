# ProfileGuard 1.0 by SOFTMAXTER

**ProfileGuard** es una suite de gestión de protección de datos de nivel empresarial escrita en PowerShell. Diseñada para administradores de sistemas y usuarios avanzados, esta herramienta proporciona una interfaz unificada para operaciones de respaldo complejas, sincronización de datos de alto rendimiento y gestión del entorno de usuario en sistemas Windows.

## 📖 Descripción General

ProfileGuard cierra la brecha entre las utilidades de copia simples y las soluciones de respaldo comerciales pesadas. Su arquitectura modular permite realizar **respaldos versionados** (con soporte para cadenas completas, incrementales y diferenciales) utilizando el algoritmo de compresión LZMA2 de 7-Zip, así como **sincronizaciones espejo** de alta velocidad mediante Robocopy.

El script implementa prácticas de seguridad avanzadas, incluyendo el cifrado **AES-256** para archivos y el uso de la **API de Protección de Datos de Windows (DPAPI)** para el almacenamiento seguro de credenciales en tareas automatizadas. Además, incluye utilidades para la gestión del sistema, como la reubicación segura de carpetas de perfil de usuario modificando el Registro de Windows.

## 🚀 Características Principales

* **Motor de Respaldo Avanzado (7-Zip):**
    * Soporte nativo para esquemas de respaldo **Completo (Full)**, **Incremental** y **Diferencial**.
    * **Cifrado AES-256** opcional con generación automática de contraseñas de alta entropía.
    * Sistema de seguimiento basado en `manifest.json` portable, permitiendo la restauración de cadenas complejas sin dependencias externas.
* **Sincronización de Alto Rendimiento (Robocopy):**
    * Modos de operación **Copy** (Actualización) y **Mirror** (Espejo/Sincronización exacta).
    * Verificación de integridad de datos mediante cálculo de Hash **SHA-256** (Deep Check).
* **Automatización Segura:**
    * Integración con el **Programador de Tareas de Windows**.
    * Almacenamiento de credenciales cifradas localmente (`.cred`) vía DPAPI; las tareas se ejecutan con privilegios elevados sin exponer contraseñas en texto plano.
* **Gestión del Entorno de Usuario:**
    * Módulo para reubicar carpetas del Shell (Escritorio, Documentos, etc.) a otras unidades físicas.
    * Modificación automática de claves de Registro (`User Shell Folders`) y movimiento de datos.
* **Mantenimiento y Autocura:**
    * **Política de Retención:** Purga inteligente de cadenas de respaldo obsoletas manteniendo la integridad referencial.
    * **Auto-actualización:** Verificación automática de versiones contra el repositorio remoto.

## 💻 Requisitos del Sistema

* **Sistema Operativo:** Windows 10 o Windows 11 (x64).
* **Entorno:** PowerShell 5.1 o superior.
* **Permisos:** Se requieren privilegios de **Administrador Local** para la ejecución (elevación automática mediante UAC).
* **Dependencias:**
    * **7-Zip:** El script detectará su ausencia e intentará instalarlo automáticamente vía **Winget** si se requieren funciones de archivado.

## 🛠️ Modo de Uso

Para iniciar la suite, ejecute el archivo `Run.bat` incluido en la raíz del directorio. Esto asegurará los permisos adecuados y el entorno de ejecución.

### Menú Principal

El script presenta una interfaz interactiva basada en consola con las siguientes opciones:

#### `[1] Respaldo Manual Inmediato`
Inicia el motor de archivado 7-Zip.
* Solicita origen y destino.
* Permite elegir entre **Completo** (todo el contenido), **Incremental** (cambios desde el último respaldo de cualquier tipo) o **Diferencial** (cambios desde el último Completo).
* Opción de cifrado: Si se activa, genera o acepta una contraseña y cifra tanto el contenido como los encabezados de archivo (`-mhe=on`).

#### `[2] Configurar Respaldo Automático Programado`
Crea una tarea persistente en Windows.
* Define frecuencia (Diaria/Semanal) y hora.
* Genera un script `.ps1` dedicado y un archivo de credencial `.cred` cifrado.
* La tarea se registra para ejecutarse con los **privilegios más altos** (`-RunLevel Highest`), permitiendo respaldos desatendidos sin intervención del usuario.

#### `[3] Administrar Respaldos Existentes`
Interfaz de gestión del archivo `manifest.json`.
* **Restaurar:** Reconstruye automáticamente la cadena de archivos necesarios (ej. Full -> Inc 1 -> Inc 2) y restaura los datos al estado seleccionado.
* **Purgar (Política de Retención):** Permite definir cuántas cadenas "Completas" mantener. El script calcula dependencias y elimina archivos `.7z` huérfanos o antiguos de forma segura.

#### `[4] Verificar Integridad de Respaldos`
Realiza una auditoría técnica de los archivos almacenados.
* Ejecuta `7z t` (Test) sobre cada archivo en el manifiesto para asegurar que no existe corrupción de bits o errores CRC.

#### `[5] Respaldo Simple (Sincronización Robocopy)`
Utiliza el binario nativo `robocopy.exe` para operaciones de sistema de archivos.
* **Modo Simple:** Copia archivos nuevos o modificados.
* **Modo Espejo (/MIR):** Replica exactamente el origen en el destino, eliminando archivos en el destino que ya no existen en el origen.
* **Verificación Hash:** Opción para calcular y comparar el checksum SHA-256 de cada archivo copiado para garantizar integridad bit a bit (intensivo en CPU/Disco).

#### `[6] Reubicar Carpetas de Usuario`
Herramienta de migración de perfil.
* Permite mover carpetas como *Escritorio*, *Documentos* o *Descargas* a una nueva ubicación (ej. de `C:\` a `D:\Data`).
* Utiliza `robocopy /MOVE` para la transferencia física y `Set-ItemProperty` para actualizar las rutas en `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`.

## 👥 Autor y Colaboradores

* **Autor Principal:** SOFTMAXTER
* **Análisis y refinamiento de código:** Realizado en colaboración con **Gemini**, para garantizar calidad del script, optimización de lógica y seguridad en el manejo de memoria.

## 🤝 Cómo Contribuir

¡Las contribuciones son bienvenidas! Si tienes ideas para mejorar **ProfileGuard**, quieres añadir una nueva funcionalidad o corregir un error, por favor sigue estos pasos:

1.  Haz un **Fork** del repositorio.
2.  Crea una nueva rama para tu funcionalidad (`git checkout -b feature/NuevaFuncionalidad`).
3.  Realiza tus cambios y haz **Commit** (`git commit -m 'Añadir nueva funcionalidad'`).
4.  Haz **Push** a la rama (`git push origin feature/NuevaFuncionalidad`).
5.  Abre un **Pull Request** describiendo detalladamente los cambios propuestos.

## ⚠️ Descargo de Responsabilidad

Este software se proporciona "tal cual", sin garantía de ningún tipo, expresa o implícita. Aunque **ProfileGuard** incluye múltiples mecanismos de verificación de integridad y ha sido probado exhaustivamente:

1.  **El autor no se hace responsable** de ninguna pérdida de datos, corrupción de archivos o daños al sistema derivados del uso de este script.
2.  La función de **Reubicación de Carpetas** modifica el Registro de Windows. Se recomienda encarecidamente crear un **Punto de Restauración del Sistema** antes de utilizar dicha función.
3.  Es responsabilidad del usuario verificar periódicamente que sus copias de seguridad sean restaurables.
