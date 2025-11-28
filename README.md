# ProfileGuard v1.1.0 by SOFTMAXTER
<p align="center">
  <img width="300" height="300" alt="ProfileGuard" src="https://github.com/user-attachments/assets/caa05243-4b2f-4974-a6de-970a2269ad5e" />
</p>
**ProfileGuard** es una suite de gestión de protección de datos de nivel empresarial escrita en PowerShell. Diseñada para administradores de sistemas y usuarios avanzados, esta herramienta proporciona una interfaz unificada y robusta para operaciones de respaldo complejas, sincronización de datos de alto rendimiento, automatización de tareas y gestión integral del entorno de usuario en sistemas Windows.

## 📖 Descripción General

ProfileGuard cierra la brecha entre las utilidades de copia simples y las soluciones de respaldo comerciales pesadas, ofreciendo una solución integral y modular:

* **Sistema de Respaldo Avanzado (7-Zip):** Su arquitectura modular permite realizar **respaldos versionados** (con soporte para cadenas completas, incrementales y diferenciales) utilizando el algoritmo de compresión LZMA2 de 7-Zip, lo que garantiza una alta eficiencia de almacenamiento.
* **Sincronización de Alto Rendimiento (Robocopy):** Facilita la sincronización y replicación de datos de alta velocidad, con modos de copia y espejo.
* **Seguridad y Automatización:** Implementa prácticas de seguridad avanzadas, incluyendo el cifrado **AES-256** para archivos y el uso de la **API de Protección de Datos de Windows (DPAPI)** para el almacenamiento seguro de credenciales en tareas automatizadas, permitiendo ejecuciones desatendidas sin riesgo de exponer contraseñas.
* **Gestión del Sistema:** Incluye utilidades para la gestión del sistema, como la reubicación segura de carpetas de perfil de usuario modificando el Registro de Windows y un visor de logs integrado para auditoría.
* **Mantenimiento y Autocura:** Cuenta con una política de retención inteligente para purgar cadenas de respaldo obsoletas manteniendo la integridad referencial, y un sistema de auto-actualización automática desde un repositorio remoto.

## 🚀 Características Principales

* **Motor de Respaldo Avanzado (7-Zip):**
    * Soporte nativo para esquemas de respaldo **Completo (Full)**, **Incremental** y **Diferencial**.
    * **Cifrado AES-256** opcional con generación automática de contraseñas de alta entropía.
    * Sistema de seguimiento basado en `manifest.json` portable, permitiendo la restauración de cadenas complejas sin dependencias externas y la reconstrucción automática de rutas de restauración.
* **Sincronización de Alto Rendimiento (Robocopy):**
    * Modos de operación **Copy** (Actualización) y **Mirror** (Espejo/Sincronización exacta).
    * Verificación de integridad de datos mediante cálculo de Hash **SHA-256** (Deep Check).
* **Automatización Segura y Flexible:**
    * Integración completa con el **Programador de Tareas de Windows** para crear y gestionar tareas de respaldo.
    * Almacenamiento de credenciales cifradas localmente (`.cred`) vía DPAPI; las tareas se ejecutan con privilegios elevados (`-RunLevel Highest`) sin exponer contraseñas en texto plano, lo que permite respaldos desatendidos seguros.
    * Opciones para editar y eliminar tareas programadas existentes directamente desde el script.
* **Gestión del Entorno de Usuario:**
    * Módulo para reubicar carpetas del Shell (Escritorio, Documentos, etc.) a otras unidades físicas.
    * Modificación automática y segura de claves de Registro (`User Shell Folders`) y movimiento físico de datos mediante Robocopy.
* **Mantenimiento y Auditoría:**
    * **Política de Retención:** Purga inteligente de cadenas de respaldo obsoletas manteniendo la integridad referencial.
    * **Verificación de Integridad:** Auditoría técnica de archivos de respaldo (`7z t`) para detectar corrupción.
    * **Visor de Logs Integrado:** Acceso fácil y centralizado a los registros de actividad del script general y de las tareas programadas para auditoría y resolución de problemas.
    * **Auto-actualización:** Verificación automática y descarga de nuevas versiones contra el repositorio remoto de GitHub.
* **Experiencia de Usuario:**
    * Interfaz de consola interactiva y fácil de usar con menús claros.
    * Diálogos gráficos para la selección de carpetas y archivos, facilitando la navegación.
    * Reinicio del Explorador de Windows integrado para aplicar cambios de reubicación de carpetas.

## 💻 Requisitos del Sistema

* **Sistema Operativo:** Windows 10 o Windows 11 (x64).
* **Entorno:** PowerShell 5.1 o superior.
* **Permisos:** Se requieren privilegios de **Administrador Local** para la ejecución. El script solicitará elevación automática mediante UAC si no se ejecuta con privilegios suficientes.
* **Dependencias:**
    * **7-Zip:** El script detectará su ausencia e intentará instalarlo automáticamente vía **Winget** si se requieren funciones de archivado. Es esencial para el motor de respaldo avanzado.
* **Configuración Adicional:** Para las notificaciones por correo electrónico, se requiere un servidor SMTP y una cuenta válida, configurables en el script.

## 🛠️ Modo de Uso

Para iniciar la suite, ejecute el archivo `Run.bat` incluido en la raíz del directorio. Esto asegurará los permisos adecuados, el entorno de ejecución correcto y lanzará el script principal de PowerShell con las políticas de ejecución necesarias.

### Menú Principal

El script presenta una interfaz interactiva basada en consola con las siguientes opciones:

#### `[1] Respaldo Manual Inmediato`
Inicia el motor de archivado 7-Zip para realizar un respaldo al momento.
* Solicita las rutas de origen y destino mediante diálogos gráficos.
* Permite elegir entre los esquemas de respaldo **Completo**, **Incremental** o **Diferencial**.
* Opción de cifrado: Si se activa, permite introducir una contraseña manual o genera automáticamente una contraseña segura, cifrando tanto el contenido como los encabezados de archivo (`-mhe=on`).

#### `[2] Configurar Respaldo Automático Programado`
Crea una tarea persistente en el Programador de Tareas de Windows.
* Guía al usuario a través de la selección de origen, destino, frecuencia (Diaria/Semanal), hora y tipo de respaldo.
* Genera un script `.ps1` dedicado para la tarea y un archivo de credencial `.cred` cifrado vía DPAPI para el manejo seguro de contraseñas.
* La tarea se registra para ejecutarse con los **privilegios más altos** (`-RunLevel Highest`) y solo cuando el usuario haya iniciado sesión, permitiendo respaldos desatendidos seguros.

#### `[2a] Editar/Eliminar Tarea Programada`
Proporciona una interfaz para gestionar las tareas de respaldo creadas por ProfileGuard.
* Lista las tareas existentes con información sobre su estado, próxima ejecución, tipo de respaldo y horario.
* Permite **editar** el horario, la frecuencia y el tipo de respaldo de una tarea existente.
* Permite **eliminar** completamente una tarea, incluyendo el script `.ps1` y el archivo `.cred` asociados.

#### `[3] Administrar Respaldos Existentes`
Interfaz de gestión del archivo `manifest.json` y las cadenas de respaldo.
* **Restaurar:** Reconstruye automáticamente la cadena de archivos necesarios (ej. Full -> Inc 1 -> Inc 2) y restaura los datos al estado seleccionado. Permite cargar una credencial DPAPI (`.cred`) para restaurar respaldos cifrados sin necesidad de introducir la contraseña manualmente.
* **Purgar (Política de Retención):** Permite definir cuántas cadenas "Completas" mantener. El script calcula dependencias y elimina archivos `.7z` huérfanos o antiguos de forma segura para liberar espacio, actualizando el manifiesto.
* **Cargar Credencial (DPAPI):** Permite cargar una credencial `.cred` en memoria para facilitar la restauración de múltiples archivos cifrados.

#### `[4] Verificar Integridad de Respaldos`
Realiza una auditoría técnica de los archivos almacenados para detectar corrupción.
* Ejecuta el comando `7z t` (Test) sobre cada archivo registrado en el manifiesto para asegurar la integridad de los datos y que no existen errores CRC.
* Proporciona un informe detallado del estado de cada archivo.

#### `[5] Respaldo Simple (Sincronización Robocopy)`
Utiliza el binario nativo `robocopy.exe` para operaciones de sistema de archivos, ideal para copias locales o a unidades de red.
* **Respaldo de Perfil de Usuario:** Preselecciona carpetas comunes del perfil (Escritorio, Documentos, etc.).
* **Respaldo Personalizado:** Permite seleccionar carpetas o archivos específicos mediante diálogos.
* **Modo Simple (Copy):** Copia archivos nuevos o modificados del origen al destino.
* **Modo Espejo (/MIR):** Replica exactamente el origen en el destino, eliminando archivos en el destino que ya no existen en el origen.
* **Verificación Hash:** Opción para calcular y comparar el checksum SHA-256 de cada archivo copiado para garantizar integridad bit a bit (intensivo en CPU/Disco), o una verificación rápida por atributos (`/L`).

#### `[6] Reubicar Carpetas de Usuario`
Herramienta de migración de perfil para mover carpetas como *Escritorio*, *Documentos* o *Descargas* a una nueva ubicación (ej. de `C:\` a `D:\Data`).
* Utiliza `robocopy /MOVE` para la transferencia física de los datos, asegurando la integridad y permisos.
* Utiliza `Set-ItemProperty` para actualizar las rutas en el Registro de Windows (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`).
* Ofrece la opción de mover los archivos y actualizar el registro, o solo actualizar el registro.
* Incluye una función para reiniciar el Explorador de Windows y aplicar los cambios.

#### `[L] VISOR DE REGISTROS (LOGS)`
Proporciona acceso directo a los archivos de registro generados por ProfileGuard para auditoría y resolución de problemas.
* Permite ver el **Registro General de Actividad** del script principal.
* Permite ver el **Registro de Tareas Programadas** para auditoría de las ejecuciones automáticas.
* Abre los archivos de log con el Bloc de notas.

### Esquemas de Respaldo Flexibles

ProfileGuard ofrece una flexibilidad total en la elección del esquema de respaldo que mejor se adapte a sus necesidades de protección de datos y almacenamiento:

* **Respaldo Completo (Full):** Crea una copia de seguridad de la totalidad de los datos seleccionados en el origen. Es el punto de partida para los respaldos incrementales y diferenciales, y el más sencillo de restaurar, pero el que más espacio ocupa y más tiempo tarda en ejecutarse.
* **Respaldo Incremental:** Copia únicamente los archivos que han sido modificados o creados desde el **último respaldo de cualquier tipo** (ya sea completo o incremental). Es el método más rápido y el que menos espacio de almacenamiento consume, pero la restauración requiere el último respaldo completo y todos los respaldos incrementales posteriores en orden. ProfileGuard maneja automáticamente esta cadena de restauración.
* **Respaldo Diferencial:** Copia todos los archivos que han sido modificados o creados desde el **último respaldo completo**. Consume más espacio que el incremental, pero la restauración es más sencilla, ya que solo requiere el último respaldo completo y el último respaldo diferencial.

ProfileGuard se encarga de gestionar automáticamente las dependencias entre estos tipos de respaldo a través de su sistema de manifiesto (`manifest.json`), asegurando la integridad de las cadenas de restauración y simplificando la gestión para el usuario.

## 👥 Autor y Colaboradores

* **Autor Principal:** SOFTMAXTER
* **Análisis y refinamiento de código:** Realizado en colaboración con **Gemini**, para garantizar calidad del script, optimización de lógica, robustez y seguridad en el manejo de memoria y procesos.

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
2.  La función de **Reubicación de Carpetas** modifica el Registro de Windows. Se recomienda encarecidamente crear un **Punto de Restauración del Sistema** antes de utilizar dicha función y asegurar que se tiene una copia de seguridad de los datos.
3.  Es responsabilidad del usuario verificar periódicamente que sus copias de seguridad sean restaurables y que el sistema de respaldo funcione según lo esperado.
