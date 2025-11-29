<#
.SYNOPSIS
    Una suite de gestión de respaldos de nivel profesional para archivar, cifrar (AES-256), reubicar perfiles y automatizar la protección de datos.

.DESCRIPTION
    ProfileGuard es una solución de protección de datos integral que unifica múltiples vectores de seguridad en una sola herramienta:

    1.  [Respaldo Avanzado] Motor basado en 7-Zip para archivos versionados (Full, Incremental, Diferencial) con cifrado militar AES-256 y seguimiento mediante 'manifest.json'.
    2.  [Sincronización] Replicación de alta velocidad (Robocopy) con modos Espejo/Copia y validación de integridad por Hash SHA-256.
    3.  [Gestión de Perfil] Herramienta para reubicar carpetas de usuario (Documentos, Escritorio, etc.) modificando el Registro de Windows de forma segura.
    4.  [Automatización] Programador de tareas con seguridad DPAPI (credenciales cifradas) y ejecución con privilegios elevados.

    El módulo es autosuficiente (instala dependencias vía Winget), cuenta con autocuración de manifiestos corruptos y sistema de actualización automática desde GitHub.

.AUTHOR
    SOFTMAXTER

.VERSION
    1.1.5
#>

[CmdletBinding()]
param(
    [switch]$EngineMode, # Si está presente, solo se ejecuta el motor

    # Parámetros para el motor (solo se usan si -EngineMode está presente)
    [string]$SourcePath,
    [string]$DestinationPath,
    [string]$BackupType,
    [bool]$IsEncrypted,
    [string]$PlainTextPassword,
    [string]$LogContext
)

$script:Version = "1.1.5"

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('INFO', 'ACTION', 'WARN', 'ERROR')]
        [string]$LogLevel,

        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    try {
        $parentDir = Split-Path -Parent $PSScriptRoot
        $logDir = Join-Path -Path $parentDir -ChildPath "Logs"
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        $logFile = Join-Path -Path $logDir -ChildPath "Registro.log"
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "[$timestamp] [$LogLevel] - $Message" | Out-File -FilePath $logFile -Append -Encoding utf8
    }
    catch {
        Write-Warning "No se pudo escribir en el archivo de log: $_"
    }
}

# --- FUNCION 1: Actualizador Automatico desde Repositorio (LOGICA CORREGIDA) ---
function Invoke-FullRepoUpdater {
    # --- CONFIGURACION ---
    # Ajusta estos valores a tu repositorio real
    $repoUser = "SOFTMAXTER"
    $repoName = "ProfileGuard"
    $repoBranch = "main" # O la rama que uses
    
    # URLs directas a los archivos "crudos" (raw)
    $versionUrl = "https://raw.githubusercontent.com/$repoUser/$repoName/$repoBranch/version.txt"
    $zipUrl = "https://github.com/$repoUser/$repoName/archive/refs/heads/$repoBranch.zip"
    
    $updateAvailable = $false
    $remoteVersionStr = ""

    try {
        Write-Host "Buscando actualizaciones..." -ForegroundColor Gray
        # Se intenta la operacion de red con un timeout corto para no retrasar el script si no hay conexion.
        # Usamos -UseBasicParsing para mayor compatibilidad y un timeout de 5 segundos.
        $response = Invoke-WebRequest -Uri $versionUrl -UseBasicParsing -Headers @{"Cache-Control"="no-cache"} -TimeoutSec 5 -ErrorAction Stop
        $remoteVersionStr = $response.Content.Trim()

        # Comparacion de versiones simple (como cadenas)
        # Esto asume que el formato es siempre X.Y.Z y que versiones mayores tienen numeros mayores
        if ($remoteVersionStr -ne $script:Version) {
            $updateAvailable = $true
        }
    }
    catch {
        # Silencioso si no hay conexion o falla la peticion, no es un error critico.
        Write-Host "No se pudo buscar actualizaciones (sin conexion o error del servidor)." -ForegroundColor Gray
        return
    }

    # --- Si hay una actualizacion, preguntamos al usuario ---
    if ($updateAvailable) {
        Write-Host "`n¡Nueva version encontrada!" -ForegroundColor Green
        Write-Host "Version Local: v$($script:Version)" -ForegroundColor Gray
        Write-Host "Version Remota: v$remoteVersionStr" -ForegroundColor Yellow
        Write-Log -LogLevel INFO -Message "UPDATER: Nueva versión detectada. Local: v$($script:Version) | Remota: v$remoteVersionStr"
        
        Write-Host ""
        $confirmation = Read-Host "¿Deseas descargar e instalar la actualizacion ahora? (S/N)"
        
        if ($confirmation.ToUpper() -eq 'S') {
            Write-Warning "`nEl actualizador se ejecutara en una nueva ventana."
            Write-Warning "Este script principal se cerrara para permitir la actualizacion."
            Write-Log -LogLevel ACTION -Message "UPDATER: Iniciando proceso de actualización. El script se cerrará."
            
            # --- Preparar el script del actualizador externo ---
            $tempDir = Join-Path $env:TEMP "ProfileGuardUpdater"
            if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force }
            New-Item -Path $tempDir -ItemType Directory | Out-Null
            $updaterScriptPath = Join-Path $tempDir "updater.ps1"
            $installPath = (Split-Path -Path $PSScriptRoot -Parent)
            $batchPath = Join-Path $installPath "Run.bat"

            # Contenido del script temporal que hara el trabajo sucio
            $updaterScriptContent = @"
param(`$parentPID)
`$ErrorActionPreference = 'Stop'
`$Host.UI.RawUI.WindowTitle = 'PROCESO DE ACTUALIZACION DE ProfileGuard - NO CERRAR'

# Funcion auxiliar para logs del actualizador
function Write-UpdateLog { param([string]`$msg) Write-Host "`n`$msg" -ForegroundColor Cyan }

try {
    `$tempDir_updater = "$tempDir"
    `$tempZip_updater = Join-Path "`$tempDir_updater" "update.zip"
    `$tempExtract_updater = Join-Path "`$tempDir_updater" "extracted"

    Write-UpdateLog "[PASO 1/6] Descargando la nueva version v$remoteVersionStr..."
    Invoke-WebRequest -Uri "$zipUrl" -OutFile "`$tempZip_updater"

    Write-UpdateLog "[PASO 2/6] Descomprimiendo archivos..."
    Expand-Archive -Path "`$tempZip_updater" -DestinationPath "`$tempExtract_updater" -Force
    # GitHub extrae en una subcarpeta con el nombre del repo y la rama (ej: ProfileGuard-main)
    `$updateSourcePath = (Get-ChildItem -Path "`$tempExtract_updater" -Directory | Select-Object -First 1).FullName

    Write-UpdateLog "[PASO 3/6] Esperando a que el proceso principal finalice..."
    try {
        # Espera a que el PID del script principal termine
        Get-Process -Id `$parentPID -ErrorAction Stop | Wait-Process -ErrorAction Stop -Timeout 30
    } catch {
        # Si el proceso ya cerro o paso el timeout, seguimos
        Write-Host "   - Proceso principal finalizado." -ForegroundColor Gray
    }

    Write-UpdateLog "[PASO 4/6] Preparando instalacion (limpiando archivos antiguos)..."
    # Excluimos carpetas de datos del usuario para no borrarlas
    `$itemsToRemove = Get-ChildItem -Path "$installPath" -Exclude "Logs", "Tools", "BackupScripts", "*.cred", "manifest.json"
    if (`$null -ne `$itemsToRemove) { 
        Remove-Item -Path `$itemsToRemove.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-UpdateLog "[PASO 5/6] Instalando nuevos archivos..."
    # Movemos todo el contenido de la carpeta extraida a la raiz de instalacion
    Copy-Item -Path "`$updateSourcePath\*" -Destination "$installPath" -Recurse -Force
    
    # Desbloqueamos los archivos descargados por si acaso
    Get-ChildItem -Path "$installPath" -Recurse | Unblock-File -ErrorAction SilentlyContinue

    Write-UpdateLog "[PASO 6/6] ¡Actualizacion completada con exito!"
    Write-Host "`nReiniciando ProfileGuard en 5 segundos..." -ForegroundColor Green
    Start-Sleep -Seconds 5
    
    # Limpieza y reinicio
    Remove-Item -Path "`$tempDir_updater" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath "$batchPath"
}
catch {
    Write-Error "`n¡ERROR CRITICO DURANTE LA ACTUALIZACION!"
    Write-Error "Detalles: `$(`$_.Exception.Message)"
    Write-Warning "Tu instalacion puede estar incompleta."
    Write-Warning "Por favor, descarga la ultima version manualmente desde el repositorio."
    Read-Host "`nPresiona Enter para cerrar esta ventana..."
}
"@
            # Guardar el script del actualizador
            $utf8NoBom = New-Object System.Text.UTF8Encoding $false
            [System.IO.File]::WriteAllText($updaterScriptPath, $updaterScriptContent, $utf8NoBom)
            
            # Lanzar el actualizador en una nueva ventana de CMD/PowerShell y cerrar este script
            $launchArgs = "/c start `"PROCESO DE ACTUALIZACION`" powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$updaterScriptPath`" -parentPID $PID"
            Start-Process cmd.exe -ArgumentList $launchArgs -WindowStyle Normal
            
            # Cerrar el script principal inmediatamente
            exit
        } else {
            Write-Host "`nActualizacion omitida por el usuario." -ForegroundColor Yellow
            Write-Log -LogLevel INFO -Message "UPDATER: El usuario ha pospuesto la actualización a v$remoteVersionStr."
            Start-Sleep -Seconds 1
        }
    }
}


# --- Verificacion de Privilegios de Administrador ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Este script necesita ser ejecutado como Administrador."
    Write-Host "Por favor, cierra esta ventana, haz clic derecho en el archivo del script y selecciona 'Ejecutar como Administrador'."
    Read-Host "Presiona Enter para salir."
    exit
}

Write-Log -LogLevel INFO -Message "================================================="
Write-Log -LogLevel INFO -Message "ProfileGuard v$($script:Version) iniciado en modo Administrador."

function Invoke-ExplorerRestart {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Host "`n[+] Reiniciando el Explorador de Windows para aplicar los cambios visuales..." -ForegroundColor Yellow
    Write-Log -LogLevel ACTION -Message "Reiniciando el Explorador de Windows a peticion del usuario."

    if ($PSCmdlet.ShouldProcess("explorer.exe", "Reiniciar")) {
        try {
            # Obtener todos los procesos del Explorador (puede haber mas de uno)
            $explorerProcesses = Get-Process -Name explorer -ErrorAction Stop
            
            # Detener los procesos
            $explorerProcesses | Stop-Process -Force
            Write-Host "   - Proceso(s) detenido(s)." -ForegroundColor Gray
            
            # Esperar a que terminen
            $explorerProcesses.WaitForExit()
            
            # Iniciar un nuevo proceso del explorador
            Start-Process "explorer.exe"
            Write-Host "   - Proceso iniciado." -ForegroundColor Gray
            Write-Host "[OK] El Explorador de Windows se ha reiniciado." -ForegroundColor Green
        }
        catch {
            Write-Error "No se pudo reiniciar el Explorador de Windows. Es posible que deba reiniciar la sesion manualmente. Error: $($_.Exception.Message)"
            Write-Log -LogLevel ERROR -Message "Fallo el reinicio del Explorador de Windows. Motivo: $($_.Exception.Message)"
            # Intento de emergencia para iniciar explorer por si se quedo detenido
            Start-Process "explorer.exe" -ErrorAction SilentlyContinue
        }
    }
}

# --- FUNCION 2: El NUEVO Motor de Creacion de Respaldos (Manual) ---
function Invoke-BackupCreation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    
    Write-Log -LogLevel INFO -Message "BACKUP/7-Zip: Iniciando creacion de respaldo manual."

    # --- 1. Verificar si 7-Zip esta disponible ---
    if (-not (Ensure-7ZipIsInstalled)) {
        Read-Host "`nPresiona Enter para volver..."
        return
    }

    # --- 2. Obtener Origen y Destino ---
    Write-Host "`n[+] Paso 1: Selecciona la CARPETA de Origen que deseas respaldar." -ForegroundColor Yellow
    $sourcePath = Select-PathDialog -DialogType 'Folder' -Title "Paso 1: Elige la Carpeta de Origen del Respaldo"
    if ([string]::IsNullOrWhiteSpace($sourcePath)) {
        Write-Warning "No se selecciono una carpeta de origen. Operacion cancelada." ; Start-Sleep -Seconds 2; return
    }
    
    Write-Host "`n[+] Paso 2: Selecciona la CARPETA de Destino donde se guardara el respaldo." -ForegroundColor Yellow
    $destinationPath = Select-PathDialog -DialogType 'Folder' -Title "Paso 2: Elige la Carpeta de Destino del Respaldo"
    if ([string]::IsNullOrWhiteSpace($destinationPath)) {
        Write-Warning "No se selecciono una carpeta de destino. Operacion cancelada." ; Start-Sleep -Seconds 2; return
    }

    # --- 3. Seleccionar Tipo de Respaldo ---
    $backupType = ''
    while ($backupType -notin @('1', '2', '3')) {
        Clear-Host
        Write-Host "[3/5] Selecciona el tipo de respaldo:"
        Write-Host "   [1] Respaldo Completo (Full)" -ForegroundColor Yellow
        Write-Host "   [2] Respaldo Incremental (Incremental)"
        Write-Host "   [3] Respaldo Diferencial (Differential)"
        $backupType = Read-Host "Elige una opcion (1-3)"
    }
    $Type = switch($backupType) { '1' { 'Full' } '2' { 'Incremental' } '3' { 'Differential' } }

	Write-Host "`n[3.5/5] Selecciona el nivel de compresion:" -ForegroundColor Yellow
    Write-Host "   [1] Rapido (Nivel 5) - Buen equilibrio entre velocidad y tamaño."
    Write-Host "   [2] Maximo (Nivel 9) - Archivo mas pequeño, pero mucho mas lento."
    $compChoice = Read-Host "Elige una opcion (1-2) [Por defecto: 1]"
    
    # Si el usuario da Enter sin elegir, se usa '1' (Rápido) por defecto
    if ([string]::IsNullOrWhiteSpace($compChoice) -or $compChoice -notin @('1', '2')) {
        $compChoice = '1'
        Write-Host "   -> Usando nivel Rápido por defecto." -ForegroundColor Gray
    }
    # Mapeamos la elección al parámetro que espera el motor
    $compressionLevel = if ($compChoice -eq '2') { 'Max' } else { 'Fast' }
    
    # --- 4. Opcion de Cifrado ---
    Write-Host "`n[4/5] ¿Deseas cifrar este respaldo con AES-256?" -ForegroundColor Yellow
    Write-Warning "Si pierdes la contrasena, NO PODRAS RECUPERAR tus archivos."
    $encryptChoice = Read-Host "(S/N)"
    
    $securePassword = $null
    $isEncrypted = $false
    $passwordTextForFile = $null 
    $passMethod = ''
    # Nueva variable para guardar la decisión del usuario
    $savePasswordToFileChoice = 'N' # <--- CAMBIO AQUÍ: Inicializamos la variable

    if ($encryptChoice.ToUpper() -eq 'S') {
        $isEncrypted = $true
        Write-Host "   [1] Introducir manualmente una contrasena segura"
        Write-Host "   [2] Generar una contrasena aleatoria segura (recomendado)"
        $passMethod = Read-Host "Elige una opcion (1-2)"
        
        if ($passMethod -eq '1') {
            $securePassword = Read-Host "Introduce una contrasena segura" -AsSecureString
        } else {
            # Generación aleatoria
            $passwordTextForFile = Generate-SecurePassword
            $securePassword = ConvertTo-SecureString $passwordTextForFile -AsPlainText -Force
            Write-Host "`n[+] Se ha generado una contrasena segura aleatoria." -ForegroundColor Green
            
            # --- SECCIÓN MODIFICADA: PREGUNTAR AL USUARIO ---
            Write-Host "`nCONTRASENA GENERADA: $passwordTextForFile" -ForegroundColor Magenta
            Write-Warning "¡Cópiala ahora! No la pierdas."
            
            # Preguntamos si quiere guardarla en archivo
            $savePasswordToFileChoice = Read-Host "`n¿Deseas que el script guarde esta contraseña en un archivo .txt en el destino? (S/N)" # <--- CAMBIO AQUÍ: La pregunta
            
            if ($savePasswordToFileChoice.ToUpper() -eq 'S') {
                 Write-Host "[INFO] Se intentará guardar la contraseña en un archivo al finalizar con éxito." -ForegroundColor Gray
            } else {
                 Write-Warning "Has elegido NO guardar la contraseña en un archivo. Asegúrate de tenerla a buen recaudo."
            }
            # --- FIN SECCIÓN MODIFICADA ---
            
            Read-Host "`nPresiona Enter para continuar..."
        }
    }
    
    # --- 5. LLAMAR AL MOTOR CENTRALIZADO ---
    Write-Host "`n[5/5] Ejecutando motor de respaldo... Esto puede tardar." -ForegroundColor Yellow
    
    # Forzamos que el motor muestre errores en pantalla en modo manual
    $success = Invoke-ProfileGuardBackupEngine -SourcePath $sourcePath -DestinationPath $destinationPath -BackupType $Type -CompressionLevel $compressionLevel -IsEncrypted $isEncrypted -SecurePassword $securePassword -LogContext "MANUAL" -WarningAction Continue

    # --- 6. Reporte y Limpieza de Contraseña ---
    if ($success) {
        Write-Host "`n[EXITO] Respaldo manual completado exitosamente." -ForegroundColor Green
        
        # --- SECCIÓN MODIFICADA: GUARDADO CONDICIONAL ---
        # Solo guardamos si estaba cifrado, fue generada aleatoriamente (metodo 2) Y el usuario dijo 'S'
        if ($isEncrypted -and $passMethod -eq '2' -and $savePasswordToFileChoice.ToUpper() -eq 'S') { # <--- CAMBIO AQUÍ: Añadida condición de la elección del usuario
            try {
                $passwordPath = Join-Path $destinationPath "Password_Generada_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
                # Usamos .NET directamente para asegurar UTF-8 sin BOM
                $utf8NoBom = New-Object System.Text.UTF8Encoding $false
                [System.IO.File]::WriteAllText($passwordPath, $passwordTextForFile, $utf8NoBom)

                Write-Warning "¡IMPORTANTE! La contrasena se ha guardado en: '$passwordPath'"
                Write-Warning "Mueva este archivo de contrasena a un lugar seguro y bórrelo de aquí."
                Write-Log -LogLevel ACTION -Message "MANUAL-BACKUP: Contraseña generada guardada en archivo de texto a petición del usuario."
            } catch {
                Write-Error "No se pudo guardar el archivo de contrasena en '$passwordPath'."
                Write-Error "Error: $($_.Exception.Message)"
                Write-Error "TU CONTRASENA ES: $passwordTextForFile"
                Write-Error "¡GUARDALA MANUALMENTE AHORA!"
                Write-Log -LogLevel ERROR -Message "MANUAL-BACKUP: Fallo al guardar el archivo de contraseña de texto."
            }
        } elseif ($isEncrypted -and $passMethod -eq '2' -and $savePasswordToFileChoice.ToUpper() -ne 'S') {
             # Recordatorio final si eligieron no guardar
             Write-Host "`n[RECORDATORIO] Elegiste no guardar la contraseña en archivo. Esperamos que la hayas anotado." -ForegroundColor Gray
        }
        # --- FIN SECCIÓN MODIFICADA ---

    } else {
        Write-Error "`nFALLO: El motor de respaldo reporto un error."
        Write-Host "Revisa los mensajes anteriores o el archivo de registro (Log) para mas detalles." -ForegroundColor Yellow
    }
    
    # Limpieza final de variables sensibles
    $securePassword = $null
    $passwordTextForFile = $null
    $savePasswordToFileChoice = $null
    [GC]::Collect()
    Read-Host "`nPresiona Enter para volver..."
}

# --- FUNCION "MOTOR" DE RESPALDO CENTRALIZADA ---
function Invoke-ProfileGuardBackupEngine {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Full', 'Incremental', 'Differential')]
        [string]$BackupType,

		[Parameter(Mandatory=$false)] # Opcional, por defecto será 'Fast'
        [ValidateSet('Fast', 'Max')]
        [string]$CompressionLevel = 'Fast', # Valor por defecto si no se especifica

        [Parameter(Mandatory=$true)]
        [bool]$IsEncrypted,

        # Acepta un string de contraseña (para tareas automaticas) o SecureString (para manual)
        [Parameter(Mandatory=$false, ParameterSetName = 'SecureStringPassword')]
        [System.Security.SecureString]$SecurePassword,

        [Parameter(Mandatory=$false, ParameterSetName = 'CredentialPassword')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false, ParameterSetName = 'StringPassword')]
        [string]$PlainTextPassword,

        [Parameter(Mandatory=$false)]
        [string]$LogContext = "ENGINE" # Para identificar en el log de donde vino la llamada
    )

	$Password = $null
    switch ($PsCmdlet.ParameterSetName) {
        'SecureStringPassword' { $Password = $SecurePassword }
        'CredentialPassword'   { $Password = $Credential }
        'StringPassword'       { $Password = $PlainTextPassword }
    }

    Write-Log -LogLevel INFO -Message "[$LogContext] Iniciando motor de respaldo 7-Zip."
    
    # --- 1. Verificar si 7-Zip esta disponible ---
    if (-not (Ensure-7ZipIsInstalled)) {
        Write-Log -LogLevel ERROR -Message "[$LogContext] 7-Zip no esta instalado o no se pudo instalar. Abortando."
        return $false
    }

    # --- 2. Cargar Manifiesto de Respaldo ---
    $manifest = Get-BackupManifest -DestinationPath $DestinationPath
    $lastFullBackup = $manifest.Backups | Where-Object { $_.Type -eq 'Full' -and $_.Source -eq $SourcePath } | Sort-Object Timestamp -Descending | Select-Object -First 1
    $lastAnyBackup = $manifest.Backups | Where-Object { $_.Source -eq $SourcePath } | Sort-Object Timestamp -Descending | Select-Object -First 1

    # --- 3. Logica de Tipos de Respaldo y Fechas ---
    $referenceDate = [datetime]::MinValue
    $archiveNameSuffix = "_FULL"
    $currentBackupType = $BackupType

    if ($currentBackupType -eq 'Incremental' -or $currentBackupType -eq 'Differential') {
        if (-not $lastFullBackup) {
            Write-Log -LogLevel WARN -Message "[$LogContext] Se solicito respaldo '$currentBackupType' pero no hay 'Full'. Forzando a 'Full'."
            $currentBackupType = 'Full'
        } else {
            if ($currentBackupType -eq 'Incremental') {
                $referenceDate = [datetime]::Parse($lastAnyBackup.Timestamp)
                $archiveNameSuffix = "_INC"
            } else { # Differential
                $referenceDate = [datetime]::Parse($lastFullBackup.Timestamp)
                $archiveNameSuffix = "_DIFF"
            }
        }
    }
	
    # --- 4. Encontrar archivos a respaldar (LÓGICA PROFESIONAL: BIT DE ARCHIVO) ---
    Write-Log -LogLevel INFO -Message "[$LogContext] Escaneando directorio en busca de cambios (usando atributos de archivo)..."
    
    # Obtenemos todos los archivos
    $allFiles = Get-ChildItem -Path $SourcePath -Recurse -File
    
    # FILTRO ROBUSTO:
    # Seleccionamos el archivo SI:
    # 1. Su fecha de modificación es posterior a la referencia (criterio clásico).
    #    - O -
    # 2. Tiene el atributo 'Archive' encendido (indicando que es nuevo, copiado o modificado).
    $filesToBackup = $allFiles | Where-Object { 
        ($_.LastWriteTime -gt $referenceDate) -or 
        ($_.Attributes -band [System.IO.FileAttributes]::Archive)
    }
    
    if ($filesToBackup.Count -eq 0) {
        Write-Log -LogLevel INFO -Message "[$LogContext] No se encontraron archivos con cambios pendientes (Atributo 'Archive' o fecha reciente). Respaldo omitido."
        return $true
    }
    Write-Log -LogLevel INFO -Message "[$LogContext] Se respaldaran $($filesToBackup.Count) archivos detectados como nuevos o modificados."

    # --- 5. Preparar argumentos de Cifrado ---
    $switch_Password = $null
    $switch_HeaderEncrypt = $null
    $passwordPlainText = $null # Solo para 7z, se limpia al final

    if ($IsEncrypted) {
        if (-not $Password) {
            Write-Log -LogLevel ERROR -Message "[$LogContext] Se solicito cifrado pero no se proporciono contrasena. Abortando."
            return $false
        }
        
        $switch_HeaderEncrypt = "-mhe=on"
        
        # Convertir la contraseña a texto plano para 7z.exe
        if ($Password -is [System.Security.SecureString]) {
            $passwordPlainText = ($Password | ConvertFrom-SecureString)
        } elseif ($Password -is [System.Management.Automation.PSCredential]) {
            $passwordPlainText = $Password.GetNetworkCredential().Password
        } else {
            $passwordPlainText = $Password.ToString()
        }
        
        $switch_Password = "-p$($passwordPlainText)"
    }
    
    # --- 6. Preparar lista de archivos para 7-Zip ---
    $tempListFile = Join-Path $env:TEMP "backup_list_$(New-Guid).txt"
    $filesToBackup | ForEach-Object { $_.FullName.Substring($SourcePath.Length + 1) } | Set-Content -Path $tempListFile -Encoding utf8

    # --- 7. Construir y Ejecutar Comando 7-Zip ---
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $archiveName = "Backup_$(Split-Path $SourcePath -Leaf)_$timestamp$archiveNameSuffix.7z"
    $archivePath = Join-Path $DestinationPath $archiveName
    
    # Determinamos el switch de 7-Zip según la elección
    # -mx=5 es Rápido (Normal), -mx=9 es Ultra (Máximo)
    $switch_Compression = if ($CompressionLevel -eq 'Max') { "-mx=9" } else { "-mx=5" }

    Write-Log -LogLevel INFO -Message "[$LogContext] Configurando 7-Zip con nivel de compresion: $CompressionLevel ($switch_Compression)."

    $7zArgs = @(
        "a"                     # Añadir a un archivo
        "`"$archivePath`""      # Archivo de salida
        "@`"$tempListFile`""    # Archivo de lista
        "-t7z"                  # Formato 7z
        $switch_Compression     # <--- MODIFICADO: Usamos la variable aquí
    )

    if ($PSCmdlet.ShouldProcess($archivePath, "Crear Respaldo ($currentBackupType)")) {
        Write-Log -LogLevel ACTION -Message "[$LogContext] Ejecutando 7z.exe $archivePath"
        
        Push-Location $SourcePath
        $process = Start-Process "7z.exe" -ArgumentList $7zArgs -Wait -NoNewWindow -PassThru
        Pop-Location

        # --- 8. Verificacion y Reporte ---
        if ($process.ExitCode -eq 0) {
            Write-Log -LogLevel ACTION -Message "[$LogContext] Exito al crear '$archiveName'."
			
			# --- NUEVO: Limpieza del Bit de Archivo (Archive Attribute) ---
            # Como el respaldo fue exitoso, "apagamos" la bandera 'Archive' en los archivos de origen
            # para indicar que ya están respaldados y no incluirlos en el próximo incremental/diferencial.
            Write-Log -LogLevel INFO -Message "[$LogContext] Limpiando atributo 'Archive' en los $($filesToBackup.Count) archivos de origen..."
            foreach ($file in $filesToBackup) {
                try {
                    # Obtenemos el objeto archivo
                    $fileItem = Get-Item -LiteralPath $file.FullName -ErrorAction Stop
                    # Si tiene el atributo Archive encendido...
                    if ($fileItem.Attributes -band [System.IO.FileAttributes]::Archive) {
                        # ...lo apagamos usando una operación bitwise AND NOT
                        $fileItem.Attributes = ($fileItem.Attributes -band (-not [System.IO.FileAttributes]::Archive))
                    }
                } catch {
                    # Si falla (ej. archivo en uso o solo lectura), solo registramos una advertencia y seguimos.
                    # El archivo se volverá a incluir en el próximo respaldo, lo cual es seguro.
                     Write-Log -LogLevel WARN -Message "[$LogContext] No se pudo limpiar el atributo 'Archive' en: $($file.FullName). Se reintentará en el próximo respaldo."
                }
            }
            Write-Log -LogLevel INFO -Message "[$LogContext] Limpieza de atributos completada."

            # --- 9. Actualizar Manifiesto (Metadatos) ---
            $newBackupEntry = [PSCustomObject]@{
                File = $archiveName
                Type = $currentBackupType
                Timestamp = (Get-Date).ToString("o")
                Source = $SourcePath
                FileCount = $filesToBackup.Count
                IsEncrypted = $IsEncrypted
                Parent = if ($currentBackupType -eq 'Full') { $null } elseif ($currentBackupType -eq 'Incremental') { $lastAnyBackup.File } else { $lastFullBackup.File }
            }
            $manifest.Backups.Add($newBackupEntry)
            Update-BackupManifest -DestinationPath $DestinationPath -Manifest $manifest
        
        } else {
            Write-Log -LogLevel ERROR -Message "[$LogContext] FALLO: 7-Zip finalizo con codigo ($($process.ExitCode))."
            # Limpieza de archivo fallido
            Remove-Item $archivePath -ErrorAction SilentlyContinue
            return $false
        }
    }
    
    # Limpieza final
    $passwordPlainText = $null
    $switch_Password = $null
    [GC]::Collect()
    Remove-Item $tempListFile -ErrorAction SilentlyContinue
    
    return $true # Exito
}

# --- FUNCION 3: Configurar Respaldo Automatico ---
function Configure-AutoBackupSchedule {
    param()
    
    Write-Host "`n[+] Configurar Respaldo Automatico Programado" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------"
    
    # --- 1. Origen, Destino ---
    Write-Host "`n[1/5] Selecciona la CARPETA de Origen." -ForegroundColor Yellow
    $sourcePath = Select-PathDialog -DialogType 'Folder' -Title "Selecciona la CARPETA de Origen"
    if ([string]::IsNullOrWhiteSpace($sourcePath)) { return }
    
    Write-Host "`n[2/5] Selecciona la CARPETA de Destino." -ForegroundColor Yellow
    $destinationPath = Select-PathDialog -DialogType 'Folder' -Title "Selecciona la CARPETA de Destino"
    if ([string]::IsNullOrWhiteSpace($destinationPath)) { return }
    
    # --- 2. Frecuencia ---
    Write-Host "`n[3/5] Configura la frecuencia:" -ForegroundColor Yellow
    Write-Host "   [1] Diario  [2] Semanal"
    $frequencyChoice = Read-Host "Elige (1-2)"
    
    $schedule = @{ Frequency = 'Daily'; Time = '24:00'; DayOfWeek = $null }
    if ($frequencyChoice -eq '2') {
        $schedule.Frequency = 'Weekly'
        $dayChoice = Read-Host "Dia (1=Lunes ... 7=Domingo)"
        $schedule.DayOfWeek = switch($dayChoice) {
            '1' { 'Monday' } '2' { 'Tuesday' } '3' { 'Wednesday' } '4' { 'Thursday' }
            '5' { 'Friday' } '6' { 'Saturday' } '7' { 'Sunday' } default { 'Sunday' }
        }
    }
    
    $validTime = $false
    while (-not $validTime) {
        $timeInput = Read-Host "Hora (HH:mm)"
        if ($timeInput -match '^(?:[01]\d|2[0-3]):[0-5]\d$') { $schedule.Time = $timeInput; $validTime = $true }
    }

    # --- 3. Tipo y Cifrado ---
    Write-Host "`n[4/5] Tipo de respaldo:" -ForegroundColor Yellow
    Write-Host "   [1] Incremental  [2] Diferencial  [3] Completo"
    $backupTypeChoice = Read-Host "Elige (1-3)"
    $Type = switch($backupTypeChoice) { '1' { 'Incremental' } '2' { 'Differential' } '3' { 'Full' } default { 'Incremental' } }
	
	# --- Selección de Compresión para la Tarea ---
    Write-Host "`n[4.5/5] Nivel de compresion para la tarea:" -ForegroundColor Yellow
    Write-Host "   [1] Rapido (Nivel 5) - Recomendado para la mayoria de los casos."
    Write-Host "   [2] Maximo (Nivel 9) - Ideal para tareas nocturnas (mas lento, menos espacio)."
    $compChoiceTask = Read-Host "Elige (1-2) [Por defecto: 1]"
    $compressionLevelTask = if ($compChoiceTask -eq '2') { 'Max' } else { 'Fast' }

    Write-Host "`n[5/5] ¿Cifrar respaldo?" -ForegroundColor Yellow
    $encryptChoice = Read-Host "(S/N)"
    $isEncrypted = $false
    $password = ""
    
    # --- SEGURIDAD: Generacion de credencial cifrada ---
    $taskName = "Backup_$(Split-Path $sourcePath -Leaf | ForEach-Object { $_ -replace '[^a-zA-Z0-9]', '' })"
    $parentDir = Split-Path -Parent $PSScriptRoot
    $scriptsDir = Join-Path -Path $parentDir -ChildPath "BackupScripts"
    if (-not (Test-Path $scriptsDir)) { New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null }
    
    if ($encryptChoice.ToUpper() -eq 'S') {
        $isEncrypted = $true
        Write-Warning "Se generara una contrasena y se guardara CIFRADA (DPAPI) en disco."
        Write-Warning "Solo ESTE usuario en ESTA PC podra ejecutar el respaldo."
        $password = Generate-SecurePassword
        
        # Guardar credencial cifrada (ASCII)
        $secureString = ConvertTo-SecureString $password -AsPlainText -Force
        $encryptedContent = $secureString | ConvertFrom-SecureString
        $credFilePath = Join-Path $scriptsDir "$taskName.cred"
        Set-Content -Path $credFilePath -Value $encryptedContent -Encoding Ascii
        
        Write-Host "Contrasena generada: $password" -ForegroundColor Magenta
        Write-Host "Archivo de credencial segura creado en: $credFilePath" -ForegroundColor Gray
        Read-Host "Anota la contrasena y presiona Enter..."
    }

    # --- 4. Generar script ---
    $backupScriptPath = Join-Path -Path $scriptsDir -ChildPath "$taskName.ps1"
    $mainScriptFullPath = $PSScriptRoot
    $isEncryptedBoolStr = if ($isEncrypted) { '$true' } else { '$false' }
    
    # Variable auxiliar para insertar el caracter '$' de forma segura sin usar acentos graves.
    $d = "$"

    # --- INICIO DE LA PLANTILLA DEL SCRIPT GENERADO (VERSIÓN SEGURA FINAL CORREGIDA) ---
    $scriptContent = @"
${d}ErrorActionPreference = 'Stop'

# --- CONFIGURACION DE LOGS ---
${d}logDir = Join-Path ${d}env:ProgramData 'ProfileGuard_Logs'
# Usamos un nombre de variable único para el archivo de log de esta tarea
${d}taskLogFile = Join-Path ${d}logDir 'Backup_Auto_Log.txt'
try { if (-not (Test-Path ${d}logDir)) { New-Item -Path ${d}logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null } } catch { exit 1 }
# La función usa la variable única y fuerza UTF8
function Write-TaskLog { param([string]${d}Message) "${d}(Get-Date) - ${d}Message" | Out-File -FilePath ${d}taskLogFile -Append -Encoding utf8 }

Write-TaskLog "--- Iniciando Tarea '$($taskName.Replace("'", "''"))' ---"

# --- DEFINICION DE VARIABLES ---
# Nota: Usamos Replace("'", "''") para escapar comillas simples en rutas si las hubiera.
${d}mainScriptToImport = '$($mainScriptFullPath.Replace("'", "''"))\ProfileGuard.ps1'
${d}taskSourcePath = '$($sourcePath.Replace("'", "''"))'
${d}taskDestinationPath = '$($destinationPath.Replace("'", "''"))'
${d}taskBackupType = '$Type'
${d}taskIsEncrypted = $isEncryptedBoolStr
${d}taskCompressionLevel = '$compressionLevelTask'

# --- SEGURIDAD DPAPI ---
# Inicializamos variables criticas en null
${d}passwordArg = ${d}null
${d}ptr = ${d}null

try {
    if (${d}taskIsEncrypted) {
        Write-TaskLog "Descifrando credencial..."
        # Usamos PSScriptRoot para que el script busque el .cred en su misma carpeta
        ${d}credFile = Join-Path "${d}PSScriptRoot" '$($taskName.Replace("'", "''")).cred'
        
        if (-not (Test-Path ${d}credFile)) { 
            throw "Archivo de credencial no encontrado. Se esperaba en: ${d}credFile. Asegurate de que el archivo .cred no haya sido movido o borrado." 
        }
        
        # Leemos el contenido cifrado y eliminamos espacios en blanco
        ${d}encryptedData = (Get-Content ${d}credFile -Raw).Trim()
        
        # 1. Convertimos el texto cifrado a SecureString usando DPAPI (contexto del usuario actual)
        ${d}secureString = ${d}encryptedData | ConvertTo-SecureString -ErrorAction Stop
        
        # 2. Creamos un BSTR (Binary String) en memoria NO administrada para poder leerla.
        # ¡ESTO ES LO QUE DEBE LIMPIARSE CORRECTAMENTE DESPUÉS!
        ${d}ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(${d}secureString)
        
        # 3. Copiamos el BSTR a una cadena de .NET normal (Managed String) para pasarla al motor.
        ${d}passwordArg = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(${d}ptr)
    }

    Write-TaskLog "Importando motor principal y ejecutando respaldo..."

    if (-not (Test-Path ${d}mainScriptToImport)) { throw "Script principal no encontrado en: ${d}mainScriptToImport" }
    # Importamos el script principal para tener acceso a la funcion del motor
    . "${d}mainScriptToImport"

    # Ejecutamos el motor con los parámetros preparados.
    # Importante: Pasamos la contraseña en texto plano (${d}passwordArg) porque el motor lo requiere asi para 7-Zip.
    ${d}success = Invoke-ProfileGuardBackupEngine -SourcePath ${d}taskSourcePath -DestinationPath ${d}taskDestinationPath -BackupType ${d}taskBackupType -CompressionLevel ${d}taskCompressionLevel -IsEncrypted ${d}taskIsEncrypted -PlainTextPassword ${d}passwordArg -LogContext 'AUTO:$($taskName.Replace("'", "''"))'

    if (${d}success) { Write-TaskLog "EXITO. El respaldo finalizo correctamente." } else { Write-TaskLog "FALLO. El motor reporto un error." }

} catch {
    # Captura global de errores en el script de la tarea
    ${d}errMsg = "ERROR CRITICO durante la ejecución de la tarea: ${d}(${d}_.Exception.Message)"
    Write-TaskLog ${d}errMsg
    # Escribimos en host por si alguien esta mirando la consola (aunque suele estar oculta)
    Write-Host ${d}errMsg -ForegroundColor Red
    exit 1 # Salimos con error
} finally {
    # --- LIMPIEZA Y CIERRE ROBUSTO (VERSIÓN SEGURA) ---
    
    # 1. Liberación CRITICA de memoria no administrada (el puntero BSTR)
    # Verificamos si el puntero existe y no es cero antes de intentar liberarlo
    # CORRECCIÓN AQUÍ: Se cambio $null por ${d}null para que se escriba literalmente en el script generado.
    if (${d}null -ne ${d}ptr -and [System.IntPtr]::Zero -ne ${d}ptr) { # <--- CORRECCIÓN CRITICA AQUI
        try {
            # ZeroFreeBSTR borra el contenido de la memoria (lo llena de ceros)
            # y luego libera la memoria no administrada para el SO.
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR(${d}ptr)
        } catch {
            # Ignoramos errores aqui para no romper el flujo de cierre.
        }
    }
    # Ahora si, es seguro anular la variable del puntero
    ${d}ptr = ${d}null

    # 2. Limpieza de variables administradas (la copia en texto plano)
    ${d}passwordArg = ${d}null
    
    # 3. Forzar la recoleccion de basura inmediata
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()

    # 4. Logging final protegido
    try {
        Write-TaskLog "--- Fin ---`n"
    } catch {
    }
}
"@
    # --- FIN DE LA PLANTILLA ---

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($backupScriptPath, $scriptContent, $utf8NoBom)    
    
	# --- 5. Crear la Tarea Programada ---
    try {
        Write-Host "`n[+] Creando tarea programada..." -ForegroundColor Yellow
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$backupScriptPath`""
        
        $trigger = $null
        if ($schedule.Frequency -eq 'Daily') { $trigger = New-ScheduledTaskTrigger -Daily -At $schedule.Time }
        else { $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $schedule.DayOfWeek -At $schedule.Time }

        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        
        Write-Host "`n[OK] Tarea creada." -ForegroundColor Green
		Write-Log -LogLevel ACTION -Message "AUTO-BACKUP: Nueva tarea programada creada: '$taskName'. Frecuencia: $($schedule.Frequency) a las $($schedule.Time). Tipo: $Type. Cifrado: $isEncrypted."
        if ($isEncrypted) { Write-Warning "Archivo .cred generado. NO LO BORRES o la tarea fallara." }
        
    } catch {
        Write-Error "Error al crear tarea: $($_.Exception.Message)"
    }
    
    $password = $null
    [GC]::Collect()
    Read-Host "`nPresiona Enter..."
}

# ===================================================================
# --- NUEVAS FUNCIONES PARA EDICION DE TAREAS ---
# ===================================================================

# --- FUNCION AUXILIAR: Traducir mascara de bits de dias a texto español ---
function Get-ReadableDays {
    param([int]$DaysBitmask)
    $days = @()
    # Estos son los valores de bit estándar del Programador de Tareas
    if ($DaysBitmask -band 1)  { $days += 'Domingo' }
    if ($DaysBitmask -band 2)  { $days += 'Lunes' }
    if ($DaysBitmask -band 4)  { $days += 'Martes' }
    if ($DaysBitmask -band 8)  { $days += 'Miércoles' }
    if ($DaysBitmask -band 16) { $days += 'Jueves' }
    if ($DaysBitmask -band 32) { $days += 'Viernes' }
    if ($DaysBitmask -band 64) { $days += 'Sabado' }
    
    if ($days.Count -eq 0) { return "Desconocido ($DaysBitmask)" }
    return ($days -join ', ')
}

# --- FUNCION AUXILIAR: Seleccionar una Tarea Existente ---
function Select-ProfileGuardTask {
    Write-Host "`nBuscando tareas programadas de ProfileGuard..." -ForegroundColor Gray
    $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    # Filtramos solo las tareas creadas por este script (prefijo Backup_)
    $scheduledBackups = @($allTasks | Where-Object { $_.TaskName -like "Backup_*" } | Sort-Object TaskName)

    if ($scheduledBackups.Count -eq 0) {
        Write-Warning "No se encontraron tareas programadas activas de ProfileGuard."
        return $null
    }

    Write-Host "Tareas encontradas:" -ForegroundColor Cyan
	Write-Host ""
    for ($i = 0; $i -lt $scheduledBackups.Count; $i++) {
        $task = $scheduledBackups[$i]
        try {
            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction Stop
            $nextRun = if ($info.NextRunTime) { $info.NextRunTime.ToString("yyyy-MM-dd HH:mm") } else { "Deshabilitada/No programada" }
        } catch {
             $nextRun = "Error al leer info"
        }

        Write-Host ("   [{0}] {1,-30} | Estado: {2,-10} | Prox. Ejecucion: {3}" -f ($i + 1), $task.TaskName, $task.State, $nextRun)
    }
    Write-Host ""
    Write-Host "   [V] Volver al menu anterior" -ForegroundColor Red

    $selection = Read-Host "`nSelecciona el numero de la tarea a editar"
    
    if ($selection.ToUpper() -eq 'V') { return $null }

    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $scheduledBackups.Count) {
        return $scheduledBackups[[int]$selection - 1]
    } else {
        Write-Warning "Seleccion invalida."
        Start-Sleep -Seconds 1
        return $null
    }
}

# --- FUNCION PRINCIPAL: Editar Tarea Programada (CORREGIDA) ---
function Edit-ScheduledTask {
    param()
    Clear-Host
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "       Editar/Eliminar Tarea Programada" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    # 1. Seleccionar la tarea
    $targetTask = Select-ProfileGuardTask
    if ($null -eq $targetTask) { return }

    $taskName = $targetTask.TaskName

    # --- LEER CONFIGURACION ACTUAL ---
    Write-Host "`nLeyendo configuracion actual de '$taskName'..." -ForegroundColor Gray

    # A) Leer del Programador de Tareas (Trigger)
    $currentTrigger = $targetTask.Triggers[0]
    $scheduleSummary = "Desconocido"
    
    try {
        $timeStr = "Desconocida"
        if ($currentTrigger.StartBoundary) {
             $timeStr = $currentTrigger.StartBoundary.split('T')[1].Substring(0,5)
        }

        if ($currentTrigger.Repetition.Interval) {
             $scheduleSummary = "Frecuencia compleja (no editable aqui)"
        } elseif ($null -ne $currentTrigger.DaysOfWeek) {
             # Usamos la funcion auxiliar para traducir los dias
             $daysReadable = Get-ReadableDays -DaysBitmask ([int]$currentTrigger.DaysOfWeek)
             $scheduleSummary = "Semanal ($daysReadable) a las $timeStr"
        } else {
             $scheduleSummary = "Diario a las $timeStr"
        }
    } catch {
        $scheduleSummary = "Error al leer el horario: $($_.Exception.Message)"
    }

    # B) Leer del script generado (.ps1) - LECTURA MEJORADA CON UTF8
    $actionArgs = $targetTask.Actions[0].Arguments
    $generatedScriptPath = $null
    $currentBackupType = "Desconocido (No se pudo leer script)"
    $currentIsEncrypted = "Desconocido"
    # NUEVO: Variable para la compresión actual
    $currentCompressionLevel = "Desconocido" 
    $scriptContentLines = $null

    # 1. Encontrar la ruta del script
    if ($actionArgs -match '-File\s+"([^"]+)"') {
        $generatedScriptPath = $matches[1]
        if (Test-Path $generatedScriptPath) {
            # 2. Leer el script linea por linea FORZANDO UTF8
            $scriptContentLines = Get-Content $generatedScriptPath -Encoding UTF8
            
            # 3. Buscar las variables linea por linea
            foreach ($line in $scriptContentLines) {
            # Eliminamos espacios al principio y al final para asegurar la comparacion
            $trimmedLine = $line.Trim()
    
           # --- Deteccion del TIPO de respaldo ---
           # Busca la linea exacta: $taskBackupType = 'Algo'
           if ($trimmedLine.StartsWith("`$taskBackupType = '") -and $trimmedLine.EndsWith("'")) {
               # Reemplaza el inicio y el fin para quedarse solo con el valor entre comillas
               $currentBackupType = $trimmedLine.Replace("`$taskBackupType = '", "").Replace("'", "")
            }

            # --- NUEVO: Deteccion del NIVEL DE COMPRESION ---
            # Busca la linea exacta: $taskCompressionLevel = 'Algo'
            if ($trimmedLine.StartsWith("`$taskCompressionLevel = '") -and $trimmedLine.EndsWith("'")) {
               # Reemplaza el inicio y el fin para quedarse solo con el valor entre comillas
               $currentCompressionLevel = $trimmedLine.Replace("`$taskCompressionLevel = '", "").Replace("'", "")
            }
    
            # --- Deteccion del ESTADO DE CIFRADO (Version Definitiva) ---
            # Verifica si la linea comienza con la variable que buscamos
            if ($trimmedLine.StartsWith("`$taskIsEncrypted =")) {
        
                # Formato literal $true o $false (Generador actual)
                # Usamos una comparacion directa y simple que no distingue mayusculas/minusculas
                if ($trimmedLine -like "*`$true*") {
                    $currentIsEncrypted = "Si"
                }
                elseif ($trimmedLine -like "*`$false*") {
                    $currentIsEncrypted = "No"
                }
            }
        }
        } else {
            Write-Error "CRITICO: El script asociado a la tarea no existe: $generatedScriptPath"
            Write-Warning "Se recomienda ELIMINAR esta tarea rota."
        }
    }

    # --- MENU DE EDICION ---
    Clear-Host
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "       Editando Tarea: $taskName" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configuracion Actual:" -ForegroundColor Yellow
    Write-Host " - Horario:    $scheduleSummary"
    Write-Host " - Tipo:       $currentBackupType"
    Write-Host " - Compresion: $currentCompressionLevel" 
    Write-Host " - Cifrado:    $currentIsEncrypted (No editable)"
    Write-Host ""
    Write-Host "--- Acciones ---" -ForegroundColor Yellow
    Write-Host "   [1] Cambiar Horario / Frecuencia (Trigger)"
    Write-Host "   [2] Cambiar Tipo de Respaldo (Full/Inc/Diff)"
    Write-Host "   [3] Cambiar Nivel de Compresion"
    Write-Host ""
    Write-Host "   [D] ELIMINAR Tarea Completamente (Tarea + Scripts)" -ForegroundColor Red
    Write-Host "   [V] Volver" -ForegroundColor Gray
    Write-Host ""

    $editChoice = Read-Host "Selecciona una opcion"

    switch ($editChoice.ToUpper()) {
        '1' { # --- CAMBIAR HORARIO (TRIGGER) ---
            Write-Host "`n--- Nuevo Horario ---" -ForegroundColor Yellow
            Write-Host "   [1] Diario  [2] Semanal"
            $freqChoice = Read-Host "Elige (1-2)"
            
            $newTrigger = $null
            $timeInput = ""
            $validTime = $false
             while (-not $validTime) {
                $timeInput = Read-Host "Nueva Hora (HH:mm)"
                if ($timeInput -match '^(?:[01]\d|2[0-3]):[0-5]\d$') { $validTime = $true }
            }

            if ($freqChoice -eq '1') {
                $newTrigger = New-ScheduledTaskTrigger -Daily -At $timeInput
            } else {
                $dayChoice = Read-Host "Dia (1=Lunes ... 7=Domingo)"
                $dayOfWeek = switch($dayChoice) { '1' { 'Monday' } '2' { 'Tuesday' } '3' { 'Wednesday' } '4' { 'Thursday' } '5' { 'Friday' } '6' { 'Saturday' } '7' { 'Sunday' } default { 'Sunday' } }
                $newTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $dayOfWeek -At $timeInput
            }

            try {
                # Se requieren privilegios elevados para Set-ScheduledTask
                Set-ScheduledTask -TaskName $taskName -Trigger $newTrigger -ErrorAction Stop | Out-Null
                Write-Host "`n[EXITO] Horario de la tarea actualizado." -ForegroundColor Green
				Write-Log -LogLevel ACTION -Message "EDIT-TASK: Se actualizó el horario de la tarea '$taskName'."
            } catch {
                Write-Error "Fallo al actualizar el horario de la tarea. Asegurate de correr como Administrador."
                Write-Error $_.Exception.Message
            }
        }
        '2' { # --- CAMBIAR TIPO DE RESPALDO (CORREGIDO NOMBRE DE VARIABLE) ---
            if ($null -eq $scriptContentLines) { Write-Warning "No se puede editar el tipo porque no se pudo leer el script generado."; return }

            Write-Host "`n--- Nuevo Tipo de Respaldo ---" -ForegroundColor Yellow
            Write-Host "Actual: $currentBackupType"
            Write-Host "   [1] Incremental  [2] Diferencial  [3] Completo"
            $typeChoice = Read-Host "Elige (1-3)"
            $newType = switch($typeChoice) { '1' { 'Incremental' } '2' { 'Differential' } '3' { 'Full' } default { $null } }

            if ($newType -and $newType -ne $currentBackupType) {
                try {
                    # Usamos el mismo metodo de lectura para encontrar la linea y reemplazarla
                    $newScriptLines = @()
                    foreach ($line in $scriptContentLines) {
                        # Buscamos la variable correcta con el prefijo '$task'
                        # CORREGIDO AQUI:
                        if ($line.Trim().StartsWith("`$taskBackupType = '")) { # <--- CORREGIDO NOMBRE VARIABLE
                            # Reemplazamos la linea completa con el nuevo valor usando el nombre correcto
                            # CORREGIDO AQUI TAMBIEN:
                            $newScriptLines += "`$taskBackupType = '$newType'" # <--- CORREGIDO NOMBRE VARIABLE
                        } else {
                            $newScriptLines += $line
                        }
                    }
                    
                    # Guardamos usando .NET para asegurar UTF-8 sin BOM
                    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
                    [System.IO.File]::WriteAllLines($generatedScriptPath, $newScriptLines, $utf8NoBom)

                    Write-Host "`n[EXITO] Tipo de respaldo actualizado a '$newType' en el script generador." -ForegroundColor Green
					Write-Log -LogLevel ACTION -Message "EDIT-TASK: Se cambió el tipo de respaldo de la tarea '$taskName' a '$newType'."
                    # Actualizamos la variable en memoria para que el menu lo refleje si volvieramos a el
                    $currentBackupType = $newType
                } catch {
                     Write-Error "Fallo al actualizar el archivo script: $generatedScriptPath"
                     Write-Error $_.Exception.Message
                }
            } else {
                Write-Warning "Operacion cancelada o tipo no valido seleccionado."
            }
        }
        # --- NUEVO BLOQUE: CAMBIAR NIVEL DE COMPRESIÓN ---
        '3' { 
            if ($null -eq $scriptContentLines) { Write-Warning "No se puede editar la compresion porque no se pudo leer el script generado."; return }

            Write-Host "`n--- Nivel de Compresion ---" -ForegroundColor Yellow
            Write-Host "Actual: $currentCompressionLevel"
            Write-Host "   [1] Rapido (Nivel 5)"
            Write-Host "   [2] Maximo (Nivel 9)"
            $compChoice = Read-Host "Elige (1-2)"
            $newCompression = switch($compChoice) { '1' { 'Fast' } '2' { 'Max' } default { $null } }

            if ($newCompression -and $newCompression -ne $currentCompressionLevel) {
                try {
                    $newScriptLines = @()
                    foreach ($line in $scriptContentLines) {
                        # Buscamos la variable correcta con el prefijo '$task'
                        if ($line.Trim().StartsWith("`$taskCompressionLevel = '")) {
                            # Reemplazamos la linea completa con el nuevo valor
                            $newScriptLines += "`$taskCompressionLevel = '$newCompression'"
                        } else {
                            $newScriptLines += $line
                        }
                    }
                    
                    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
                    [System.IO.File]::WriteAllLines($generatedScriptPath, $newScriptLines, $utf8NoBom)

                    Write-Host "`n[EXITO] Nivel de compresion actualizado a '$newCompression' en el script generador." -ForegroundColor Green
					Write-Log -LogLevel ACTION -Message "EDIT-TASK: Se cambio el nivel de compresion de la tarea '$taskName' a '$newCompression'."
                    $currentCompressionLevel = $newCompression
                } catch {
                     Write-Error "Fallo al actualizar el archivo script: $generatedScriptPath"
                     Write-Error $_.Exception.Message
                }
            } else {
                Write-Warning "Operacion cancelada o nivel no valido seleccionado."
            }
        }
        # -------------------------------------------------
        'D' { # --- ELIMINAR TAREA ---
            Write-Warning "`n¡ADVERTENCIA DE ELIMINACION!"
            Write-Host "Se eliminara la tarea de Windows '$taskName'."
            if ($generatedScriptPath) {
                 Write-Host "Tambien se eliminaran los archivos asociados en 'BackupScripts':"
                 Write-Host " - $generatedScriptPath"
                 $credPath = $generatedScriptPath -replace '\.ps1$', '.cred'
                 if (Test-Path $credPath) { Write-Host " - $credPath (Archivo de credencial)" }
            }
            
            $confirm = Read-Host "`nEscribe 'ELIMINAR' para confirmar"
            if ($confirm -eq 'ELIMINAR') {
                try {
                    # 1. Eliminar del Programador de Tareas
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                    Write-Host "Tarea de Windows eliminada." -ForegroundColor Gray

                    # 2. Eliminar archivos de script y credencial asociados
                    if ($generatedScriptPath -and (Test-Path $generatedScriptPath)) {
                        Remove-Item $generatedScriptPath -Force
                        Write-Host "Script .ps1 eliminado." -ForegroundColor Gray
                        
                        $credPath = $generatedScriptPath -replace '\.ps1$', '.cred'
                        if (Test-Path $credPath) {
                            Remove-Item $credPath -Force
                            Write-Host "Archivo .cred eliminado." -ForegroundColor Gray
                        }
                    }
                    Write-Host "`n[EXITO] Tarea y archivos asociados eliminados correctamente." -ForegroundColor Green
					Write-Log -LogLevel ACTION -Message "EDIT-TASK: Se eliminó completamente la tarea programada '$taskName' y sus archivos asociados."
                } catch {
                    Write-Error "Error durante la eliminacion: $($_.Exception.Message)"
                }
            } else {
                Write-Host "Eliminacion cancelada." -ForegroundColor Yellow
            }
        }
    }
    Read-Host "`nPresiona Enter para continuar..."
}

# --- FUNCION 4: Administrar Respaldos (CORREGIDA) ---
function Manage-ExistingBackups {
    param()
    
    Write-Host "`n[+] Administrar Respaldos Existentes" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------"
    
    # --- 1. Seleccionar la carpeta de destino ---
    Write-Host "`n[+] Por favor, selecciona la CARPETA de Destino que contiene el manifiesto ('manifest.json')." -ForegroundColor Yellow
    $destinationPath = Select-PathDialog -DialogType 'Folder' -Title "Selecciona la Carpeta de Destino de tus Respaldos"
    if ([string]::IsNullOrWhiteSpace($destinationPath)) {
        Write-Warning "No se selecciono una carpeta. Operacion cancelada." ; Start-Sleep -Seconds 2; return
    }
    
    # --- 2. Cargar Manifiesto ---
    $manifest = Get-BackupManifest -DestinationPath $destinationPath
    if ($manifest.Backups.Count -eq 0) {
        Write-Host "`n[INFO] No se encontraron respaldos registrados en el manifiesto de esta ubicacion." -ForegroundColor Yellow
        Read-Host "`nPresiona Enter para continuar..."
        return
    }
    
    # --- Variable para almacenar la credencial cargada en memoria ---
    $loadedCredential = $null

    # --- Carga inicial de la lista ---
    $allBackups = @($manifest.Backups | ForEach-Object {
        $_ | Add-Member -MemberType NoteProperty -Name 'Selected' -Value $false -Force
        $status = "Available"; if (-not (Test-Path (Join-Path $destinationPath $_.File))) { $status = "Missing" }
        $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value $status -Force
        $_ 
    } | Sort-Object Timestamp -Descending)

    # --- 3. Bucle de Gestion ---
    $choice = ""
    while ($choice.ToUpper() -ne "V") {
        Clear-Host
        Write-Host "=======================================================" -ForegroundColor Cyan
        Write-Host "         Administrar Respaldos en: $destinationPath    " -ForegroundColor Cyan
        Write-Host "=======================================================" -ForegroundColor Cyan
        
        # --- Indicador de estado de credencial ---
        if ($null -ne $loadedCredential) {
            Write-Host "`n[ESTADO] Credencial DPAPI cargada en memoria." -ForegroundColor Green
        } else {
            Write-Host "`n[ESTADO] Ninguna credencial cargada. Se solicitara contrasena si es necesario." -ForegroundColor Gray
        }

        Write-Host "`nLista de respaldos registrados:" -ForegroundColor Yellow
        Write-Host ""

        for ($i = 0; $i -lt $allBackups.Count; $i++) {
            $backup = $allBackups[$i]
            $statusMarker = if ($backup.Selected) { "[X]" } else { "[ ]" }
            $statusColor = if ($backup.Status -eq "Available") { "Green" } else { "Red" }
            $encryptMarker = if ($backup.IsEncrypted) { "[CIFRADO]" } else { "[Simple]" }
            $dateStr = "Fecha invalida"; try { $dateStr = ([datetime]$backup.Timestamp).ToString("yyyy-MM-dd HH:mm") } catch { $dateStr = $backup.Timestamp }

            Write-Host ("   [{0,2}] {1} {2} {3,-12} {4} -> {5}" -f ($i + 1), $statusMarker, $dateStr, $backup.Type, $encryptMarker, $backup.File) -ForegroundColor $statusColor
        }
        
        $selectedCount = @($allBackups | Where-Object { $_.Selected }).Count
        if ($selectedCount -gt 0) { Write-Host "`n   ($selectedCount elemento(s) seleccionado(s))" -ForegroundColor Cyan }
        
        Write-Host "`n--- Acciones ---" -ForegroundColor Yellow
        Write-Host "   [Numero] Marcar/Desmarcar        [T] Seleccionar Todos"
        Write-Host "   [R] Restaurar seleccionados      [N] Desmarcar Todos"
        Write-Host "   [D] Eliminar seleccionados"
        Write-Host ""
        Write-Host "   [C] Cargar Credencial (DPAPI) para restauracion automatica" -ForegroundColor Cyan
        Write-Host "   [P] Purgar Respaldos Antiguos (Politica de Retencion)" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "   [V] Volver al menu anterior (Descarga la credencial de memoria)" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host "Selecciona una opcion"
        
        switch ($choice.ToUpper()) {
            "C" { # --- OPCION DE CARGAR CREDENCIAL DPAPI ---
                Write-Host "`n[+] Selecciona el archivo de credencial (.cred) que deseas cargar." -ForegroundColor Yellow
                $defaultCredDir = Join-Path (Split-Path -Parent $PSScriptRoot) "BackupScripts"
                if (-not (Test-Path $defaultCredDir)) { $defaultCredDir = $env:USERPROFILE }

                $credPath = $null
                try {
                    Add-Type -AssemblyName System.Windows.Forms
                    $dialog = New-Object System.Windows.Forms.OpenFileDialog
                    $dialog.Title = "Selecciona el archivo de credencial (.cred)"
                    $dialog.InitialDirectory = $defaultCredDir
                    $dialog.Filter = "Archivos de credencial (*.cred)|*.cred|Todos los archivos (*.*)|*.*"
                    if ($dialog.ShowDialog() -eq 'OK') {
                        $credPath = $dialog.FileName
                    }
                } catch {
                     $credPath = Read-Host "Escribe la ruta completa al archivo .cred"
                }

                if ([string]::IsNullOrWhiteSpace($credPath) -or (-not (Test-Path $credPath))) {
                    Write-Warning "No se selecciono un archivo valido. Operacion cancelada."
                } else {
                    Write-Host "Intentando descifrar '$credPath'..." -ForegroundColor Gray
                    try {
                        # --- EL CORAZON DE LA SEGURIDAD DPAPI (METODO BLINDADO V2) ---
                        # 1. Leemos todo el texto usando .NET con codificación ASCII explícita.
                        # 2. Usamos .Trim() para eliminar cualquier espacio en blanco o salto de línea al inicio/final.
                        $encryptedContent = [System.IO.File]::ReadAllText($credPath, [System.Text.Encoding]::ASCII).Trim() # <--- CORREGIDO: Lectura robusta de texto + Trim
                        
                        # Usar DPAPI para descifrar
                        $loadedCredential = $encryptedContent | ConvertTo-SecureString -ErrorAction Stop
                        Write-Host "[EXITO] Credencial descifrada y cargada en memoria de forma segura." -ForegroundColor Green
                        Write-Log -LogLevel ACTION -Message "MANAGE: Credencial DPAPI cargada desde '$credPath'."
                    } catch {
                        Write-Error "FALLO al descifrar la credencial."
                        Write-Error "Asegurate de que eres el mismo usuario que creo el archivo .cred en esta maquina."
                        Write-Error "Detalles: $($_.Exception.Message)"
                        $loadedCredential = $null
                    }
                }
                Read-Host "Presiona Enter para continuar..."
            }
            "R" {
                $selectedBackups = $allBackups | Where-Object { $_.Selected }
                if ($selectedBackups.Count -eq 0) {
                    Write-Warning "No has seleccionado ningun respaldo para restaurar." ; Start-Sleep -Seconds 2; continue
                }
                # PASAMOS LA CREDENCIAL CARGADA A LA FUNCION DE RESTAURACION
                Invoke-RestoreBackupChain -Manifest $manifest -DestinationPath $destinationPath -SelectedBackups $selectedBackups -MasterSecurePassword $loadedCredential
            }
            "D" {
                $selectedBackups = $allBackups | Where-Object { $_.Selected }
                if ($selectedBackups.Count -eq 0) { Write-Warning "No has seleccionado ningun respaldo para eliminar." ; Start-Sleep -Seconds 2; continue }
                Write-Warning "¡ADVERTENCIA! Eliminar un respaldo COMPLETO o INCREMENTAL puede romper la cadena de restauracion."
                $confirm = Read-Host "¿Estas seguro de eliminar los $($selectedBackups.Count) archivos Y sus entradas del manifiesto? (S/N)"
                if ($confirm.ToUpper() -eq 'S') {
                    try {
                        foreach ($backup in $selectedBackups) {
                            $fullPath = Join-Path $destinationPath $backup.File
                            Write-Host "Eliminando $fullPath..." -ForegroundColor Gray
							Write-Log -LogLevel ACTION -Message "MANAGE: Eliminando respaldo manual '$($backup.File)'."
                            if (Test-Path $fullPath) { Remove-Item $fullPath -Force -ErrorAction Stop }
                            $manifest.Backups.Remove($backup) | Out-Null
                        }
                        Update-BackupManifest -DestinationPath $destinationPath -Manifest $manifest
                        Write-Host "[OK] Respaldos eliminados correctamente." -ForegroundColor Green
                        $allBackups = @($manifest.Backups | ForEach-Object {
                            $_ | Add-Member -MemberType NoteProperty -Name 'Selected' -Value $false -Force
                            $status = "Available"; if (-not (Test-Path (Join-Path $destinationPath $_.File))) { $status = "Missing" }
                            $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value $status -Force
                            $_ 
                        } | Sort-Object Timestamp -Descending)
                        Read-Host "Presiona Enter para continuar..."
                    } catch {
                        Write-Error "Ocurrio un error durante la eliminacion: $($_.Exception.Message)"
                        Read-Host "Presiona Enter para continuar..."
                    }
                }
            }
            "P" {
                Write-Log -LogLevel INFO -Message "BACKUP/Manage: Usuario selecciono Purgar Respaldos."
                Invoke-PruneBackups -Manifest $manifest -DestinationPath $destinationPath
                $manifest = Get-BackupManifest -DestinationPath $destinationPath
                $allBackups = @($manifest.Backups | ForEach-Object {
                    $_ | Add-Member -MemberType NoteProperty -Name 'Selected' -Value $false -Force
                    $status = "Available"; if (-not (Test-Path (Join-Path $destinationPath $_.File))) { $status = "Missing" }
                    $_ | Add-Member -MemberType NoteProperty -Name 'Status' -Value $status -Force
                    $_
                } | Sort-Object Timestamp -Descending)
                Read-Host "`nPurga finalizada. Presiona Enter para refrescar..."
            }
            "T" { $allBackups.ForEach({$_.Selected = $true}) }
            "N" { $allBackups.ForEach({$_.Selected = $false}) }
            "V" { 
                # Limpieza de seguridad al salir del menú
                $loadedCredential = $null
                [GC]::Collect()
                continue 
            }
            default {
                if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $allBackups.Count) {
                    $index = [int]$choice - 1
                    $allBackups[$index].Selected = -not $allBackups[$index].Selected
                }
            }
        }
    }
}

# --- FUNCION: Logica de Purga de Respaldos (CORREGIDA) ---
function Invoke-PruneBackups {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [PSCustomObject]$Manifest,
        [string]$DestinationPath
    )

    Write-Host "`n--- Politica de Retencion de Respaldos ---" -ForegroundColor Magenta
    
    $keepCountInput = Read-Host "Introduce el numero de cadenas de Respaldo COMPLETO que deseas conservar (ej: 2)"
    if (-not ($keepCountInput -match '^\d+$') -or [int]$keepCountInput -lt 1) {
        Write-Warning "Entrada invalida. Se debe conservar al menos 1 cadena. Cancelando."
        Start-Sleep -Seconds 2
        return
    }
    $keepCount = [int]$keepCountInput

    # --- 1. Identificar todas las cadenas de respaldo (por Origen) ---
    # Verificamos que existan respaldos antes de agrupar
    if ($null -eq $Manifest.Backups -or $Manifest.Backups.Count -eq 0) {
        Write-Warning "No hay respaldos para purgar."
        return
    }
    $chains = $Manifest.Backups | Group-Object Source

    $filesToDelete = @()
    $filesToKeep = @()

    foreach ($chain in $chains) {
        $source = $chain.Name
        Write-Host "`n[+] Analizando cadena para: $source" -ForegroundColor Cyan
        
        $backupsInChain = $chain.Group
        $fullBackups = $backupsInChain | Where-Object { $_.Type -eq 'Full' } | Sort-Object Timestamp -Descending
        
        if ($fullBackups.Count -le $keepCount) {
            Write-Host "   - Se encontraron $($fullBackups.Count) cadenas. Politica de retencion ($keepCount) no alcanzada. No se purgara nada." -ForegroundColor Green
            $filesToKeep += $backupsInChain 
            continue
        }

        # --- 2. Identificar cadenas a MANTENER ---
        $fullBackupsToKeep = $fullBackups | Select-Object -First $keepCount
        $filesToKeep += $fullBackupsToKeep

        foreach ($full in $fullBackupsToKeep) {
            $children = Get-BackupChildren -Manifest $Manifest -Parent $full
            if ($children) {
                 $filesToKeep += $children
            }
        }
        
        # --- 3. Identificar cadenas a ELIMINAR ---
        $fullBackupsToDelete = $fullBackups | Select-Object -Skip $keepCount
        $filesToDelete += $fullBackupsToDelete
        
        foreach ($full in $fullBackupsToDelete) {
            $children = Get-BackupChildren -Manifest $Manifest -Parent $full
            if ($children) {
                 $filesToDelete += $children
            }
        }
        
        Write-Host "   - Se conservaran $($fullBackupsToKeep.Count) cadenas." -ForegroundColor Gray
        Write-Host "   - Se purgaran $($fullBackupsToDelete.Count) cadenas antiguas." -ForegroundColor Yellow
    }

    if ($filesToDelete.Count -eq 0) {
        Write-Host "`n[INFO] No se encontraron respaldos obsoletos para purgar." -ForegroundColor Green
        return
    }

    # --- 4. Confirmacion Final ---
    Write-Warning "`n¡CONFIRMACION!"
    Write-Host "Se eliminaran permanentemente los siguientes $($filesToDelete.Count) archivos de respaldo:"
    $filesToDelete | ForEach-Object { Write-Host "   - $($_.File)" -ForegroundColor Red }
    
    $confirm = Read-Host "Escribe 'PURGAR' para confirmar esta accion"
    if ($confirm -ne 'PURGAR') {
        Write-Warning "Accion cancelada por el usuario."
        Start-Sleep -Seconds 2
        return
    }

    # --- 5. Ejecucion de Purga ---
    foreach ($file in $filesToDelete) {
        if ($PSCmdlet.ShouldProcess($file.File, "Eliminar archivo obsoleto")) {
            Write-Host "Eliminando $($file.File)..." -ForegroundColor Gray
            $fullPath = Join-Path $DestinationPath $file.File
            if (Test-Path $fullPath) {
                Remove-Item $fullPath -ErrorAction SilentlyContinue
            }
            # Eliminamos del manifiesto en memoria
            $Manifest.Backups.Remove($file) | Out-Null
        }
    }

    Update-BackupManifest -DestinationPath $DestinationPath -Manifest $Manifest
    Write-Host "[OK] Purga completada." -ForegroundColor Green
}

# --- FUNCION AUXILIAR: Encontrar Hijos de un Respaldo ---
function Get-BackupChildren {
    param(
        [PSCustomObject]$Manifest,
        [PSCustomObject]$Parent
    )
    
    $children = [System.Collections.Generic.List[PSCustomObject]]::new()
    $directChildren = $Manifest.Backups | Where-Object { $_.Parent -eq $Parent.File }
    
    foreach ($child in $directChildren) {
        $children.Add($child)
        # Recursion: Llama a si misma para encontrar los hijos de este hijo
        $grandChildren = Get-BackupChildren -Manifest $Manifest -Parent $child
        $children.AddRange($grandChildren)
    }
    
    return $children
}

# --- FUNCION 5: Verificar Integridad ---
function Verify-BackupIntegrity {
    param()
    
    Write-Host "`n[+] Verificar Integridad de Respaldos" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------"
    
    # --- 1. Seleccionar la carpeta de destino ---
    Write-Host "`n[+] Por favor, selecciona la CARPETA de Destino que contiene el manifiesto." -ForegroundColor Yellow
    $destinationPath = Select-PathDialog -DialogType 'Folder' -Title "Selecciona la Carpeta de Destino de tus Respaldos"
    if ([string]::IsNullOrWhiteSpace($destinationPath)) {
        Write-Warning "No se selecciono una carpeta. Operacion cancelada." ; Start-Sleep -Seconds 2; return
    }

    # --- 2. Cargar Manifiesto ---
    $manifest = Get-BackupManifest -DestinationPath $destinationPath
    if ($manifest.Backups.Count -eq 0) {
        Write-Host "`n[INFO] No se encontraron respaldos registrados en el manifiesto." -ForegroundColor Yellow
        Read-Host "`nPresiona Enter para continuar..."
        return
    }

    # --- 3. Verificar si 7-Zip esta disponible ---
    if (-not (Ensure-7ZipIsInstalled)) {
        Read-Host "`nPresiona Enter para volver..."
        return
    }

    Write-Host "`n[+] Verificando la integridad de $($manifest.Backups.Count) archivos de respaldo..." -ForegroundColor Yellow
    $issuesFound = 0
    # Asignamos el resultado del foreach directamente al array
    $verificationResults = foreach ($backup in $manifest.Backups) {
        $archivePath = Join-Path $destinationPath $backup.File
        $result = [PSCustomObject]@{ Check = $backup.File; Status = "ERROR"; Details = "Archivo no encontrado" }

        if (Test-Path $archivePath) {
            Write-Host "   - Probando $($backup.File)..." -ForegroundColor Gray
            # ... (el resto del código dentro del if/else sigue igual) ...
            if ($exitCode -eq 0) {
                # Exito
                $result.Status = "OK"
                $result.Details = "Archivo integro."
            } elseif ($backup.IsEncrypted -and ($output -match "Wrong password" -or $exitCode -eq 2)) {
                # Esto es un "exito" para un archivo cifrado
                $result.Status = "OK (Cifrado)"
                $result.Details = "El archivo esta cifrado y parece ser valido."
            } else {
                # Error real
                $result.Status = "Error"
                $result.Details = "¡Archivo corrupto! (Codigo: $exitCode)"
                # IMPORTANTE: No podemos incrementar $issuesFound aquí dentro porque
                # estamos en un pipeline que retorna objetos. Lo haremos después.
            }
        } else {
            # Archivo no encontrado
        }

        # Emitimos el objeto $result al final de cada iteración
        $result
    }

    # Ahora, contamos los errores basándonos en los resultados finales
    $issuesFound = ($verificationResults | Where-Object { $_.Status -eq "Error" -or $_.Status -eq "ERROR" }).Count

    # --- 4. Mostrar Resultados ---
    Write-Host "`nResultados de la verificacion:" -ForegroundColor Cyan
    $verificationResults | ForEach-Object {
        $statusColor = switch ($_.Status) {
            "OK" { "Green" }
            "OK (Cifrado)" { "Green" }
            "Error" { "Red" }
            default { "White" }
        }
        Write-Host "   $($_.Check): $($_.Status) - $($_.Details)" -ForegroundColor $statusColor
    }
    
    if ($issuesFound -eq 0) {
        Write-Host "`n[OK] Todos los respaldos en el manifiesto estan integros y disponibles." -ForegroundColor Green
		Write-Log -LogLevel INFO -Message "VERIFY: Verificación de integridad completada con ÉXITO para $($manifest.Backups.Count) archivos."
    } else {
        Write-Host "`n[ERROR CRITICO] Se encontraron $issuesFound problemas (archivos corruptos o faltantes)." -ForegroundColor Red
        Write-Host "Revisa los detalles. Es posible que la cadena de respaldo este rota." -ForegroundColor Red
		Write-Log -LogLevel ERROR -Message "VERIFY: Verificación de integridad finalizó con $issuesFound ERRORES."
    }
    
    Read-Host "`nPresiona Enter para continuar..."
}

# --- FUNCION 6: Logica de Restauracion de Cadena (CORREGIDA) ---
function Invoke-RestoreBackupChain {
    param(
        [PSCustomObject]$Manifest,
        [string]$DestinationPath,
        [PSCustomObject[]]$SelectedBackups,
        # Nuevo parametro opcional para pasar una contraseña ya descifrada
        [System.Security.SecureString]$MasterSecurePassword = $null
    )
    
    if (-not (Ensure-7ZipIsInstalled)) { return }
    
    Write-Host "`n[+] Selecciona la CARPETA de Destino donde se restauraran los archivos." -ForegroundColor Yellow
    $restorePath = Select-PathDialog -DialogType 'Folder' -Title "Elige la Carpeta de Destino de la Restauracion"
    if ([string]::IsNullOrWhiteSpace($restorePath)) {
        Write-Warning "No se selecciono una carpeta. Operacion cancelada." ; Start-Sleep -Seconds 2; return
    }

    # Diccionario para guardar contraseñas ingresadas manualmente durante esta sesion
    $sessionPasswords = @{}

    foreach ($selectedBackup in $SelectedBackups) {
        Write-Host "`n--- Iniciando Restauracion de: $($selectedBackup.File) ---" -ForegroundColor Cyan
        Write-Log -LogLevel INFO -Message "RESTORE: Iniciando calculo de cadena para '$($selectedBackup.File)'."
        
        # --- 1. Construir la cadena de restauracion ---
        $restoreChain = [System.Collections.Generic.List[PSCustomObject]]::new()
        $current = $selectedBackup
        $brokenChain = $false
        while ($current -ne $null) {
            $restoreChain.Insert(0, $current)
            if ($current.Parent -eq $null) {
                $current = $null # Llego al Full
            } else {
                $parentFound = $Manifest.Backups | Where-Object { $_.File -eq $current.Parent } | Select-Object -First 1
                if ($null -eq $parentFound) {
                    $msg = "CRITICO: Cadena rota. Falta el archivo padre en el registro: '$($current.Parent)'"
                    Write-Host $msg -ForegroundColor Red
                    Write-Log -LogLevel ERROR -Message "RESTORE: $msg"
                     $brokenChain = $true
                     break
                }
                $current = $parentFound
            }
        }
        
        if ($brokenChain) { continue }

        Write-Host "[INFO] Este respaldo depende de $($restoreChain.Count) archivo(s):" -ForegroundColor Gray
        $restoreChain | ForEach-Object { Write-Host "   - $($_.File)" }

        # --- 2. Ejecutar la cadena ---
        $globalSuccess = $true

        foreach ($backupFile in $restoreChain) {
            $archivePath = Join-Path $DestinationPath $backupFile.File
            if (-not (Test-Path $archivePath)) {
                $msg = "¡FALTANTE! No se puede encontrar el archivo fisico '$($backupFile.File)'. La cadena de restauracion esta ROTA."
                Write-Error $msg
                Write-Log -LogLevel ERROR -Message $msg
                $globalSuccess = $false
                break
            }
            
            Write-Host "`n[+] Aplicando: $($backupFile.File)..." -ForegroundColor Yellow
            Write-Log -LogLevel ACTION -Message "RESTORE: Extrayendo '$($backupFile.File)' hacia '$restorePath'."

            $7zArgs = @("x", "`"$archivePath`"", "-o`"$restorePath`"", "-y")
            
            if ($backupFile.IsEncrypted) {
                $passwordToUse = $null

                # PRIORIDAD 1: Usar Credencial Maestra cargada (DPAPI)
                if ($null -ne $MasterSecurePassword) {
                    $passwordToUse = $MasterSecurePassword
                # PRIORIDAD 2: Usar contraseña ya ingresada manualmente en esta sesión
                } elseif ($sessionPasswords.ContainsKey($backupFile.File)) {
                    $passwordToUse = $sessionPasswords[$backupFile.File]
                } 
                # PRIORIDAD 3: Preguntar al usuario
                else {
                    Write-Host "Este archivo esta cifrado." -ForegroundColor Cyan
                    if ($null -eq $MasterSecurePassword) { Write-Host "(Consejo: Puedes usar la opcion 'C' en el menu anterior para cargar un archivo .cred)" -ForegroundColor Gray }
                    $passwordToUse = Read-Host "Introduce la contrasena para '$($backupFile.File)'" -AsSecureString
                    # Guardamos la contraseña manual por si se necesita para otro archivo de la misma cadena
                    $sessionPasswords[$backupFile.File] = $passwordToUse
                }
                
                # Convertir SecureString a BSTR para 7-Zip de forma segura
                $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordToUse)
                $plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
                $7zArgs += "-p$plainPass"
                # Limpieza inmediata del texto plano en memoria no gestionada
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }
            
            # Ejecutar 7-Zip visible
            $process = Start-Process "7z.exe" -ArgumentList $7zArgs -Wait -NoNewWindow -PassThru
            
            if ($process.ExitCode -ne 0) {
                $msg = "¡FALLO! 7-Zip fallo al extraer '$($backupFile.File)' (Codigo: $($process.ExitCode)). Contrasena incorrecta o archivo corrupto."
                Write-Error $msg
                Write-Log -LogLevel ERROR -Message $msg
                $globalSuccess = $false
                break
            }
        }

        if ($globalSuccess) {
            $msg = "Restauracion de '$($selectedBackup.File)' completada exitosamente en '$restorePath'."
            Write-Host "`n[EXITO] $msg" -ForegroundColor Green
            Write-Log -LogLevel ACTION -Message $msg
        } else {
            Write-Host "`n[FALLO] La restauracion de '$($selectedBackup.File)' ha fallado." -ForegroundColor Red
        }
    }
    
    # Limpieza de memoria
    $sessionPasswords = $null; [GC]::Collect()
    Read-Host "`nPresiona Enter para continuar..."
}

# ===================================================================
# --- FUNCIONES AUXILIARES DE RESPALDO (NUEVAS Y MODIFICADAS) ---
# ===================================================================

# --- Gestor del Manifiesto ---
function Get-BackupManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    
    $manifestPath = Join-Path $DestinationPath "manifest.json"
    
    # CASO 1: El archivo existe (Lectura normal)
    if (Test-Path $manifestPath) {
        try {
            Write-Log -LogLevel INFO -Message "BACKUP/7-Zip: Leyendo manifiesto existente en '$manifestPath'."
            
            $jsonContent = Get-Content $manifestPath -Raw
            $manifest = $jsonContent | ConvertFrom-Json
            
            # Asegurarse de que 'Backups' sea una Lista y eliminar duplicados
            $cleanList = New-Object System.Collections.Generic.List[PSCustomObject]
            $seenFiles = @{} 

            if ($null -ne $manifest.Backups) {
                $rawBackups = [PSCustomObject[]]@($manifest.Backups)
                foreach ($backup in $rawBackups) {
                    $fileName = $backup.File
                    if (-not $seenFiles.ContainsKey($fileName)) {
                        $seenFiles[$fileName] = $true
                        $cleanList.Add($backup)
                    }
                }
            }
            $manifest.Backups = $cleanList
            return $manifest

        } catch {
            # Manejo de archivo corrupto
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $corruptFile = Join-Path $DestinationPath "manifest_corrupt_$timestamp.json"
            
            Write-Warning "¡ALERTA CRITICA! El archivo 'manifest.json' esta corrupto."
            try { Copy-Item -Path $manifestPath -Destination $corruptFile -Force } catch {}

            Write-Log -LogLevel ERROR -Message "BACKUP/7-Zip: Manifiesto corrupto. Se inicia nueva cadena."
            
            # Retornamos estructura vacia
            return [PSCustomObject]@{ 
                ManifestVersion = "1.0-Recovered"
                Backups = [System.Collections.Generic.List[PSCustomObject]]::new() 
            }
        }
    } 
    # CASO 2: El archivo NO existe (Primer respaldo)
    else {
        Write-Log -LogLevel INFO -Message "BACKUP/7-Zip: No se encontro manifiesto. Creando uno nuevo."
        return [PSCustomObject]@{ 
            ManifestVersion = "1.0"
            Backups = [System.Collections.Generic.List[PSCustomObject]]::new() 
        }
    }
}

# --- Escritor del Manifiesto ---
function Update-BackupManifest {
    param(
        [string]$DestinationPath,
        [PSCustomObject]$Manifest
    )
    $manifestPath = Join-Path $DestinationPath "manifest.json"
    try {
        $Manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding utf8
        Write-Host "[INFO] Manifiesto de respaldo actualizado." -ForegroundColor Gray
        Write-Log -LogLevel INFO -Message "BACKUP/7-Zip: Manifiesto '$manifestPath' actualizado."
    } catch {
        Write-Warning "No se pudo actualizar el manifiesto JSON. Este respaldo no sera rastreado."
        Write-Log -LogLevel ERROR -Message "BACKUP/7-Zip: Fallo al escribir en '$manifestPath'."
    }
}

# --- FUNCION FALTANTE: Verificar Motor de Software ---
function Test-SoftwareEngine {
    param(
        [string]$Engine
    )
    if ($Engine -eq 'Winget') {
        # Verifica si el comando winget existe en el sistema
        return (Get-Command "winget" -ErrorAction SilentlyContinue) -ne $null
    }
    return $false
}

# --- Verificador/Instalador de 7-Zip ---
function Ensure-7ZipIsInstalled {
    $7zPath = Get-Command "7z" -ErrorAction SilentlyContinue
    if ($7zPath) { return $true }

    Write-Warning "El modulo de Respaldo Avanzado requiere 7-Zip."
    Write-Warning "No se ha detectado '7z.exe' en tu sistema."

    # Usar el motor de software existente para instalarlo
    if (Test-SoftwareEngine -Engine 'Winget') {
        $installChoice = Read-Host "`n¿Deseas instalar 7-Zip (ID: 7zip.7zip) usando Winget ahora? (S/N)"
        if ($installChoice.ToUpper() -eq 'S') {
            Write-Host "`n[+] Instalando 7-Zip via Winget..." -ForegroundColor Yellow
            try {
                Write-Log -LogLevel ACTION -Message "BACKUP/7-Zip: Intentando instalar 7-Zip via Winget."
                winget install --id 7zip.7zip -s winget --accept-package-agreements --accept-source-agreements --silent
                
                # Volver a verificar
                $7zPath = Get-Command "7z" -ErrorAction SilentlyContinue
                if ($7zPath) {
                    Write-Host "[OK] 7-Zip instalado correctamente." -ForegroundColor Green
                    return $true
                } else {
                    Write-Error "La instalacion de 7-Zip parece haber fallado."
                    return $false
                }
            } catch {
                Write-Error "Fallo la instalacion de 7-Zip con Winget. Error: $($_.Exception.Message)"
                return $false
            }
        } else {
            Write-Host "[INFO] Instalacion omitida. No se puede continuar con el respaldo avanzado." -ForegroundColor Gray
            return $false
        }
    } else {
        Write-Error "No se detecto Winget. Por favor, instala 7-Zip manualmente para usar esta funcion."
        return $false
    }
}

# --- Generador de Contraseñas Seguro ---
function Generate-SecurePassword {
    Write-Log -LogLevel INFO -Message "SECURITY: Generando nueva contraseña segura (Método Moderno CSPRNG)."
    
    # Definimos la longitud deseada y el conjunto de caracteres permitidos.
    # Incluimos mayúsculas, minúsculas, números y una selección de símbolos seguros.
    $length = 32
    $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|:<>?'
    $charSetLength = $charSet.Length
    
    try {
        # 1. Crear un buffer de bytes para almacenar la aleatoriedad.
        # Necesitamos un byte por cada carácter que tendrá la contraseña.
        $randomBytes = New-Object byte[] $length

        # 2. Instanciar el Generador de Números Aleatorios Criptográficamente Seguro (CSPRNG).
        # Esta clase es el estándar de seguridad en .NET y funciona en todas las versiones de PowerShell.
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        
        # 3. Llenar el buffer con bytes aleatorios criptográficamente fuertes.
        $rng.GetBytes($randomBytes)

        # 4. Convertir los bytes aleatorios en caracteres de nuestro conjunto.
        # Usamos un StringBuilder para una concatenación eficiente en memoria.
        $passwordBuilder = [System.Text.StringBuilder]::new($length)
        
        foreach ($byte in $randomBytes) {
            # Usamos el operador módulo (%) para mapear el valor del byte (0-255) 
            # a un índice válido dentro de nuestro conjunto de caracteres.
            $index = $byte % $charSetLength
            $passwordBuilder.Append($charSet[$index]) | Out-Null
        }

        # 5. Limpiar recursos de seguridad.
        $rng.Dispose()

        # Devolver la contraseña final como cadena.
        return $passwordBuilder.ToString()

    } catch {
        # Fallback de emergencia extremo (muy improbable que ocurra).
        Write-Warning "Error inesperado en el generador CSPRNG. Usando método de respaldo simple."
        Write-Log -LogLevel ERROR -Message "SECURITY CRITICO: Fallo en Generate-SecurePassword moderno. Error: $($_.Exception.Message)"
        
        # Get-Random no es criptográficamente seguro, pero sirve como último recurso para no detener el script.
        # Usamos un set más simple para asegurar compatibilidad.
        $fallbackChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return -join ($fallbackChars | Get-Random -Count 32)
    }
}

# --- FUNCION 7: Contenedor de Respaldo Simple (Robocopy) ---
function Invoke-SimpleRobocopyBackupMenu {
    Write-Log -LogLevel INFO -Message "BACKUP/Robocopy: Usuario entro al submenu de respaldo simple."

    # Funcion interna para no repetir el menu de seleccion de modo
    function Get-BackupMode {
        Write-Host ""
        Write-Host "--- Elige un modo de respaldo ---" -ForegroundColor Yellow
        Write-Host "   [1] Simple (Copiar y Actualizar)"
        Write-Host "       Copia archivos nuevos o modificados. No borra nada en el destino." -ForegroundColor Gray
        Write-Host "   [2] Sincronizacion (Espejo)"
        Write-Host "       Hace que el destino sea identico al origen. Borra archivos en el destino." -ForegroundColor Red
        
        $modeChoice = Read-Host "`nSelecciona el modo"
        
        switch ($modeChoice) {
            '1' { return 'Copy' }
            '2' { return 'Mirror' }
            default {
                Write-Warning "Opcion invalida." ; Start-Sleep -Seconds 2
                return $null
            }
        }
    }

    Clear-Host
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "          Respaldo Simple (Sincronizacion Robocopy)      " -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "--- Elige un tipo de respaldo ---" -ForegroundColor Yellow
    Write-Host "   [1] Respaldo de Perfil de Usuario (Escritorio, Documentos, etc.)"
    Write-Host "   [2] Respaldo de Carpeta o Archivo(s) Personalizado"
    Write-Host ""
    Write-Host "   [V] Volver al menu anterior" -ForegroundColor Red
    Write-Host ""
    
    $backupChoice = Read-Host "Selecciona una opcion"
    
    if ($backupChoice.ToUpper() -eq 'V') { return }

    switch ($backupChoice.ToUpper()) {
        '1' {
            Write-Log -LogLevel INFO -Message "BACKUP/Robocopy: Usuario selecciono 'Respaldo de Perfil de Usuario'."
            $backupMode = Get-BackupMode
            if ($backupMode) {
                Invoke-UserDataBackup -Mode $backupMode
            }
        }
        '2' {
            Write-Log -LogLevel INFO -Message "BACKUP/Robocopy: Usuario selecciono 'Respaldo Personalizado'."
            $typeChoice = Read-Host "Deseas seleccionar una [C]arpeta o [A]rchivo(s)?"
            $dialogType = ""
            $dialogTitle = ""

            if ($typeChoice.ToUpper() -eq 'C') {
                $dialogType = 'Folder'
                $dialogTitle = "Respaldo Personalizado: Elige la Carpeta de Origen"
            } elseif ($typeChoice.ToUpper() -eq 'A') {
                $dialogType = 'File'
                $dialogTitle = "Respaldo Personalizado: Elige el o los Archivo(s) de Origen"
            } else {
                Write-Warning "Opcion invalida."; Start-Sleep -Seconds 2; return
            }

            $customPath = Select-PathDialog -DialogType $dialogType -Title $dialogTitle

            if ($customPath) {
                $backupMode = Get-BackupMode
                if ($backupMode) {
                    Invoke-UserDataBackup -Mode $backupMode -CustomSourcePath $customPath
                }
            } else {
                Write-Warning "No se selecciono ninguna ruta. Operacion cancelada."
                Start-Sleep -Seconds 2
            }
        }
        default { Write-Warning "Opcion no valida." ; Start-Sleep -Seconds 2 }
    }
}

# --- FUNCION 8: Logica de Respaldo Robocopy ---
function Invoke-UserDataBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Copy', 'Mirror')]
        [string]$Mode,

        [string[]]$CustomSourcePath
    )

    # 1. Determinamos el origen: automatico o personalizado
    $backupType = 'Folders'
    $sourcePaths = @()
    if ($CustomSourcePath) {
        if ($CustomSourcePath.Count -eq 1 -and (Get-Item $CustomSourcePath[0]).PSIsContainer) {
            $backupType = 'Folders'
            $sourcePaths = $CustomSourcePath
        } else {
            $backupType = 'Files'
            $sourcePaths = $CustomSourcePath
        }
    } else {
        $backupType = 'Folders'
        $sourcePaths = @(
            [System.Environment]::GetFolderPath('Desktop')
			[System.Environment]::GetFolderPath('MyDocuments')
            [System.Environment]::GetFolderPath('MyPictures')
            [System.Environment]::GetFolderPath('MyMusic')
            [System.Environment]::GetFolderPath('MyVideos')
        ) | Where-Object { Test-Path $_ }
    }
    
    # 2. Solicitamos y validamos el destino
    Write-Host "`n[+] Por favor, selecciona la carpeta de destino para el respaldo..." -ForegroundColor Yellow
    $destinationPath = Select-PathDialog -DialogType 'Folder' -Title "Paso 2: Elige la Carpeta de Destino del Respaldo"
    
    if ([string]::IsNullOrWhiteSpace($destinationPath)) {
        Write-Warning "No se selecciono una carpeta de destino. Operacion cancelada." ; Start-Sleep -Seconds 2; return
    }

    # Comprobacion inteligente de Origen vs. Destino
    $sourceDriveLetter = (Get-Item -Path $sourcePaths[0]).PSDrive.Name
    $destinationDriveLetter = (Get-Item -Path $destinationPath).PSDrive.Name
    if ($sourceDriveLetter.ToUpper() -eq $destinationDriveLetter.ToUpper()) {
        Write-Warning "El destino esta en la misma unidad que el origen (Unidad $($sourceDriveLetter.ToUpper()):)."
        Write-Warning "Un respaldo en el mismo disco no protege contra fallos del disco fisico."
        if ((Read-Host "Estas seguro de que deseas continuar? (S/N)").ToUpper() -ne 'S') {
            Write-Host "[INFO] Operacion cancelada." -ForegroundColor Yellow; Start-Sleep -Seconds 2; return
        }
    }
    
    # Calculamos el espacio requerido
    Write-Host "`n[+] Calculando espacio requerido para el respaldo. Esto puede tardar..." -ForegroundColor Yellow
    $sourceTotalSize = 0
    try {
        if ($backupType -eq 'Files') {
            $sourceTotalSize = ($sourcePaths | Get-Item | Measure-Object -Property Length -Sum).Sum
        } else {
            foreach ($folder in $sourcePaths) {
                $sourceTotalSize += (Get-ChildItem -Path $folder -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum
            }
        }
    } catch {
        Write-Warning "No se pudo calcular el tamano total. Error: $($_.Exception.Message)"
    }
    
    $destinationFreeSpace = (Get-Volume -DriveLetter $destinationDriveLetter).SizeRemaining
    $sourceTotalSizeGB = [math]::Round($sourceTotalSize / 1GB, 2)
    $destinationFreeSpaceGB = [math]::Round($destinationFreeSpace / 1GB, 2)
    Write-Host "Espacio requerido estimado: $sourceTotalSizeGB GB"
    Write-Host "Espacio disponible en el destino ($($destinationDriveLetter.ToUpper()):): $destinationFreeSpaceGB GB"

    if ($sourceTotalSize -gt $destinationFreeSpace) {
        Write-Error "No hay suficiente espacio en el disco de destino para completar el respaldo."
        Read-Host "`nOperacion abortada. Presiona Enter para volver al menu..."
        return
    }

    # 3. Configuramos Robocopy
    $logDir = Join-Path (Split-Path -Parent $PSScriptRoot) "Logs"
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory | Out-Null }
    $logFile = Join-Path $logDir "Respaldo_Robocopy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').log"
    $baseRoboCopyArgs = @("/COPY:DAT", "/R:3", "/W:5", "/XJ", "/NP", "/TEE")

    # 4. Mostramos el resumen y pedimos confirmacion final
    Clear-Host
    $modeDescription = if ($Mode -eq 'Mirror') { "Sincronizacion Completa (Modo Espejo)" } else { "Respaldo Simple (Anadir/Actualizar)" }
    Write-Host "--- RESUMEN DE LA OPERACION DE RESPALDO ---" -ForegroundColor Cyan
    Write-Host "Modo: $modeDescription"
    Write-Host "Destino: $destinationPath"
    if ($backupType -eq 'Files') {
        Write-Host "Archivos de Origen:"
    } else {
        Write-Host "Carpetas de Origen:"
    }
    $sourcePaths | ForEach-Object { Write-Host " - $_" }
    if ($Mode -eq 'Mirror') {
        Write-Warning "El Modo Espejo eliminara cualquier archivo en el destino que no exista en el origen."
    }
    Write-Host "Se generara un registro detallado en: $logFile"
    
	Write-Log -LogLevel ACTION -Message "BACKUP: Iniciando operacion. Modo: '$Mode'. Origen: $($sourcePaths -join ', '). Destino: '$destinationPath'."
	
    Write-Host ""
    Write-Host "--- CONFIRMACION FINAL ---" -ForegroundColor Yellow
    Write-Host "   [S] Si, iniciar solo el respaldo"
    Write-Host "   [V] Si, respaldar Y verificar (Comprobacion Rapida)"
    Write-Host "   [H] Si, respaldar Y verificar (Comprobacion Profunda por Hash - MUY LENTO)"
    Write-Host "   [N] No, cancelar operacion"
    $confirmChoice = Read-Host "`nElige una opcion"

    $verificationType = 'None' # Valor por defecto
    switch ($confirmChoice.ToUpper()) {
        'S' { $verificationType = 'None' }
        'V' { $verificationType = 'Fast' }
        'H' { $verificationType = 'Deep' }
        'N' { Write-Host "[INFO] Operacion cancelada por el usuario." -ForegroundColor Yellow; Start-Sleep -Seconds 2; return }
        default { Write-Warning "Opcion no valida. Operacion cancelada."; Start-Sleep -Seconds 2; return }
    }

    # 5. Ejecutamos el respaldo
    $logArg = "/LOG+:`"$logFile`""

    if ($backupType -eq 'Files') {
        Write-Host "`n[+] Respaldando $($sourcePaths.Count) archivo(s) hacia '$destinationPath'..." -ForegroundColor Yellow
        $baseFileArgs = $baseRoboCopyArgs
        $filesByDirectory = $sourcePaths | Get-Item | Group-Object -Property DirectoryName
        foreach ($group in $filesByDirectory) {
            $sourceDir = $group.Name
            $fileNames = $group.Group | ForEach-Object { "`"$($_.Name)`"" }
            Write-Host " - Procesando lote desde '$sourceDir'..." -ForegroundColor Gray
            $currentArgs = @("`"$sourceDir`"", "`"$destinationPath`"") + $fileNames + $baseFileArgs + $logArg
            Start-Process "robocopy.exe" -ArgumentList $currentArgs -Wait -NoNewWindow
        }
    } else {
        $folderArgs = $baseRoboCopyArgs + "/E"
        if ($Mode -eq 'Mirror') {
            $folderArgs = $baseRoboCopyArgs + "/MIR"
        }
        foreach ($sourceFolder in $sourcePaths) {
            $folderName = Split-Path $sourceFolder -Leaf
            $destinationFolder = Join-Path $destinationPath $folderName
            Write-Host "`n[+] Respaldando '$folderName' hacia '$destinationFolder'..." -ForegroundColor Yellow
            $currentArgs = @("`"$sourceFolder`"", "`"$destinationFolder`"") + $folderArgs + $logArg
            Start-Process "robocopy.exe" -ArgumentList $currentArgs -Wait -NoNewWindow
        }
    }

    Write-Host "`n[EXITO] Operacion de respaldo completada." -ForegroundColor Green
	switch ($verificationType) {
        'Fast' {
			Write-Log -LogLevel INFO -Message "BACKUP: Iniciando verificacion rapida (Robocopy /L)."
            Invoke-BackupRobocopyVerification -logFile $logFile -baseRoboCopyArgs $baseRoboCopyArgs -backupType $backupType -sourcePaths $sourcePaths -destinationPath $destinationPath -Mode $Mode
        }
        'Deep' {
			Write-Log -LogLevel INFO -Message "BACKUP: Iniciando verificacion profunda (Hash SHA256)."
            Invoke-BackupHashVerification -sourcePaths $sourcePaths -destinationPath $destinationPath -backupType $backupType -logFile $logFile
        }
        # Si es 'None', no hacemos nada
    }
    Write-Host "Se ha guardado un registro detallado en '$logFile'"
    if ((Read-Host "Deseas abrir el archivo de registro ahora? (S/N)").ToUpper() -eq 'S') {
        Start-Process "notepad.exe" -ArgumentList $logFile
    }
    Read-Host "`nPresiona Enter para volver al menu..."
}

# --- FUNCION 9: Auxiliar de Dialogo ---
# (Esta funcion es necesaria para todos los modulos)
function Select-PathDialog {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Folder', 'File')]
        [string]$DialogType,

        [string]$Title,

        [string]$Filter = "Todos los archivos (*.*)|*.*"
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        if ($DialogType -eq 'Folder') {
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.Description = $Title
            if ($dialog.ShowDialog() -eq 'OK') {
                return $dialog.SelectedPath
            }
        } elseif ($DialogType -eq 'File') {
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Title = $Title
            $dialog.Filter = $Filter
            $dialog.CheckFileExists = $true
            $dialog.CheckPathExists = $true
            $dialog.Multiselect = $true # Permitimos seleccionar multiples archivos
            if ($dialog.ShowDialog() -eq 'OK') {
                return $dialog.FileNames # Devolvemos un array de nombres de archivo
            }
        }
    } catch {
        Write-Error "No se pudo mostrar el dialogo de seleccion. Error: $($_.Exception.Message)"
    }
    
    return $null # Devuelve nulo si el usuario cancela
}

# --- FUNCIONES 10 y 11: Auxiliares de Robocopy ---
function Invoke-BackupRobocopyVerification {
    [CmdletBinding()]
    param(
        $logFile, $baseRoboCopyArgs, $backupType, $sourcePaths, $destinationPath, $Mode
    )

    Write-Host "`n[+] Iniciando comprobacion de integridad (modo de solo listado)..." -ForegroundColor Yellow
    Write-Output "`r`n`r`n================================================`r`n" | Out-File -FilePath $logFile -Append -Encoding UTF8
    Write-Output "   INICIO DE LA COMPROBACION DE INTEGRIDAD (RAPIDA)`r`n" | Out-File -FilePath $logFile -Append -Encoding UTF8
    Write-Output "================================================`r`n" | Out-File -FilePath $logFile -Append -Encoding UTF8

    $verifyBaseArgs = $baseRoboCopyArgs + "/L"
    $logArg = "/LOG+:`"$logFile`""

    if ($backupType -eq 'Files') {
        $filesByDirectory = $sourcePaths | Get-Item | Group-Object -Property DirectoryName
        foreach ($group in $filesByDirectory) {
            $sourceDir = $group.Name
            $fileNames = $group.Group | ForEach-Object { "`"$($_.Name)`"" }
            Write-Host " - Verificando lote desde '$sourceDir'..." -ForegroundColor Gray
            $currentArgs = @("`"$sourceDir`"", "`"$destinationPath`"") + $fileNames + $verifyBaseArgs + $logArg
            Start-Process "robocopy.exe" -ArgumentList $currentArgs -Wait -NoNewWindow
        }
    } else {
        $folderArgs = $verifyBaseArgs + "/E"
        if ($Mode -eq 'Mirror') { $folderArgs = $verifyBaseArgs + "/MIR" }
        foreach ($sourceFolder in $sourcePaths) {
            $folderName = Split-Path $sourceFolder -Leaf
            $destinationFolder = Join-Path $destinationPath $folderName
            Write-Host "`n[+] Verificando '$folderName' en '$destinationFolder'..." -ForegroundColor Gray
            $currentArgs = @("`"$sourceFolder`"", "`"$destinationFolder`"") + $folderArgs + $logArg
            Start-Process "robocopy.exe" -ArgumentList $currentArgs -Wait -NoNewWindow
        }
    }
    
    Write-Host "[OK] Comprobacion de integridad finalizada. Revisa el registro para ver los detalles." -ForegroundColor Green
    Write-Host "   Si no aparecen archivos listados en la seccion de verificacion, la copia es integra." -ForegroundColor Gray
}

function Invoke-BackupHashVerification {
    [CmdletBinding()]
    param(
        $sourcePaths, $destinationPath, $backupType, $logFile
    )
    
    Write-Host "`n[+] Iniciando comprobacion profunda por Hash (SHA256). Esto puede ser MUY LENTO." -ForegroundColor Yellow
    
    $sourceFiles = @()
    if ($backupType -eq 'Files') {
        $sourceFiles = $sourcePaths | Get-Item
    } else {
        $sourcePaths | ForEach-Object { $sourceFiles += Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue }
    }

    if ($sourceFiles.Count -eq 0) { Write-Warning "No se encontraron archivos de origen para verificar."; return }

    $totalFiles = $sourceFiles.Count
    $checkedFiles = 0
    $mismatchedFiles = 0
    $missingFiles = 0
    $mismatchedFileList = [System.Collections.Generic.List[string]]::new()
    $missingFileList = [System.Collections.Generic.List[string]]::new()

    foreach ($sourceFile in $sourceFiles) {
        $checkedFiles++
        Write-Progress -Activity "Verificando hashes de archivos" -Status "Procesando: $($sourceFile.Name)" -PercentComplete (($checkedFiles / $totalFiles) * 100)
        
        $destinationFile = ""
        if ($backupType -eq 'Folders') {
             $baseSourceFolder = ($sourcePaths | Where-Object { $sourceFile.FullName.StartsWith($_) })[0]
             $relativePath = $sourceFile.FullName.Substring($baseSourceFolder.Length)
             $destinationFolder = (Join-Path $destinationPath (Split-Path $baseSourceFolder -Leaf))
             $destinationFile = Join-Path $destinationFolder $relativePath
        } else {
             $destinationFile = Join-Path $destinationPath $sourceFile.Name
        }
        
        if (Test-Path $destinationFile) {
            try {
                $sourceHash = (Get-FileHash $sourceFile.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                $destHash = (Get-FileHash $destinationFile -Algorithm SHA256 -ErrorAction Stop).Hash
                if ($sourceHash -ne $destHash) {
                    $mismatchedFiles++
                    $message = "DISCREPANCIA DE HASH: $($sourceFile.FullName)"
                    Write-Warning $message
                    $mismatchedFileList.Add($message)
                }
            } catch {
                $message = "ERROR DE LECTURA: No se pudo calcular el hash de '$($sourceFile.Name)' o su par. Puede estar en uso."
                Write-Warning $message
                $mismatchedFileList.Add($message)
            }
        } else {
            $missingFiles++
            $message = "ARCHIVO FALTANTE en el destino: $($sourceFile.FullName)"
            Write-Warning $message
            $missingFileList.Add($message)
        }
    }

    Write-Progress -Activity "Verificacion por Hash" -Completed
    Write-Host "`n--- RESUMEN DE LA COMPROBACION PROFUNDA ---" -ForegroundColor Cyan
    Write-Host "Archivos totales verificados: $totalFiles"
    $mismatchColor = if ($mismatchedFiles -gt 0) { 'Red' } else { 'Green' }
    Write-Host "Archivos con discrepancias  : $mismatchedFiles" -ForegroundColor $mismatchColor
    $missingColor = if ($missingFiles -gt 0) { 'Red' } else { 'Green' }
    Write-Host "Archivos faltantes en destino: $missingFiles" -ForegroundColor $missingColor
    
    $logSummary = @"

-------------------------------------------------
   RESUMEN DE LA COMPROBACION PROFUNDA POR HASH
-------------------------------------------------
Archivos totales verificados: $totalFiles
Archivos con discrepancias  : $mismatchedFiles
Archivos faltantes en destino: $missingFiles
"@
    if ($mismatchedFileList.Count -gt 0) {
        $logSummary += "`r`n`r`n--- LISTA DE DISCREPANCIAS ---`r`n"
        $logSummary += ($mismatchedFileList | Out-String)
    }
    if ($missingFileList.Count -gt 0) {
        $logSummary += "`r`n`r`n--- LISTA DE ARCHIVOS FALTANTES ---`r`n"
        $logSummary += ($missingFileList | Out-String)
    }
    $logSummary | Out-File -FilePath $logFile -Append -Encoding UTF8
    
    if ($mismatchedFiles -eq 0 -and $missingFiles -eq 0) {
        Write-Host "[OK] La integridad de todos los archivos ha sido verificada con exito." -ForegroundColor Green
    } else {
        Write-Error "Se encontraron problemas de integridad en la copia de seguridad."
    }
}

# ===================================================================
# --- MoDULO DE REUBICACIoN DE CARPETAS DE USUARIO ---
# ===================================================================

function Move-UserProfileFolders {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    Write-Log -LogLevel INFO -Message "Usuario entro al Modulo de Reubicacion de Carpetas de Usuario."

    $folderMappings = @{
        'Escritorio' = @{ RegValue = 'Desktop'; DefaultName = 'Desktop' }
        'Documentos' = @{ RegValue = 'Personal'; DefaultName = 'Documents' }
        'Descargas'  = @{ RegValue = '{374DE290-123F-4565-9164-39C4925E467B}'; DefaultName = 'Downloads' }
        'Musica'     = @{ RegValue = 'My Music'; DefaultName = 'Music' }
        'Imagenes'   = @{ RegValue = 'My Pictures'; DefaultName = 'Pictures' }
        'Videos'     = @{ RegValue = 'My Video'; DefaultName = 'Videos' }
    }
    $registryPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"

    Write-Host "`n[+] Paso 1: Selecciona la carpeta RAIZ donde se crearan las nuevas carpetas de usuario." -ForegroundColor Yellow
    Write-Host "    (Ejemplo: Si seleccionas 'D:\MisDatos', se crearan 'D:\MisDatos\Escritorio', 'D:\MisDatos\Documentos', etc.)" -ForegroundColor Gray
    $newBasePath = Select-PathDialog -DialogType Folder -Title "Selecciona la NUEVA UBICACION BASE para tus carpetas"
    
    if ([string]::IsNullOrWhiteSpace($newBasePath)) {
        Write-Warning "Operacion cancelada. No se selecciono una ruta de destino."
        Start-Sleep -Seconds 2
        return
    }
    
    $currentUserProfilePath = $env:USERPROFILE
    if ($newBasePath.StartsWith($currentUserProfilePath, [System.StringComparison]::OrdinalIgnoreCase)) {
         Write-Error "La nueva ubicacion base no puede estar dentro de tu perfil de usuario actual ('$currentUserProfilePath')."
         Read-Host "`nOperacion abortada. Presiona Enter para volver..."
         return
    }

    $selectableFolders = $folderMappings.Keys | Sort-Object
    $folderItems = @()
    foreach ($folderName in $selectableFolders) {
        $folderItems += [PSCustomObject]@{
            Name     = $folderName
            Selected = $false
        }
    }

    $choice = ''
    while ($choice.ToUpper() -ne 'C' -and $choice.ToUpper() -ne 'V') {
        Clear-Host
        Write-Host "=======================================================" -ForegroundColor Cyan
        Write-Host "      Selecciona las Carpetas de Usuario a Reubicar    " -ForegroundColor Cyan
        Write-Host "=======================================================" -ForegroundColor Cyan
        Write-Host "Nueva Ubicacion Base: $newBasePath" -ForegroundColor Yellow
        Write-Host "Marca las carpetas que deseas mover a esta nueva ubicacion."
        Write-Host ""
        
        for ($i = 0; $i -lt $folderItems.Count; $i++) {
            $item = $folderItems[$i]
            $status = if ($item.Selected) { "[X]" } else { "[ ]" }
            $currentPath = (Get-ItemProperty -Path $registryPath -Name $folderMappings[$item.Name].RegValue -ErrorAction SilentlyContinue).($folderMappings[$item.Name].RegValue)
            $currentPathExpanded = try { [Environment]::ExpandEnvironmentVariables($currentPath) } catch { $currentPath }
            Write-Host ("   [{0}] {1} {2,-12} -> Actual: {3}" -f ($i + 1), $status, $item.Name, $currentPathExpanded)
        }
        
        $selectedCount = $folderItems.Where({$_.Selected}).Count
        if ($selectedCount -gt 0) {
            Write-Host ""
            Write-Host "   ($selectedCount carpeta(s) seleccionada(s))" -ForegroundColor Cyan
        }

        Write-Host "`n--- Acciones ---" -ForegroundColor Yellow
        Write-Host "   [Numero] Marcar/Desmarcar        [T] Marcar Todas"
        Write-Host "   [C] Continuar con la Reubicacion [N] Desmarcar Todas"
        Write-Host ""
        Write-Host "   [V] Cancelar y Volver" -ForegroundColor Red
        Write-Host ""
        $choice = Read-Host "Selecciona una opcion"

        if ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $folderItems.Count) {
            $index = [int]$choice - 1
            $folderItems[$index].Selected = -not $folderItems[$index].Selected
        } elseif ($choice.ToUpper() -eq 'T') { $folderItems.ForEach({$_.Selected = $true}) }
        elseif ($choice.ToUpper() -eq 'N') { $folderItems.ForEach({$_.Selected = $false}) }
        elseif ($choice.ToUpper() -notin @('C', 'V')) {
             Write-Warning "Opcion no valida." ; Start-Sleep -Seconds 1
        }
    }

    if ($choice.ToUpper() -eq 'V') {
        Write-Host "Operacion cancelada por el usuario." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    $foldersToProcess = $folderItems | Where-Object { $_.Selected }
    if ($foldersToProcess.Count -eq 0) {
        Write-Warning "No se selecciono ninguna carpeta para mover."
        Start-Sleep -Seconds 2
        return
    }

    Clear-Host
    Write-Host "--- RESUMEN DE LA REUBICACION ---" -ForegroundColor Cyan
    Write-Host "Nueva Ubicacion Base: $newBasePath"
    Write-Host "Se modificaran las siguientes carpetas:" -ForegroundColor Yellow
    
    $operations = @()
    foreach ($folder in $foldersToProcess) {
        $regValueName = $folderMappings[$folder.Name].RegValue
        $currentPathReg = (Get-ItemProperty -Path $registryPath -Name $regValueName -ErrorAction SilentlyContinue).($regValueName)
        $currentPathExpanded = try { [Environment]::ExpandEnvironmentVariables($currentPathReg) } catch { $currentPathReg }
        $newFolderName = $folderMappings[$folder.Name].DefaultName
        $newFullPath = Join-Path -Path $newBasePath -ChildPath $newFolderName

        Write-Host " - $($folder.Name)"
        Write-Host "     Ruta Actual Registrada: $currentPathExpanded" -ForegroundColor Gray
        Write-Host "     NUEVA Ruta a Registrar: $newFullPath" -ForegroundColor Green
        
        $operations += [PSCustomObject]@{
            Name = $folder.Name
            RegValueName = $regValueName
            CurrentPath = $currentPathExpanded
            NewPath = $newFullPath
        }
    }

    Write-Warning "`n¡ADVERTENCIA MUY IMPORTANTE!"
    Write-Warning "- Cierra TODAS las aplicaciones que puedan estar usando archivos de estas carpetas."
    Write-Warning "- Si eliges 'Mover y Registrar', el proceso puede tardar MUCHO tiempo."
    Write-Warning "- NO interrumpas el proceso una vez iniciado."

    Write-Host ""
    Write-Host "--- TIPO DE ACCION ---" -ForegroundColor Yellow
    Write-Host "   [M] Mover Archivos Y Actualizar Registro (Accion Completa, Lenta)"
    Write-Host "   [R] Solo Actualizar Registro (Rapido - ¡ASEGURATE de que los archivos ya estan en el destino" -ForegroundColor Red
    Write-Host "       o el destino esta vacio!)" -ForegroundColor Red
    Write-Host "   [N] Cancelar"
    
    $actionChoice = Read-Host "`nElige el tipo de accion a realizar"
    $actionType = ''

    switch ($actionChoice.ToUpper()) {
        'M' { $actionType = 'MoveAndRegister' }
        'R' { $actionType = 'RegisterOnly' }
        default {
            Write-Host "Operacion cancelada por el usuario." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return
        }
    }

    Write-Warning "`nConfirmacion Final:"
    $confirmation = Read-Host "¿Estas COMPLETAMENTE SEGURO de continuar con la accion '$actionType'? (Escribe 'SI' para confirmar)"
    if ($confirmation -ne 'SI') {
        Write-Host "Operacion cancelada por el usuario." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        return
    }

    Write-Host "`n[+] Iniciando proceso. NO CIERRES ESTA VENTANA..." -ForegroundColor Yellow
    Write-Log -LogLevel INFO -Message "REUBICACION: Iniciando proceso con accion '$actionType' para $($operations.Count) carpetas hacia '$newBasePath'."
    $globalSuccess = $true
    $explorerRestartNeeded = $false

    foreach ($op in $operations) {
        Write-Host "`n--- Procesando Carpeta: $($op.Name) ---" -ForegroundColor Cyan
        
        # 1. Crear directorio de destino (Siempre necesario)
        Write-Host "  [1/3] Asegurando directorio de destino '$($op.NewPath)'..." -ForegroundColor Gray
        $destinationDirCreated = $false
        try {
            if (-not (Test-Path $op.NewPath)) {
                New-Item -Path $op.NewPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                 Write-Host "  -> Directorio creado." -ForegroundColor Green
            } else {
                 Write-Host "  -> Directorio ya existe." -ForegroundColor Gray
            }
            $destinationDirCreated = $true
        } catch {
            Write-Error "  -> FALLO al crear el directorio de destino. Omitiendo carpeta '$($op.Name)'. Error: $($_.Exception.Message)"
            Write-Log -LogLevel ERROR -Message "REUBICACION: Fallo al crear directorio '$($op.NewPath)'. Carpeta '$($op.Name)' omitida. Error: $($_.Exception.Message)"
            $globalSuccess = $false
            continue
        }

        # 2. Mover contenido (Solo si se eligio la accion completa)
        $robocopySucceeded = $true # Asumimos exito si no se mueve nada
        if ($actionType -eq 'MoveAndRegister') {
            Write-Host "  [2/3] Moviendo contenido desde '$($op.CurrentPath)'..." -ForegroundColor Gray
            Write-Warning "      (Esto puede tardar. Se abrira una ventana de Robocopy por cada carpeta)"
            
            $robocopyLogDir = Join-Path (Split-Path -Parent $PSScriptRoot) "Logs"
            $robocopyLogFile = Join-Path $robocopyLogDir "Robocopy_Move_$($op.Name)_$(Get-Date -Format 'yyyyMMddHHmmss').log"
            $robocopyArgs = @(
                "`"$($op.CurrentPath)`"" # Origen
                "`"$($op.NewPath)`""    # Destino
                "/MOVE"                 # Mueve archivos Y directorios (los elimina del origen)
                "/E"                    # Copia subdirectorios, incluidos los vacios
                "/COPY:DAT"             # Copia Datos, Atributos, Timestamps
                "/DCOPY:T"              # Copia Timestamps de directorios
                "/R:2"                  # Numero de reintentos en caso de fallo
                "/W:5"                  # Tiempo de espera entre reintentos
                "/MT:8"                 # Usa 8 hilos para copiar (puede acelerar en discos rapidos)
                "/NJH"                  # No Job Header
                "/NJS"                  # No Job Summary
                "/NP"                   # No Progress
                "/TEE"                  # Muestra en consola Y en log
                "/LOG:`"$robocopyLogFile`"" # Guarda el log detallado
            )
            
            Write-Log -LogLevel ACTION -Message "REUBICACION: Iniciando Robocopy /MOVE para '$($op.Name)' de '$($op.CurrentPath)' a '$($op.NewPath)'."
            
            $processInfo = Start-Process "robocopy.exe" -ArgumentList $robocopyArgs -Wait -PassThru -WindowStyle Minimized
            
            if ($processInfo.ExitCode -ge 8) {
                Write-Error "  -> FALLO Robocopy al mover '$($op.Name)' (Codigo de salida: $($processInfo.ExitCode))."
                Write-Error "     Los archivos pueden estar parcialmente movidos. Revisa el log: $robocopyLogFile"
                Write-Log -LogLevel ERROR -Message "REUBICACION: Robocopy fallo para '$($op.Name)' (Codigo: $($processInfo.ExitCode)). Log: $robocopyLogFile"
                $globalSuccess = $false
                $robocopySucceeded = $false 
                # NO continuamos con el cambio de registro si el movimiento fallo
                continue 
            } else {
                 Write-Host "  -> Movimiento completado (Codigo Robocopy: $($processInfo.ExitCode))." -ForegroundColor Green
                 Write-Log -LogLevel ACTION -Message "REUBICACION: Robocopy completado para '$($op.Name)' (Codigo: $($processInfo.ExitCode)). Log: $robocopyLogFile"
            }
        } else { # Si $actionType es 'RegisterOnly'
             Write-Host "  [2/3] Omitiendo movimiento de archivos (Modo 'Solo Registrar')." -ForegroundColor Gray
        }

        # 3. Actualizar el Registro (Si la creacion del dir fue exitosa Y (Robocopy fue exitoso O se eligio 'Solo Registrar'))
        if ($destinationDirCreated -and $robocopySucceeded) {
            Write-Host "  [3/3] Actualizando la ruta en el Registro..." -ForegroundColor Gray
            try {
                Set-ItemProperty -Path $registryPath -Name $op.RegValueName -Value $op.NewPath -Type String -Force -ErrorAction Stop
                Write-Host "  -> Registro actualizado exitosamente." -ForegroundColor Green
                Write-Log -LogLevel ACTION -Message "REUBICACION: Registro actualizado para '$($op.Name)' a '$($op.NewPath)'."
                $explorerRestartNeeded = $true
            } catch {
                Write-Error "  -> FALLO CRITICO al actualizar el registro para '$($op.Name)'. Error: $($_.Exception.Message)"
                # Distinguir el mensaje de error segun la accion
                if ($actionType -eq 'MoveAndRegister') {
                    Write-Error "     La carpeta se movio, pero Windows aun apunta a la ubicacion antigua."
                } else {
                    Write-Error "     Windows no pudo ser actualizado para apuntar a la nueva ubicacion."
                }
                Write-Log -LogLevel ERROR -Message "REUBICACION CRITICO: Fallo al actualizar registro para '$($op.Name)' a '$($op.NewPath)'. Error: $($_.Exception.Message)"
                $globalSuccess = $false
            }
        } else {
             Write-Warning "  [3/3] Omitiendo actualizacion de registro debido a error previo en este paso."
        }
    }

    Write-Host "`n--- PROCESO DE REUBICACION FINALIZADO ---" -ForegroundColor Cyan
    if ($globalSuccess) {
        Write-Host "[EXITO] Todas las carpetas seleccionadas se han procesado." -ForegroundColor Green
        Write-Log -LogLevel INFO -Message "REUBICACION: Proceso finalizado con exito aparente para las carpetas seleccionadas (Accion: $actionType)."
    } else {
        Write-Error "[FALLO PARCIAL] Ocurrieron errores durante el proceso. Revisa los mensajes anteriores y los logs."
        Write-Log -LogLevel ERROR -Message "REUBICACION: Proceso finalizado con uno o mas errores (Accion: $actionType)."
    }

    if ($explorerRestartNeeded) {
        Write-Host "\nEs necesario reiniciar el Explorador de Windows (o cerrar sesion y volver a iniciar) para que los cambios surtan efecto." -ForegroundColor Yellow
        $restartChoice = Read-Host "¿Deseas reiniciar el Explorador ahora? (S/N)"
        if ($restartChoice.ToUpper() -eq 'S') {
            Invoke-ExplorerRestart
        }
    }

    Read-Host "`nPresiona Enter para volver al menu..."
}

# ===================================================================
# --- MODULO DE RESPALDO DE DATOS ---
# ===================================================================

function Start-ProfileGuardMenu {

	Invoke-FullRepoUpdater

    $mainChoice = ''
    do {
        # 1. Buscamos todas las tareas "Backup_*"
        $allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        $scheduledBackups = @($allTasks | Where-Object { $_.TaskName -like "Backup_*" })
        
        # 2. Filtramos las activas
        $activeScheduled = @($scheduledBackups | Where-Object { $_.State -eq "Ready" -or $_.State -eq "Running" })
        
        $nextScheduledRun = "No programado"
        $nextTaskName = ""

        if ($activeScheduled.Count -gt 0) {
            try {
                # Obtenemos la informacion de tiempo de TODAS las tareas y ordenamos por la mas cercana
                $nextInfo = $activeScheduled | Get-ScheduledTaskInfo | Sort-Object -Property NextRunTime | Select-Object -First 1
                
                if ($nextInfo.NextRunTime) {
                    $nextScheduledRun = $nextInfo.NextRunTime.ToString("yyyy-MM-dd HH:mm")
                    $nextTaskName = "($($nextInfo.TaskName))"
                }
            } catch {
                $nextScheduledRun = "Pendiente (calculando...)"
            }
        }

        $headerInfo = "Usuario: $($env:USERNAME) | Equipo: $($env:COMPUTERNAME)"
        Clear-Host
        Write-Host "=======================================================" -ForegroundColor Cyan
        Write-Host ("      ProfileGuard v{0} by SOFTMAXTER" -f $script:Version) -ForegroundColor Cyan
        Write-Host ($headerInfo.PadLeft(55)) -ForegroundColor Gray
        Write-Host "=======================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "--- Estado de Respaldo Automatico ---" -ForegroundColor Yellow
        
        if ($nextTaskName) {
             Write-Host "   Proximo respaldo: $nextScheduledRun $nextTaskName" -ForegroundColor White
        } else {
             Write-Host "   Proximo respaldo: $nextScheduledRun"
        }
        
        Write-Host "   Respaldos automaticos activos: $([int]$activeScheduled.Count)"
        Write-Host ""
        Write-Host "--- Acciones de Respaldo ---" -ForegroundColor Yellow
        Write-Host "   [1] Respaldo Manual Inmediato (Cifrado o Simple)" -ForegroundColor White
        Write-Host "       (Crea un respaldo Completo, Incremental o Diferencial ahora)" -ForegroundColor Gray
        Write-Host "   [2] Configurar Respaldo Automatico Programado" -ForegroundColor White
        Write-Host "       (Establece horarios para respaldos sin intervencion)" -ForegroundColor Gray
		Write-Host "   [2a] Editar/Eliminar Tarea Programada" -ForegroundColor Yellow
        Write-Host "        (Modificar horario, tipo o borrar tareas existentes)" -ForegroundColor Gray
        Write-Host "   [3] Administrar Respaldos Existentes" -ForegroundColor White
        Write-Host "       (Ver, restaurar o eliminar respaldos anteriores)" -ForegroundColor Gray
        Write-Host "   [4] Verificar Integridad de Respaldos" -ForegroundColor White
        Write-Host "       (Comprueba que tus respaldos esten completos y sin corrupcion)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "--- Herramientas ---" -ForegroundColor Yellow
        Write-Host "   [5] Respaldo Simple (Sincronizacion Robocopy)" -ForegroundColor Green
        Write-Host "       (Copia rapida y sin cifrar. Ideal para copias locales/NAS)" -ForegroundColor Gray
        Write-Host "   [6] Reubicar Carpetas de Usuario (Escritorio, Documentos, etc.)" -ForegroundColor Yellow
        Write-Host "       (Mueve tus carpetas personales a otra unidad o ubicacion)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "-------------------------------------------------------"
        Write-Host ""
        Write-Host "   [L] VISOR DE REGISTROS (LOGS)" -ForegroundColor Gray
        Write-Host "   [S] Salir del script" -ForegroundColor Red
        Write-Host ""
        
        $mainChoice = Read-Host "Selecciona una opcion"
        if ($mainChoice) { 
             Write-Log -LogLevel INFO -Message "BACKUP: Usuario selecciono la opcion '$($mainChoice.ToUpper())'."
        }
        
        switch ($mainChoice.ToUpper()) {
            '1' { Invoke-BackupCreation }
            '2' { Configure-AutoBackupSchedule }
			'2A' { Edit-ScheduledTask }
            '3' { Manage-ExistingBackups }
            '4' { Verify-BackupIntegrity }
            '5' { Invoke-SimpleRobocopyBackupMenu }
            '6' { Move-UserProfileFolders }
            'L' {
                # --- Definir las rutas de los logs ---
                $parentDir = Split-Path -Parent $PSScriptRoot
                $generalLogFile = Join-Path -Path $parentDir -ChildPath "Logs\Registro.log"

                $scheduledLogFile = Join-Path -Path $env:ProgramData -ChildPath "ProfileGuard_Logs\Backup_Log.txt"

                # --- Sub-menú de selección ---
                Clear-Host
                Write-Host "`n========================================" -ForegroundColor Cyan
                Write-Host "    VISOR DE REGISTROS (LOGS)    " -ForegroundColor White
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host "`nSelecciona el archivo de registro que deseas abrir:" -ForegroundColor Yellow
                Write-Host "`n   [1] Registro General de Actividad" -ForegroundColor White
                Write-Host "       (Acciones realizadas en ProfileGuard)" -ForegroundColor Gray
                Write-Host "`n   [2] Registro de Tareas Programadas" -ForegroundColor White
                Write-Host "       (Ejecuciones automaticas y sus resultados, por el Respaldo Automatico)" -ForegroundColor Gray
                Write-Host "`n   [V] Volver al menu principal" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Cyan

                $logChoice = Read-Host "`nElige una opcion (1-2, V)"

                switch ($logChoice.ToUpper()) {
                    '1' {
                        if (Test-Path $generalLogFile) {
                            Write-Host "`n[+] Abriendo registro general..." -ForegroundColor Green
                            Start-Process notepad.exe -ArgumentList $generalLogFile
                        } else {
                            Write-Warning "`nEl archivo de registro general ('$generalLogFile') aun no existe."
                            Read-Host "Presiona Enter para continuar..."
                        }
                    }
                    '2' {
                        if (Test-Path $scheduledLogFile) {
                            Write-Host "`n[+] Abriendo registro de tareas programadas..." -ForegroundColor Green
                            Start-Process notepad.exe -ArgumentList $scheduledLogFile
                        } else {
                            Write-Warning "`nEl registro de tareas programadas ('$scheduledLogFile') no se encuentra."
                            Write-Host "Posiblemente aun no se ha ejecutado ninguna tarea automatica." -ForegroundColor Gray
                            Read-Host "Presiona Enter para continuar..."
                        }
                    }
                    'V' {
                        # No hace nada, vuelve al menu principal
                    }
                    default {
                        Write-Warning "Opcion no valida."
                        Start-Sleep -Seconds 1
                    }
                }
            }
            'S' { Write-Host "`nGracias por usar ProfileGuard by SOFTMAXTER!" }
            default {
                if (-not [string]::IsNullOrWhiteSpace($mainChoice)) {
                    Write-Host "`n[ERROR] Opcion no valida. Por favor, intenta de nuevo." -ForegroundColor Red
                    Read-Host "`nPresiona Enter para continuar..."
                }
            }
        }

    } while ($mainChoice.ToUpper() -ne 'S')

    Write-Log -LogLevel INFO -Message "ProfileGuard cerrado por el usuario."
    Write-Log -LogLevel INFO -Message "================================================="
}

if ($MyInvocation.InvocationName -ne '.') {
    Start-ProfileGuardMenu
}
