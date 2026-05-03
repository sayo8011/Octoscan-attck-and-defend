# ============================================================
#   OctoDefend-AD -- Server Side
#   Verificador y corrector de seguridad para Windows Server
#   Laboratorio universitario - uso educativo
#   creado por: sayo
# ============================================================
# powershell -ExecutionPolicy Bypass -File OctoDefend-Server.ps1
# ============================================================

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +=========================================================+" -ForegroundColor Green
    Write-Host "  |       OctoDefend-AD  --  Server Side                   |" -ForegroundColor Green
    Write-Host "  |       Verificador y Corrector de Seguridad AD          |" -ForegroundColor Green
    Write-Host "  +=========================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Laboratorio universitario - uso educativo" -ForegroundColor Yellow
    Write-Host "  creado por: sayo" -ForegroundColor DarkGray
    Write-Host ""
}

$global:PASS  = 0
$global:FAIL  = 0
$global:FIXED = 0
$global:WARN  = 0
$global:ReportLines = @()
$global:ReportPath = ""

function Log-Ok    { param($msg) Write-Host "  [OK]    $msg" -ForegroundColor Green;  $global:PASS++;  $global:ReportLines += "[OK]    $msg" }
function Log-Fail  { param($msg) Write-Host "  [FAIL]  $msg" -ForegroundColor Red;    $global:FAIL++;  $global:ReportLines += "[FAIL]  $msg" }
function Log-Fixed { param($msg) Write-Host "  [FIXED] $msg" -ForegroundColor Cyan;   $global:FIXED++; $global:ReportLines += "[FIXED] $msg" }
function Log-Warn  { param($msg) Write-Host "  [WARN]  $msg" -ForegroundColor Yellow; $global:WARN++;  $global:ReportLines += "[WARN]  $msg" }
function Log-Info  { param($msg) Write-Host "  [INFO]  $msg" -ForegroundColor White;                   $global:ReportLines += "[INFO]  $msg" }
function Log-Section { param($msg)
    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor Blue
    Write-Host "  >> $msg" -ForegroundColor White
    Write-Host "  ==========================================" -ForegroundColor Blue
    Write-Host ""
    $global:ReportLines += "`n========================================`n  $msg`n========================================"
}

function Setup-Report {
    Write-Host "  Configuracion del reporte" -ForegroundColor White
    Write-Host "  ------------------------------------------" -ForegroundColor White
    Write-Host ""
    $basePath = Read-Host "  [?] Donde guardar el reporte? (ej: C:\Users\Administrador\Desktop)"
    if (-not (Test-Path $basePath)) {
        Write-Host "  Ruta no encontrada, usando Desktop" -ForegroundColor Yellow
        $basePath = [Environment]::GetFolderPath("Desktop")
    }
    $nombre = Read-Host "  [?] Nombre del reporte (ej: auditoria_1)"
    if ([string]::IsNullOrWhiteSpace($nombre)) { $nombre = (Get-Date -Format "yyyyMMdd_HHmmss") }
    $nombre = $nombre -replace '[^\w\-]', '_'
    $folder = Join-Path $basePath "octodefend_$nombre"
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $global:ReportPath = Join-Path $folder "reporte_seguridad.txt"
    $ts = Get-Date
    $global:ReportLines += "OctoDefend-AD Server Side | $ts"
    Log-Info "Reporte en: $folder"
    Write-Host ""
    Read-Host "  Presiona ENTER para iniciar la auditoria"
}

function Check-Fix-Firewall {
    Log-Section "FIREWALL -- PUERTOS CRITICOS"
    $puertos = @(
        @{Puerto=445;  Nombre="SMB";       Regla="Bloquear SMB 445"},
        @{Puerto=135;  Nombre="RPC";       Regla="Bloquear RPC 135"},
        @{Puerto=139;  Nombre="NetBIOS";   Regla="Bloquear NetBIOS 139"},
        @{Puerto=5985; Nombre="WinRM";     Regla="BLOCK WINRM 5985"},
        @{Puerto=5986; Nombre="WinRM-SSL"; Regla="BLOCK WINRM 5986"}
    )
    foreach ($p in $puertos) {
        $regla = Get-NetFirewallRule -DisplayName $p.Regla -ErrorAction SilentlyContinue
        if ($regla -and $regla.Enabled -eq "True" -and $regla.Action -eq "Block") {
            Log-Ok "Puerto $($p.Puerto) ($($p.Nombre)) -- bloqueado OK"
        } else {
            Log-Fail "Puerto $($p.Puerto) ($($p.Nombre)) -- NO bloqueado"
            Remove-NetFirewallRule -DisplayName $p.Regla -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $p.Regla `
                -Direction Inbound -Protocol TCP `
                -LocalPort $p.Puerto -Action Block | Out-Null
            Log-Fixed "Puerto $($p.Puerto) ($($p.Nombre)) -- bloqueado OK"
        }
    }
}

function Check-Fix-Anonimo {
    Log-Section "ENUMERACION ANONIMA (RestrictAnonymous)"
    $val = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymous" -ErrorAction SilentlyContinue).RestrictAnonymous
    if ($val -ge 1) {
        Log-Ok "RestrictAnonymous = $val -- enumeracion anonima bloqueada OK"
    } else {
        Log-Fail "RestrictAnonymous = $val -- enumeracion anonima PERMITIDA"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "RestrictAnonymous" -Value 1
        Log-Fixed "RestrictAnonymous configurado a 1 OK"
    }
}

function Check-Fix-SMBv1 {
    Log-Section "SMBv1 -- PROTOCOLO INSEGURO"
    $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
    if ($smb1 -eq $false) {
        Log-Ok "SMBv1 desactivado OK"
    } else {
        Log-Fail "SMBv1 ACTIVO -- protocolo inseguro habilitado"
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Log-Fixed "SMBv1 desactivado OK"
    }
}

function Check-Fix-SMBSigning {
    Log-Section "SMB SIGNING"
    $config   = Get-SmbServerConfiguration
    $required = $config.RequireSecuritySignature
    $enabled  = $config.EnableSecuritySignature
    if ($required -eq $true) {
        Log-Ok "SMB Signing requerido OK"
    } elseif ($enabled -eq $true) {
        Log-Warn "SMB Signing habilitado pero NO requerido -- corrigiendo"
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Log-Fixed "SMB Signing requerido ahora OK"
    } else {
        Log-Fail "SMB Signing DESACTIVADO"
        Set-SmbServerConfiguration -EnableSecuritySignature $true -Force
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Log-Fixed "SMB Signing activado y requerido OK"
    }
}

function Check-Fix-WinRM {
    Log-Section "WINRM -- ACCESO REMOTO"
    $svc = Get-Service WinRM -ErrorAction SilentlyContinue
    if ($svc.Status -eq "Stopped" -and $svc.StartType -eq "Disabled") {
        Log-Ok "WinRM detenido y desactivado OK"
        # FIX: Si WinRM esta detenido no intentamos acceder a WSMan
        return
    }
    Log-Fail "WinRM activo -- StartType=$($svc.StartType) Status=$($svc.Status)"
    try {
        $unencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction Stop).Value
        if ($unencrypted -eq "true") {
            Set-Item WSMan:\localhost\Service\AllowUnencrypted $false -ErrorAction SilentlyContinue
        }
    } catch { }
    Stop-Service WinRM -Force -ErrorAction SilentlyContinue
    Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue
    Log-Fixed "WinRM detenido y desactivado OK"
}

function Check-Fix-Passwords {
    Log-Section "POLITICA DE CONTRASENAS"

    # FIX: Usar net accounts y parsear por numero directamente de cada linea
    $policy = net accounts 2>$null

    # Longitud minima -- buscar la linea que tenga numeros relacionados con longitud
    $minLine = $policy | Where-Object { $_ -match "m.nima|minimum|minima" -and $_ -match "\d" } | Select-Object -First 1
    if ($minLine) {
        $minLen = [int]([regex]::Match($minLine, '\d+').Value)
    } else {
        $minLen = 0
    }

    if ($minLen -ge 10) {
        Log-Ok "Longitud minima = $minLen caracteres OK"
    } else {
        Log-Fail "Longitud minima = $minLen -- muy corta (minimo 10)"
        net accounts /minpwlen:10 | Out-Null
        Log-Fixed "Longitud minima configurada a 10 OK"
    }

    # Complejidad via secedit
    secedit /export /cfg "$env:TEMP\sec.cfg" /quiet 2>$null | Out-Null
    $secContent  = Get-Content "$env:TEMP\sec.cfg" -ErrorAction SilentlyContinue
    $complexLine = ($secContent | Select-String "PasswordComplexity" | Select-Object -First 1).ToString()
    if ($complexLine -match "= 1") {
        Log-Ok "Complejidad de contrasena activa OK"
    } else {
        Log-Fail "Complejidad de contrasena INACTIVA"
        Log-Warn "Activala en: secpol.msc -> Directiva de contrasenas -> Complejidad"
    }

    # Edad maxima -- buscar linea con "xpir" o "age" o "caducan"
    $maxLine = $policy | Where-Object { $_ -match "xpir|caducan|age|vencim" -and $_ -match "\d" } | Select-Object -First 1
    if ($maxLine) {
        $maxAge = [int]([regex]::Match($maxLine, '\d+').Value)
    } else {
        $maxAge = 0
    }

    if ($maxAge -le 90 -and $maxAge -gt 0) {
        Log-Ok "Edad maxima de contrasena = $maxAge dias OK"
    } else {
        Log-Fail "Edad maxima = $maxAge dias -- configurando a 60 dias"
        net accounts /maxpwage:60 | Out-Null
        Log-Fixed "Edad maxima configurada a 60 dias OK"
    }
}

function Check-Fix-Lockout {
    Log-Section "BLOQUEO DE CUENTA (Anti-BruteForce)"

    # FIX: Leer directamente el valor del registro en lugar de parsear net accounts
    $domain = $env:USERDOMAIN
    try {
        $acctPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $threshold  = $acctPolicy.LockoutThreshold
    } catch {
        # Si no hay AD module usar net accounts
        $policy    = net accounts 2>$null
        $lockLine  = $policy | Where-Object { $_ -match "bloqueo|lockout|threshold" -and $_ -match "\d" } | Select-Object -First 1
        if ($lockLine) {
            $threshold = [int]([regex]::Match($lockLine, '\d+').Value)
        } else {
            $threshold = 0
        }
    }

    if ($threshold -ge 3 -and $threshold -le 10) {
        Log-Ok "Umbral de bloqueo = $threshold intentos OK"
    } else {
        Log-Fail "Umbral de bloqueo = $threshold -- configurando proteccion anti fuerza bruta"
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
        Log-Fixed "Bloqueo configurado: 5 intentos / 30 min OK"
    }
}

function Check-Fix-LDAPSigning {
    Log-Section "LDAP SIGNING"
    $val = (Get-ItemProperty `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
    if ($val -eq 2) {
        Log-Ok "LDAP Signing = Requerir firma OK"
    } elseif ($val -eq 1) {
        Log-Warn "LDAP Signing = Negociar (no forzado) -- corrigiendo"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LDAPServerIntegrity" -Value 2
        Log-Fixed "LDAP Signing configurado a Requerir OK"
    } else {
        Log-Fail "LDAP Signing DESACTIVADO"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            -Name "LDAPServerIntegrity" -Value 2
        Log-Fixed "LDAP Signing activado OK"
    }
}

function Check-Fix-LLMNR {
    Log-Section "LLMNR Y NETBIOS"
    $llmnr = (Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    if ($llmnr -eq 0) {
        Log-Ok "LLMNR desactivado OK"
    } else {
        Log-Fail "LLMNR ACTIVO -- puede usarse para ataques de envenenamiento"
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
            -Name "EnableMulticast" -Value 0
        Log-Fixed "LLMNR desactivado OK"
    }
    $adapters  = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
    $netbiosOk = $true
    foreach ($a in $adapters) {
        if ($a.TcpipNetbiosOptions -ne 2) {
            $netbiosOk = $false
            $a.SetTcpipNetbios(2) | Out-Null
        }
    }
    if ($netbiosOk) {
        Log-Ok "NetBIOS desactivado en todos los adaptadores OK"
    } else {
        Log-Fixed "NetBIOS desactivado en adaptadores de red OK"
    }
}

function Check-Fix-Auditoria {
    Log-Section "AUDITORIA DE EVENTOS"

    # FIX: Usar GUIDs de subcategoria que funcionan en cualquier idioma
    # Alternativa: usar nombres en ingles que auditpol acepta siempre
    $checks = @(
        @{Sub="{0CCE923F-69AE-11D9-BED3-505054503030}"; Nombre="Validacion de credenciales"},
        @{Sub="{0CCE9215-69AE-11D9-BED3-505054503030}"; Nombre="Inicio de sesion"},
        @{Sub="{0CCE9217-69AE-11D9-BED3-505054503030}"; Nombre="Bloqueo de cuenta"},
        @{Sub="{0CCE9235-69AE-11D9-BED3-505054503030}"; Nombre="Administracion de cuentas de usuario"}
    )

    foreach ($c in $checks) {
        $output = auditpol /get /subcategory:"$($c.Sub)" 2>$null
        $linea  = $output | Where-Object { $_ -match $c.Sub -or ($output.IndexOf($_) -gt 0 -and $_ -match "\S") } | Select-Object -Last 1

        if ($linea -match "Success and Failure|Aciertos y errores") {
            Log-Ok "Auditoria '$($c.Nombre)' -- activa OK"
        } else {
            Log-Fail "Auditoria '$($c.Nombre)' -- INACTIVA o parcial"
            auditpol /set /subcategory:"$($c.Sub)" /success:enable /failure:enable | Out-Null
            Log-Fixed "Auditoria '$($c.Nombre)' -- activada OK"
        }
    }
}

function Show-Reporte {
    Log-Section "RESUMEN FINAL"
    Write-Host ""
    Write-Host "  Resultado de la auditoria" -ForegroundColor White
    Write-Host "  ------------------------------------------" -ForegroundColor White
    Write-Host ""
    Write-Host "  [OK]    Controles seguros:           $global:PASS"  -ForegroundColor Green
    Write-Host "  [FAIL]  Problemas encontrados:       $global:FAIL"  -ForegroundColor Red
    Write-Host "  [FIXED] Corregidos automaticamente:  $global:FIXED" -ForegroundColor Cyan
    Write-Host "  [WARN]  Advertencias:                $global:WARN"  -ForegroundColor Yellow
    Write-Host ""
    if ($global:FAIL -eq 0 -and $global:WARN -eq 0) {
        Write-Host "  El servidor esta correctamente configurado" -ForegroundColor Green
    } elseif ($global:FIXED -gt 0) {
        Write-Host "  Se corrigieron $global:FIXED problemas automaticamente" -ForegroundColor Cyan
        Write-Host "  Ejecuta gpupdate /force para aplicar todos los cambios" -ForegroundColor Yellow
    } else {
        Write-Host "  Hay problemas que requieren atencion manual" -ForegroundColor Yellow
    }
    Write-Host ""
    if ($global:FIXED -gt 0) {
        Log-Info "Aplicando politicas de grupo..."
        gpupdate /force | Out-Null
        Log-Info "gpupdate /force ejecutado OK"
    }
    $ts = Get-Date
    $global:ReportLines += "`nRESUMEN: OK=$global:PASS | FAIL=$global:FAIL | FIXED=$global:FIXED | WARN=$global:WARN | $ts"
    $global:ReportLines | Out-File -FilePath $global:ReportPath -Encoding UTF8
    Write-Host "  Reporte guardado en: $global:ReportPath" -ForegroundColor Green
    Write-Host ""
}

function Show-Menu {
    while ($true) {
        Write-Host ""
        Write-Host "  Que deseas hacer?" -ForegroundColor White
        Write-Host ""
        Write-Host "  [1]  Auditoria completa + autocorreccion (todo de una vez)" -ForegroundColor Cyan
        Write-Host "  [2]  Solo Firewall"            -ForegroundColor Cyan
        Write-Host "  [3]  Solo Enumeracion anonima" -ForegroundColor Cyan
        Write-Host "  [4]  Solo SMBv1 y SMB Signing" -ForegroundColor Cyan
        Write-Host "  [5]  Solo WinRM"               -ForegroundColor Cyan
        Write-Host "  [6]  Solo Contrasenas"         -ForegroundColor Cyan
        Write-Host "  [7]  Solo Bloqueo de cuenta"   -ForegroundColor Cyan
        Write-Host "  [8]  Solo LDAP Signing"        -ForegroundColor Cyan
        Write-Host "  [9]  Solo LLMNR y NetBIOS"     -ForegroundColor Cyan
        Write-Host "  [10] Solo Auditoria"           -ForegroundColor Cyan
        Write-Host "  [0]  Salir"                    -ForegroundColor Cyan
        Write-Host ""
        $op = Read-Host "  [?] Opcion"
        $global:PASS = 0; $global:FAIL = 0; $global:FIXED = 0; $global:WARN = 0
        switch ($op) {
            "1"  {
                Check-Fix-Firewall; Check-Fix-Anonimo; Check-Fix-SMBv1
                Check-Fix-SMBSigning; Check-Fix-WinRM; Check-Fix-Passwords
                Check-Fix-Lockout; Check-Fix-LDAPSigning; Check-Fix-LLMNR
                Check-Fix-Auditoria; Show-Reporte
            }
            "2"  { Check-Fix-Firewall;    Show-Reporte }
            "3"  { Check-Fix-Anonimo;     Show-Reporte }
            "4"  { Check-Fix-SMBv1; Check-Fix-SMBSigning; Show-Reporte }
            "5"  { Check-Fix-WinRM;       Show-Reporte }
            "6"  { Check-Fix-Passwords;   Show-Reporte }
            "7"  { Check-Fix-Lockout;     Show-Reporte }
            "8"  { Check-Fix-LDAPSigning; Show-Reporte }
            "9"  { Check-Fix-LLMNR;       Show-Reporte }
            "10" { Check-Fix-Auditoria;   Show-Reporte }
            "0"  { Write-Host "  Saliendo..." -ForegroundColor Green; exit }
            default { Write-Host "  Opcion invalida" -ForegroundColor Red }
        }
    }
}

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  ERROR: Ejecuta este script como Administrador" -ForegroundColor Red
    Write-Host "  Click derecho en PowerShell -> Ejecutar como administrador" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Presiona ENTER para salir"
    exit 1
}

Write-Banner
Setup-Report
Show-Menu
