<#
    RDP Security Toolkit
    - Lokale Root-CA
    - Server- & Clientzertifikate
    - RDP TLS-Bindung
    - Firewall-HÃ¤rtung
    - Brute-Force-Protection
    - Zertifikatserneuerung
    - HTML-Report
#>

$ErrorActionPreference = "Stop"
$BasePath = "$env:USERPROFILE\Desktop\RDP-PKI"
New-Item -ItemType Directory -Force -Path $BasePath | Out-Null

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# ================================
# 1. Root-CA erstellen
# ================================
function New-LocalRootCA {
    Write-Info "Erstelle lokale Root-CA..."

    $existing = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=LocalDevRootCA" }
    if ($existing) {
        Write-Warn "Root-CA existiert bereits. Verwende bestehende."
        return $existing | Select-Object -First 1
    }

    $rootCA = New-SelfSignedCertificate `
        -Type Custom `
        -KeyUsage CertSign, CRLSign, DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -Subject "CN=LocalDevRootCA" `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -HashAlgorithm "SHA256" `
        -NotAfter (Get-Date).AddYears(10) `
        -TextExtension @("2.5.29.19={critical}{text}ca=true&pathlength=1")

    $caPath = Join-Path $BasePath "RootCA.cer"
    Export-Certificate -Cert $rootCA -FilePath $caPath | Out-Null
    Import-Certificate -FilePath $caPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

    Write-Ok "Root-CA erstellt und installiert."
    return $rootCA
}

# ================================
# 2. RDP-Serverzertifikat erstellen
# ================================
function New-RdpServerCert {
    param([Parameter(Mandatory=$true)] $RootCA)

    Write-Info "Erstelle RDP-Serverzertifikat..."

    $serverCert = New-SelfSignedCertificate `
        -Type Custom `
        -DnsName "localhost","127.0.0.1",$env:COMPUTERNAME `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -Subject ("CN={0}" -f $env:COMPUTERNAME) `
        -Signer $RootCA `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -HashAlgorithm "SHA256" `
        -NotAfter (Get-Date).AddYears(3) `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

    $serverPfx = Join-Path $BasePath "RdpServer.pfx"
    $serverPwd = ConvertTo-SecureString "server123" -AsPlainText -Force
    Export-PfxCertificate -Cert $serverCert -FilePath $serverPfx -Password $serverPwd | Out-Null

    Write-Ok "RDP-Serverzertifikat erstellt."
    return $serverCert
}

# ================================
# 3. RDP-Clientzertifikat erstellen
# ================================
function New-RdpClientCert {
    param([Parameter(Mandatory=$true)] $RootCA)

    Write-Info "Erstelle Clientzertifikat..."

    $clientCert = New-SelfSignedCertificate `
        -Type Custom `
        -Subject "CN=RdpClient" `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -Signer $RootCA `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -HashAlgorithm "SHA256" `
        -NotAfter (Get-Date).AddYears(3) `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")

    $clientPfx = Join-Path $BasePath "RdpClient.pfx"
    $clientPwd = ConvertTo-SecureString "client123" -AsPlainText -Force
    Export-PfxCertificate -Cert $clientCert -FilePath $clientPfx -Password $clientPwd | Out-Null

    Write-Ok "Clientzertifikat erstellt."
    return $clientCert
}

# ================================
# 4. RDP TLS konfigurieren
# ================================
function Configure-RdpTls {
    param([Parameter(Mandatory=$true)] $ServerCert)

    Write-Info "Konfiguriere RDP fÃ¼r TLS..."

    $thumb = ($ServerCert.Thumbprint).Replace(" ", "")
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

    Set-ItemProperty -Path $regPath -Name "SSLCertificateSHA1Hash" -Value $thumb
    Set-ItemProperty -Path $regPath -Name "UserAuthentication" -Value 1
    Set-ItemProperty -Path $regPath -Name "SecurityLayer" -Value 2
    Set-ItemProperty -Path $regPath -Name "MinEncryptionLevel" -Value 3

    $schannel = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    New-Item -Path $schannel -Force | Out-Null
    Set-ItemProperty -Path $schannel -Name "Enabled" -Value 1
    Set-ItemProperty -Path $schannel -Name "DisabledByDefault" -Value 0

    Restart-Service TermService -Force

    Write-Ok "RDP TLS-Konfiguration abgeschlossen."
}

# ================================
# 5. Firewall-HÃ¤rtung
# ================================
function Harden-RdpFirewall {
    Write-Info "HÃ¤rten der Firewall..."

    Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Disable-NetFirewallRule | Out-Null

    New-NetFirewallRule `
        -DisplayName "RDP Restricted" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 3389 `
        -Action Allow `
        -Profile Any `
        -RemoteAddress "192.168.0.0/24" `
        -ErrorAction SilentlyContinue | Out-Null

    Write-Ok "Firewall gehÃ¤rtet."
}

# ================================
# 6. Brute-Force-Protection
# ================================
function Enable-BruteforceProtection {
    Write-Info "Aktiviere Brute-Force-Protection..."

    secedit /export /cfg "$BasePath\secpol.cfg" | Out-Null
    $cfg = Get-Content "$BasePath\secpol.cfg"

    $cfg = $cfg -replace 'LockoutBadCount = \d+', 'LockoutBadCount = 5'
    $cfg = $cfg -replace 'ResetLockoutCount = \d+', 'ResetLockoutCount = 15'
    $cfg = $cfg -replace 'LockoutDuration = \d+', 'LockoutDuration = 15'

    $cfg | Set-Content "$BasePath\secpol.cfg"
    secedit /configure /db "$BasePath\secpol.sdb" /cfg "$BasePath\secpol.cfg" /areas SECURITYPOLICY | Out-Null

    Write-Ok "Brute-Force-Protection aktiviert."
}

# ================================
# 7. Zertifikatserneuerung
# ================================
function Renew-RdpServerCert {
    Write-Info "PrÃ¼fe Zertifikatserneuerung..."

    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq ("CN={0}" -f $env:COMPUTERNAME) } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $cert) {
        Write-Warn "Kein Serverzertifikat gefunden."
        return
    }

    $daysLeft = (New-TimeSpan -Start (Get-Date) -End $cert.NotAfter).Days
    if ($daysLeft -gt 30) {
        Write-Ok "Zertifikat noch gÃ¼ltig."
        return
    }

    Write-Warn "Zertifikat lÃ¤uft bald ab â€“ erneuere..."

    $rootCA = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq "CN=LocalDevRootCA" } |
        Select-Object -First 1

    $newCert = New-RdpServerCert -RootCA $rootCA
    Configure-RdpTls -ServerCert $newCert

    Write-Ok "Zertifikat erneuert."
}

# ================================
# 8. HTML-Report
# ================================
function New-RdpSecurityReport {
    Write-Info "Erstelle HTML-Report..."

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $props = Get-ItemProperty -Path $regPath

    $cert = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq ("CN={0}" -f $env:COMPUTERNAME) } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    $obj = [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        RdpTlsThumbprint    = $props.SSLCertificateSHA1Hash
        NLA_Enabled         = ($props.UserAuthentication -eq 1)
        SecurityLayer       = $props.SecurityLayer
        MinEncryptionLevel  = $props.MinEncryptionLevel
        Cert_Subject        = $cert.Subject
        Cert_NotAfter       = $cert.NotAfter
        Cert_DaysLeft       = (New-TimeSpan -Start (Get-Date) -End $cert.NotAfter).Days
    }

    $pre = "<h1>RDP Security Report</h1><p>Stand: $(Get-Date)</p>"
    $html = $obj | ConvertTo-Html -Title "RDP Security Report" -PreContent $pre

    $reportPath = Join-Path $BasePath "RdpSecurityReport.html"
    $html | Set-Content $reportPath -Encoding UTF8

    Write-Ok "HTML-Report erstellt."
}

# ================================
# MAIN
# ================================
Write-Host "=== RDP Security Toolkit startet ===" -ForegroundColor Magenta

$rootCA     = New-LocalRootCA
$serverCert = New-RdpServerCert -RootCA $rootCA
$clientCert = New-RdpClientCert -RootCA $rootCA

Configure-RdpTls -ServerCert $serverCert
Harden-RdpFirewall
Enable-BruteforceProtection
Renew-RdpServerCert
New-RdpSecurityReport

Write-Host ("=== Fertig. Alle Artefakte: " + $BasePath + " ===") -ForegroundColor Magenta
