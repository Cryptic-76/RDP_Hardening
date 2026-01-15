# RDP Security Toolkit

Das **RDP Security Toolkit** ist ein PowerShell‑basiertes Hardening‑Framework, das Windows‑Systeme gegen unbefugte Remotezugriffe absichert.  
Es automatisiert die Erstellung einer lokalen Zertifizierungsstelle, bindet ein TLS‑Zertifikat an RDP, härtet Firewall‑Regeln, aktiviert Brute‑Force‑Schutz und erzeugt einen vollständigen Sicherheitsreport.

Das Toolkit ist modular aufgebaut und kann jederzeit erweitert werden.

---

## 🚀 Funktionsübersicht

Das Skript führt folgende Schritte automatisch aus:

### 1. Lokale Root‑CA erstellen
- Erstellt eine lokale Zertifizierungsstelle (Root‑CA)
- Installiert das Root‑Zertifikat im vertrauenswürdigen Stammzertifikatsspeicher
- Exportiert die CA als `RootCA.cer`

### 2. RDP‑Serverzertifikat erzeugen
- Erstellt ein TLS‑Zertifikat für den RDP‑Dienst
- Enthält SAN‑Einträge für:
  - `localhost`
  - `127.0.0.1`
  - Computername
- Exportiert das Zertifikat als `RdpServer.pfx`

### 3. RDP‑Clientzertifikat erzeugen
- Erstellt ein Client‑Authentifizierungszertifikat
- Exportiert es als `RdpClient.pfx`

### 4. RDP auf TLS‑Zertifikat binden
- Bindet das Serverzertifikat an den RDP‑Dienst
- Aktiviert:
  - TLS‑only Mode
  - Network Level Authentication (NLA)
  - Hohe Verschlüsselungsstufe
- Erzwingt TLS 1.2 für RDP
- Startet den RDP‑Dienst neu

### 5. Firewall‑Härtung
- Deaktiviert alle Standard‑RDP‑Regeln
- Erstellt eine eigene Regel:
  - Port: **3389**
  - Remote‑Netz: **192.168.0.0/24** (anpassbar)
  - Nur eingehender Verkehr erlaubt

### 6. Brute‑Force‑Protection
- Setzt Account‑Lockout‑Richtlinien:
  - 5 Fehlversuche
  - 15 Minuten Sperrzeit
  - 15 Minuten Reset‑Timer
- Exportiert die Richtlinie in die PKI‑Struktur

### 7. Zertifikatserneuerung
- Prüft das aktuelle RDP‑Zertifikat
- Erneuert es automatisch, wenn weniger als 30 Tage Restlaufzeit vorhanden sind

### 8. HTML‑Sicherheitsreport
Erstellt eine Datei:
