# Upkeep für REDAXO 5

(https://github.com/KLXM/upkeep/blob/main/assets/css/screen.jpg?raw=true)


Ein modernes, schlankes AddOn für Wartungsarbeiten.

## Features der 1. Version

- **Frontend-Sperre** mit eleganter und anpassbarer Wartungsseite
- **Backend-Sperre** für Redakteure (Admins haben immer Zugriff)
- **Domain-spezifische Sperren** für Multidomains mit YRewrite
- **Passwort-Bypass** zum Testen des Frontends im Wartungsmodus
- **Automatischer Zugang** für angemeldete Benutzer (konfigurierbar)
- **IP-Whitelist** mit einfacher Übernahme der aktuellen IP-Adresse
- **Konfigurierbare HTTP-Statuscodes** (503, 403, 307) mit Retry-After Header
- **Konsolen-Befehle** für Remote-Management
- **API zur Steuerung aus der Ferne**


## Installation

1. Das AddOn über den REDAXO Installer installieren oder von GitHub herunterladen und installieren.
2. Konfigurieren Sie die Einstellungen über das REDAXO-Backend.

## Konfiguration

### Frontend-Wartungsmodus

Im Tab "Frontend" können Sie:
- Den Wartungsmodus aktivieren oder deaktivieren
- Den Titel und die Nachricht für die Wartungsseite anpassen
- Ein Passwort für den Testzugang festlegen
- Festlegen, ob angemeldete Benutzer Zugriff haben sollen
- IP-Adressen hinzufügen, die immer Zugriff haben
- Den HTTP-Statuscode (503, 403, 307) und Retry-After Header konfigurieren

### Backend

Im Tab "Backend" können Sie:
- Den Ukeep-Mode für das Backend aktivieren oder deaktivieren (sperrt alle Benutzer außer Administratoren)

### Domain-Einstellungen (nur bei YRewrite)

Wenn YRewrite installiert ist, können Sie im Tab "Domains":
- Den Ukeep-Mode für einzelne Domains aktivieren oder deaktivieren

## Anpassen der Ukeep-Seite

Sie können die Wartungsseite anpassen, indem Sie ein eigenes Fragment erstellen:

1. Erstellen Sie den Ordner `fragments/upkeep` in Ihrem Project-AddOn
2. Kopieren Sie die Datei `fragments/upkeep/frontend.php` aus dem Upkeep-AddOn dorthin
3. Passen Sie den Inhalt der Datei nach Ihren Wünschen an

## Konsolen-Befehle

Sie können den Wartungsmodus auch über die Konsole aktivieren oder deaktivieren:

```bash
# Frontend-Ukeep aktivieren
php redaxo/bin/console upkeep:mode frontend on

# Frontend-Ukeep deaktivieren
php redaxo/bin/console upkeep:mode frontend off

# Backend-Ukeep aktivieren
php redaxo/bin/console upkeep:mode backend on

# Backend-Ukeep deaktivieren
php redaxo/bin/console upkeep:mode backend off
```

## API-Referenz für das REDAXO Upkeep AddOn

Das Upkeep-AddOn bietet API, mit der Sie den Wartungsmodus programmgesteuert abfragen und ändern können. Dies ist besonders nützlich für automatisierte Wartungsabläufe, CI/CD-Pipelines oder Monitoring.

### Einrichtung

1. Navigieren Sie zu den Frontend-Einstellungen des AddOns
2. Im Abschnitt "API-Einstellungen" können Sie einen API-Token generieren oder selbst eingeben
3. Der Token wird für alle API-Anfragen benötigt
4. Lassen Sie das Token-Feld leer, um die API zu deaktivieren

### Grundlegende API-Verwendung

Die API wird über den REDAXO-API-Mechanismus aufgerufen:

```
https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=AKTION
```

Alle API-Anfragen benötigen folgende Parameter:
- `rex-api-call=upkeep`: Ruft die Upkeep-API auf
- `token=IHR_API_TOKEN`: Authentifizierung mit Ihrem API-Token
- `action=AKTION`: Die auszuführende Aktion

Alle Anfragen liefern JSON-Antworten zurück.

### Verfügbare Aktionen

#### Status abfragen

Ruft den aktuellen Status aller Wartungsmodi ab.

```
index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=status
```

Beispielantwort:
```json
{
  "success": true,
  "frontend_active": true,
  "backend_active": false,
  "all_domains_locked": false
}
```

#### Frontend-Wartungsmodus aktivieren/deaktivieren

Aktiviert oder deaktiviert den Frontend-Wartungsmodus.

```
index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_frontend&status=1
```

Parameter:
- `status=1`: Aktivieren des Wartungsmodus
- `status=0`: Deaktivieren des Wartungsmodus

Beispielantwort:
```json
{
  "success": true,
  "frontend_active": true
}
```

#### Backend-Wartungsmodus aktivieren/deaktivieren

Aktiviert oder deaktiviert den Backend-Wartungsmodus.

```
index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_backend&status=1
```

Parameter:
- `status=1`: Aktivieren des Wartungsmodus
- `status=0`: Deaktivieren des Wartungsmodus

Beispielantwort:
```json
{
  "success": true,
  "backend_active": true
}
```

#### Alle YRewrite-Domains sperren/entsperren

Aktiviert oder deaktiviert den Wartungsmodus für alle YRewrite-Domains auf einmal.

```
index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_all_domains&status=1
```

Parameter:
- `status=1`: Alle Domains sperren
- `status=0`: Domainsperre aufheben

Beispielantwort:
```json
{
  "success": true,
  "all_domains_locked": true
}
```

#### Einzelne YRewrite-Domain sperren/entsperren

Aktiviert oder deaktiviert den Wartungsmodus für eine bestimmte YRewrite-Domain.

```
index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_domain&domain=example.com&status=1
```

Parameter:
- `domain=DOMAIN_NAME`: Name der Domain (z.B. example.com)
- `status=1`: Domain sperren
- `status=0`: Domain entsperren

Beispielantwort:
```json
{
  "success": true,
  "domain": "example.com",
  "status": true
}
```

### Anwendungsbeispiele

### Mit cURL in einem Shell-Script

```bash
#!/bin/bash
# Wartungsmodus aktivieren vor Backup oder Deployment
curl "https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_frontend&status=1"

# Backup- oder Deployment-Prozess hier...

# Wartungsmodus wieder deaktivieren
curl "https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_frontend&status=0"
```

#### Mit PHP (z.B. in einem Cronjob oder Deployment-Script)

```php
<?php
// Wartungsmodus aktivieren
$response = file_get_contents('https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_frontend&status=1');
$result = json_decode($response, true);

if ($result['success']) {
    // Wartungsarbeiten durchführen...
    
    // Wartungsmodus wieder deaktivieren
    file_get_contents('https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_frontend&status=0');
}
```

#### Mit JavaScript/AJAX für ein Administrationsinterface

```javascript
// Status abfragen
fetch('https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=status')
  .then(response => response.json())
  .then(data => {
    console.log('Wartungsmodus Status:', data);
  });

// Wartungsmodus aktivieren
fetch('https://example.com/index.php?rex-api-call=upkeep&token=IHR_API_TOKEN&action=set_frontend&status=1')
  .then(response => response.json())
  .then(data => {
    if (data.success) {
      console.log('Wartungsmodus aktiviert');
    }
  });
```

### Fehlerbehandlung

Bei ungültigen oder fehlerhaften Anfragen gibt die API einen entsprechenden Fehlercode zurück:

```json
{
  "success": false,
  "error": "Invalid token"
}
```

Mögliche Fehlermeldungen:
- `"Invalid token"`: Der API-Token ist ungültig oder fehlt
- `"Invalid action"`: Die angegebene Aktion wird nicht unterstützt
- `"Domain not found"`: Die angegebene Domain existiert nicht
- `"Invalid domain or YRewrite not available"`: YRewrite ist nicht verfügbar oder die Domain ist ungültig

HTTP-Statuscodes:
- `200 OK`: Anfrage erfolgreich
- `400 Bad Request`: Ungültige Anfrage
- `401 Unauthorized`: Ungültiger API-Token

### Sicherheitshinweise

- Bewahren Sie Ihren API-Token sicher auf
- Setzen Sie den Token zurück, wenn Sie vermuten, dass er kompromittiert wurde
- Verwenden Sie nach Möglichkeit HTTPS für alle API-Aufrufe
- Beschränken Sie den Zugriff auf die API über Ihre Server-Konfiguration
- Die API bietet keine Ratengrenzwerte, implementieren Sie bei Bedarf eigene Maßnahmen gegen Missbrauch

## Extension Points

- `UPKEEP_ALLOWED_PATHS`: Hier können Sie Pfade definieren, die vom Wartungsmodus ausgenommen werden sollen (z.B. für APIs oder bestimmte Medien)

## Autorenschaft

- KLXM Crossmedia

## Lizenz

MIT License - siehe LICENSE.md
