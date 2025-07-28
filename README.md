# Upkeep für REDAXO 5

![Screenshot](https://github.com/KLXM/upkeep/blob/main/assets/css/screen.jpg?raw=true)


Ein modernes, schlankes AddOn für Wartungsarbeiten.

## Features

- **Frontend-Sperre** mit eleganter und anpassbarer Wartungsseite
- **Backend-Sperre** für Redakteure (Admins haben immer Zugriff)
- **Domain-spezifische Sperren** für Multidomains mit YRewrite
- **URL-Redirects** für automatische Weiterleitungen mit Wildcard-Unterstützung
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

### URL-Redirects

Im Tab "URL-Redirects" können Sie:
- Domains und Pfade zu beliebigen URLs weiterleiten
- **Wildcard-Redirects** für dynamische Pfad-Weiterleitung
- HTTP-Statuscodes konfigurieren (301, 302, 303, 307, 308)
- Redirects aktivieren/deaktivieren

**Wildcard-Beispiele:**
```
Blog-Umzug:    old-blog.com/posts/* → new-blog.com/articles/*
Shop-Umzug:    shop.com/kategorie/* → example.com/shop/*
```

**Anwendungsfälle:**
- SEO-Weiterleitungen bei Domain-Umzügen
- Dynamische Pfad-Umleitungen mit Wildcard-Unterstützung
- Temporäre Wartungs-Redirects

## Anpassen der Wartungsseite

Sie können die Wartungsseite anpassen, indem Sie ein eigenes Fragment erstellen:

1. Erstellen Sie den Ordner `fragments/upkeep` in Ihrem Project-AddOn
2. Kopieren Sie die Datei `fragments/upkeep/frontend.php` aus dem Upkeep-AddOn dorthin
3. Passen Sie den Inhalt der Datei nach Ihren Wünschen an

## Konsolen-Befehle

```bash
# Frontend-Wartungsmodus aktivieren/deaktivieren
php redaxo/bin/console upkeep:mode frontend on|off

# Backend-Wartungsmodus aktivieren/deaktivieren
php redaxo/bin/console upkeep:mode backend on|off

# Backend-Wartungsmodus aktivieren/deaktivieren
php redaxo/bin/console upkeep:mode backend on|off
```

## API

Das Upkeep-AddOn bietet eine REST-API für automatisierte Wartungsabläufe:

### API-Token einrichten
1. **Frontend-Einstellungen** > API-Token generieren
2. Token für alle API-Anfragen verwenden

### API-Verwendung
```
GET: /index.php?rex-api-call=upkeep&token=TOKEN&action=ACTION
```

**Verfügbare Aktionen:**
- `action=status` - Wartungsmodus-Status abfragen
- `action=set_frontend&status=1|0` - Frontend-Wartung aktivieren/deaktivieren
- `action=set_backend&status=1|0` - Backend-Wartung aktivieren/deaktivieren

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

## URL-Redirects

Automatische Weiterleitungen von Domains und Pfaden mit Wildcard-Unterstützung:

**Konfiguration:** Upkeep > URL-Redirects

**HTTP-Codes:** 301 (permanent), 302 (temporär), 303, 307, 308

**Wildcard-Beispiele:**
```
Blog-Umzug:     old-blog.com/posts/* → new-blog.com/articles/*
Shop-Umzug:     shop.com/kategorie/* → example.com/shop/*
Domain-Umzug:   old-company.com → https://new-company.com
```

**Features:**
- Wildcard-Pfade mit `/*` und dynamischer `*`-Ersetzung
- Path-Traversal-Schutz und RFC-konforme Domain-Validierung
- Pfad-Priorität (längere Pfade haben Vorrang)
- Frühe Ausführung vor Wartungsmodus-Prüfung

## Extension Points

- `UPKEEP_ALLOWED_PATHS`: Pfade vom Wartungsmodus ausnehmen

## Lizenz

MIT License
