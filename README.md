# Upkeep für REDAXO 5

![Screenshot](https://github.com/KLXM/upkeep/blob/main/assets/css/screen.jpg?raw=true)


Ein modernes, schlankes AddOn für Wartungsarbeiten.

## Features

- **Frontend-Sperre** mit eleganter und anpassbarer Wartungsseite
- **Backend-Sperre** für Redakteure (Admins haben immer Zugriff)
- **Domain-spezifische Sperren** für Multidomains mit YRewrite
- **Domain-Mapping** für automatische Weiterleitungen von Domains zu beliebigen URLs
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

### Domain-Mapping

Im Tab "Domain-Mapping" können Sie:
- Domains zu beliebigen URLs weiterleiten
- **Wildcard-Redirects** für dynamische Pfad-Weiterleitung
- HTTP-Statuscodes für Weiterleitungen konfigurieren (301, 302, 303, 307, 308)
- Domain-Mappings aktivieren oder deaktivieren
- Beschreibungen für bessere Übersicht hinzufügen

**Anwendungsfälle für Domain-Mapping:**
- Weiterleitung alter Domains auf neue URLs
- Temporäre Weiterleitungen während Wartungsarbeiten
- Umleitung von Subdomains auf Hauptseiten
- SEO-Weiterleitungen für Domainwechsel
- **Wildcard-Redirects für Pfad-basierte Umleitungen**

### Wildcard-Redirects

Wildcard-Redirects ermöglichen dynamische Pfad-Weiterleitung mit Platzhaltern:

**Beispiel 1: Blog-Umzug**
```
Quell-Domain: old-blog.com
Quell-Pfad: /posts/*
Ziel-URL: https://new-blog.com/articles/*
HTTP-Code: 301
Wildcard: ✓ Aktiv
```
Resultat: `old-blog.com/posts/artikel-name` → `https://new-blog.com/articles/artikel-name`

**Beispiel 2: Kategorie-Umleitung**
```
Quell-Domain: shop.example.com
Quell-Pfad: /kategorie/*
Ziel-URL: https://example.com/shop/kategorie/*
HTTP-Code: 301
Wildcard: ✓ Aktiv
```
Resultat: `shop.example.com/kategorie/schuhe/nike` → `https://example.com/shop/kategorie/schuhe/nike`

**Wildcard-Funktionen:**
- **Dynamische Pfad-Ersetzung**: Der `*` wird durch den verbleibenden Pfad ersetzt
- **Sichere Validierung**: Path-Traversal-Schutz gegen `..` und Backslashes
- **RFC-konforme Domain-Prüfung**: Strikte Domain-Validierung
- **Pfad-Priorität**: Längere Pfade haben Vorrang vor kürzeren

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

## Domain-Mapping

Das Domain-Mapping ermöglicht es, eingehende Anfragen von bestimmten Domains automatisch zu anderen URLs weiterzuleiten. Dies ist besonders nützlich für:

- **Domain-Umzüge**: Weiterleitung von alten auf neue Domains
- **SEO-Optimierung**: Permanente Weiterleitungen (301) für bessere Suchmaschinenrankings
- **Wartungsarbeiten**: Temporäre Weiterleitungen (302/307) während Updates
- **Subdomain-Management**: Zentrale Verwaltung von Subdomain-Weiterleitungen
- **Wildcard-Redirects**: Dynamische Pfad-basierte Weiterleitungen mit Platzhaltern

### Domain-Mapping konfigurieren

1. Navigieren Sie zu **Upkeep > URL-Redirects** im Backend
2. Klicken Sie auf "URL-Redirect hinzufügen"
3. Füllen Sie das Formular aus:
   - **Quell-Domain**: Die eingehende Domain (z.B. `old-domain.com`)
   - **Quell-Pfad**: Optionaler Pfad für spezifische Weiterleitungen (z.B. `/blog/*`)
   - **Ziel-URL**: Die URL, zu der weitergeleitet werden soll (z.B. `https://new-domain.com/start`)
   - **HTTP-Code**: Der HTTP-Statuscode für die Weiterleitung
   - **Wildcard-Redirect**: Aktiviert dynamische Pfad-Ersetzung mit `*`
   - **Status**: Aktiv/Inaktiv für die Weiterleitung
   - **Beschreibung**: Optionale Beschreibung für bessere Übersicht

### HTTP-Statuscodes für Weiterleitungen

| Code | Typ | Verwendung |
|------|-----|------------|
| **301** | Permanent Redirect | Für dauerhafte Domain-Umzüge, SEO-freundlich |
| **302** | Found (Temporary) | Für temporäre Weiterleitungen |
| **303** | See Other | Nach POST-Anfragen |
| **307** | Temporary Redirect | Behält HTTP-Methode bei |
| **308** | Permanent Redirect | Permanent + behält HTTP-Methode bei |

### Funktionsweise

Das Domain-Mapping wird **vor** allen anderen Prüfungen ausgeführt:

1. **Domain-Prüfung**: System prüft die eingehende Domain
2. **Datenbankabfrage**: Suche nach aktivem Domain-Mapping
3. **Weiterleitung**: Bei Treffer sofortige Weiterleitung mit konfiguriertem HTTP-Code
4. **Normale Verarbeitung**: Bei keinem Treffer normale REDAXO-Verarbeitung

### Beispiele

#### Permanente Domain-Weiterleitung (SEO)
```
Quell-Domain: old-company.com
Quell-Pfad: (leer)
Ziel-URL: https://new-company.com
HTTP-Code: 301
Status: Aktiv
Beschreibung: Permanente Weiterleitung nach Rebranding
```

#### Subdomain zu Hauptseite
```
Quell-Domain: blog.example.com
Quell-Pfad: (leer)
Ziel-URL: https://example.com/blog
HTTP-Code: 301
Status: Aktiv
Beschreibung: Blog-Subdomain auf Hauptseite umleiten
```

#### Wildcard-Redirect für Blog-Artikel
```
Quell-Domain: old-blog.com
Quell-Pfad: /posts/*
Ziel-URL: https://new-blog.com/articles/*
HTTP-Code: 301
Wildcard: ✓ Aktiv
Status: Aktiv
Beschreibung: Alle Blog-Posts zu neuer Struktur weiterleiten
```
Resultat: `old-blog.com/posts/artikel-name` → `https://new-blog.com/articles/artikel-name`

#### Wildcard-Redirect für Shop-Kategorien
```
Quell-Domain: shop.example.com
Quell-Pfad: /kategorie/*
Ziel-URL: https://example.com/shop/*
HTTP-Code: 301
Wildcard: ✓ Aktiv
Status: Aktiv
Beschreibung: Shop-Kategorien zur Hauptseite weiterleiten
```
Resultat: `shop.example.com/kategorie/schuhe/nike` → `https://example.com/shop/schuhe/nike`

#### Temporäre Wartungsweiterleitung
```
Quell-Domain: shop.example.com
Quell-Pfad: (leer)
Ziel-URL: https://example.com/wartung
HTTP-Code: 302
Status: Aktiv
Beschreibung: Temporäre Weiterleitung während Shop-Wartung
```

### Tipps und Best Practices

**URL-Format:**
- URLs ohne Protokoll werden automatisch mit `https://` ergänzt
- Verwenden Sie vollständige URLs mit Protokoll für beste Kontrolle

**Wildcard-Redirects:**
- Quell-Pfad muss mit `/*` enden (z.B. `/blog/*`, `/kategorie/*`)
- Ziel-URL muss `*` enthalten, um den dynamischen Teil zu ersetzen
- Längere Pfade haben Vorrang vor kürzeren (z.B. `/blog/tech/*` vor `/blog/*`)
- Path-Traversal-Schutz verhindert `..` und Backslashes in Pfaden

**SEO-Optimierung:**
- Nutzen Sie 301-Weiterleitungen für permanente Domain-Wechsel
- Dokumentieren Sie Weiterleitungen in der Beschreibung
- Vermeiden Sie Weiterleitungsschleifen
- Wildcard-Redirects erhalten die URL-Struktur für bessere SEO

**Performance:**
- Domain-Mappings werden frühzeitig geprüft (vor Wartungsmodus)
- Minimale Datenbankabfrage nur bei Frontend-Anfragen
- Keine zusätzliche Latenz bei nicht gemappten Domains
- Pfad-Priorität vermeidet unnötige Datenbankabfragen

**Verwaltung:**
- Nutzen Sie den Status-Toggle für temporäre Deaktivierung
- Beschreibungen helfen bei der Übersicht komplexer Setups
- Regelmäßige Überprüfung nicht mehr benötigter Mappings
- Testen Sie Wildcard-Redirects vor der Aktivierung

## Extension Points

- `UPKEEP_ALLOWED_PATHS`: Hier können Sie Pfade definieren, die vom Wartungsmodus ausgenommen werden sollen (z.B. für APIs oder bestimmte Medien)

## Autorenschaft

- KLXM Crossmedia

## Lizenz

MIT License - siehe LICENSE.md
