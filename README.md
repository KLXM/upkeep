# REDAXO Upkeep AddOn v1.3.0

![Screenshot](https://github.com/KLXM/upkeep/blob/main/assets/css/screen.jpg?raw=true)

Ein umfassendes Wartungs- und Sicherheits-AddOn für REDAXO CMS mit Frontend-/Backend-Wartungsmodi, URL-Redirects und integriertem Intrusion Prevention System (IPS).

## 🚀 Features

### Wartungsmodi
- **Frontend-Wartungsmodus**: Zeigt Besuchern eine elegante Wartungsseite an
- **Backend-Wartungsmodus**: Sperrt den Backend-Zugang für bestimmte Benutzergruppen  
- **Domain-spezifische Sperren**: Für Multidomains mit YRewrite
- **Flexible Berechtigungen**: Wartungsmodi können unabhängig voneinander aktiviert werden
- **Passwort-Bypass**: Zum Testen des Frontends im Wartungsmodus
- **IP-Whitelist**: Mit einfacher Übernahme der aktuellen IP-Adresse

### URL-Redirects
- **Wildcard-Unterstützung**: Flexible URL-Umleitungen mit Platzhaltern (`old-blog.com/posts/*` → `new-blog.com/articles/*`)
- **Pfad-Ersetzung**: Automatische Übertragung von URL-Parametern
- **HTTP-Status-Codes**: Konfigurierbare Redirect-Codes (301, 302, 303, 307, 308)
- **Path-Traversal-Schutz**: RFC-konforme Domain-Validierung

### Intrusion Prevention System (IPS) 🛡️
- **Echtzeit-Bedrohungserkennung**: Automatische Erkennung von Angriffsmustern
- **CMS-spezifische Patterns**: Schutz vor WordPress, TYPO3, Drupal und Joomla Exploits
- **Positivliste**: Ausnahmen für vertrauenswürdige IPs
- **Rate Limiting**: Schutz vor Brute-Force-Angriffen (100 Requests/Minute)
- **Custom Patterns**: Eigene Bedrohungsmuster mit Regex-Unterstützung
- **Umfassende Protokollierung**: Detaillierte Logs aller Sicherheitsereignisse

### Backend-Integration
- **Status-Indikatoren**: Live-Anzeige der aktiven Systeme (B/F/R/S)
- **Benutzerfreundliche Oberfläche**: Intuitive Bootstrap-basierte UI
- **Responsive Design**: Optimiert für Desktop und Mobile
- **Konsolen-Befehle**: Für Remote-Management
- **REST-API**: Zur Steuerung aus der Ferne

## 📋 Systemvoraussetzungen

- **REDAXO**: Version 5.18 oder höher
- **PHP**: Version 8.0 oder höher
- **MySQL**: Version 5.7 oder höher

## 🔧 Installation

1. AddOn über das REDAXO Backend installieren
2. AddOn aktivieren  
3. Die Datenbanktabellen werden automatisch erstellt
4. Konfiguration über das Backend-Menü "Upkeep"

## 📚 Verwendung

### Wartungsmodi aktivieren

#### Frontend-Wartungsmodus
```
Backend → Upkeep → Frontend → Wartungsmodus aktivieren
```
- Zeigt allen Besuchern eine Wartungsseite
- Benutzer mit entsprechenden Rechten können weiterhin zugreifen
- Konfigurierbare HTTP-Statuscodes (503, 403, 307) mit Retry-After Header

#### Backend-Wartungsmodus  
```
Backend → Upkeep → Backend → Wartungsmodus aktivieren
```
- Sperrt den Backend-Zugang
- Nur Administratoren können sich anmelden

### URL-Redirects einrichten

#### Einfache Weiterleitung
```
Quelle: /alte-seite
Ziel: /neue-seite  
Status: 301
```

#### Wildcard-Weiterleitung
```
Quelle: /blog/*
Ziel: /aktuelles/$1
Status: 301
```

**Wildcard-Beispiele:**
```
Blog-Umzug:    old-blog.com/posts/* → new-blog.com/articles/*
Shop-Umzug:    shop.com/kategorie/* → example.com/shop/*
Domain-Umzug:  old-company.com → https://new-company.com
```

### Intrusion Prevention System 🛡️

#### Automatischer Schutz
Das IPS läuft automatisch und prüft alle eingehenden Requests auf:
- Bekannte Angriffsmuster
- CMS-spezifische Exploits  
- Verdächtige URL-Parameter
- Rate-Limiting-Verstöße

#### Positivliste verwalten
```
Backend → Upkeep → IPS → Positivliste
```
- IP-Adressen hinzufügen, die nie blockiert werden sollen
- Nützlich für eigene IPs oder vertrauenswürdige Services

#### Custom Patterns
```
Backend → Upkeep → IPS → Patterns
```
- Eigene Bedrohungsmuster definieren
- Regex-Unterstützung
- Verschiedene Schweregrade (low, medium, high, critical)

## 🛡️ Sicherheitsfeatures

### Eingebaute Bedrohungserkennung

#### WordPress-Exploits
```
/wp-admin/
/wp-content/plugins/
/wp-includes/
xmlrpc.php
```

#### TYPO3-Exploits
```
/typo3/
/typo3conf/
/typo3temp/
/fileadmin/
```

#### Drupal-Exploits
```
/sites/default/
/modules/
/themes/
/core/
```

#### Joomla-Exploits
```
/administrator/
/components/
/modules/
/plugins/
```

#### Allgemeine Angriffsmuster
```
SQL-Injection Versuche
XSS-Payloads
Directory Traversal  
Shell-Injection
```

### Rate Limiting
- **Standard**: 100 Requests pro Minute
- **Burst-Schutz**: Temporäre Sperrung bei Überschreitung
- **Konfigurierbar**: Anpassbare Limits per IP

## 📊 Status-Indikatoren

Das AddOn zeigt Live-Status im Backend-Menü:

- **B** (🔴): Backend-Wartungsmodus aktiv
- **F** (🔴): Frontend-Wartungsmodus aktiv
- **R** (🟢): URL-Redirects aktiv  
- **S** (🟡/🔴): IPS-Status (Gelb: Warnungen, Rot: Kritische Bedrohungen)

## 🔍 Monitoring und Logs

### Bedrohungsprotokoll
```
Backend → Upkeep → IPS → Bedrohungen
```
- Chronologische Auflistung aller Sicherheitsereignisse
- IP-Adressen, Patterns und Request-Details
- Filtermöglichkeiten nach Schweregrad

### Blockierte IPs
```
Backend → Upkeep → IPS → Blockierte IPs
```
- Übersicht aller gesperrten IP-Adressen
- Grund der Sperrung
- Entsperrmöglichkeit

## ⚙️ Konfiguration

### Datenbankstruktur

Das AddOn erstellt folgende Tabellen:
- `rex_upkeep_domain_mapping`: URL-Redirects
- `rex_upkeep_ips_blocked_ips`: Gesperrte IP-Adressen
- `rex_upkeep_ips_threat_log`: Bedrohungsprotokoll
- `rex_upkeep_ips_custom_patterns`: Benutzerdefinierte Patterns
- `rex_upkeep_ips_rate_limit`: Rate-Limiting-Daten
- `rex_upkeep_ips_positivliste`: Vertrauenswürdige IPs

## Anpassen der Wartungsseite

Sie können die Wartungsseite anpassen, indem Sie ein eigenes Fragment erstellen:

1. Erstellen Sie den Ordner `fragments/upkeep` in Ihrem Project-AddOn
2. Kopieren Sie die Datei `fragments/upkeep/frontend.php` aus dem Upkeep-AddOn dorthin
3. Passen Sie den Inhalt der Datei nach Ihren Wünschen an

## 🔧 Entwicklung

### Hooks und Events

Das AddOn registriert sich in der `boot.php`:
```php
// Intrusion Prevention - höchste Priorität
IntrusionPrevention::checkRequest();

// Wartungsmodi
rex_extension::register('PACKAGES_INCLUDED', function() {
    if (rex::isFrontend()) {
        Upkeep::checkFrontend();
    }
    if (rex::isBackend()) {
        Upkeep::checkBackend();
    }
});
```

### API-Verwendung

```php
// IPS-Status abfragen
$threats = IntrusionPrevention::getRecentThreats();

// Custom Pattern hinzufügen
IntrusionPrevention::addCustomPattern($pattern, $description, $severity);

// IP zur Positivliste hinzufügen
IntrusionPrevention::addToPositivliste($ip, $description);
```

## 📈 Changelog

### Version 1.3.0
- **UI-Optimierungen**: Verbessertes Design ohne problematische `<code>`-Tags
- **Kompakter Button**: "+" Button für Pattern hinzufügen passt in enge Panels
- **Bessere Lesbarkeit**: Optimierte Darstellung von Code-Beispielen und IPs
- **Bootstrap-Integration**: Konsistente Verwendung von Bootstrap-Klassen

### Version 1.2.0
- **Vollständiges IPS**: Intrusion Prevention System mit Echtzeit-Schutz
- **CMS-Patterns**: Spezifische Bedrohungserkennung für WordPress, TYPO3, Drupal, Joomla
- **Positivliste-System**: Ausnahmen für vertrauenswürdige IP-Adressen
- **Rate-Limiting**: Schutz vor Brute-Force-Angriffen
- **Status-Indikatoren**: Live-Anzeige im Backend-Menü (B/F/R/S)
- **Umfassende Protokollierung**: Detaillierte Logs aller Sicherheitsereignisse

### Version 1.1.0
- **Wildcard-Redirects**: URL-Redirects mit Wildcard-Unterstützung (`/*`)
- **Pfad-Ersetzung**: Dynamische Parameter-Übertragung bei Redirects
- **HTTP-Status-Codes**: Konfigurierbare Redirect-Codes (301, 302, 303, 307, 308)
- **Path-Traversal-Schutz**: RFC-konforme Domain-Validierung

### Version 1.0.0
- **Grundlegende Wartungsmodi**: Frontend- und Backend-Sperrung
- **Benutzerrechte-Integration**: Admin-Bypass und rollenbasierte Zugriffe
- **Domain-spezifische Sperren**: Multidomains mit YRewrite-Unterstützung

## API

Das Upkeep-AddOn bietet eine REST-API für automatisierte Wartungsabläufe:

### API-Verwendung
```
GET: /index.php?rex-api-call=upkeep&token=TOKEN&action=ACTION
```

**Verfügbare Aktionen:**
- `action=status` - Wartungsmodus-Status abfragen
- `action=set_frontend&status=1|0` - Frontend-Wartung aktivieren/deaktivieren
- `action=set_backend&status=1|0` - Backend-Wartung aktivieren/deaktivieren

**Beispiel:**
```bash
# Wartungsmodus aktivieren
curl "https://example.com/index.php?rex-api-call=upkeep&token=TOKEN&action=set_frontend&status=1"
```

## Konsolen-Befehle

```bash
# Frontend-Wartungsmodus aktivieren/deaktivieren
php redaxo/bin/console upkeep:mode frontend on|off

# Backend-Wartungsmodus aktivieren/deaktivieren
php redaxo/bin/console upkeep:mode backend on|off
```

## Extension Points

- `UPKEEP_ALLOWED_PATHS`: Pfade vom Wartungsmodus ausnehmen

## 🤝 Support

- **Issues**: Über GitHub Issues melden
- **Dokumentation**: Siehe REDAXO-Community
- **Community**: REDAXO Slack-Channel

## 📄 Lizenz

MIT License

## 👥 Autor

**Thomas Skerbis** - KLXM Crossmedia

---

**Upkeep v1.3.0** - Ihr zuverlässiger Partner für REDAXO-Wartung und -Sicherheit! 🛡️ 

