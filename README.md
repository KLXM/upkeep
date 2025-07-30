# REDAXO Upkeep AddOn

Wartungs- und Sicherheits-AddOn für REDAXO CMS.

## Features

- **Wartungsmodi**: Frontend/Backend getrennt steuerbar
- **URL-Redirects**: Mit Wildcard-Unterstützung (`/old/* → /new/*`)
- **Intrusion Prevention System (IPS)**: Automatischer Schutz vor Angriffen
- **Dashboard**: Live-Status aller Systeme
- **API/Console**: Remote-Management

## Installation

1. AddOn installieren und aktivieren
2. Konfiguration über Backend → Upkeep

## Quick Start

```bash
# Wartungsmodus aktivieren
Backend → Upkeep → Frontend/Backend

# Redirects einrichten
Backend → Upkeep → Domains

# IPS konfigurieren  
Backend → Upkeep → IPS
```
## Developer Info

### Requirements
- REDAXO 5.15+
- PHP 8.0+  
- MySQL 5.7+

### API Usage

```php
// Wartungsmodus
use KLXM\Upkeep\Upkeep;
$isActive = Upkeep::isFrontendMaintenanceActive();

// IPS
use KLXM\Upkeep\IntrusionPrevention;
IntrusionPrevention::checkRequest();
$isBlocked = IntrusionPrevention::isBlocked($ip);

// Redirects
use KLXM\Upkeep\DomainMapping;

```

### Console Commands

```bash
# Wartungsmodus
php bin/console upkeep:mode frontend on|off
php bin/console upkeep:status

# IPS
php bin/console upkeep:ips-cleanup
```

### REST API

```bash
curl "example.com/index.php?rex-api-call=upkeep&token=TOKEN&action=status"
```

---

**Maintainer**: KLXM  
**License**: MIT
$redirect = DomainMapping::getRedirectForUrl('https://old-site.com/blog/article-1');
if ($redirect) {
    DomainMapping::executeRedirect($redirect['target'], $redirect['status_code']);
}

// Wildcard-Unterstützung
$mappedUrl = DomainMapping::mapWildcardUrl('/blog/category/tech', '/blog/*', '/articles/*');
// Ergebnis: '/articles/category/tech'
```

### KLXM\Upkeep\MaintenanceView

Template-System für Wartungsseiten.

```php
// Wartungsseite rendern
$content = MaintenanceView::renderMaintenancePage([
    'title' => 'Website im Wartungsmodus',
    'message' => 'Wir arbeiten an Verbesserungen...',
    'retry_after' => 3600
]);

// Custom Templates
MaintenanceView::setCustomTemplate('/path/to/custom-template.php');
```

### Konfiguration über rex_config

```php
// IPS-Einstellungen
rex_config::set('upkeep', 'ips_active', true);
rex_config::set('upkeep', 'ips_rate_limiting_enabled', false);
rex_config::set('upkeep', 'ips_burst_limit', 600);
rex_config::set('upkeep', 'ips_captcha_trust_duration', 24);

// Wartungsmodus-Einstellungen
rex_config::set('upkeep', 'frontend_maintenance_active', true);
rex_config::set('upkeep', 'maintenance_retry_after', 3600);
rex_config::set('upkeep', 'allowed_ips', "192.168.1.1\n10.0.0.1");

// URL-Redirect-Einstellungen
rex_config::set('upkeep', 'redirect_cache_enabled', true);
rex_config::set('upkeep', 'redirect_log_enabled', false);
```

## 🤝 Support

- **Issues**: Über GitHub Issues melden
- **Dokumentation**: Siehe REDAXO-Community
- **Community**: REDAXO Slack-Channel

## 📄 Lizenz

MIT License

## 👥 Autor

**Thomas Skerbis** - KLXM Crossmedia

---

**Upkeep** - Zuverlässiger Partner für REDAXO-Wartung und -Sicherheit! 🛡️
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

### Rate Limiting (Experten-Einstellungen)
- **Standard**: Deaktiviert (Webserver sollte Rate Limiting übernehmen)
- **Aktivierung**: Nur über Konfiguration für Experten
- **DoS-Schutz**: Sehr hohe Limits nur für extreme Angriffe
- **Konfiguration**: Über `rex_config::set()` - siehe Dokumentation unten

#### Rate Limiting Konfiguration (nur für Experten):
```php
// Rate Limiting aktivieren (Standard: false)
rex_config::set('upkeep', 'ips_rate_limiting_enabled', true);

// Debug-Modus aktivieren (Standard: false) - nur für Entwicklung!
rex_config::set('upkeep', 'ips_debug_mode', true);

// Limits konfigurieren (Standard-Werte)
rex_config::set('upkeep', 'ips_burst_limit', 600);      // 600 Requests/Minute (10/Sekunde)
rex_config::set('upkeep', 'ips_strict_limit', 200);     // 200 für kritische Bereiche
rex_config::set('upkeep', 'ips_burst_window', 60);      // 60 Sekunden Zeitfenster
```

⚠️ **Wichtig**: Rate Limiting sollte normalerweise auf Webserver-Ebene erfolgen!

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

### Datenbereinigung 🗂️
```
Backend → Upkeep → IPS → Datenbereinigung
```
- **Automatische Bereinigung**: 1% Wahrscheinlichkeit bei jedem Frontend-Request
- **Manuelle Bereinigung**: Admin-Interface mit Live-Statistiken
- **Konsolen-Kommando**: `php bin/console upkeep:ips:cleanup`
- **Cronjob-Bereinigung**: Automatisch über das REDAXO Cronjob-AddOn (empfohlen)

#### Was wird bereinigt:
- **Abgelaufene IP-Sperrungen**: Temporäre Sperrungen nach Ablaufzeit
- **Alte Bedrohungs-Logs**: Einträge älter als 30 Tage
- **Rate-Limit-Daten**: Zeitfenster-Daten älter als 2 Stunden
- **Permanente Sperrungen**: Bleiben erhalten (nur manuelle Entsperrung)

## ⚙️ Konfiguration

### Datenbankstruktur

Das AddOn erstellt folgende Tabellen:
- `rex_upkeep_domain_mapping`: URL-Redirects
- `rex_upkeep_ips_blocked_ips`: Gesperrte IP-Adressen
- `rex_upkeep_ips_threat_log`: Bedrohungsprotokoll
- `rex_upkeep_ips_custom_patterns`: Benutzerdefinierte Patterns
- `rex_upkeep_ips_rate_limit`: Rate-Limiting-Daten
- `rex_upkeep_ips_positivliste`: Vertrauenswürdige IPs

### Cronjob-Integration 🕒

Für optimale Performance und Datenbank-Hygiene wird die Verwendung des REDAXO Cronjob-AddOns empfohlen:

1. **Cronjob-AddOn installieren** (falls nicht vorhanden)
2. **Backend → AddOns → Cronjob → Neuer Cronjob**
3. **Typ auswählen**: "Upkeep IPS: Bereinigung veralteter Sicherheitsdaten"
4. **Konfiguration**:
   - **Ausführung**: Täglich um 02:00 Uhr (empfohlen)
   - **Threat Log Aufbewahrung**: 30 Tage (Standard)
5. **Aktivieren**

#### Cronjob-Bereinigung umfasst:
- **Abgelaufene temporäre IP-Sperren** (automatisch)
- **Alte Threat-Log-Einträge** (konfigurierbare Aufbewahrungszeit)
- **Veraltete Rate-Limiting-Daten** (älter als 24h)
- **Abgelaufene CAPTCHA-Vertrauenseinträge** (automatisch)
- **Tabellen-Optimierung** (OPTIMIZE TABLE für bessere Performance)

> **Hinweis**: Der Cronjob ersetzt die 1%-Chance-Bereinigung bei Frontend-Requests und reduziert die Server-Last erheblich.

## 🔧 Erweiterte Konfiguration

### IPS Rate Limiting (nur für Experten)

Rate Limiting ist standardmäßig **deaktiviert** und sollte normalerweise auf Webserver-Ebene erfolgen. Für spezielle Anforderungen kann es über die Konfiguration aktiviert werden:

```php
// Rate Limiting aktivieren
rex_config::set('upkeep', 'ips_rate_limiting_enabled', true);

// Burst Limit (Requests pro Minute) - Standard: 600
rex_config::set('upkeep', 'ips_burst_limit', 600);

// Strict Limit für kritische Bereiche - Standard: 200  
rex_config::set('upkeep', 'ips_strict_limit', 200);

// Zeitfenster in Sekunden - Standard: 60
rex_config::set('upkeep', 'ips_burst_window', 60);

// Rate Limiting wieder deaktivieren
rex_config::set('upkeep', 'ips_rate_limiting_enabled', false);
```

**Hinweise:**
- Diese Einstellungen sind nicht über das Backend-Interface verfügbar
- Rate Limiting sollte normalerweise über Apache/Nginx erfolgen  
- Die Limits sind bewusst sehr hoch für DoS-Schutz, nicht normale Nutzung
- Gute Bots erhalten automatisch doppelte Limits
- Debug-Modus nur für Entwicklung aktivieren - erzeugt sehr viele Log-Einträge!

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

## � Konsolen-Kommandos

### Wartungsmodi verwalten
```bash
# Frontend-Wartungsmodus aktivieren/deaktivieren
php bin/console upkeep:mode frontend on|off

# Backend-Wartungsmodus aktivieren/deaktivieren
php bin/console upkeep:mode backend on|off
```

### IPS-Datenbereinigung
```bash
# Manuelle Bereinigung ausführen
php bin/console upkeep:ips:cleanup

# Für Cronjob (täglich um 2:00 Uhr)
0 2 * * * cd /pfad/zu/redaxo && php bin/console upkeep:ips:cleanup >/dev/null 2>&1
```

**Bereinigt automatisch:**
- Abgelaufene temporäre IP-Sperrungen
- Bedrohungs-Logs älter als 30 Tage  
- Rate-Limit-Daten älter als 2 Stunden

## �📈 Changelog

### Version 1.3.0 - Erweiterte Sicherheit 🛡️
- **CAPTCHA-Entsperrung**: Menschliche Verifikation mit mathematischen Aufgaben
- **Multilingual Support**: Deutsch/Englisch mit automatischer Spracherkennung und Sprachumschalter
- **Bot-Erkennung**: Intelligente Erkennung legitimer Bots (Google, Bing, Facebook, etc.)
- **Reverse DNS**: Timeout-geschützte Verifikation (3s max) mit dns_get_record() + gethostbyaddr() Fallback
- **Forward DNS**: Robuste A/AAAA Record Lookups mit gethostbyname() Fallback  
- **DNS-Caching**: Intelligentes Caching (24h positive, 1h negative) zur Performance-Optimierung
- **Temporäre Positivliste**: 24h automatische Vertrauensstellung nach CAPTCHA-Entsperrung
- **Optionales Rate-Limiting**: Standardmäßig deaktiviert (Webserver sollte das übernehmen)
- **Intelligente URI-Limits**: Pfad-basierte Rate-Limits (normal/admin/assets/api)
- **CAPTCHA-Rehabilitation**: Komplette IP-Bereinigung inkl. Bedrohungshistorie
- **Automatische Bereinigung**: Selbstreinigende Datenbank mit 1% Chance pro Request
- **Erweiterte Konsolen-Befehle**: IPS-Cleanup und detaillierte Status-Abfragen
- **UI-Optimierungen**: Verbessertes Design ohne problematische `<code>`-Tags
- **Verbesserte Logs**: Detaillierte Protokollierung aller Sicherheitsereignisse

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

## 🔧 Konsolen-Befehle

### Wartungsmodi
```bash
# Frontend-Wartungsmodus aktivieren/deaktivieren
php bin/console upkeep:mode frontend on|off

# Backend-Wartungsmodus aktivieren/deaktivieren
php bin/console upkeep:mode backend on|off

# Status abfragen
php bin/console upkeep:status
```

### IPS-Management
```bash
# IPS-Bereinigung (abgelaufene Sperren, alte Logs)
php bin/console upkeep:ips-cleanup

# IPS-Status einer IP prüfen
php bin/console upkeep:ips-status <IP-ADRESSE>
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

**Upkeep** - ADDON für REDAXO-Wartung und -Sicherheit! 🛡️ 

