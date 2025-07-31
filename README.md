# REDAXO Upkeep AddOn

Wartungs- und Sicherheits-AddOn für REDAXO CMS.

## Features

- **Wartungsmodi**: Frontend/Backend getrennt steuerbar
- **URL-Redirects**: Mit Wildcard-Unterstützung (`/old/* -> /new/*`)
- **Intrusion Prevention System (IPS)**: Automatischer Schutz vor Angriffen
- **Monitor-Only Modus**: Nur loggen ohne automatisches Blocken
- **Extension Points**: Externes Logging (fail2ban, Grafana, etc.)
- **GeoIP-Integration**: Länder-Anzeige für IP-Adressen mit DB-IP.com
- **Dashboard**: Live-Status aller Systeme mit schnellen Aktionen
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

## Detaillierte Funktionen

### Dashboard

Das Dashboard bietet eine zentrale Übersicht über alle Upkeep-Funktionen:

- **System-Status**: Zeigt den aktuellen Status von Wartungsmodi, IPS und Domain-Redirects
- **Sicherheits-Übersicht**: Live-Statistiken zu Bedrohungen und gesperrten IPs
- **Länder-Analyse**: Visualisierung gesperrter IPs nach Herkunftsländern
- **Schnellaktionen**: Direkter Zugriff auf wichtige Funktionen

#### Status-Indikatoren

- **Wartungsmodus aktiv**: Frontend/Backend-Status mit Anzahl erlaubter IPs
- **System läuft normal**: Alle Dienste verfügbar
- **Sicherheit aktiv**: IPS läuft mit Rate-Limiting-Status
- **Monitor-Only Modus**: Nur Logging, keine automatischen Sperrungen
- **Sicherheitswarnung**: IPS deaktiviert - sofortige Aktivierung empfohlen

### Domain Mapping & URL-Redirects

Leistungsstarkes System für Domain- und URL-Weiterleitungen:

#### Funktionen
- **Domain-Redirects**: Vollständige Domain-Weiterleitung
- **Pfad-basierte Redirects**: Spezifische URL-Pfade umleiten
- **Wildcard-Unterstützung**: Dynamische Pfad-Ersetzung (`/old/* -> /new/*`)
- **HTTP-Status-Codes**: 301, 302, 307, 308 für SEO-optimierte Redirects
- **Global aktivieren/deaktivieren**: Master-Schalter für alle Mappings

#### Wildcard-Redirects
```
Quelle: example.com/old/*
Ziel: https://new-domain.com/new/*

Beispiel:
example.com/old/category/page -> https://new-domain.com/new/category/page
```

#### Sicherheitsfeatures
- **Path Traversal Schutz**: Verhindert "../" in Pfaden
- **RFC-konforme Domain-Validierung**
- **URL-Format-Prüfung**

#### Fehlermeldungen
- **Pfade müssen mit / beginnen**: Korrekte URL-Struktur erforderlich
- **Wildcard-Pfade müssen mit /* enden**: Für dynamische Ersetzung
- **Pfade dürfen keine ".." enthalten**: Sicherheitsschutz
- **Target URL ist erforderlich**: Ziel-URL muss angegeben werden

### Intrusion Prevention System (IPS)

Umfassendes Sicherheitssystem mit mehreren Schutzebenen:

#### Pattern-System

**Standard-Patterns**: Vordefinierte Sicherheitsregeln für häufige Angriffsvektoren
- **Kritische Bedrohungen**: Sofortige permanente Sperrung
- **CMS-spezifische Zugriffe**: WordPress, TYPO3, etc. Detection
- **Admin-Panel-Zugriffe**: Schutz vor Brute-Force-Angriffen
- **Konfigurationsdateien**: Schutz sensibler Bereiche
- **Web-Shells**: Malware-Upload-Erkennung
- **SQL-Injection**: Pattern für Datenbankattacken
- **RegEx-Patterns**: Erweiterte reguläre Ausdrücke

**Custom Patterns**: Eigene Sicherheitsregeln definieren
- **String-Patterns**: Einfache Textsuche
- **RegEx-Patterns**: Komplexe Muster mit Flags
- **Schweregrade**: LOW (nur Log) → CRITICAL (permanent gesperrt)

#### Schweregrade und Konsequenzen
- **LOW**: Nur Protokollierung, keine Sperrung
- **MEDIUM**: 15 Minuten temporäre Sperrung
- **HIGH**: 1 Stunde temporäre Sperrung
- **CRITICAL**: Permanente Sperrung

#### Monitor-Only Modus
Für Testumgebungen und neue Pattern:
- Alle Bedrohungen werden protokolliert
- Keine automatischen Sperrungen
- Ideal für Pattern-Tests vor Produktivsetzung

#### GeoIP-Integration
- **Länder-Erkennung**: IP-Adressen zu Ländern zuordnen
- **Statistiken**: Bedrohungen nach Herkunftsländern
- **DB-IP.com Database**: Kostenlose, regelmäßig aktualisierte GeoIP-Daten

#### Positivliste (Whitelist)
Vertrauenswürdige IPs vor automatischer Sperrung schützen:
- **Admin-IPs**: Backend-Administratoren
- **CDN-IPs**: Cloudflare, etc.
- **Monitoring-Services**: Uptime-Checker
- **API-Clients**: Vertrauenswürdige automatisierte Services
- **CIDR-Notation**: IP-Bereiche (z.B. 192.168.1.0/24)

#### Rate-Limiting
- **Request-Limits**: Schutz vor DoS-Angriffen
- **CAPTCHA-System**: Entsperrung für legitime Benutzer
- **Vertrauens-Zeitraum**: 24h Schutz nach erfolgreicher CAPTCHA-Lösung

#### Cleanup-System
Automatische Datenbankpflege:
- **Abgelaufene Sperrungen**: Temporäre Blocks automatisch entfernen
- **Alte Logs**: Threat-Logs nach 30 Tagen löschen
- **Rate-Limit-Einträge**: Nach 2 Stunden bereinigen
- **CAPTCHA-Vertrauen**: Veraltete Einträge entfernen
- **Cronjob-Integration**: Automatische nächtliche Bereinigung

### Wartungsmodi

#### Frontend-Wartungsmodus
- **Passwort-Schutz**: Optionaler Zugang für bestimmte Benutzer
- **IP-Erlaubnisliste**: Bestimmte IPs vom Wartungsmodus ausschließen
- **Angemeldete Benutzer**: REDAXO-Backend-Nutzer automatisch ausschließen
- **Custom Wartungsseite**: Individueller Titel und Nachricht
- **HTTP-Status-Codes**: SEO-konforme 503/403 Responses
- **Retry-After Header**: Suchmaschinen-freundliche Signale

#### Backend-Wartungsmodus
- **Admin-Only**: Nur Administratoren haben Zugang
- **Vollständige Sperrung**: Alle anderen Benutzer werden ausgeschlossen
- **Sichere Wartung**: Updates ohne Benutzer-Interferenz

### API & Console Commands

#### Console Commands
```bash
# Wartungsmodus steuern
php redaxo/bin/console upkeep:mode frontend on
php redaxo/bin/console upkeep:mode backend off

# IPS Cleanup
php redaxo/bin/console upkeep:ips:cleanup
```

#### REST API
```php
// API-Token in den Einstellungen generieren
POST /upkeep/api
{
    "action": "toggle_maintenance",
    "type": "frontend",
    "active": true,
    "token": "your-api-token"
}
```

## Wartungshinweise und Best Practices

### Standard-Pattern Bearbeitung
⚠️ **Wichtige Hinweise**:
- **Vorsicht bei RegEx**: Fehlerhafte reguläre Ausdrücke können Fehler verursachen
- **Deaktivierung überdenken**: Patterns nur deaktivieren wenn sicher nicht benötigt
- **Sofortige Wirkung**: Änderungen wirken sich sofort auf Sicherheitsprüfungen aus
- **Backup empfohlen**: Vor größeren Änderungen Datenbank-Backup erstellen

### Pattern-Kategorien Erklärung

#### Kritische Bedrohungen (Immediate Block)
Patterns die sofortige permanente Sperrung auslösen:
- Shell-Injections: `system(`, `exec(`, `passthru(`
- PHP-Code-Injection: `<?php`, `eval(`
- Path-Traversal: `../../../`
- Null-Byte-Attacks: `%00`

#### CMS-spezifische Zugriffe
Erkennung von CMS-Scanner und Exploit-Versuchen:
- WordPress: `/wp-admin/`, `/wp-content/`, `wp-config.php`
- TYPO3: `/typo3/`, `/typo3conf/`, `typo3temp`
- Joomla: `/administrator/`, `configuration.php`
- Drupal: `/sites/default/`, `settings.php`

#### Admin-Panel-Zugriffe
Schutz vor Brute-Force-Angriffen:
- `/admin`, `/administrator`, `/login`
- `/panel`, `/control`, `/manage`
- `/backend`, `/cms`, `/wp-admin`

### Cleanup und Performance

#### Automatische Bereinigung
- **Häufigkeit**: Bei jedem Request 1% Wahrscheinlichkeit
- **Abgelaufene IPs**: Werden bei Prüfung automatisch ignoriert
- **Alte Logs**: Werden nach 30 Tagen gelöscht
- **Rate-Limits**: Werden nach 2 Stunden gelöscht
- **Cronjob**: Tägliche vollständige Bereinigung empfohlen

#### Performance-Optimierung
- **Datenbank-Indizes**: Automatisch für alle relevanten Felder gesetzt
- **Lazy Loading**: Nur benötigte Daten werden geladen
- **Cache-friendly**: Minimale Datenbankabfragen pro Request

## Fehlerbehebung

### Häufige Probleme

#### "Standard-Pattern-Tabelle fehlt"
**Ursache**: AddOn-Installation unvollständig
**Lösung**: AddOns → Upkeep → Reinstall

#### "GeoIP-Datenbank nicht verfügbar"
**Ursache**: GeoIP-Datenbank nicht installiert
**Lösung**: IPS → Einstellungen → "GeoIP-Datenbank installieren"

#### Legitime Benutzer werden gesperrt
**Ursache**: Zu restriktive Custom Patterns
**Lösung**: 
1. Monitor-Only Modus aktivieren
2. Logs analysieren 
3. Patterns anpassen
4. Betroffene IPs zur Positivliste hinzufügen

#### Performance-Probleme
**Ursache**: Große Threat-Log-Tabelle
**Lösung**: IPS → Cleanup → Manuelle Bereinigung

### Debug-Modus

Für Entwicklung und Fehlersuche:
```php
// Debug-Modus in config.yml aktivieren
ips_debug_mode: true
```

Debug-Informationen in REDAXO-Log:
- Jede IPS-Prüfung wird protokolliert
- Pattern-Matches werden geloggt
- Performance-Metriken werden erfasst

## Developer Info

### Requirements
- REDAXO 5.15+
- PHP 8.0+  
- MySQL 5.7+ / MariaDB 10.3+

### API Usage

```php
// Wartungsmodus
use KLXM\Upkeep\Upkeep;
$isActive = Upkeep::isFrontendMaintenanceActive();

// IPS
use KLXM\Upkeep\IntrusionPrevention;
IntrusionPrevention::checkRequest();
$isBlocked = IntrusionPrevention::isBlocked($ip);

// Monitor-Only Modus (nur loggen, nicht blocken)
$isMonitorOnly = IntrusionPrevention::isMonitorOnlyMode();

// Redirects
use KLXM\Upkeep\DomainMapping;
DomainMapping::checkAndRedirect();

// GeoIP
use KLXM\Upkeep\GeoIP;
$country = GeoIP::getCountry('8.8.8.8');
// Returns: ['code' => 'US', 'name' => 'United States']
$countryInfo = IntrusionPrevention::getCountryByIp('8.8.8.8');
// Returns: ['code' => 'US', 'name' => 'United States']
```

### Extension Points

```php
// Externes Logging für jede erkannte Bedrohung
rex_extension::register('UPKEEP_IPS_THREAT_DETECTED', function($ep) {
    $data = $ep->getSubject();
    // $data enthält: ip, uri, threat_type, severity, pattern, etc.
    
    // Beispiel 1: Grafana/InfluxDB Logging
    sendToGrafana($data);
    
    // Beispiel 2: Elasticsearch
    sendToElasticsearch($data);
    
    // Beispiel 3: Slack/Discord Alerts
    if ($data['severity'] === 'CRITICAL') {
        sendSlackAlert($data);
    }
});

// fail2ban-kompatibles Logging
rex_extension::register('UPKEEP_IPS_FAIL2BAN_LOG', function($ep) {
    $params = $ep->getSubject();
    // Custom fail2ban logging
    myCustomLogger($params['message'], $params['logData']);
});
```

#### Grafana/InfluxDB Integration

```php
function sendToGrafana($data) {
    $influxData = [
        'measurement' => 'redaxo_security',
        'tags' => [
            'severity' => $data['severity'],
            'threat_type' => $data['threat_type'],
            'server' => gethostname()
        ],
        'fields' => [
            'ip' => $data['ip'],
            'uri' => $data['uri'],
            'pattern' => $data['pattern'],
            'user_agent' => $data['user_agent'] ?? '',
            'count' => 1
        ],
        'timestamp' => time() * 1000000000 // nanoseconds
    ];
    
    // InfluxDB REST API
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'http://influxdb:8086/write?db=monitoring',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => formatInfluxLine($influxData),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5
    ]);
    curl_exec($ch);
    curl_close($ch);
}
```

#### Elasticsearch Integration

```php
function sendToElasticsearch($data) {
    $document = [
        '@timestamp' => date('c'),
        'source' => 'redaxo-ips',
        'severity' => $data['severity'],
        'threat_type' => $data['threat_type'],
        'client_ip' => $data['ip'],
        'request_uri' => $data['uri'],
        'pattern_matched' => $data['pattern'],
        'user_agent' => $data['user_agent'] ?? '',
        'server' => gethostname(),
        'geoip' => getGeoIP($data['ip'])
    ];
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'http://elasticsearch:9200/security-logs/_doc',
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($document),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5
    ]);
    curl_exec($ch);
    curl_close($ch);
}
```

#### Slack/Discord Alerts

```php
function sendSlackAlert($data) {
    $webhook = 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL';
    
    $message = [
        'text' => "🚨 REDAXO Security Alert",
        'attachments' => [[
            'color' => $data['severity'] === 'CRITICAL' ? 'danger' : 'warning',
            'fields' => [
                ['title' => 'IP Address', 'value' => $data['ip'], 'short' => true],
                ['title' => 'Threat Type', 'value' => $data['threat_type'], 'short' => true],
                ['title' => 'URI', 'value' => $data['uri'], 'short' => false],
                ['title' => 'Pattern', 'value' => $data['pattern'], 'short' => false],
                ['title' => 'Server', 'value' => gethostname(), 'short' => true],
                ['title' => 'Time', 'value' => date('Y-m-d H:i:s'), 'short' => true]
            ]
        ]]
    ];
    
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $webhook,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($message),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5
    ]);
    curl_exec($ch);
    curl_close($ch);
}
```

#### Syslog Integration

```php
rex_extension::register('UPKEEP_IPS_THREAT_DETECTED', function($ep) {
    $data = $ep->getSubject();
    
    // RFC3164 Syslog format
    $priority = $data['severity'] === 'CRITICAL' ? 2 : 4; // critical : warning
    $facility = 16; // local0
    $syslogPriority = $facility * 8 + $priority;
    
    $message = sprintf(
        "<%d>%s %s redaxo-ips[%d]: %s threat from %s to %s (pattern: %s)",
        $syslogPriority,
        date('M d H:i:s'),
        gethostname(),
        getmypid(),
        $data['severity'],
        $data['ip'],
        $data['uri'],
        $data['pattern']
    );
    
    // Send to syslog server
    $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_sendto($sock, $message, strlen($message), 0, '127.0.0.1', 514);
    socket_close($sock);
});
```

### fail2ban Integration

Aktiviere fail2ban-Logging:
```php
rex_config::set('upkeep', 'ips_fail2ban_logging', true);
rex_config::set('upkeep', 'ips_fail2ban_logfile', '/var/log/redaxo_ips.log');
```

fail2ban filter (`/etc/fail2ban/filter.d/redaxo-ips.conf`):
```ini
[Definition]
failregex = ^.* \[REDAXO-IPS\] (HIGH|CRITICAL) threat from <HOST>:.*$
ignoreregex =
```

fail2ban jail (`/etc/fail2ban/jail.local`):
```ini
[redaxo-ips]
enabled = true
port = http,https
filter = redaxo-ips
logpath = /var/log/redaxo_ips.log
maxretry = 3
bantime = 3600
findtime = 600
```

#### Extension Points für Entwickler

Zusätzlich zum File-Logging können Extension Points verwendet werden:

- `UPKEEP_IPS_THREAT_DETECTED` - Für jede erkannte Bedrohung
- `UPKEEP_IPS_FAIL2BAN_LOG` - Für fail2ban-spezifisches Logging

Diese ermöglichen flexibles externes Logging ohne Dateisystem-Zugriff.

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

