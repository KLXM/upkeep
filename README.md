# REDAXO Upkeep AddOn

Comprehensive maintenance and security add-on for REDAXO CMS.

## Core Features

- **🔧 Maintenance Modes**: Frontend/Backend separately controllable
- **🌐 Multilingual Maintenance Pages**: Professional multilingual user interface
- **🔀 URL Redirects**: With wildcard support (`/old/* -> /new/*`)
- **🛡️ Intrusion Prevention System (IPS)**: Automatic protection against attacks
- **📊 Security Advisor**: SSL certificates, Live-Mode checks, CSP management
- **💾 Mail Security**: Badword filter and spam protection for PHPMailer
- **� Mail Reporting**: Comprehensive email reports for all security events
- **🏥 System Health API**: JSON/Plain text monitoring endpoints for external tools
- **�📈 Dashboard**: Live status of all systems with quick actions
- **⚡ API/Console**: Remote management capabilities

## Installation

1. Install and activate the add-on via REDAXO Backend
2. Configure via Backend → Upkeep

## Quick Start

1. **Maintenance Mode**: Backend → Upkeep → Frontend/Backend
2. **Security Setup**: Backend → Upkeep → IPS → Enable Protection
3. **Security Review**: Backend → Upkeep → Security Advisor → Run Scan
4. **Mail Security**: Automatically active after installation

## Main Components

All features include comprehensive documentation directly in the Backend interface:

### 🔧 Maintenance Modes
**Location**: `Backend → Upkeep → Frontend/Backend`
- Multilingual maintenance pages with elegant language switching
- IP allowlists and password protection
- URL bypass functionality with session management

### 🛡️ Intrusion Prevention System (IPS)  
**Location**: `Backend → Upkeep → IPS`
- Automatic threat detection with pattern matching
- GeoIP integration and country-based analysis
- Rate limiting and CAPTCHA system
- Monitor-Only mode for safe testing

### 📊 Security Advisor
**Location**: `Backend → Upkeep → Security Advisor`
- SSL certificate validation
- REDAXO Live-Mode detection
- Server security headers analysis
- CSP (Content Security Policy) management
- Automated security scoring

### 💾 Mail Security
**Location**: `Backend → Upkeep → Mail Security`  
- Badword filtering for PHPMailer messages
- Spam protection with customizable patterns
- Integration via `PHPMAILER_PRE_SEND` extension point

### 🔀 Domain & URL Management
**Location**: `Backend → Upkeep → Domains`
- Powerful redirect system with wildcard support
- SEO-friendly HTTP status codes
- Domain mapping capabilities

### � Mail Reporting
**Location**: `Backend → Upkeep → Mail Reporting`
- Comprehensive email reports for all Upkeep activities
- Immediate and bundle sending modes
- Security Advisor scan reports
- IPS threat notifications
- Maintenance mode changes
- PHPMailer error replacement
- Console command for cronjob integration

### 🏥 System Health API
**Location**: `Backend → Upkeep → System Health`
- JSON and plain text monitoring endpoints
- External monitoring tool integration (Nagios, Zabbix, Grafana)
- Comprehensive system status information
- Secure API key authentication
- Real-time health status levels

### �📈 Dashboard
**Location**: `Backend → Upkeep` (Main page)
- Live system status overview
- Security threat statistics  
- Quick action buttons for common tasks

## Requirements
- REDAXO 5.15+
- PHP 8.0+  
- MySQL 5.7+ / MariaDB 10.3+

## Console Commands

```bash
# Maintenance modes
php bin/console upkeep:mode frontend on|off
php bin/console upkeep:mode backend on|off
php bin/console upkeep:status

# IPS cleanup
php bin/console upkeep:ips:cleanup

# Security scans
php bin/console upkeep:security:scan

# Mail reporting bundle
php bin/console upkeep:mail-reporting:send-bundle --interval=3600
```

## REST API

### System Health API 🏥

**Location**: `Backend → Upkeep → System Health`

The System Health API provides comprehensive monitoring capabilities for external tools like Nagios, Zabbix, or custom monitoring scripts.

#### Configuration
1. **Enable API**: `Backend → Upkeep → System Health → Enable System Health API`
2. **Generate Key**: Secure access key is automatically generated
3. **Test Endpoints**: Use built-in test buttons to verify functionality

#### API Endpoints

```bash
# Basic JSON Status
curl "https://example.com/?rex-api-call=upkeep_system_health&health_key=YOUR_KEY"

# Detailed JSON Status (includes PHP extensions, database info)
curl "https://example.com/?rex-api-call=upkeep_system_health&health_key=YOUR_KEY&detailed=1"

# Plain Text Status (for simple monitoring)
curl "https://example.com/?rex-api-call=upkeep_system_health&health_key=YOUR_KEY&format=text"
```

#### Response Format

**JSON Response Structure:**
```json
{
  "timestamp": 1726677123,
  "datetime": "2025-09-18 18:40:43",
  "server": "localhost",
  "status": "ok",
  "upkeep": {
    "version": "1.9.0",
    "maintenance": {
      "frontend": false,
      "backend": false
    },
    "security_advisor": {
      "enabled": true,
      "score": 85,
      "grade": "B",
      "critical_issues": 0,
      "warning_issues": 2
    },
    "ips": {
      "enabled": true,
      "active": true,
      "monitor_only": false,
      "recent_threats_24h": 3
    },
    "mail_reporting": {
      "enabled": true,
      "mode": "bundle",
      "log_files_count": 5
    }
  },
  "redaxo": {
    "version": "5.20.0",
    "safe_mode": false,
    "debug_mode": false,
    "live_mode": true
  },
  "system": {
    "php_version": "8.4.11",
    "memory_limit": "256M",
    "max_execution_time": "30"
  }
}
```

**Plain Text Response:**
```
Upkeep System Health Status
===========================

Status: OK
Timestamp: 2025-09-18 18:40:43
Server: localhost

REDAXO:
- Version: 5.20.0
- Live Mode: Yes
- Debug Mode: No

Security Advisor:
- Score: 85
- Grade: B
- Critical Issues: 0

IPS:
- Active: Yes
- Recent Threats (24h): 3
```

#### Status Levels
- **`ok`**: All systems operational
- **`warning`**: Maintenance mode active or high threat activity
- **`critical`**: Critical security issues detected

#### Integration Examples

**Nagios/Icinga Check:**
```bash
#!/bin/bash
HEALTH_KEY="your-health-key-here"
URL="https://your-domain.com/?rex-api-call=upkeep_system_health&health_key=$HEALTH_KEY"

STATUS=$(curl -s "$URL" | jq -r '.status')

case $STATUS in
  "ok")     echo "OK - System healthy"; exit 0 ;;
  "warning") echo "WARNING - System issues detected"; exit 1 ;;
  "critical") echo "CRITICAL - Critical issues detected"; exit 2 ;;
  *)        echo "UNKNOWN - Unable to determine status"; exit 3 ;;
esac
```

**Grafana Integration:**
```bash
# Add as Grafana data source (JSON API)
curl -H "Content-Type: application/json" \
  "https://your-domain.com/?rex-api-call=upkeep_system_health&health_key=YOUR_KEY&detailed=1"
```

### Legacy Maintenance API

```bash
# Get system status
curl "example.com/index.php?rex-api-call=upkeep&token=TOKEN&action=status"

# Toggle maintenance mode
curl "example.com/index.php?rex-api-call=upkeep&token=TOKEN&action=set_frontend&status=1"
```

## Extension Points

```php
// External threat logging
rex_extension::register('UPKEEP_IPS_THREAT_DETECTED', function($ep) {
    $data = $ep->getSubject();
    // Send to external monitoring systems
});

// Mail security filtering
rex_extension::register('PHPMAILER_PRE_SEND', function($ep) {
    // Automatic badword and spam filtering
});
```

## Database Tables

The add-on creates these tables:
- `rex_upkeep_domain_mapping` - URL redirects
- `rex_upkeep_ips_blocked_ips` - Blocked IP addresses  
- `rex_upkeep_ips_threat_log` - Security event log
- `rex_upkeep_ips_custom_patterns` - Custom security patterns
- `rex_upkeep_mail_security` - Mail filtering rules

---

**Maintainer**: FriendsOfREDAXO  
**License**: MIT

🛡️ **Upkeep** - Your reliable partner for REDAXO maintenance and security!### Extension Points

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

**Maintainer**: FriendsOfREDAXO  
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

**Maintainer**: FriendsOfREDAXO  
**License**: MIT
$redirect = DomainMapping::getRedirectForUrl('https://old-site.com/blog/article-1');
if ($redirect) {
    DomainMapping::executeRedirect($redirect['target'], $redirect['status_code']);
}

// Wildcard-Unterstützung
$mappedUrl = DomainMapping::mapWildcardUrl('/blog/category/tech', '/blog/*', '/articles/*');
// Ergebnis: '/articles/category/tech'
```

### FriendsOfRedaxo\Upkeep\MaintenanceView

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

**Thomas Skerbis** - FriendsOfREDAXO

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

**Thomas Skerbis** - FriendsOfREDAXO

---

**Upkeep** - ADDON für REDAXO-Wartung und -Sicherheit! 🛡️ 

