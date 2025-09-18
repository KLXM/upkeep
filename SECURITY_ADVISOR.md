# Security Advisor - Upkeep AddOn

## Übersicht

Der Security Advisor des Upkeep AddOns bietet eine umfassende Analyse der Sicherheitskonfiguration Ihrer REDAXO-Installation. Er prüft kritische Sicherheitsaspekte und gibt konkrete Empfehlungen zur Verbesserung der Website-Sicherheit.

## Features

### 🔍 **Automatisierte Sicherheitsprüfungen**
- **SSL-Zertifikate**: Validierung und Ablaufzeiten aller Domains
- **REDAXO Live-Modus**: Prüfung der Produktionseinstellungen
- **Server-Header**: Analyse auf Informationslecks und Sicherheits-Header
- **PHP-Konfiguration**: Überprüfung gefährlicher Funktionen und Einstellungen
- **Datenbank-Sicherheit**: Passwort-Stärke und Konfiguration
- **Dateiberechtigungen**: Kontrolle kritischer Datei- und Verzeichnisberechtigungen
- **Session-Sicherheit**: Validierung der Session-Konfiguration
- **Content Security Policy**: CSP-Header-Analyse

### 📊 **Bewertungssystem**
- **Sicherheitsscore**: 0-100% mit Notensystem (A+ bis F)
- **Prioritätseinstufung**: High/Medium/Low Severity
- **Statusklassifizierung**: Success/Warning/Error/Info
- **Gesamtbewertung**: Automatische Gewichtung nach Kritikalität

### 📈 **Reporting & Monitoring**
- **Dashboard-Integration**: Quick-Overview im Hauptbereich
- **Detaillierte Berichte**: Vollständige Analyse mit Empfehlungen
- **Export-Funktionen**: JSON-Export für externe Systeme
- **Console Commands**: CLI-basierte Automatisierung

## Installation & Einrichtung

### Voraussetzungen

Der Security Advisor ist Teil des Upkeep AddOns und erfordert:
- REDAXO 5.18.1 oder höher
- PHP 8.2 oder höher
- `upkeep[security]` Berechtigung für Zugriff

### Aktivierung

1. **AddOn aktivieren**: Upkeep im REDAXO Backend aktivieren
2. **Berechtigungen setzen**: `upkeep[security]` Rolle zuweisen
3. **Erste Prüfung**: Security Advisor aufrufen und Scan starten

## Sicherheitsprüfungen im Detail

### 1. REDAXO Live-Modus

**Was wird geprüft:**
- Debug-Modus deaktiviert
- Setup-Modus beendet
- Safe-Modus-Status

**Empfohlene Einstellungen:**
```yaml
# config.yml
debug:
    enabled: false
    throw_always_exception: false
```

**Behebung:**
- `debug: enabled: false` in `config.yml` setzen
- Setup-Flag entfernen falls vorhanden
- REDAXO-Installation finalisieren

### 2. SSL-Zertifikate

**Was wird geprüft:**
- Gültigkeit aller Domain-Zertifikate
- Ablaufdaten (Warnung < 30 Tage)
- Zertifikatskette und Aussteller
- SSL-Verbindungsstatus

**Automatische Prüfung:**
```php
// Für alle YRewrite-Domains
$domains = rex_yrewrite::getDomains();
foreach ($domains as $domain) {
    $sslCheck = $securityAdvisor->checkDomainSsl($domain->getName());
}
```

**Behebung:**
- Gültige SSL-Zertifikate installieren (Let's Encrypt, Kaufzertifikat)
- Automatische Erneuerung einrichten
- Zertifikatskette vollständig konfigurieren

### 3. Server-Header

**Problematische Header:**
- `Server: Apache/2.4.41` → Version preisgegeben
- `X-Powered-By: PHP/8.2.0` → PHP-Version sichtbar

**Empfohlene Sicherheits-Header:**
```apache
# .htaccess
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options SAMEORIGIN
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

**PHP-Konfiguration:**
```ini
# php.ini
expose_php = Off
```

### 4. PHP-Konfiguration

**Gefährliche Funktionen deaktivieren:**
```ini
# php.ini
disable_functions = eval,exec,system,shell_exec,passthru,file_get_contents,file_put_contents,fopen,fwrite
```

**Sichere Einstellungen:**
```ini
display_errors = Off
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off
register_globals = Off
```

### 5. Datenbank-Sicherheit

**Empfohlene Konfiguration:**
```yml
# config.yml
database:
    default:
        host: localhost  # Nur lokale Verbindungen
        login: redaxo_user  # Spezifischer Benutzer, nicht root
        password: "starkes-zufälliges-passwort-min-12-zeichen"
```

**Sicherheitsmaßnahmen:**
- Mindestens 12 Zeichen lange, zufällige Passwörter
- Spezifische Datenbankbenutzer statt root
- Localhost-only Verbindungen
- Regelmäßige Backups

### 6. Dateiberechtigungen

**Empfohlene Berechtigungen:**

```bash
# Verzeichnisse
chmod 755 redaxo/data/
chmod 755 redaxo/cache/
chmod 755 media/

# Kritische Dateien
chmod 600 redaxo/data/config.yml
chmod 600 redaxo/src/addons/*/config.yml

# Ausführbare Dateien
chmod 644 *.php
```

**Automatische Prüfung:**
- Übermäßig offene Berechtigungen (777, 666)
- Kritische Konfigurationsdateien
- Webserver-Zugriff auf sensible Bereiche

### 7. Session-Sicherheit

**Problem:** Session-Cookies sind nicht sicher konfiguriert.

#### Empfohlene PHP-Einstellungen:
```ini
# php.ini
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.cookie_samesite = "Strict"
session.gc_maxlifetime = 1440  # 24 Minuten
```

#### Hosting-spezifische Lösungen:

**📁 .htaccess Alternative (wenn php.ini nicht verfügbar):**
```apache
# .htaccess
php_value session.cookie_httponly 1
php_value session.cookie_secure 1
php_value session.use_strict_mode 1
```

**🖥️ cPanel:**
1. **Software** → **Select PHP Version**
2. **Extensions** → PHP-Konfiguration
3. Aktivieren: `session.cookie_httponly` 
4. Aktivieren: `session.cookie_secure`
5. Aktivieren: `session.use_strict_mode`

**🔧 Plesk:**
1. **Websites & Domains** → **PHP-Einstellungen**
2. Häkchen setzen bei `session.cookie_httponly`
3. `session.cookie_secure` aktivieren
4. `session.use_strict_mode` aktivieren

**🏠 Shared Hosting:**
```php
# Als Fallback in redaxo/src/core/boot.php nach den ersten Zeilen:
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.use_strict_mode', '1');
```

**🎯 Strato/1&1/Ionos:**
- Über das Control Panel → PHP-Konfiguration
- Oder Support-Ticket für Session-Parameter

**⚡ Was diese Einstellungen bewirken:**
- `cookie_httponly`: Verhindert JavaScript-Zugriff auf Session-Cookies (XSS-Schutz)
- `cookie_secure`: Cookies nur über HTTPS übertragen (MITM-Schutz)
- `use_strict_mode`: Verhindert Session-Fixation-Angriffe

### 8. Content Security Policy (CSP)

**Grundlegende CSP:**
```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    connect-src 'self';
    frame-ancestors 'none';
">
```

**Erweiterte CSP-Integration:**
```php
// boot.php
rex_extension::register('OUTPUT_FILTER', function($ep) {
    $content = $ep->getSubject();
    $csp = "default-src 'self'; script-src 'self' 'unsafe-inline'";
    
    $content = str_replace(
        '</head>',
        '<meta http-equiv="Content-Security-Policy" content="' . $csp . '">' . "\n</head>",
        $content
    );
    
    $ep->setSubject($content);
});
```

## Dashboard Integration

### Sicherheits-Widgets

Der Security Advisor integriert sich nahtlos in das Upkeep Dashboard:

```php
// Automatische Integration
$stats = $securityAdvisor->getDashboardStats();

// Verfügbare Metriken:
$stats['security_score'];     // 0-100%
$stats['security_grade'];     // A+ bis F
$stats['critical_issues'];    // Anzahl kritischer Probleme
$stats['warning_issues'];     // Anzahl Warnungen
$stats['last_check'];        // Timestamp letzter Scan
$stats['overall_status'];    // success/warning/error
```

### Quick Actions

- **Security Scan starten**: Direkt vom Dashboard
- **Detaillierte Berichte**: Vollständige Analyse-Ansicht
- **Export-Funktionen**: JSON-Download für externe Tools

## API Integration

### REST Endpoints

```bash
# Sicherheitsscan durchführen
curl -X POST "https://ihre-domain.de/api/upkeep/security/scan" \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Sicherheitsstatus abrufen
curl -X GET "https://ihre-domain.de/api/upkeep/security/status" \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Detaillierte Berichte abrufen
curl -X GET "https://ihre-domain.de/api/upkeep/security/reports" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### PHP-Integration

```php
use KLXM\Upkeep\SecurityAdvisor;

$advisor = new SecurityAdvisor();

// Vollständige Prüfung
$results = $advisor->runAllChecks();

// Dashboard-Statistiken
$stats = $advisor->getDashboardStats();

// Einzelne Prüfungen
$advisor->checkRedaxoLiveMode();
$advisor->checkSslCertificates();
$advisor->checkServerHeaders();
```

## Console Commands

### Grundlegende Verwendung

```bash
# Vollständiger Sicherheitsscan
php redaxo/bin/console upkeep:security:scan

# Nur kritische Probleme anzeigen
php redaxo/bin/console upkeep:security:scan --filter=error

# JSON-Export
php redaxo/bin/console upkeep:security:scan --format=json --output-file=security_report.json

# Zusammenfassung für Monitoring
php redaxo/bin/console upkeep:security:scan --format=summary --silent
```

### Automatisierung

**Cron Job Setup:**
```bash
# Tägliche Sicherheitsprüfung um 2:00 Uhr
0 2 * * * cd /path/to/redaxo && php bin/console upkeep:security:scan --format=summary --silent
```

**Monitoring Integration:**
```bash
#!/bin/bash
# security-check.sh

RESULT=$(php redaxo/bin/console upkeep:security:scan --format=summary --silent)
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
    # Kritische Probleme gefunden
    echo "CRITICAL: $RESULT" | mail -s "Security Alert" admin@domain.de
elif [ $EXIT_CODE -eq 1 ]; then
    # Warnungen gefunden
    echo "WARNING: $RESULT" | mail -s "Security Warning" admin@domain.de
fi
```

### Exit-Codes

- `0`: Keine Probleme gefunden
- `1`: Warnungen vorhanden
- `2`: Kritische Probleme gefunden

## Erweiterte Konfiguration

### Custom Security Checks

```php
// boot.php - Eigene Prüfungen hinzufügen
rex_extension::register('UPKEEP_SECURITY_CHECKS', function($ep) {
    $checks = $ep->getParam('checks');
    
    // Custom Check hinzufügen
    $checks['custom_check'] = [
        'name' => 'Custom Security Check',
        'callback' => function() {
            // Ihre Prüflogik hier
            return [
                'status' => 'success',
                'score' => 10,
                'description' => 'Custom check passed'
            ];
        }
    ];
    
    $ep->setParam('checks', $checks);
});
```

### Threshold-Konfiguration

```php
// Eigene Bewertungsschwellen
$addon = rex_addon::get('upkeep');
$addon->setConfig('security_thresholds', [
    'excellent' => 95,  // A+
    'good' => 85,       // A
    'acceptable' => 70, // B
    'poor' => 50,       // C
    'critical' => 30    // D
]);
```

### Notification Hooks

```php
// boot.php - Benachrichtigungen bei kritischen Problemen
rex_extension::register('UPKEEP_SECURITY_CRITICAL', function($ep) {
    $issues = $ep->getParam('critical_issues');
    $score = $ep->getParam('security_score');
    
    // E-Mail-Benachrichtigung
    $message = "Kritische Sicherheitsprobleme gefunden:\n";
    foreach ($issues as $issue) {
        $message .= "- " . $issue['name'] . "\n";
    }
    
    mail('admin@domain.de', 'Security Alert', $message);
    
    // Slack-Benachrichtigung
    $webhook = 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK';
    $payload = json_encode([
        'text' => "Security Score: {$score}% - Immediate action required!",
        'color' => 'danger'
    ]);
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => $payload
        ]
    ]);
    
    file_get_contents($webhook, false, $context);
});
```

## Best Practices

### 1. Regelmäßige Scans

```bash
# Wöchentliche Vollprüfung
0 2 * * 1 cd /path/to/redaxo && php bin/console upkeep:security:scan --format=json --output-file=/var/log/redaxo-security-$(date +\%Y-\%m-\%d).json

# Tägliche Quick-Checks
0 8 * * * cd /path/to/redaxo && php bin/console upkeep:security:scan --filter=error --format=summary
```

### 2. Baseline-Sicherheit

**Minimale Sicherheitsanforderungen:**
- SSL-Zertifikate für alle Domains
- REDAXO Live-Modus aktiviert
- Server-Header nicht preisgeben
- Starke Datenbank-Passwörter
- Korrekte Dateiberechtigungen

### 3. Incident Response

**Bei kritischen Problemen:**
1. Sofortige Benachrichtigung der Administratoren
2. Automatische Dokumentation der Probleme
3. Verfolgung der Behebungsmaßnahmen
4. Erneute Prüfung nach Fixes

### 4. Compliance & Dokumentation

```bash
# Monatliche Compliance-Berichte
php redaxo/bin/console upkeep:security:scan --format=json --output-file=compliance-$(date +%Y-%m).json
```

## Troubleshooting

### Häufige Probleme

#### Problem: SSL-Prüfung schlägt fehl

**Ursachen:**
- Firewall blockiert Port 443
- Selbstsignierte Zertifikate
- Falsche Domain-Konfiguration

**Lösung:**
```bash
# Manuelle SSL-Prüfung
openssl s_client -connect ihre-domain.de:443 -servername ihre-domain.de

# Zertifikatsinformationen
openssl x509 -in certificate.crt -text -noout
```

#### Problem: PHP-Konfiguration kann nicht geändert werden

**Shared Hosting Einschränkungen:**
- `.htaccess` PHP-Direktiven verwenden
- Hosting-Provider kontaktieren
- Alternative Sicherheitsmaßnahmen implementieren

```apache
# .htaccess Alternative
php_value expose_php Off
php_value display_errors Off
```

#### Problem: Berechtigung fehlt

**Fehler:** "Access denied for Security Advisor"

**Lösung:**
```sql
-- Berechtigung hinzufügen
UPDATE rex_user_role 
SET perms = CONCAT(perms, '|upkeep[security]') 
WHERE name = 'admin';
```

### Debug-Modus

```php
// Detaillierte Fehlerausgabe aktivieren
$addon = rex_addon::get('upkeep');
$addon->setConfig('security_debug', true);

// Einzelne Checks debuggen
$advisor = new SecurityAdvisor();
$advisor->setDebug(true);
$results = $advisor->checkSslCertificates();
```

## Security Empfehlungen

### 1. Proaktive Sicherheit

- **Automatisierte Scans**: Tägliche oder wöchentliche Prüfungen
- **Monitoring**: Integration in bestehende Überwachungssysteme
- **Alerting**: Sofortige Benachrichtigung bei kritischen Problemen

### 2. Defense in Depth

```bash
# Mehrschichtige Sicherheit
# 1. Netzwerk-Level (Firewall, DDoS-Schutz)
# 2. Server-Level (OS-Updates, Service-Hardening)
# 3. Anwendungs-Level (REDAXO Security Advisor)
# 4. Daten-Level (Verschlüsselung, Backups)
```

### 3. Incident Response Plan

1. **Erkennung**: Automatische Alerts bei Sicherheitsproblemen
2. **Bewertung**: Schnelle Einschätzung der Kritikalität
3. **Eindämmung**: Sofortige Schutzmaßnahmen
4. **Behebung**: Systematische Problemlösung
5. **Nachbereitung**: Dokumentation und Verbesserungen

### 4. Compliance Tracking

```php
// Compliance-Berichte für Audits
$complianceReport = [
    'timestamp' => time(),
    'security_score' => $results['summary']['score'],
    'critical_issues' => $results['summary']['critical_issues'],
    'ssl_status' => $results['checks']['ssl_certificates']['status'],
    'privacy_settings' => [
        'debug_mode' => !rex::isDebugMode(),
        'server_headers_secure' => $results['checks']['server_headers']['score'] >= 8
    ]
];

file_put_contents('compliance-' . date('Y-m') . '.json', json_encode($complianceReport));
```

## Changelog

### Version 1.8.1
- ✅ Vollständige SSL-Zertifikatsprüfung
- ✅ REDAXO Live-Modus Validierung
- ✅ Server-Header Sicherheitsanalyse
- ✅ PHP-Konfigurationsprüfung
- ✅ Datenbank-Sicherheitsbewertung
- ✅ Dateiberechtigungskontrolle
- ✅ Session-Sicherheitsvalidierung
- ✅ CSP-Header-Analyse
- ✅ Console Command Integration
- ✅ Dashboard Integration
- ✅ Export-Funktionen

### Geplante Features
- 🔄 OWASP Top 10 Compliance Checks
- 🔄 Advanced Malware Scanning
- 🔄 Security Headers Score Integration
- 🔄 Automated Fix Suggestions
- 🔄 Integration mit externen Security Services

## Support

Für Support und weitere Informationen:

- **GitHub**: https://github.com/klxm/upkeep
- **Issues**: https://github.com/klxm/upkeep/issues
- **Dokumentation**: Backend → Upkeep → Security Advisor → Security Advisor Dokumentation
- **REDAXO Forum**: https://www.redaxo.org/forum/

---

*Diese Dokumentation wird kontinuierlich aktualisiert. Letzte Aktualisierung: September 2025*