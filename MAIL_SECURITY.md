# Mail Security System - Upkeep AddOn

## Übersicht

Das Mail Security System ist ein umfassendes Sicherheitsmodul des Upkeep AddOns, das E-Mail-Kommunikation vor Spam, Badwords und schädlichen Inhalten schützt. Es integriert sich nahtlos in PHPMailer und bietet erweiterte Funktionen wie IP/Domain-Blocklisting, Rate-Limiting und umfangreiche Protokollierung.

## Features

### 🛡️ Kernfunktionen
- **Badword-Filter**: Automatische Erkennung und Blockierung von unerwünschten Begriffen
- **IP/Domain Blocklist**: Sperrung von E-Mails basierend auf Absender-IP oder Domain
- **Rate Limiting**: Schutz vor E-Mail-Spam durch Frequenzbegrenzung
- **Threat Detection**: Erkennung von Code-Injection und anderen Bedrohungen
- **Integration**: Nahtlose Integration in PHPMailer über Extension Points

### 📊 Monitoring & Analytics
- **Dashboard**: Übersichtliche Statistiken und Status-Informationen
- **Threat Log**: Detaillierte Protokollierung aller Sicherheitsereignisse
- **Real-time Monitoring**: Live-Updates über erkannte Bedrohungen
- **Berichte**: Zusammenfassungen über blockierte E-Mails und Trends

### ⚙️ Verwaltung
- **Backend-Interface**: Vollständige Verwaltung über REDAXO-Backend
- **Bulk-Operationen**: Massenbearbeitung von Blocklist-Einträgen
- **Export/Import**: Datenaustausch für Backup und Migration
- **Automatische Bereinigung**: Regelmäßige Bereinigung alter Logs

## Installation

Das Mail Security System ist Teil des Upkeep AddOns und wird automatisch installiert. Nach der Installation sind folgende Schritte erforderlich:

1. **Aktivierung**: Mail Security über die Einstellungen aktivieren
2. **Konfiguration**: Badwords und Blocklist-Einträge definieren
3. **Testing**: Funktionalität mit Test-E-Mails verifizieren

## Konfiguration

### Grundeinstellungen

```php
// Mail Security aktivieren/deaktivieren
$addon->setConfig('mail_security_active', true);

// Badword-Filter aktivieren
$addon->setConfig('badword_filter_enabled', true);

// IP/Domain Blocklist aktivieren
$addon->setConfig('blocklist_enabled', true);

// Rate Limiting aktivieren
$addon->setConfig('mail_rate_limiting_enabled', true);
```

### Rate Limiting Konfiguration

```php
// E-Mails pro Minute (Standard: 5)
$addon->setConfig('mail_rate_limit_per_minute', 5);

// E-Mails pro Stunde (Standard: 50)
$addon->setConfig('mail_rate_limit_per_hour', 50);

// E-Mails pro Tag (Standard: 500)
$addon->setConfig('mail_rate_limit_per_day', 500);
```

### Bedrohungserkennung

```php
// Code-Injection Schutz
$addon->setConfig('code_injection_protection', true);

// HTML-Injection Schutz  
$addon->setConfig('html_injection_protection', true);

// Script-Tag Erkennung
$addon->setConfig('script_tag_detection', true);
```

## Badword-Management

### Badwords hinzufügen

**Backend**: `Upkeep → Mail Security → Badwords`

**Programmatisch**:
```php
use KLXM\Upkeep\MailSecurityFilter;

// Einzelnes Badword hinzufügen
MailSecurityFilter::addBadword('spam', 'high');

// Mehrere Badwords hinzufügen
$badwords = [
    ['word' => 'casino', 'severity' => 'medium'],
    ['word' => 'viagra', 'severity' => 'high'],
    ['word' => '/\b(win|winner)\b/i', 'severity' => 'low', 'is_regex' => true]
];

foreach ($badwords as $badword) {
    MailSecurityFilter::addBadword(
        $badword['word'],
        $badword['severity'],
        $badword['is_regex'] ?? false
    );
}
```

### Eigene Patterns erstellen

Das Mail Security System unterstützt sowohl einfache Text-Patterns als auch komplexe reguläre Ausdrücke (Regex) für die Erkennung von unerwünschten Inhalten.

#### Einfache Text-Patterns

Einfache Text-Patterns werden exakt oder als Teilstring gesucht:

```php
// Exakte Übereinstimmung
MailSecurityFilter::addBadword('casino', 'medium');

// Teilstring-Suche (case-insensitive)
MailSecurityFilter::addBadword('lottery', 'low');
```

**Hinweis**: Einfache Patterns sind case-insensitive und finden auch Teilübereinstimmungen.

#### Reguläre Ausdrücke (Regex)

Für komplexere Muster verwenden Sie reguläre Ausdrücke. Diese müssen mit `/` beginnen und enden:

```php
// Grundsyntax für Regex-Patterns
MailSecurityFilter::addBadword('/pattern/modifiers', 'severity', true);
```

##### Regex-Modifier

| Modifier | Bedeutung | Beispiel |
|----------|-----------|----------|
| `i` | Case-insensitive | `/spam/i` findet "Spam", "SPAM", "spam" |
| `m` | Multi-line | `/^Subject:/m` findet Zeilenanfänge |
| `s` | DOTALL (`.` matcht auch \n) | `/begin.*end/s` über mehrere Zeilen |
| `x` | Ignoriert Leerzeichen | `/spam word/x` ignoriert Leerzeichen im Pattern |

##### Häufige Regex-Patterns

**1. Wortgrenzen (Whole Words Only)**
```php
// Findet nur das exakte Wort "win", nicht "winner" oder "twin"
MailSecurityFilter::addBadword('/\bwin\b/i', 'low', true);

// Mehrere Varianten
MailSecurityFilter::addBadword('/\b(win|winner|winning)\b/i', 'medium', true);
```

**2. Zahlen und Beträge**
```php
// Verdächtige Preisangaben
MailSecurityFilter::addBadword('/\$\d{1,3}(,\d{3})*(\.\d{2})?/', 'medium', true);

// Prozentangaben
MailSecurityFilter::addBadword('/\d{1,3}%/', 'low', true);
```

**3. URLs und Domains**
```php
// Verdächtige Domains
MailSecurityFilter::addBadword('/\.xyz$|\.top$|\.win$/i', 'high', true);

// URL-Schemata
MailSecurityFilter::addBadword('/https?:\/\/[^\s]+/', 'medium', true);
```

**4. Telefonnummern**
```php
// US-Telefonnummern
MailSecurityFilter::addBadword('/\b\d{3}-\d{3}-\d{4}\b/', 'medium', true);

// Internationale Nummern
MailSecurityFilter::addBadword('/\+\d{1,3}\s?\d{1,4}[\s\-\.]?\d{1,4}[\s\-\.]?\d{1,4}/', 'medium', true);
```

**5. Datumsmuster**
```php
// Datumsangaben
MailSecurityFilter::addBadword('/\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/', 'low', true);

// Uhrzeiten
MailSecurityFilter::addBadword('/\b\d{1,2}:\d{2}\s?(am|pm)?\b/i', 'low', true);
```

**6. Spam-typische Phrasen**
```php
// Dringlichkeit signalisieren
MailSecurityFilter::addBadword('/urgent|immediate|asap|emergency/i', 'medium', true);

// Geldbezogene Begriffe
MailSecurityFilter::addBadword('/million|thousand|billion|fortune/i', 'medium', true);

// Handlungsaufforderungen
MailSecurityFilter::addBadword('/click here|call now|contact us/i', 'low', true);
```

**7. E-Mail-spezifische Patterns**
```php
// Mehrfachausrufezeichen
MailSecurityFilter::addBadword('/!{2,}/', 'low', true);

// Großbuchstaben-Blöcke
MailSecurityFilter::addBadword('/[A-Z]{5,}/', 'low', true);

// Wiederholte Wörter
MailSecurityFilter::addBadword('/\b(\w+)\s+\1\b/i', 'low', true);
```

##### Erweiterte Regex-Techniken

**Lookahead und Lookbehind**
```php
// Positive Lookahead: Wort gefolgt von bestimmten Zeichen
MailSecurityFilter::addBadword('/password(?=\s*[:=]\s*)/i', 'high', true);

// Negative Lookbehind: Nicht nach bestimmten Zeichen
MailSecurityFilter::addBadword('/(?<!(?:re|un))subscribe/i', 'low', true);
```

**Quantifier**
```php
// Optionale Teile
MailSecurityFilter::addBadword('/free(?:dom)?(?:dom)?/i', 'medium', true);

// Wiederholungen
MailSecurityFilter::addBadword('/ha{1,3}/i', 'low', true); // ha, haa, haaa
```

**Character Classes**
```php
// Beliebige Ziffern
MailSecurityFilter::addBadword('/[0-9]+/', 'low', true);

// Wortzeichen
MailSecurityFilter::addBadword('/\w+/', 'low', true);

// Leerzeichen
MailSecurityFilter::addBadword('/\s+/', 'low', true);
```

#### Regex-Testing und Debugging

**1. Online-Tools**
- [Regex101](https://regex101.com) - Interaktiver Regex-Tester
- [RegExr](https://regexr.com) - Visual Regex Builder
- [Regex Tester](https://www.regextester.com) - Einfacher Tester

**2. Test-Strategien**
```php
// Test-Email erstellen
$testEmail = "Subject: WIN BIG CASH PRIZE!\n\nDear user,\n\nYou have won $1,000,000!";

// Pattern testen
$pattern = '/\bwin\b.*\b(cash|prize|money)\b/i';
if (preg_match($pattern, $testEmail)) {
    echo "Pattern matched!";
}
```

**3. Häufige Fehler vermeiden**
```php
// ❌ Falsch: Zu gierig
MailSecurityFilter::addBadword('/<.*>/', 'medium', true); // Findet zu viel

// ✅ Richtig: Nicht-gierig
MailSecurityFilter::addBadword('/<.*?>/', 'medium', true); // Findet einzelne Tags

// ❌ Falsch: Performance-Problem
MailSecurityFilter::addBadword('/a.*b.*c.*d/', 'medium', true); // Zu viele .* 

// ✅ Richtig: Spezifischer
MailSecurityFilter::addBadword('/a[^b]*b[^c]*c[^d]*d/', 'medium', true);
```

#### Pattern-Priorisierung

**Severity-Level definieren**
```php
// Kritische Patterns (sofort blockieren)
MailSecurityFilter::addBadword('/password.*hack/i', 'critical', true);
MailSecurityFilter::addBadword('/bank.*account.*steal/i', 'critical', true);

// Hohe Priorität (wahrscheinlich Spam)
MailSecurityFilter::addBadword('/lottery.*winner/i', 'high', true);
MailSecurityFilter::addBadword('/inheritance.*fund/i', 'high', true);

// Mittlere Priorität (verdächtig)
MailSecurityFilter::addBadword('/free.*money/i', 'medium', true);
MailSecurityFilter::addBadword('/urgent.*action/i', 'medium', true);

// Niedrige Priorität (nur loggen)
MailSecurityFilter::addBadword('/special.*offer/i', 'low', true);
MailSecurityFilter::addBadword('/discount/i', 'low', true);
```

#### Kategorisierung von Patterns

Verwenden Sie Kategorien, um Patterns zu organisieren:

```php
$patterns = [
    // Finanzbetrug
    ['word' => '/\b(win|won|winner)\b.*\$\d+/i', 'severity' => 'high', 'category' => 'financial_fraud', 'is_regex' => true],
    ['word' => '/lottery.*prize/i', 'severity' => 'high', 'category' => 'financial_fraud', 'is_regex' => true],
    
    // Phishing
    ['word' => '/verify.*account/i', 'severity' => 'high', 'category' => 'phishing', 'is_regex' => true],
    ['word' => '/suspended.*account/i', 'severity' => 'high', 'category' => 'phishing', 'is_regex' => true],
    
    // Malware
    ['word' => '/download.*exe/i', 'severity' => 'medium', 'category' => 'malware', 'is_regex' => true],
    ['word' => '/infected.*file/i', 'severity' => 'medium', 'category' => 'malware', 'is_regex' => true],
    
    // Spam
    ['word' => '/free.*gift/i', 'severity' => 'low', 'category' => 'spam', 'is_regex' => true],
    ['word' => '/guaranteed.*income/i', 'severity' => 'low', 'category' => 'spam', 'is_regex' => true],
];

// Massenimport
foreach ($patterns as $pattern) {
    MailSecurityFilter::addBadword(
        $pattern['word'],
        $pattern['severity'],
        $pattern['is_regex'],
        $pattern['category']
    );
}
```

### Badword-Kategorien

| Kategorie | Beschreibung | Beispiele |
|-----------|--------------|-----------|
| **Spam** | Typische Spam-Begriffe | casino, lottery, winner |
| **Adult** | Nicht jugendfreie Inhalte | adult, xxx, sex |
| **Phishing** | Betrügerische Begriffe | urgent, verify account, suspended |
| **Malware** | Schädliche Begriffe | download now, infected, virus |
| **Financial** | Finanzbetrug | wire transfer, bitcoin scam |
| **Custom** | Benutzerdefiniert | Projektspezifische Begriffe |

## IP/Domain Blocklist

### Blocklist-Einträge verwalten

**Backend**: `Upkeep → Mail Security → Blocklist`

**Programmatisch**:
```php
use KLXM\Upkeep\MailSecurityFilter;

// IP-Adresse sperren
MailSecurityFilter::addToBlocklist('192.168.1.100', 'ip', 'Spam-Quelle');

// Domain sperren
MailSecurityFilter::addToBlocklist('spam-domain.com', 'domain', 'Bekannte Spam-Domain');

// E-Mail-Adresse sperren
MailSecurityFilter::addToBlocklist('spammer@evil.com', 'email', 'Spam-Account');

// Mit Ablaufzeit (24 Stunden)
MailSecurityFilter::addToBlocklist(
    '10.0.0.50', 
    'ip', 
    'Temporäre Sperrung',
    new DateTime('+24 hours')
);
```

### Blocklist-Typen

| Typ | Beschreibung | Format | Beispiel |
|-----|--------------|---------|----------|
| **IP** | IP-Adresse | IPv4/IPv6 | `192.168.1.100` |
| **Domain** | Domain-Name | FQDN | `spam-domain.com` |
| **Email** | E-Mail-Adresse | user@domain | `spammer@evil.com` |
| **Subnet** | IP-Bereich | CIDR | `192.168.1.0/24` |

### Wildcard-Unterstützung

```php
// Domain-Wildcards
MailSecurityFilter::addToBlocklist('*.spam-network.com', 'domain', 'Spam-Netzwerk');

// E-Mail-Wildcards
MailSecurityFilter::addToBlocklist('*@phishing-site.org', 'email', 'Phishing-Domain');
```

## Rate Limiting

### Funktionsweise

Das Rate Limiting System überwacht E-Mail-Versand basierend auf:
- **IP-Adresse** des Absenders
- **Zeitfenster** (Minute, Stunde, Tag)
- **Konfigurierte Limits**

### Limits konfigurieren

**Backend**: `Upkeep → Mail Security → Settings → Rate Limiting`

**Konfigurationsdatei**:
```php
// config.yml
mail_security:
    rate_limiting:
        enabled: true
        per_minute: 5
        per_hour: 50
        per_day: 500
        whitelist_ips:
            - '127.0.0.1'
            - '::1'
```

### Rate Limiting Status prüfen

```php
use KLXM\Upkeep\MailSecurityFilter;

$ip = '192.168.1.100';
$isBlocked = MailSecurityFilter::isRateLimitExceeded($ip);

if ($isBlocked) {
    echo "Rate Limit für IP {$ip} überschritten";
}
```

## Threat Detection

### Erkannte Bedrohungstypen

| Typ | Beschreibung | Aktion |
|-----|--------------|--------|
| **mail_badword** | Badword in E-Mail erkannt | Block + Log |
| **mail_blocklist_ip** | IP auf Blocklist | Block + Log |
| **mail_blocklist_domain** | Domain auf Blocklist | Block + Log |
| **mail_code_injection** | Code-Injection Versuch | Block + Log |
| **mail_rate_limit** | Rate Limit überschritten | Block + Log |
| **mail_html_injection** | HTML-Injection erkannt | Block + Log |

### Code-Injection Patterns

Das System erkennt folgende Injection-Muster:

```php
// PHP Code Injection
'/<\?php.*?\?>/i'
'/<script.*?<\/script>/is'
'/<\?.*?\?>/i'

// SQL Injection
'/union\s+select/i'
'/drop\s+table/i'
'/insert\s+into/i'

// JavaScript Injection
'/javascript:/i'
'/vbscript:/i'
'/onload\s*=/i'
'/onerror\s*=/i'

// HTML Injection
'/<iframe.*?>/i'
'/<object.*?>/i'
'/<embed.*?>/i'
```

## API-Dokumentation

### REST API Endpoints

Das Mail Security System bietet folgende API-Endpoints:

#### Authentifizierung

```http
POST /api/upkeep/auth
Content-Type: application/json

{
    "api_token": "your_api_token_here"
}
```

#### Mail Security Status

```http
GET /api/upkeep/mail-security/status
Authorization: Bearer {token}
```

**Response**:
```json
{
    "status": "success",
    "data": {
        "active": true,
        "threats_24h": 45,
        "blocked_emails_24h": 12,
        "badwords_count": 156,
        "blocklist_count": 89,
        "rate_limit_blocks_24h": 3
    }
}
```

#### Badwords verwalten

**Alle Badwords abrufen**:
```http
GET /api/upkeep/mail-security/badwords
Authorization: Bearer {token}
```

**Badword hinzufügen**:
```http
POST /api/upkeep/mail-security/badwords
Authorization: Bearer {token}
Content-Type: application/json

{
    "word": "spam",
    "severity": "high",
    "is_regex": false,
    "category": "spam"
}
```

**Badword aktualisieren**:
```http
PUT /api/upkeep/mail-security/badwords/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
    "word": "updated-word",
    "severity": "medium",
    "status": 1
}
```

**Badword löschen**:
```http
DELETE /api/upkeep/mail-security/badwords/{id}
Authorization: Bearer {token}
```

#### Blocklist verwalten

**Blocklist-Einträge abrufen**:
```http
GET /api/upkeep/mail-security/blocklist
Authorization: Bearer {token}
```

**Zur Blocklist hinzufügen**:
```http
POST /api/upkeep/mail-security/blocklist
Authorization: Bearer {token}
Content-Type: application/json

{
    "entry": "spam-domain.com",
    "type": "domain",
    "reason": "Known spam domain",
    "expires_at": "2024-12-31 23:59:59"
}
```

**Blocklist-Eintrag entfernen**:
```http
DELETE /api/upkeep/mail-security/blocklist/{id}
Authorization: Bearer {token}
```

#### Threat Log

**Bedrohungsprotokoll abrufen**:
```http
GET /api/upkeep/mail-security/threats
Authorization: Bearer {token}
```

**Parameter**:
- `limit`: Anzahl Einträge (Standard: 50)
- `offset`: Offset für Paginierung
- `severity`: Filter nach Schweregrad
- `type`: Filter nach Bedrohungstyp
- `from_date`: Startdatum (YYYY-MM-DD)
- `to_date`: Enddatum (YYYY-MM-DD)

**Beispiel**:
```http
GET /api/upkeep/mail-security/threats?limit=100&severity=high&from_date=2024-01-01
```

### PHP API

#### MailSecurityFilter Klasse

```php
use KLXM\Upkeep\MailSecurityFilter;

// Mail-Filterung (wird automatisch von PHPMailer aufgerufen)
$result = MailSecurityFilter::filterMail($phpmailer);

// Manuelle Prüfung
$isThreat = MailSecurityFilter::checkForThreats($content, $headers);

// Dashboard-Statistiken
$stats = MailSecurityFilter::getDashboardStats();

// Badword prüfen
$hasBadword = MailSecurityFilter::containsBadwords($text);

// IP auf Blocklist prüfen
$isBlocklisted = MailSecurityFilter::isBlocklisted('192.168.1.100', 'ip');

// Rate Limit prüfen
$isLimited = MailSecurityFilter::isRateLimitExceeded('192.168.1.100');
```

#### Event Hooks

```php
// Extension Point für eigene Filter
rex_extension::register('PHPMAILER_PRE_SEND', function($ep) {
    $mailer = $ep->getParam('mailer');
    
    // Eigene Sicherheitsprüfungen hier
    $customCheck = myCustomSecurityCheck($mailer);
    
    if (!$customCheck) {
        $ep->setParam('send', false);
        $ep->setParam('message', 'Custom security check failed');
    }
});

// Nach Mail Security Filterung
rex_extension::register('UPKEEP_MAIL_SECURITY_FILTERED', function($ep) {
    $result = $ep->getParam('result');
    $mailer = $ep->getParam('mailer');
    
    // Eigene Aktionen nach Filterung
    if (!$result['allowed']) {
        // Benachrichtigung an Admin
        notifyAdminOfBlockedEmail($result, $mailer);
    }
});
```

## Database Schema

### Tabellen-Übersicht

#### upkeep_mail_badwords
```sql
CREATE TABLE upkeep_mail_badwords (
    id INT PRIMARY KEY AUTO_INCREMENT,
    word VARCHAR(500) NOT NULL,
    is_regex TINYINT(1) DEFAULT 0,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    category VARCHAR(100) DEFAULT 'general',
    status TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_word (word(100)),
    INDEX idx_status (status),
    INDEX idx_category (category)
);
```

#### upkeep_mail_blocklist
```sql
CREATE TABLE upkeep_mail_blocklist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    entry VARCHAR(500) NOT NULL,
    type ENUM('ip', 'domain', 'email') NOT NULL,
    ip_address VARCHAR(45) NULL,
    reason TEXT,
    status TINYINT(1) DEFAULT 1,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_entry (entry(100)),
    INDEX idx_type (type),
    INDEX idx_ip_address (ip_address),
    INDEX idx_status_expires (status, expires_at)
);
```

#### upkeep_mail_threat_log
```sql
CREATE TABLE upkeep_mail_threat_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    threat_type VARCHAR(100) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    email_data JSON,
    threat_details JSON,
    blocked TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_threat_type (threat_type),
    INDEX idx_severity (severity),
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at),
    INDEX idx_blocked (blocked)
);
```

#### upkeep_mail_rate_limit
```sql
CREATE TABLE upkeep_mail_rate_limit (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    email_count INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_created (ip_address, created_at)
);
```

## Monitoring & Alerting

### Dashboard-Metriken

Das Mail Security Dashboard zeigt folgende Metriken:

- **Bedrohungen (24h)**: Anzahl erkannter Bedrohungen
- **Blockierte E-Mails (24h)**: Anzahl blockierter E-Mails
- **Aktive Badwords**: Anzahl aktiver Badword-Filter
- **Blocklist-Einträge**: Anzahl aktiver Sperren
- **Rate Limit Blocks**: Rate-Limiting Ereignisse

### Logging

Alle Sicherheitsereignisse werden protokolliert:

```php
// Log-Struktur
[
    'timestamp' => '2024-01-15 14:30:22',
    'threat_type' => 'mail_badword',
    'severity' => 'high',
    'ip_address' => '192.168.1.100',
    'details' => [
        'badword' => 'casino',
        'email_subject' => 'Win big at our casino!',
        'sender' => 'spammer@example.com'
    ],
    'action' => 'blocked'
]
```

### Alerts konfigurieren

```php
// Threshold-basierte Alerts
$config = [
    'threat_threshold_per_hour' => 100,
    'blocked_emails_threshold_per_day' => 1000,
    'new_badwords_alert' => true,
    'blocklist_changes_alert' => true
];

// Alert-Empfänger
$alert_recipients = [
    'admin@example.com',
    'security@example.com'
];
```

## Performance-Optimierung

### Caching

Das System nutzt effizientes Caching für:
- **Badwords**: In-Memory Cache für häufige Prüfungen
- **Blocklist**: Redis/Memcache für schnelle IP-Lookups
- **Rate Limits**: Temporäre Speicherung für aktuelle Limits

### Database-Optimierung

```sql
-- Index-Optimierungen
CREATE INDEX idx_mail_threats_composite ON upkeep_mail_threat_log 
    (threat_type, created_at, severity);

CREATE INDEX idx_mail_blocklist_lookup ON upkeep_mail_blocklist 
    (type, entry(100), status, expires_at);

-- Partitionierung für große Tabellen
ALTER TABLE upkeep_mail_threat_log 
PARTITION BY RANGE (UNIX_TIMESTAMP(created_at)) (
    PARTITION p202401 VALUES LESS THAN (UNIX_TIMESTAMP('2024-02-01')),
    PARTITION p202402 VALUES LESS THAN (UNIX_TIMESTAMP('2024-03-01')),
    -- weitere Partitionen...
);
```

### Cleanup-Strategien

```php
// Automatische Bereinigung alter Logs
$cleanup_config = [
    'threat_log_retention_days' => 90,
    'rate_limit_retention_hours' => 24,
    'cleanup_batch_size' => 1000,
    'cleanup_interval' => '0 2 * * *' // Täglich um 2:00 Uhr
];
```

## Troubleshooting

### Häufige Probleme

#### Mail wird fälschlicherweise blockiert

1. **Überprüfen Sie das Threat Log**:
   ```
   Backend → Mail Security → Threat Log
   ```

2. **Badword-Filter anpassen**:
   - Entfernen Sie überreaktive Badwords
   - Verwenden Sie präzisere RegEx-Patterns

3. **Blocklist prüfen**:
   - Überprüfen Sie IP/Domain-Sperren
   - Entfernen Sie falsche Einträge

#### Rate Limiting zu restriktiv

1. **Limits anpassen**:
   ```
   Backend → Mail Security → Settings → Rate Limiting
   ```

2. **Whitelist konfigurieren**:
   - Fügen Sie vertrauenswürdige IPs hinzu
   - Konfigurieren Sie Ausnahmen

3. **Monitoring aktivieren**:
   - Überwachen Sie Rate Limit Events
   - Anpassung basierend auf Nutzungsmustern

#### Performance-Probleme

1. **Database-Indizes prüfen**:
   ```sql
   SHOW INDEX FROM upkeep_mail_threat_log;
   ```

2. **Log-Bereinigung aktivieren**:
   ```
   Backend → Mail Security → Cleanup → Automatische Bereinigung
   ```

3. **Caching optimieren**:
   - Redis/Memcache für Blocklist
   - APCu für Badwords

### Debug-Modus

```php
// Debug-Informationen aktivieren
$addon->setConfig('mail_security_debug', true);

// Debug-Log prüfen
$debug_log = rex_path::addonData('upkeep', 'mail_security_debug.log');
```

## Sicherheits-Best Practices

### 1. Regelmäßige Updates
- Badword-Listen aktualisieren
- Blocklist-Einträge überprüfen
- Threat-Patterns anpassen

### 2. Monitoring
- Dashboard täglich überprüfen
- Alert-Schwellwerte anpassen
- Performance-Metriken überwachen

### 3. Backup & Recovery
- Regelmäßige Datenbank-Backups
- Konfiguration dokumentieren
- Rollback-Strategien definieren

### 4. Access Control
- API-Token regelmäßig rotieren
- Backend-Zugriff beschränken
- Audit-Logs aktivieren

## Changelog

### Version 1.8.1
- ✅ Vollständige Mail Security Integration
- ✅ Dashboard-Integration
- ✅ API-Endpoints
- ✅ Threat Detection
- ✅ Rate Limiting
- ✅ Automatische Bereinigung

### Geplante Features
- 🔄 Machine Learning Spam Detection
- 🔄 Advanced Threat Intelligence
- 🔄 Real-time Notifications
- 🔄 Grafana Integration
- 🔄 Mobile App Support

## Support

Für Support und weitere Informationen:

- **GitHub**: https://github.com/klxm/upkeep
- **Issues**: https://github.com/klxm/upkeep/issues
- **Dokumentation**: Backend → Upkeep → Hilfe & Dokumentation
- **REDAXO Forum**: https://www.redaxo.org/forum/

---

*Diese Dokumentation wird kontinuierlich aktualisiert. Letzte Aktualisierung: September 2025*