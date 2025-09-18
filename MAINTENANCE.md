# Wartung - Upkeep AddOn

## Übersicht

Das Wartungs-System des Upkeep AddOns bietet umfassende Funktionen zur Website-Wartung und -Verwaltung. Es ermöglicht die zentrale Steuerung von Frontend- und Backend-Wartungsmodi sowie die Verwaltung von Domain-spezifischen Einstellungen.

## Features

### 🌐 Frontend-Wartung
- **Wartungsseite**: Automatische Anzeige einer Wartungsseite für Besucher
- **Mehrsprachigkeit**: Unterstützung für mehrsprachige Wartungsseiten
- **Passwort-Schutz**: Optionaler Passwort-geschützter Zugang
- **IP-Whitelist**: Spezifische IP-Adressen vom Wartungsmodus ausschließen
- **Bypass-Parameter**: URL-Parameter für direkten Zugang

### 👥 Backend-Wartung
- **Admin-Only Modus**: Backend nur für Administratoren zugänglich
- **Benutzer-Ausschluss**: Nicht-Admin Benutzer werden ausgesperrt
- **Sicherheitsmeldung**: Informative Meldung für gesperrte Benutzer
- **Notfallzugang**: Administratoren behalten immer Zugang

### 🌍 Domain-Verwaltung
- **YRewrite Integration**: Wartungsmodus pro Domain konfigurierbar
- **Domain-spezifisch**: Einzelne Domains unabhängig verwalten
- **Bulk-Operationen**: Alle Domains gleichzeitig sperren/entsperren
- **Override-Funktion**: Domain-Einstellungen überschreiben globale Einstellungen

## Installation & Einrichtung

### Voraussetzungen

Das Wartungs-System ist Teil des Upkeep AddOns und erfordert:
- REDAXO 5.18.1 oder höher
- PHP 8.2 oder höher
- Für Domain-Verwaltung: YRewrite AddOn

### Grundkonfiguration

1. **AddOn aktivieren**: Upkeep im REDAXO Backend aktivieren
2. **Berechtigungen setzen**: Entsprechende Benutzerrechte vergeben
3. **Wartungsseite anpassen**: Texte und Design konfigurieren

## Frontend-Wartung

### Aktivierung

**Backend**: `Upkeep → Wartung → Frontend`

**Programmatisch**:
```php
$addon = rex_addon::get('upkeep');
$addon->setConfig('frontend_active', true);
```

**Console Command**:
```bash
php redaxo/bin/console upkeep:mode frontend on
```

### Wartungsseite konfigurieren

#### Grundeinstellungen

```php
// Wartungsseite aktivieren
$addon->setConfig('frontend_active', true);

// Seitentitel
$addon->setConfig('maintenance_page_title', 'Website wird gewartet');

// Wartungsmeldung
$addon->setConfig('maintenance_page_message', 'Wir führen aktuell Wartungsarbeiten durch. Bitte versuchen Sie es in Kürze erneut.');

// HTTP Status Code
$addon->setConfig('http_status_code', 503);

// Retry-After Header (Sekunden)
$addon->setConfig('retry_after', 3600);
```

#### Mehrsprachige Wartungsseiten

**Backend**: `Upkeep → Wartung → Frontend → Mehrsprachigkeit`

**JSON-Konfiguration**:
```json
{
    "de": {
        "title": "Website wird gewartet",
        "message": "Wir führen aktuell Wartungsarbeiten durch."
    },
    "en": {
        "title": "Site under maintenance",
        "message": "We are currently performing maintenance work."
    },
    "fr": {
        "title": "Site en maintenance",
        "message": "Nous effectuons actuellement des travaux de maintenance."
    }
}
```

**Programmatisch**:
```php
$multilangConfig = [
    'enabled' => true,
    'default_language' => 'de',
    'texts' => [
        'de' => [
            'title' => 'Website wird gewartet',
            'message' => 'Wartungsarbeiten in Bearbeitung...'
        ],
        'en' => [
            'title' => 'Site under maintenance',
            'message' => 'Maintenance work in progress...'
        ]
    ]
];

$addon->setConfig('multilanguage_settings', $multilangConfig);
```

### Zugriffs-Kontrolle

#### IP-Whitelist

**Backend**: `Upkeep → Wartung → Frontend → Erlaubte IP-Adressen`

**Konfiguration**:
```php
// Einzelne IPs
$allowedIPs = [
    '192.168.1.100',    // Lokale IP
    '203.0.113.0',      // Büro IP
    '2001:db8::1'       // IPv6
];

// IP-Bereiche (CIDR)
$allowedIPRanges = [
    '192.168.1.0/24',   // Lokales Netzwerk
    '203.0.113.0/24',   // Büro-Netzwerk
    '10.0.0.0/8'        // Private Klasse A
];

$addon->setConfig('allowed_ips', implode(',', array_merge($allowedIPs, $allowedIPRanges)));
```

#### Passwort-Schutz

```php
// Frontend-Passwort setzen
$addon->setConfig('frontend_password', password_hash('mein-wartungs-passwort', PASSWORD_DEFAULT));

// Angemeldete Backend-Benutzer ausschließen
$addon->setConfig('bypass_logged_in', true);
```

#### URL-Parameter Bypass

```php
// Bypass-Parameter aktivieren
$addon->setConfig('allow_bypass_param', true);

// Parameter-Schlüssel definieren
$addon->setConfig('bypass_param_key', 'maintenance_bypass');

// Verwendung: https://ihre-domain.de/?maintenance_bypass=1
```

### HTTP-Einstellungen

```php
// HTTP Status Codes
$httpCodes = [
    503 => 'Service Unavailable (mit Cache-Control)',
    503 => 'Service Unavailable (ohne Cache-Control)', 
    403 => 'Forbidden',
    307 => 'Temporary Redirect'
];

$addon->setConfig('http_status_code', 503);

// Cache-Control Header
$addon->setConfig('cache_control_enabled', true);

// Retry-After Header (empfohlen: 3600 = 1 Stunde)
$addon->setConfig('retry_after', 3600);
```

## Backend-Wartung

### Aktivierung

**Backend**: `Upkeep → Wartung → Backend`

**Programmatisch**:
```php
$addon = rex_addon::get('upkeep');
$addon->setConfig('backend_active', true);
```

**Console Command**:
```bash
php redaxo/bin/console upkeep:mode backend on
```

### Funktionsweise

Wenn der Backend-Wartungsmodus aktiviert ist:

1. **Admin-Zugang**: Nur Benutzer mit Admin-Rechten können sich anmelden
2. **Normale Benutzer**: Werden ausgesperrt und sehen eine Wartungsmeldung
3. **Aktive Sessions**: Nicht-Admin Benutzer werden automatisch abgemeldet
4. **API-Zugriff**: APIs sind weiterhin für Administratoren verfügbar

### Wartungsmeldung anpassen

```php
// Backend-Wartungsmeldung
$message = 'Das REDAXO-Backend befindet sich im Wartungsmodus und ist vorübergehend nicht verfügbar. Bitte kontaktieren Sie den Administrator.';

$addon->setConfig('backend_maintenance_message', $message);

// Kontakt-Informationen
$addon->setConfig('backend_contact_info', 'admin@ihre-domain.de');
```

### Sicherheitshinweise

- **Notfallzugang**: Administratoren behalten immer Zugang
- **Database-Zugriff**: Bei kritischen Problemen über Datenbank deaktivierbar
- **File-Override**: Über `.maintenance` Datei im Root-Verzeichnis steuerbar

## Domain-Verwaltung

### YRewrite Integration

**Voraussetzung**: YRewrite AddOn muss installiert und aktiviert sein.

**Backend**: `Upkeep → Wartung → Domains`

### Domain-spezifische Wartung

```php
// Einzelne Domain in Wartung versetzen
$yrewrite = rex_yrewrite::getDomainByName('www.example.com');
if ($yrewrite) {
    $domainConfig = [
        'domain_id' => $yrewrite->getId(),
        'maintenance_active' => true,
        'override_global' => true
    ];
    
    $addon->setConfig('domain_' . $yrewrite->getId(), $domainConfig);
}
```

### Bulk-Operationen

```php
// Alle Domains sperren
$addon->setConfig('all_domains_locked', true);

// Ausnahme-Domains definieren
$exceptions = ['admin.example.com', 'api.example.com'];
$addon->setConfig('domain_exceptions', $exceptions);
```

### Domain-Status prüfen

```php
function getDomainMaintenanceStatus(): array {
    $addon = rex_addon::get('upkeep');
    $domains = rex_yrewrite::getDomains();
    $status = [];
    
    foreach ($domains as $domain) {
        $domainConfig = $addon->getConfig('domain_' . $domain->getId(), []);
        $status[$domain->getName()] = [
            'id' => $domain->getId(),
            'maintenance_active' => $domainConfig['maintenance_active'] ?? false,
            'override_global' => $domainConfig['override_global'] ?? false
        ];
    }
    
    return $status;
}
```

## API Integration

### REST Endpoints

Das Wartungs-System bietet API-Endpoints für externe Steuerung:

#### Frontend-Wartung steuern

```bash
# Aktivieren
curl -X POST \
  "https://ihre-domain.de/api/upkeep/maintenance/frontend" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -d '{"active": true}'

# Status abfragen
curl -X GET \
  "https://ihre-domain.de/api/upkeep/maintenance/status" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

#### Backend-Wartung steuern

```bash
# Aktivieren (nur für Admins)
curl -X POST \
  "https://ihre-domain.de/api/upkeep/maintenance/backend" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -d '{"active": true, "message": "Geplante Wartung bis 15:00 Uhr"}'
```

### Webhook Integration

```php
// Webhook bei Wartungsmodus-Änderungen
rex_extension::register('UPKEEP_MAINTENANCE_CHANGED', function($ep) {
    $type = $ep->getParam('type'); // 'frontend' oder 'backend'
    $active = $ep->getParam('active');
    $user = $ep->getParam('user');
    
    // Webhook-URL benachrichtigen
    $webhook_url = 'https://monitoring.example.com/webhook';
    $payload = [
        'event' => 'maintenance_changed',
        'type' => $type,
        'active' => $active,
        'changed_by' => $user->getLogin(),
        'timestamp' => date('c')
    ];
    
    // HTTP POST Request
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-Type: application/json',
            'content' => json_encode($payload)
        ]
    ]);
    
    file_get_contents($webhook_url, false, $context);
});
```

## Console Commands

### Verfügbare Befehle

```bash
# Frontend-Wartung
php redaxo/bin/console upkeep:mode frontend on
php redaxo/bin/console upkeep:mode frontend off
php redaxo/bin/console upkeep:mode frontend status

# Backend-Wartung
php redaxo/bin/console upkeep:mode backend on
php redaxo/bin/console upkeep:mode backend off
php redaxo/bin/console upkeep:mode backend status

# Domain-Wartung
php redaxo/bin/console upkeep:domain lock example.com
php redaxo/bin/console upkeep:domain unlock example.com
php redaxo/bin/console upkeep:domain status
```

### Cron Jobs

```bash
# Automatische Wartung um 2:00 Uhr
0 2 * * * /usr/bin/php /path/to/redaxo/bin/console upkeep:mode frontend on

# Wartung nach 6 Stunden beenden
0 8 * * * /usr/bin/php /path/to/redaxo/bin/console upkeep:mode frontend off
```

## Template Integration

### Wartungsseite customizen

**Template-Datei**: `templates/maintenance.php`

```php
<!DOCTYPE html>
<html lang="<?= $language ?>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= htmlspecialchars($title) ?></title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .maintenance-container {
            text-align: center;
            max-width: 600px;
            padding: 2rem;
            background: rgba(255,255,255,0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
        }
        .maintenance-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
        .maintenance-title {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            font-weight: 300;
        }
        .maintenance-message {
            font-size: 1.2rem;
            line-height: 1.6;
            margin-bottom: 2rem;
            opacity: 0.9;
        }
        .maintenance-footer {
            font-size: 0.9rem;
            opacity: 0.7;
        }
        .language-switcher {
            position: absolute;
            top: 20px;
            right: 20px;
        }
        .language-switcher a {
            color: white;
            text-decoration: none;
            margin: 0 5px;
            padding: 5px 10px;
            border-radius: 5px;
            background: rgba(255,255,255,0.2);
        }
    </style>
</head>
<body>
    <?php if ($multilanguage_enabled): ?>
    <div class="language-switcher">
        <?php foreach ($available_languages as $lang => $lang_title): ?>
            <a href="?lang=<?= $lang ?>" <?= $lang === $current_language ? 'style="background: rgba(255,255,255,0.3)"' : '' ?>>
                <?= strtoupper($lang) ?>
            </a>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <div class="maintenance-container">
        <div class="maintenance-icon">🔧</div>
        <h1 class="maintenance-title"><?= htmlspecialchars($title) ?></h1>
        <div class="maintenance-message"><?= nl2br(htmlspecialchars($message)) ?></div>
        
        <?php if ($password_required): ?>
        <form method="post" style="margin-top: 2rem;">
            <input type="password" name="maintenance_password" placeholder="Passwort eingeben" 
                   style="padding: 12px; border: none; border-radius: 5px; margin-right: 10px;">
            <button type="submit" style="padding: 12px 24px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer;">
                Zugang
            </button>
        </form>
        <?php endif; ?>
        
        <div class="maintenance-footer">
            <?php if ($retry_after > 0): ?>
                <p>Nächster Versuch empfohlen in: <?= gmdate('H:i:s', $retry_after) ?></p>
            <?php endif; ?>
            <p>© <?= date('Y') ?> <?= rex::getServerName() ?></p>
        </div>
    </div>
</body>
</html>
```

### Template-Hooks

```php
// Eigene Template-Hooks
rex_extension::register('UPKEEP_MAINTENANCE_TEMPLATE', function($ep) {
    $template_vars = $ep->getParam('template_vars');
    
    // Eigene Variablen hinzufügen
    $template_vars['company_name'] = 'Ihre Firma GmbH';
    $template_vars['contact_email'] = 'support@ihre-domain.de';
    $template_vars['estimated_completion'] = '15:00 Uhr';
    
    $ep->setParam('template_vars', $template_vars);
});
```

## Monitoring & Logging

### Status-Monitoring

```php
// Dashboard-Integration
function getMaintenanceStats(): array {
    $addon = rex_addon::get('upkeep');
    
    return [
        'frontend_active' => $addon->getConfig('frontend_active', false),
        'backend_active' => $addon->getConfig('backend_active', false),
        'domains_locked' => $addon->getConfig('all_domains_locked', false),
        'allowed_ips_count' => count(explode(',', $addon->getConfig('allowed_ips', ''))),
        'last_changed' => $addon->getConfig('last_maintenance_change'),
        'changed_by' => $addon->getConfig('last_maintenance_user')
    ];
}
```

### Log-Integration

```php
// Wartungsänderungen protokollieren
rex_extension::register('UPKEEP_MAINTENANCE_CHANGED', function($ep) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'type' => $ep->getParam('type'),
        'action' => $ep->getParam('active') ? 'activated' : 'deactivated',
        'user' => rex::getUser()?->getLogin() ?? 'system',
        'ip' => rex_request::server('REMOTE_ADDR', 'string', ''),
        'user_agent' => rex_request::server('HTTP_USER_AGENT', 'string', '')
    ];
    
    rex_logger::factory()->info('Maintenance mode changed', $logEntry);
});
```

### External Monitoring

```php
// Health Check Endpoint
rex_extension::register('PACKAGES_INCLUDED', function() {
    if (rex_request::get('health-check') === 'maintenance') {
        $addon = rex_addon::get('upkeep');
        
        $status = [
            'maintenance_active' => [
                'frontend' => $addon->getConfig('frontend_active', false),
                'backend' => $addon->getConfig('backend_active', false)
            ],
            'timestamp' => time(),
            'version' => $addon->getVersion()
        ];
        
        header('Content-Type: application/json');
        echo json_encode($status);
        exit;
    }
});

// Verwendung: https://ihre-domain.de/?health-check=maintenance
```

## Best Practices

### 1. Planung von Wartungsfenstern

```php
// Geplante Wartung mit Vorankündigung
function scheduleMaintenanceWindow(DateTime $start, DateTime $end, string $reason): void {
    $addon = rex_addon::get('upkeep');
    $maintenanceWindow = [
        'start' => $start->format('Y-m-d H:i:s'),
        'end' => $end->format('Y-m-d H:i:s'),
        'reason' => $reason,
        'scheduled_by' => rex::getUser()?->getLogin(),
        'created_at' => date('Y-m-d H:i:s')
    ];
    
    $addon->setConfig('scheduled_maintenance', $maintenanceWindow);
    
    // E-Mail-Benachrichtigung an Administratoren
    sendMaintenanceNotification($maintenanceWindow);
}
```

### 2. Automatisierte Tests

```php
// Wartungsseite testen
function testMaintenancePage(): bool {
    $addon = rex_addon::get('upkeep');
    
    // Temporär aktivieren
    $originalState = $addon->getConfig('frontend_active', false);
    $addon->setConfig('frontend_active', true);
    
    try {
        // HTTP Request zur eigenen Domain
        $response = file_get_contents(rex::getServer());
        $httpCode = $http_response_header[0] ?? '';
        
        // Prüfungen
        $tests = [
            'http_503' => strpos($httpCode, '503') !== false,
            'maintenance_text' => strpos($response, 'Wartung') !== false,
            'html_valid' => strpos($response, '</html>') !== false
        ];
        
        return !in_array(false, $tests, true);
    } finally {
        // Original-Zustand wiederherstellen
        $addon->setConfig('frontend_active', $originalState);
    }
}
```

### 3. Backup vor Wartung

```php
// Automatisches Backup vor Wartungsaktivierung
rex_extension::register('UPKEEP_MAINTENANCE_BEFORE_ACTIVATE', function($ep) {
    if ($ep->getParam('type') === 'frontend') {
        // Database Backup
        $backup = rex_backup::factory();
        $backup->create('pre_maintenance_' . date('Y-m-d_H-i-s'));
        
        // File Backup für kritische Dateien
        $criticalFiles = [
            rex_path::core('config.yml'),
            rex_path::addon('upkeep', 'config.yml')
        ];
        
        foreach ($criticalFiles as $file) {
            if (file_exists($file)) {
                copy($file, $file . '.backup.' . time());
            }
        }
    }
});
```

### 4. Rollback-Mechanismus

```php
// Emergency Rollback über .emergency Datei
function checkEmergencyRollback(): void {
    $emergencyFile = rex_path::base('.emergency');
    
    if (file_exists($emergencyFile)) {
        $addon = rex_addon::get('upkeep');
        
        // Alle Wartungsmodi deaktivieren
        $addon->setConfig('frontend_active', false);
        $addon->setConfig('backend_active', false);
        $addon->setConfig('all_domains_locked', false);
        
        // Emergency-Datei entfernen
        unlink($emergencyFile);
        
        // Log-Eintrag
        rex_logger::factory()->emergency('Emergency rollback executed', [
            'file' => $emergencyFile,
            'timestamp' => date('Y-m-d H:i:s')
        ]);
    }
}

// Bei jedem Request prüfen
rex_extension::register('PACKAGES_INCLUDED', 'checkEmergencyRollback');
```

## Troubleshooting

### Häufige Probleme

#### Problem: Wartungsseite wird nicht angezeigt

**Lösung 1**: Cache leeren
```php
rex_delete_cache();
```

**Lösung 2**: Template-Pfad prüfen
```php
$templatePath = rex_path::addon('upkeep', 'templates/maintenance.php');
if (!file_exists($templatePath)) {
    // Template-Datei fehlt
    echo "Template nicht gefunden: " . $templatePath;
}
```

#### Problem: Admin kann nicht mehr auf Backend zugreifen

**Lösung**: Database-Override
```sql
UPDATE rex_config 
SET value = '0' 
WHERE namespace = 'upkeep' 
AND key = 'backend_active';
```

#### Problem: IP-Whitelist funktioniert nicht

**Debugging**:
```php
$currentIP = rex_request::server('REMOTE_ADDR', 'string', '');
$allowedIPs = explode(',', rex_addon::get('upkeep')->getConfig('allowed_ips', ''));

echo "Aktuelle IP: " . $currentIP . "\n";
echo "Erlaubte IPs: " . implode(', ', $allowedIPs) . "\n";

foreach ($allowedIPs as $allowedIP) {
    if (trim($allowedIP) === $currentIP) {
        echo "IP gefunden!\n";
        break;
    }
}
```

### Debug-Modus

```php
// Debug-Informationen aktivieren
$addon = rex_addon::get('upkeep');
$addon->setConfig('maintenance_debug', true);

// Debug-Log prüfen
$debugLog = rex_path::addonData('upkeep', 'maintenance_debug.log');
if (file_exists($debugLog)) {
    echo file_get_contents($debugLog);
}
```

## Sicherheitshinweise

### 1. API-Token Sicherheit

```php
// Starke API-Token generieren
function generateSecureApiToken(): string {
    return base64_encode(random_bytes(32));
}

// Token regelmäßig rotieren
function rotateApiToken(): void {
    $addon = rex_addon::get('upkeep');
    $newToken = generateSecureApiToken();
    $addon->setConfig('api_token', $newToken);
    
    // Alte Token ungültig machen
    rex_logger::factory()->info('API token rotated');
}
```

### 2. Brute-Force Schutz

```php
// Rate Limiting für Wartungsseiten-Zugriffe
function checkMaintenanceRateLimit(string $ip): bool {
    $attempts = rex_cache::get('maintenance_attempts_' . $ip, 0);
    
    if ($attempts >= 5) {
        // IP für 1 Stunde sperren
        rex_cache::set('maintenance_blocked_' . $ip, true, 3600);
        return false;
    }
    
    return true;
}
```

### 3. Sichere Konfiguration

```php
// Sichere Standard-Konfiguration
$secureDefaults = [
    'frontend_password' => null, // Kein Standard-Passwort
    'bypass_param_key' => bin2hex(random_bytes(16)), // Zufälliger Parameter
    'api_token' => null, // API standardmäßig deaktiviert
    'allowed_ips' => '', // Keine Standard-IPs
    'http_status_code' => 503, // Korrekte HTTP-Codes
    'retry_after' => 3600 // Angemessene Retry-Zeit
];
```

## Changelog

### Version 1.8.1
- ✅ Gruppierung in Wartung-Bereich
- ✅ Frontend-Wartung mit Mehrsprachigkeit
- ✅ Backend-Wartung für Admin-Only Modus
- ✅ Domain-spezifische Wartung
- ✅ Console Commands
- ✅ API Integration
- ✅ Template-System
- ✅ Monitoring & Logging

### Geplante Features
- 🔄 Geplante Wartungsfenster
- 🔄 Progressive Web App Support
- 🔄 Social Media Integration
- 🔄 Advanced Analytics
- 🔄 Mobile Benachrichtigungen

## Support

Für Support und weitere Informationen:

- **GitHub**: https://github.com/klxm/upkeep
- **Issues**: https://github.com/klxm/upkeep/issues
- **Dokumentation**: Backend → Upkeep → Wartung → Wartung Dokumentation
- **REDAXO Forum**: https://www.redaxo.org/forum/

---

*Diese Dokumentation wird kontinuierlich aktualisiert. Letzte Aktualisierung: September 2025*