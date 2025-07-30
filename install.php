<?php
/**
 * Installation des Upkeep AddOns
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();

// AddOn in Setup-AddOns in der config.yml aufnehmen
$configFile = rex_path::coreData('config.yml');
$config = rex_file::getConfig($configFile);
if (array_key_exists('setup_addons', $config) && !in_array('upkeep', $config['setup_addons'], true)) {
    $config['setup_addons'][] = 'upkeep';
    rex_file::putConfig($configFile, $config);
}

// Eigene IP-Adresse automatisch in die erlaubte IP-Liste aufnehmen
$currentIp = rex_server('REMOTE_ADDR', 'string', '');
$allowedIps = $addon->getConfig('allowed_ips', '');

if ($currentIp && $allowedIps === '') {
    $addon->setConfig('allowed_ips', $currentIp);
}

// Standard-Passwort generieren, wenn keines gesetzt ist
if ($addon->getConfig('frontend_password', '') === '') {
    $randomPassword = bin2hex(random_bytes(4)); // 8 Zeichen langes zufälliges Passwort
    
    $addon->setConfig('frontend_password', $randomPassword);
    
    // Hinweis mit dem Passwort anzeigen (nur bei Installation)
    rex_extension::register('OUTPUT_FILTER', function(rex_extension_point $ep) use ($randomPassword) {
        $content = $ep->getSubject();
        $message = '<div class="alert alert-info">';
        $message .= 'Ein zufälliges Passwort wurde für den Frontend-Zugang generiert: <strong>' . $randomPassword . '</strong><br>';
        $message .= 'Bitte notieren Sie sich dieses Passwort oder ändern Sie es in den Einstellungen.';
        $message .= '</div>';
        
        $content = str_replace('</body>', $message . '</body>', $content);
        $ep->setSubject($content);
    });
}

// Domain-Mapping-Tabelle erstellen
rex_sql_table::get(rex::getTable('upkeep_domain_mapping'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('source_domain', 'varchar(255)', false))
    ->ensureColumn(new rex_sql_column('source_path', 'varchar(500)', true, null))
    ->ensureColumn(new rex_sql_column('target_url', 'text', false))
    ->ensureColumn(new rex_sql_column('redirect_code', 'int(3)', false, '301'))
    ->ensureColumn(new rex_sql_column('is_wildcard', 'tinyint(1)', false, '0'))
    ->ensureColumn(new rex_sql_column('status', 'tinyint(1)', false, '1'))
    ->ensureColumn(new rex_sql_column('description', 'text', true))
    ->ensureColumn(new rex_sql_column('createdate', 'datetime', false))
    ->ensureColumn(new rex_sql_column('updatedate', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('source_domain', ['source_domain']))
    ->ensure();

// IPS Blocked IPs Tabelle erstellen
rex_sql_table::get(rex::getTable('upkeep_ips_blocked_ips'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('ip_address', 'varchar(45)', false)) // IPv6-kompatibel
    ->ensureColumn(new rex_sql_column('block_type', 'enum("temporary","permanent")', false, 'temporary'))
    ->ensureColumn(new rex_sql_column('expires_at', 'datetime', true))
    ->ensureColumn(new rex_sql_column('reason', 'text', true))
    ->ensureColumn(new rex_sql_column('threat_level', 'enum("low","medium","high","critical")', false, 'medium'))
    ->ensureColumn(new rex_sql_column('created_at', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('ip_lookup', ['ip_address', 'expires_at']))
    ->ensure();

// IPS Threat Log Tabelle erstellen
rex_sql_table::get(rex::getTable('upkeep_ips_threat_log'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('ip_address', 'varchar(45)', false))
    ->ensureColumn(new rex_sql_column('request_uri', 'text', false))
    ->ensureColumn(new rex_sql_column('user_agent', 'text', true))
    ->ensureColumn(new rex_sql_column('threat_type', 'varchar(100)', false))
    ->ensureColumn(new rex_sql_column('threat_category', 'varchar(100)', true))
    ->ensureColumn(new rex_sql_column('pattern_matched', 'varchar(500)', true))
    ->ensureColumn(new rex_sql_column('severity', 'enum("low","medium","high","critical")', false))
    ->ensureColumn(new rex_sql_column('action_taken', 'varchar(100)', false))
    ->ensureColumn(new rex_sql_column('created_at', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('ip_time', ['ip_address', 'created_at']))
    ->ensureIndex(new rex_sql_index('severity_time', ['severity', 'created_at']))
    ->ensure();

// IPS Custom Patterns Tabelle erstellen
rex_sql_table::get(rex::getTable('upkeep_ips_custom_patterns'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('pattern', 'varchar(500)', false))
    ->ensureColumn(new rex_sql_column('description', 'text', true))
    ->ensureColumn(new rex_sql_column('severity', 'enum("low","medium","high","critical")', false, 'medium'))
    ->ensureColumn(new rex_sql_column('is_regex', 'tinyint(1)', false, '0'))
    ->ensureColumn(new rex_sql_column('status', 'tinyint(1)', false, '1'))
    ->ensureColumn(new rex_sql_column('created_at', 'datetime', false))
    ->ensureColumn(new rex_sql_column('updated_at', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('status', ['status']))
    ->ensure();

// IPS Default Patterns Tabelle erstellen - für anpassbare Standard-Patterns
rex_sql_table::get(rex::getTable('upkeep_ips_default_patterns'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('category', 'varchar(100)', false))
    ->ensureColumn(new rex_sql_column('pattern', 'varchar(500)', false))
    ->ensureColumn(new rex_sql_column('description', 'text', true))
    ->ensureColumn(new rex_sql_column('severity', 'enum("low","medium","high","critical")', false, 'medium'))
    ->ensureColumn(new rex_sql_column('is_regex', 'tinyint(1)', false, '0'))
    ->ensureColumn(new rex_sql_column('status', 'tinyint(1)', false, '1'))
    ->ensureColumn(new rex_sql_column('is_default', 'tinyint(1)', false, '1')) // Kennzeichnet vorgegebene Patterns
    ->ensureColumn(new rex_sql_column('created_at', 'datetime', false))
    ->ensureColumn(new rex_sql_column('updated_at', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('category_status', ['category', 'status']))
    ->ensureIndex(new rex_sql_index('status', ['status']))
    ->ensure();

// IPS Rate Limiting Tabelle erstellen
rex_sql_table::get(rex::getTable('upkeep_ips_rate_limit'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('ip_address', 'varchar(45)', false))
    ->ensureColumn(new rex_sql_column('request_count', 'int(11)', false, '1'))
    ->ensureColumn(new rex_sql_column('window_start', 'datetime', false))
    ->ensureColumn(new rex_sql_column('last_request', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('ip_window', ['ip_address', 'window_start']))
    ->ensure();

// IPS Positivliste Tabelle erstellen
rex_sql_table::get(rex::getTable('upkeep_ips_positivliste'))
    ->ensureColumn(new rex_sql_column('id', 'int(11)', false, null, 'auto_increment'))
    ->ensureColumn(new rex_sql_column('ip_address', 'varchar(45)', false)) // IPv6-kompatibel
    ->ensureColumn(new rex_sql_column('ip_range', 'varchar(50)', true)) // CIDR-Notation für IP-Bereiche
    ->ensureColumn(new rex_sql_column('description', 'varchar(255)', true))
    ->ensureColumn(new rex_sql_column('category', 'enum("admin","cdn","monitoring","api","trusted","captcha_verified_temp")', false, 'trusted'))
    ->ensureColumn(new rex_sql_column('expires_at', 'datetime', true)) // NULL = permanent, sonst Ablaufzeit
    ->ensureColumn(new rex_sql_column('status', 'tinyint(1)', false, '1'))
    ->ensureColumn(new rex_sql_column('created_at', 'datetime', false))
    ->ensureColumn(new rex_sql_column('updated_at', 'datetime', false))
    ->setPrimaryKey('id')
    ->ensureIndex(new rex_sql_index('ip_lookup', ['ip_address', 'status']))
    ->ensureIndex(new rex_sql_index('range_lookup', ['ip_range', 'status']))
    ->ensureIndex(new rex_sql_index('expires_lookup', ['expires_at']))
    ->ensure();

// Aktuelle Admin-IP automatisch zur Positivliste hinzufügen
if ($currentIp) {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT COUNT(*) as count FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE ip_address = ?', [$currentIp]);
    
    if ((int) $sql->getValue('count') === 0) {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
        $sql->setValue('ip_address', $currentIp);
        $sql->setValue('description', 'Automatisch hinzugefügte Admin-IP bei Installation');
        $sql->setValue('category', 'admin');
        $sql->setValue('status', 1);
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
        $sql->insert();
    }
}

// IPS standardmäßig aktivieren
if ($addon->getConfig('ips_active') === null) {
    $addon->setConfig('ips_active', true);
}

// Rate-Limiting standardmäßig DEAKTIVIERT (Webserver sollte das machen)
if ($addon->getConfig('ips_rate_limiting_enabled') === null) {
    $addon->setConfig('ips_rate_limiting_enabled', false);
}

// CAPTCHA-Vertrauensdauer konfigurieren (Standard: 24 Stunden)
if ($addon->getConfig('ips_captcha_trust_duration') === null) {
    $addon->setConfig('ips_captcha_trust_duration', 24);
}

// Rate-Limiting Konfiguration (sehr hoch - nur für DoS-Schutz)
if ($addon->getConfig('ips_burst_limit') === null) {
    $addon->setConfig('ips_burst_limit', 600); // 10 Requests pro Sekunde = echte DoS-Schwelle
}

if ($addon->getConfig('ips_strict_limit') === null) {
    $addon->setConfig('ips_strict_limit', 200); // Auch Admin-Bereiche sehr großzügig
}

if ($addon->getConfig('ips_burst_window') === null) {
    $addon->setConfig('ips_burst_window', 60); // 60 Sekunden Fenster
}

// Standard-Patterns in die Datenbank migrieren, falls noch nicht vorhanden
$sql = rex_sql::factory();
$sql->setQuery('SELECT COUNT(*) as count FROM ' . rex::getTable('upkeep_ips_default_patterns'));
$existingPatterns = (int) $sql->getValue('count');

if ($existingPatterns === 0) {
    // Standard-Patterns definieren - diese können später über das Backend angepasst werden
    $defaultPatterns = [
        // Kritische Patterns - Sofortige IP-Sperrung
        'immediate_block' => [
            'patterns' => [
                '/xmlrpc.php' => 'WordPress XML-RPC Angriffe',
                '/.env' => 'Environment-Datei Zugriff',
                '/.git/' => 'Git Repository Zugriff',
                '/shell.php' => 'Shell-Script Upload',
                '/c99.php' => 'C99 Shell',
                '/r57.php' => 'R57 Shell',
                '/webshell.php' => 'Web Shell',
                '/backdoor.php' => 'Backdoor Script',
                '/cmd.php' => 'Command Execution Script',
                '/eval.php' => 'Eval Script',
                '/base64.php' => 'Base64 Encoded Script',
                '/phpinfo.php' => 'PHP Info Disclosure',
                '/../' => 'Directory Traversal (einfach)',
                '/../../' => 'Directory Traversal (doppelt)',
                '/../../../' => 'Directory Traversal (dreifach)',
                '%2e%2e%2f' => 'URL-encoded Directory Traversal',
                '%252e%252e%252f' => 'Double URL-encoded Directory Traversal',
                'union+select' => 'SQL Injection (UNION SELECT)',
                'union%20select' => 'URL-encoded SQL Injection',
                'drop+table' => 'SQL Injection (DROP TABLE)',
                'drop%20table' => 'URL-encoded DROP TABLE',
            ],
            'severity' => 'critical'
        ],
        
        // WordPress-spezifische Pfade
        'wordpress' => [
            'patterns' => [
                '/wp-admin/' => 'WordPress Admin-Bereich',
                '/wp-login.php' => 'WordPress Login-Seite',
                '/wp-content/' => 'WordPress Content-Verzeichnis',
                '/wp-includes/' => 'WordPress Includes-Verzeichnis',
                '/wp-config.php' => 'WordPress Konfigurationsdatei',
                '/wp-cron.php' => 'WordPress Cron-Script',
                '/wp-json/' => 'WordPress REST API',
                '/wp-trackback.php' => 'WordPress Trackback'
            ],
            'severity' => 'high'
        ],
        
        // TYPO3-spezifische Pfade
        'typo3' => [
            'patterns' => [
                '/typo3/' => 'TYPO3 Backend-Bereich',
                '/typo3conf/' => 'TYPO3 Konfiguration',
                '/typo3/backend.php' => 'TYPO3 Backend Entry Point',
                '/typo3/index.php' => 'TYPO3 Backend Index',
                '/typo3/install/' => 'TYPO3 Install Tool',
                '/typo3temp/' => 'TYPO3 Temp-Verzeichnis',
                '/fileadmin/' => 'TYPO3 File Admin',
                '/t3lib/' => 'TYPO3 Library',
                '/typo3_src/' => 'TYPO3 Source'
            ],
            'severity' => 'high'
        ],
        
        // Drupal-spezifische Pfade
        'drupal' => [
            'patterns' => [
                '/user/login' => 'Drupal Login',
                '/admin/' => 'Drupal Admin-Bereich',
                '/node/' => 'Drupal Node-Zugriff',
                '/sites/default/' => 'Drupal Site Config',
                '/modules/' => 'Drupal Module-Verzeichnis',
                '/themes/' => 'Drupal Theme-Verzeichnis',
                '/core/' => 'Drupal Core-Verzeichnis',
                '/web.config' => 'Drupal IIS Config',
                '/.htaccess' => 'Drupal Apache Config',
                '/update.php' => 'Drupal Update Script',
                '/install.php' => 'Drupal Install Script'
            ],
            'severity' => 'high'
        ],
        
        // Joomla-spezifische Pfade
        'joomla' => [
            'patterns' => [
                '/administrator/' => 'Joomla Administrator',
                '/components/' => 'Joomla Components',
                '/modules/' => 'Joomla Module',
                '/plugins/' => 'Joomla Plugins',
                '/templates/' => 'Joomla Templates',
                '/libraries/' => 'Joomla Libraries',
                '/configuration.php' => 'Joomla Konfiguration',
                '/htaccess.txt' => 'Joomla .htaccess Template',
                '/web.config.txt' => 'Joomla web.config Template'
            ],
            'severity' => 'high'
        ],
        
        // Allgemeine Admin-Panels
        'admin_panels' => [
            'patterns' => [
                '/admin' => 'Admin Panel (allgemein)',
                '/admin.php' => 'Admin PHP Script',
                '/administrator' => 'Administrator Panel',
                '/phpmyadmin/' => 'phpMyAdmin Interface',
                '/pma/' => 'phpMyAdmin (kurz)',
                '/mysql/' => 'MySQL Interface',
                '/cpanel/' => 'cPanel Interface',
                '/webmail/' => 'Webmail Interface',
                '/control/' => 'Control Panel',
                '/manager/' => 'Manager Interface',
                '/dashboard/' => 'Dashboard Interface'
            ],
            'severity' => 'high'
        ],
        
        // Config- und Sensitive-Files
        'config_files' => [
            'patterns' => [
                '/.env' => 'Environment Config',
                '/.git/' => 'Git Repository',
                '/.svn/' => 'SVN Repository',
                '/config.php' => 'PHP Config File',
                '/config.inc.php' => 'PHP Include Config',
                '/settings.php' => 'Settings File',
                '/local.xml' => 'Local XML Config',
                '/database.yml' => 'Database YAML Config',
                '/config.yml' => 'YAML Config File',
                '/secrets.yml' => 'Secrets YAML File'
            ],
            'severity' => 'critical'
        ],
        
        // Shell- und Malware-Uploads
        'shells' => [
            'patterns' => [
                '/shell.php' => 'Generic Shell Script',
                '/c99.php' => 'C99 Web Shell',
                '/r57.php' => 'R57 Web Shell',
                '/webshell.php' => 'Web Shell Script',
                '/backdoor.php' => 'Backdoor Script',
                '/hack.php' => 'Hack Script',
                '/evil.php' => 'Evil Script',
                '/cmd.php' => 'Command Script'
            ],
            'severity' => 'critical'
        ],
        
        // Info-Disclosure
        'info_disclosure' => [
            'patterns' => [
                '/phpinfo.php' => 'PHP Info Script',
                '/info.php' => 'Info Script',
                '/test.php' => 'Test Script',
                '/temp.php' => 'Temporary Script',
                '/debug.php' => 'Debug Script',
                '/status.php' => 'Status Script',
                '/server-status' => 'Apache Server Status',
                '/server-info' => 'Apache Server Info'
            ],
            'severity' => 'medium'
        ],
        
        // Path Traversal-Patterns
        'path_traversal' => [
            'patterns' => [
                '../' => 'Directory Traversal (basic)',
                '..\\' => 'Directory Traversal (Windows)',
                '%2e%2e%2f' => 'URL-encoded Traversal',
                '%2e%2e%5c' => 'URL-encoded Windows Traversal',
                '..%2f' => 'Mixed encoding Traversal',
                '..%5c' => 'Mixed encoding Windows Traversal',
                '%c0%ae%c0%ae%c0%af' => 'Unicode Traversal',
                '%252e%252e%252f' => 'Double URL-encoded Traversal'
            ],
            'severity' => 'high'
        ],
        
        // SQL-Injection-Patterns
        'sql_injection' => [
            'patterns' => [
                "' OR '1'='1" => 'SQL Injection (Classic)',
                '" OR "1"="1' => 'SQL Injection (Double Quotes)',
                'UNION SELECT' => 'SQL Injection (UNION)',
                'DROP TABLE' => 'SQL Injection (DROP)',
                'INSERT INTO' => 'SQL Injection (INSERT)',
                'UPDATE SET' => 'SQL Injection (UPDATE)',
                'DELETE FROM' => 'SQL Injection (DELETE)',
                '/*' => 'SQL Comment Block',
                'xp_cmdshell' => 'SQL Server Command Execution',
                'sp_executesql' => 'SQL Server Dynamic SQL'
            ],
            'severity' => 'critical'
        ],

        // SQL Comment Pattern (separat da problematisch für REDAXO URLs)
        'sql_comments' => [
            'patterns' => [
                ' -- ' => 'SQL Comment Injection (kann REDAXO URLs betreffen)'
            ],
            'severity' => 'high',
            'default_status' => 0  // Deaktiviert da -- in REDAXO URLs vorkommen kann
        ],
        
        // RegEx-basierte Patterns für erweiterte Erkennung
        'regex_patterns' => [
            'patterns' => [
                '/\.(php|asp|jsp|pl|py|rb|cgi)$/i' => 'Script-Datei Endungen',
                '/union\s+select/i' => 'SQL Injection (UNION SELECT)',
                '/select\s+.*\s+from/i' => 'SQL Injection (SELECT FROM)',
                '/\b(wget|curl|lynx|nc|netcat)\b/i' => 'Command Injection Tools',
                '/\b(eval|exec|system|shell_exec|passthru)\s*\(/i' => 'PHP Code Execution',
                '/javascript:\s*alert\s*\(/i' => 'XSS Alert Pattern',
                '/on\w+\s*=\s*["\'][^"\']*["\']/i' => 'HTML Event Handler XSS',
                '/<script[^>]*>/i' => 'Script Tag Injection',
                '/\${[^}]+}/i' => 'Expression Language Injection',
                '/\.\.(\/|\\\\|%2f|%5c){2,}/i' => 'Directory Traversal (erweitert)',
                '/base64_decode\s*\(/i' => 'Base64 Decode Attempts',
                '/file_get_contents\s*\(/i' => 'File Access Attempts',
                '/\b(rm|del|rmdir)\s+/i' => 'File Deletion Commands',
                '/\b(cat|type|more|less)\s+/i' => 'File Reading Commands',
                '/\b(passwd|shadow|hosts|httpd\.conf)\b/i' => 'System File Access',
                '/proc\/\w+/i' => 'Linux Proc Filesystem Access',
                '/etc\/(passwd|shadow|group|hosts)/i' => 'Linux System Files',
                '/windows\/(system32|temp)/i' => 'Windows System Directories',
                '/\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+\b/' => 'IP:Port Kombinationen (Backdoor)',
                '/\b(powershell|cmd\.exe|bash|sh)\b/i' => 'Shell Executables'
            ],
            'severity' => 'high',
            'is_regex' => true
        ]
    ];
    
    // Patterns in die Datenbank einfügen
    $sql = rex_sql::factory();
    $currentTime = date('Y-m-d H:i:s');
    
    foreach ($defaultPatterns as $category => $data) {
        $isRegex = isset($data['is_regex']) && $data['is_regex'] === true;
        $defaultStatus = isset($data['default_status']) ? $data['default_status'] : 1; // Standard: aktiviert
        
        foreach ($data['patterns'] as $pattern => $description) {
            $sql->setTable(rex::getTable('upkeep_ips_default_patterns'));
            $sql->setValue('category', $category);
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('severity', $data['severity']);
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', $defaultStatus);
            $sql->setValue('is_default', 1);
            $sql->setValue('created_at', $currentTime);
            $sql->setValue('updated_at', $currentTime);
            $sql->insert();
        }
    }
}
