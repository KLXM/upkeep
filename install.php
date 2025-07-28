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
