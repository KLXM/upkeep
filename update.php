<?php

// Update-Script für Upkeep AddOn v1.3.0
// Führt Database-Updates für IPS durch

$sql = rex_sql::factory();

try {
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

    echo rex_view::success('IPS-Datenbanktabellen erfolgreich erstellt/aktualisiert!');

} catch (Exception $e) {
    echo rex_view::error('Fehler beim Erstellen der IPS-Tabellen: ' . $e->getMessage());
}

// Konfiguration auf aktuelle Standards setzen (v1.3.0+)
$addon = rex_addon::get('upkeep');

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
