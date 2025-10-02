<?php
/**
 * Deinstallation des Upkeep AddOns
 */

// AddOn aus der config.yml entfernen
$configFile = rex_path::coreData('config.yml');
$config = rex_file::getConfig($configFile);

if (array_key_exists('setup_addons', $config) && in_array('upkeep', $config['setup_addons'], true)) {
    $config['setup_addons'] = array_filter($config['setup_addons'], static function ($addon) {
        return $addon !== 'upkeep';
    });
    rex_file::putConfig($configFile, $config);
}

// Alle vom AddOn erstellten Tabellen löschen
$tables = [
    'upkeep_domain_mapping',
    'upkeep_ips_blocked_ips',
    'upkeep_ips_threat_log',
    'upkeep_ips_custom_patterns',
    'upkeep_ips_default_patterns',  // Neue Tabelle für Standard-Patterns
    'upkeep_ips_rate_limit',
    'upkeep_ips_positivliste',
    'upkeep_ips_whitelist',         // Falls noch vorhanden (alte Bezeichnung)
    // Mail Security Tabellen
    'upkeep_mail_rate_limit',
    'upkeep_mail_badwords',
    'upkeep_mail_blocklist',
    'upkeep_mail_threat_log',
    'upkeep_mail_default_patterns'  // Standard-Mail-Patterns
];

foreach ($tables as $table) {
    $fullTableName = rex::getTable($table);
    $sql = rex_sql::factory();
    
    try {
        // Tabelle löschen (IF EXISTS verhindert Fehler bei bereits gelöschten Tabellen)
        $sql->setQuery("DROP TABLE IF EXISTS `{$fullTableName}`");
        rex_logger::factory()->info("Tabelle {$fullTableName} erfolgreich gelöscht.");
    } catch (Exception $e) {
        rex_logger::factory()->error("Fehler beim Löschen der Tabelle {$fullTableName}: " . $e->getMessage());
    }
}

// Alle AddOn-Konfigurationen löschen
$addon = rex_addon::get('upkeep');
if ($addon->isInstalled()) {
    // Alle Config-Werte löschen
    $configKeys = [
        'allowed_ips',
        'frontend_password',
        'ips_active',
        'ips_rate_limiting_enabled',
        'ips_captcha_trust_duration',
        'ips_burst_limit',
        'ips_strict_limit',
        'ips_burst_window',
        // Mail Security Einstellungen
        'mail_security_active',
        'mail_rate_limiting_enabled',
        'mail_rate_limit_per_minute',
        'mail_rate_limit_per_hour',
        'mail_rate_limit_per_day',
        'mail_security_debug',
        'mail_security_detailed_logging',
        // Mehrsprachigkeits-Einstellungen
        'multilanguage_enabled',
        'multilanguage_default',
        'multilanguage_texts'
    ];
    
    foreach ($configKeys as $key) {
        $addon->removeConfig($key);
    }
    
    rex_logger::factory()->info("Alle Upkeep AddOn-Konfigurationen erfolgreich gelöscht.");
}
