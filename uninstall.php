<?php

/**
 * Deinstallation: Tabellen, Einstellungen und Daten von upkeep entfernen.
 */

// Eintrag aus älteren Versionen in den Setup-AddOns der config.yml entfernen
$configFile = rex_path::coreData('config.yml');
$config = rex_file::getConfig($configFile);
if (isset($config['setup_addons']) && is_array($config['setup_addons']) && in_array('upkeep', $config['setup_addons'], true)) {
    $config['setup_addons'] = array_values(array_filter($config['setup_addons'], static fn ($a) => 'upkeep' !== $a));
    rex_file::putConfig($configFile, $config);
}

$tables = [
    'upkeep_domain_mapping',
    'upkeep_ips_blocked_ips',
    'upkeep_ips_threat_log',
    'upkeep_ips_custom_patterns',
    'upkeep_ips_default_patterns',
    'upkeep_ips_rate_limit',
    'upkeep_ips_positivliste',
    'upkeep_ips_whitelist',
    'upkeep_mail_rate_limit',
    'upkeep_mail_badwords',
    'upkeep_mail_blocklist',
    'upkeep_mail_threat_log',
    'upkeep_mail_default_patterns',
    'upkeep_form_log',
];
$sql = rex_sql::factory();
foreach ($tables as $table) {
    try {
        $sql->setQuery('DROP TABLE IF EXISTS ' . $sql->escapeIdentifier(rex::getTable($table)));
    } catch (rex_sql_exception $e) {
        rex_logger::logException($e);
    }
}

foreach (['KLXM\Upkeep\Schema\SecuritySchema', 'KLXM\Upkeep\Schema\FormProtectionSchema'] as $schema) {
    if (class_exists($schema) && method_exists($schema, 'drop')) {
        try {
            $schema::drop();
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }
}

rex_config::removeNamespace('upkeep');
