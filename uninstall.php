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
