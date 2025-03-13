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
