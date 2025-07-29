<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Einstellungen speichern
if (rex_post('save', 'bool')) {
    $config = [
        'ips_active' => rex_post('ips_active', 'bool'),
        'ips_block_title' => rex_post('ips_block_title', 'string', 'Access Denied'),
        'ips_block_message' => rex_post('ips_block_message', 'string', 'Your request has been blocked by our security system.'),
        'ips_contact_info' => rex_post('ips_contact_info', 'string', ''),
    ];
    
    foreach ($config as $key => $value) {
        $addon->setConfig($key, $value);
    }
    
    echo rex_view::success($addon->i18n('upkeep_settings_saved'));
}

// Aktuelle Einstellungen laden
$ipsActive = (bool) $addon->getConfig('ips_active', false);
$blockTitle = $addon->getConfig('ips_block_title', 'Access Denied');
$blockMessage = $addon->getConfig('ips_block_message', 'Your request has been blocked by our security system.');
$contactInfo = $addon->getConfig('ips_contact_info', '');

// Formular
echo '<form method="post">';
echo '<input type="hidden" name="save" value="1">';

echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-cog"></i> IPS Grundeinstellungen';
echo '</div>';
echo '<div class="panel-body">';

echo '<div class="form-group">';
echo '<label class="control-label">';
echo '<input type="checkbox" name="ips_active" value="1"' . ($ipsActive ? ' checked' : '') . '> ';
echo $addon->i18n('upkeep_ips_active');
echo '</label>';
echo '<p class="help-block">Aktiviert das Intrusion Prevention System für das Frontend</p>';
echo '</div>';

echo '</div>';
echo '</div>';

echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-ban"></i> Blockierungsseite';
echo '</div>';
echo '<div class="panel-body">';

echo '<div class="form-group">';
echo '<label for="ips_block_title">Titel der Blockierungsseite</label>';
echo '<input type="text" class="form-control" id="ips_block_title" name="ips_block_title" value="' . rex_escape($blockTitle) . '">';
echo '</div>';

echo '<div class="form-group">';
echo '<label for="ips_block_message">Nachricht</label>';
echo '<textarea class="form-control" id="ips_block_message" name="ips_block_message" rows="3">' . rex_escape($blockMessage) . '</textarea>';
echo '</div>';

echo '<div class="form-group">';
echo '<label for="ips_contact_info">Kontaktinformationen (optional)</label>';
echo '<input type="text" class="form-control" id="ips_contact_info" name="ips_contact_info" value="' . rex_escape($contactInfo) . '">';
echo '<p class="help-block">E-Mail oder andere Kontaktinformationen für blockierte Benutzer</p>';
echo '</div>';

echo '</div>';
echo '</div>';

// Rate Limiting Information Panel
echo '<div class="panel panel-warning">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-shield"></i> Rate Limiting (Experten-Einstellungen)';
echo '</div>';
echo '<div class="panel-body">';
echo '<p><strong>Rate Limiting ist standardmäßig deaktiviert</strong> und sollte nur von Experten aktiviert werden.</p>';
echo '<p>Die Konfiguration erfolgt über folgende Config-Einstellungen:</p>';
echo '<ul>';
echo '<li><code>ips_rate_limiting_enabled</code> - Aktiviert/Deaktiviert das Rate Limiting (Standard: false)</li>';
echo '<li><code>ips_burst_limit</code> - Maximale Requests pro Minute (Standard: 600)</li>';
echo '<li><code>ips_strict_limit</code> - Limit für kritische Bereiche (Standard: 200)</li>';
echo '<li><code>ips_burst_window</code> - Zeitfenster in Sekunden (Standard: 60)</li>';
echo '</ul>';
echo '<p class="help-block"><strong>Hinweis:</strong> Rate Limiting sollte normalerweise auf Webserver-Ebene (Apache/Nginx) erfolgen. Diese Einstellungen sind nur für DoS-Schutz bei extremen Angriffen gedacht.</p>';
echo '</div>';
echo '</div>';

echo '<div class="form-group">';
echo '<button type="submit" class="btn btn-primary">';
echo '<i class="fa fa-save"></i> ' . $addon->i18n('upkeep_save');
echo '</button>';
echo '</div>';

echo '</form>';

// System Status
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> System Status';
echo '</div>';
echo '<div class="panel-body">';
echo '<dl class="dl-horizontal">';
echo '<dt>IPS Status:</dt>';
echo '<dd>' . ($ipsActive ? '<span class="label label-success">Aktiv</span>' : '<span class="label label-danger">Inaktiv</span>') . '</dd>';
echo '<dt>Rate Limiting:</dt>';
$rateLimitingEnabled = (bool) $addon->getConfig('ips_rate_limiting_enabled', false);
echo '<dd>' . ($rateLimitingEnabled ? '<span class="label label-warning">Aktiv (Experten-Modus)</span>' : '<span class="label label-default">Deaktiviert</span>') . '</dd>';
echo '<dt>PHP Version:</dt>';
echo '<dd>' . PHP_VERSION . '</dd>';
echo '<dt>REDAXO Version:</dt>';
echo '<dd>' . rex::getVersion() . '</dd>';
echo '</dl>';
echo '</div>';
echo '</div>';
