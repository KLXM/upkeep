<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Einstellungen speichern
if (rex_post('save', 'bool')) {
    $config = [
        'ips_active' => rex_post('ips_active', 'bool'),
        'ips_burst_limit' => rex_post('ips_burst_limit', 'int', 10),
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
$burstLimit = (int) $addon->getConfig('ips_burst_limit', 10);
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

echo '<div class="form-group">';
echo '<label for="ips_burst_limit">Rate Limit (Requests pro Minute)</label>';
echo '<input type="number" class="form-control" id="ips_burst_limit" name="ips_burst_limit" value="' . $burstLimit . '" min="1" max="1000">';
echo '<p class="help-block">Maximale Anzahl Requests pro Minute pro IP</p>';
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
echo '<dt>Rate Limit:</dt>';
echo '<dd>' . $burstLimit . ' Requests/Minute</dd>';
echo '<dt>PHP Version:</dt>';
echo '<dd>' . PHP_VERSION . '</dd>';
echo '<dt>REDAXO Version:</dt>';
echo '<dd>' . rex::getVersion() . '</dd>';
echo '</dl>';
echo '</div>';
echo '</div>';
