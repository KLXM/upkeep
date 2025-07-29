<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Einstellungen speichern
if (rex_post('save', 'bool')) {
    $config = [
        'ips_active' => rex_post('ips_active', 'bool'),
        'ips_contact_info' => rex_post('ips_contact_info', 'string', ''),
        'ips_captcha_trust_duration' => rex_post('ips_captcha_trust_duration', 'int', 24),
        'ips_debug_mode' => rex_post('ips_debug_mode', 'bool'),
    ];
    
    foreach ($config as $key => $value) {
        $addon->setConfig($key, $value);
    }
    
    echo rex_view::success($addon->i18n('upkeep_settings_saved'));
}

// Aktuelle Einstellungen laden
$ipsActive = (bool) $addon->getConfig('ips_active', false);
$contactInfo = $addon->getConfig('ips_contact_info', '');
$captchaTrustDuration = (int) $addon->getConfig('ips_captcha_trust_duration', 24);
$debugMode = (bool) $addon->getConfig('ips_debug_mode', false);

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
echo '<label for="ips_captcha_trust_duration">CAPTCHA-Vertrauensdauer (Stunden)</label>';
echo '<input type="number" class="form-control" id="ips_captcha_trust_duration" name="ips_captcha_trust_duration" value="' . $captchaTrustDuration . '" min="1" max="168">';
echo '<p class="help-block">Wie lange (in Stunden) eine IP nach erfolgreicher CAPTCHA-Entsperrung vertrauenswürdig bleibt (Standard: 24 Stunden, Maximum: 168 Stunden/7 Tage)</p>';
echo '</div>';

echo '<div class="form-group">';
echo '<label class="control-label">';
echo '<input type="checkbox" name="ips_debug_mode" value="1"' . ($debugMode ? ' checked' : '') . '> ';
echo 'Debug-Modus aktivieren';
echo '</label>';
echo '<p class="help-block"><strong>Warnung:</strong> Debug-Modus schreibt viele Log-Einträge für jeden Request. Nur für Entwicklung und Troubleshooting aktivieren!</p>';
echo '</div>';

echo '</div>';
echo '</div>';

echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-life-ring"></i> Support-Einstellungen';
echo '</div>';
echo '<div class="panel-body">';

echo '<div class="form-group">';
echo '<label for="ips_contact_info">Kontaktinformationen (optional)</label>';
echo '<input type="text" class="form-control" id="ips_contact_info" name="ips_contact_info" value="' . rex_escape($contactInfo) . '">';
echo '<p class="help-block">E-Mail oder andere Kontaktinformationen für blockierte Benutzer auf der Sperrseite</p>';
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

echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-cogs"></i> Erweiterte IPS-Konfiguration';
echo '</div>';
echo '<div class="panel-body">';
echo '<p><strong>Weitere IPS-Einstellungen</strong> können über die Konfiguration angepasst werden:</p>';
echo '<ul>';
echo '<li><code>ips_cleanup_auto</code> - Automatische Datenbereinigung aktivieren (Standard: true)</li>';
echo '<li><code>ips_log_retention_days</code> - Aufbewahrungszeit für Logs in Tagen (Standard: 30)</li>';
echo '</ul>';
echo '<p><strong>Beispiel-Konfiguration:</strong></p>';
echo '<pre><code>// Logs 60 Tage aufbewahren';
echo "\n" . 'rex_config::set(\'upkeep\', \'ips_log_retention_days\', 60);';
echo "\n\n" . '// Automatische Bereinigung deaktivieren';
echo "\n" . 'rex_config::set(\'upkeep\', \'ips_cleanup_auto\', false);</code></pre>';
echo '</div>';
echo '</div>';

echo '<div class="panel panel-success">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> Sperrseite-Information';
echo '</div>';
echo '<div class="panel-body">';
echo '<p><strong>Die Sperrseite wird automatisch generiert</strong> und ist mehrsprachig (Deutsch/Englisch).</p>';
echo '<ul>';
echo '<li>Automatische Spracherkennung basierend auf Browser-Einstellungen</li>';
echo '<li>CAPTCHA-Entsperrung mit mathematischen Aufgaben</li>';
echo '<li>Moderne, responsive Oberfläche</li>';
echo '<li>24h temporäre Positivliste nach erfolgreicher Entsperrung</li>';
echo '</ul>';
echo '<p class="help-block"><strong>Hinweis:</strong> Nur die Kontaktinformationen können über das Interface angepasst werden. Titel und Nachrichten sind fest definiert und mehrsprachig.</p>';
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
echo '<dt>Debug-Modus:</dt>';
echo '<dd>' . ($debugMode ? '<span class="label label-warning">Aktiv</span>' : '<span class="label label-success">Deaktiviert</span>') . '</dd>';
echo '<dt>PHP Version:</dt>';
echo '<dd>' . PHP_VERSION . '</dd>';
echo '<dt>REDAXO Version:</dt>';
echo '<dd>' . rex::getVersion() . '</dd>';
echo '</dl>';
echo '</div>';
echo '</div>';
