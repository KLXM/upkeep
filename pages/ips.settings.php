<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// GeoIP-Datenbank aktualisieren
if (rex_post('update_geo', 'bool')) {
    if (class_exists('KLXM\Upkeep\GeoIP')) {
        if (IntrusionPrevention::updateGeoDatabase()) {
            echo rex_view::success('GeoIP-Datenbank erfolgreich aktualisiert');
        } else {
            echo rex_view::error('Fehler beim Aktualisieren der GeoIP-Datenbank');
        }
    } else {
        echo rex_view::error('GeoIP-Funktionalität nicht verfügbar');
    }
}

// Einstellungen speichern
if (rex_post('save', 'bool')) {
    $config = [
        'ips_active' => rex_post('ips_active', 'bool'),
        'ips_monitor_only' => rex_post('ips_monitor_only', 'bool'),
        'ips_disable_system_logging' => rex_post('ips_disable_system_logging', 'bool'),
        'ips_fail2ban_logging' => rex_post('ips_fail2ban_logging', 'bool'),
        'ips_fail2ban_logfile' => rex_post('ips_fail2ban_logfile', 'string', '/var/log/redaxo_ips.log'),
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
$monitorOnly = (bool) $addon->getConfig('ips_monitor_only', false);
$disableSystemLogging = (bool) $addon->getConfig('ips_disable_system_logging', false);
$fail2banLogging = (bool) $addon->getConfig('ips_fail2ban_logging', false);
$fail2banLogfile = $addon->getConfig('ips_fail2ban_logfile', '/var/log/redaxo_ips.log');
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
echo '<label class="control-label">';
echo '<input type="checkbox" name="ips_monitor_only" value="1"' . ($monitorOnly ? ' checked' : '') . ' id="monitor-only-checkbox"> ';
echo 'Monitor-Only Modus';
echo '</label>';
echo '<p class="help-block"><strong>Monitor-Only:</strong> Bedrohungen werden nur protokolliert, aber nicht blockiert. Ideal zum Testen und Feintuning der Patterns ohne Ausfallrisiko.</p>';
echo '</div>';

echo '<div class="form-group">';
echo '<label class="control-label">';
echo '<input type="checkbox" name="ips_disable_system_logging" value="1"' . ($disableSystemLogging ? ' checked' : '') . ' id="disable-system-logging-checkbox"> ';
echo 'System-Logging deaktivieren';
echo '</label>';
echo '<p class="help-block"><strong>Wichtig:</strong> Deaktiviert alle IPS-Logs im REDAXO-System-Log. Bedrohungen werden nur noch in der IPS-Datenbank gespeichert. Kritische Fehler (Exceptions) werden weiterhin geloggt.</p>';
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
echo '<i class="fa fa-file-text"></i> Externes Logging';
echo '</div>';
echo '<div class="panel-body">';

echo '<div class="form-group">';
echo '<label class="control-label">';
echo '<input type="checkbox" name="ips_fail2ban_logging" value="1"' . ($fail2banLogging ? ' checked' : '') . '> ';
echo 'fail2ban-kompatibles Logging aktivieren';
echo '</label>';
echo '<p class="help-block">Schreibt Bedrohungen in ein fail2ban-kompatibles Format für externe Verarbeitung</p>';
echo '</div>';

echo '<div class="form-group">';
echo '<label for="ips_fail2ban_logfile">Log-Datei Pfad</label>';
echo '<input type="text" class="form-control" id="ips_fail2ban_logfile" name="ips_fail2ban_logfile" value="' . rex_escape($fail2banLogfile) . '">';
echo '<p class="help-block">Absoluter Pfad zur Log-Datei (Standard: /var/log/redaxo_ips.log). Verzeichnis muss beschreibbar sein.</p>';
echo '</div>';

echo '<div class="alert alert-info">';
echo '<h5><i class="fa fa-info-circle"></i> Extension Points für Entwickler</h5>';
echo '<p>Zusätzlich zum File-Logging können Extension Points verwendet werden:</p>';
echo '<ul style="margin-bottom: 0;">';
echo '<li><span class="text-monospace text-primary">UPKEEP_IPS_THREAT_DETECTED</span> - Für jede erkannte Bedrohung</li>';
echo '<li><span class="text-monospace text-primary">UPKEEP_IPS_FAIL2BAN_LOG</span> - Für fail2ban-spezifisches Logging</li>';
echo '</ul>';
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

echo '<div class="form-group text-center" style="margin-top: 20px;">';
echo '<button type="submit" class="btn btn-primary btn-lg">';
echo '<i class="fa fa-save"></i> ' . $addon->i18n('upkeep_save');
echo '</button>';
echo '</div>';

echo '</form>';

// Rate Limiting Information Panel
echo '<div class="panel panel-warning">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-shield"></i> Rate Limiting (Experten-Einstellungen)';
echo '</div>';
echo '<div class="panel-body">';
echo '<p><strong>Rate Limiting ist standardmäßig deaktiviert</strong> und sollte nur von Experten aktiviert werden.</p>';
echo '<p>Die Konfiguration erfolgt über folgende Config-Einstellungen:</p>';
echo '<ul>';
echo '<li><span class="text-monospace text-primary">ips_rate_limiting_enabled</span> - Aktiviert/Deaktiviert das Rate Limiting (Standard: false)</li>';
echo '<li><span class="text-monospace text-primary">ips_burst_limit</span> - Maximale Requests pro Minute (Standard: 600)</li>';
echo '<li><span class="text-monospace text-primary">ips_strict_limit</span> - Limit für kritische Bereiche (Standard: 200)</li>';
echo '<li><span class="text-monospace text-primary">ips_burst_window</span> - Zeitfenster in Sekunden (Standard: 60)</li>';
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
echo '<li><span class="text-monospace text-primary">ips_cleanup_auto</span> - Automatische Datenbereinigung aktivieren (Standard: true)</li>';
echo '<li><span class="text-monospace text-primary">ips_log_retention_days</span> - Aufbewahrungszeit für Logs in Tagen (Standard: 30)</li>';
echo '</ul>';
echo '<p><strong>Beispiel-Konfiguration:</strong></p>';
echo '<div class="well well-sm">';
echo '<span class="text-monospace text-success">// Logs 60 Tage aufbewahren</span><br>';
echo '<span class="text-monospace text-primary">rex_config::set(\'upkeep\', \'ips_log_retention_days\', 60);</span><br><br>';
echo '<span class="text-monospace text-success">// Automatische Bereinigung deaktivieren</span><br>';
echo '<span class="text-monospace text-primary">rex_config::set(\'upkeep\', \'ips_cleanup_auto\', false);</span>';
echo '</div>';
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

// GeoIP-Management
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-globe"></i> GeoIP-Datenbank';
echo '</div>';
echo '<div class="panel-body">';

if (class_exists('KLXM\Upkeep\GeoIP')) {
    $geoStatus = IntrusionPrevention::getGeoDatabaseStatus();
    
    echo '<div class="row">';
    echo '<div class="col-md-6">';
    echo '<h5>Status</h5>';
    echo '<dl class="dl-horizontal">';
    echo '<dt>Verfügbar:</dt>';
    echo '<dd>' . ($geoStatus['available'] ? '<span class="label label-success">Ja</span>' : '<span class="label label-danger">Nein</span>') . '</dd>';
    echo '<dt>Quelle:</dt>';
    echo '<dd>' . ucfirst($geoStatus['source']) . '</dd>';
    if ($geoStatus['file_date']) {
        echo '<dt>Datum:</dt>';
        echo '<dd>' . $geoStatus['file_date'] . '</dd>';
        echo '<dt>Größe:</dt>';
        echo '<dd>' . number_format($geoStatus['file_size'] / 1024 / 1024, 1) . ' MB</dd>';
    }
    echo '</dl>';
    echo '</div>';
    
    echo '<div class="col-md-6">';
    echo '<h5>Verwaltung</h5>';
    if ($geoStatus['available']) {
        echo '<p class="text-success"><i class="fa fa-check-circle"></i> GeoIP-Datenbank ist einsatzbereit</p>';
        echo '<p><small class="text-muted">Die Datenbank wird für die Länder-Anzeige in der Bedrohungsliste verwendet.</small></p>';
    } else {
        echo '<p class="text-danger"><i class="fa fa-exclamation-triangle"></i> Keine GeoIP-Datenbank verfügbar</p>';
        echo '<p><small class="text-muted">Ohne GeoIP-Datenbank werden keine Länderinformationen angezeigt.</small></p>';
    }
    echo '</div>';
    echo '</div>';
    
    echo '<hr>';
    echo '<div class="row">';
    echo '<div class="col-md-12">';
    echo '<h5>Datenbank-Update</h5>';
    echo '<p>Die GeoIP-Datenbank wird von <strong>DB-IP.com</strong> bereitgestellt (kostenlose Version). Updates erfolgen monatlich.</p>';
    echo '<form method="post" style="display: inline-block;">';
    echo '<input type="hidden" name="update_geo" value="1">';
    echo '<button type="submit" class="btn btn-default" onclick="return confirm(\'GeoIP-Datenbank jetzt aktualisieren?\');">';
    echo '<i class="fa fa-download"></i> Datenbank aktualisieren';
    echo '</button>';
    echo '</form>';
    echo '</div>';
    echo '</div>';
} else {
    echo '<div class="alert alert-warning">';
    echo '<h5><i class="fa fa-exclamation-triangle"></i> GeoIP nicht verfügbar</h5>';
    echo '<p>Die GeoIP-Funktionalität ist nicht verfügbar. Möglicherweise fehlen Abhängigkeiten.</p>';
    echo '<p><strong>Benötigt:</strong> <span class="text-monospace text-primary">geoip2/geoip2</span> Composer-Paket</p>';
    echo '</div>';
}

echo '</div>';
echo '</div>';

// System Status
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> System Status';
echo '</div>';
echo '<div class="panel-body">';
echo '<dl class="dl-horizontal">';
echo '<dt>IPS Status:</dt>';
echo '<dd>' . ($ipsActive ? '<span class="label label-success">Aktiv</span>' : '<span class="label label-danger">Inaktiv</span>') . '</dd>';
echo '<dt>Monitor-Only:</dt>';
echo '<dd>' . ($monitorOnly ? '<span class="label label-warning">Aktiv (Nur Logging)</span>' : '<span class="label label-success">Deaktiviert</span>') . '</dd>';
echo '<dt>System-Logging:</dt>';
echo '<dd>' . ($disableSystemLogging ? '<span class="label label-warning">Deaktiviert</span>' : '<span class="label label-success">Aktiv</span>') . '</dd>';
echo '<dt>fail2ban Logging:</dt>';
echo '<dd>' . ($fail2banLogging ? '<span class="label label-info">Aktiv</span>' : '<span class="label label-default">Deaktiviert</span>') . '</dd>';
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
