<?php
/**
 * Test-Datei für die Modul-Konfiguration
 * Diese Datei kann temporär aufgerufen werden, um die Funktionalität zu testen
 */

// Für Testzwecke - kann später entfernt werden
if (!defined('REX_BACKEND') || !REX_BACKEND) {
    exit('Zugriff nur über Backend möglich');
}

$addon = rex_addon::get('upkeep');

echo '<h3>Modul-Konfiguration Test</h3>';

// Aktuelle Einstellungen anzeigen
echo '<p><strong>Security Advisor:</strong> ' . ($addon->getConfig('security_advisor_enabled', true) ? 'Aktiviert' : 'Deaktiviert') . '</p>';
echo '<p><strong>Mail Security:</strong> ' . ($addon->getConfig('mail_security_enabled', true) ? 'Aktiviert' : 'Deaktiviert') . '</p>';
echo '<p><strong>Reporting:</strong> ' . ($addon->getConfig('reporting_enabled', true) ? 'Aktiviert' : 'Deaktiviert') . '</p>';

// Seitenkonfiguration anzeigen
$page = $addon->getProperty('page');
if ($page && isset($page['subpages'])) {
    echo '<h4>Verfügbare Subpages:</h4>';
    echo '<ul>';
    foreach ($page['subpages'] as $key => $subpage) {
        $title = is_array($subpage) ? ($subpage['title'] ?? $key) : $subpage;
        echo '<li>' . $key . ' - ' . $title . '</li>';
    }
    echo '</ul>';
}

echo '<p><em>Diese Datei kann nach dem Test gelöscht werden.</em></p>';