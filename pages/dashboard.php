<?php

use FriendsOfRedaxo\Upkeep\SecurityAdvisor;
use FriendsOfRedaxo\Upkeep\IntrusionPrevention;
use FriendsOfRedaxo\Upkeep\MailSecurityFilter;

$addon = rex_addon::get('upkeep');
$advisor = new SecurityAdvisor();

// IPS-Statistiken abrufen
try {
    $ipsStats = IntrusionPrevention::getStatistics();
} catch (Exception $e) {
    // Fallback wenn Tabellen noch nicht existieren
    $ipsStats = [
        'blocked_ips' => 0,
        'threats_today' => 0,
        'threats_week' => 0,
        'top_threats' => []
    ];
}

// Mail-Security-Statistiken abrufen
try {
    $mailStats = MailSecurityFilter::getDashboardStats();
} catch (Exception $e) {
    // Fallback wenn Mail-Security noch nicht installiert
    $mailStats = [
        'active' => false,
        'threats_24h' => 0,
        'blocked_emails_24h' => 0,
        'badwords_count' => 0,
        'blocklist_count' => 0
    ];
}

// IPS-Status
$ipsActive = IntrusionPrevention::isActive();

// CSS für Animation
echo '<style>
.version-status-success {
    animation: pulse-success 2s infinite;
    background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
    border-color: #28a745;
    color: #155724 !important;
}

.version-status-success h4,
.version-status-success p {
    color: #155724 !important;
}

@keyframes pulse-success {
    0% {
        box-shadow: 0 0 0 0 rgba(40, 167, 69, 0.4);
    }
    70% {
        box-shadow: 0 0 0 10px rgba(40, 167, 69, 0);
    }
    100% {
        box-shadow: 0 0 0 0 rgba(40, 167, 69, 0);
    }
}

.version-icon-success {
    animation: bounce 2s infinite;
}

@keyframes bounce {
    0%, 20%, 60%, 100% {
        transform: translateY(0);
    }
    40% {
        transform: translateY(-10px);
    }
    80% {
        transform: translateY(-5px);
    }
}

.version-status-warning {
    animation: pulse-warning 3s infinite;
    color: #856404 !important;
}

.version-status-warning h4,
.version-status-warning p {
    color: #856404 !important;
}

@keyframes pulse-warning {
    0%, 100% {
        background-color: #fff3cd;
    }
    50% {
        background-color: #ffeaa7;
    }
}

.version-status-danger {
    animation: pulse-danger 2s infinite;
    color: #721c24 !important;
}

.version-status-danger h4,
.version-status-danger p {
    color: #721c24 !important;
}

@keyframes pulse-danger {
    0%, 100% {
        background-color: #f8d7da;
    }
    50% {
        background-color: #f5c6cb;
    }
}
</style>';

// REDAXO Version Check - IMMER anzeigen mit Animation
$redaxoCheck = $advisor->checkRedaxoVersion();

// Alert-Klasse und Icon basierend auf Status
$alertClass = match($redaxoCheck['status']) {
    'up_to_date' => 'alert-success version-status-success',
    'critical' => 'alert-danger version-status-danger',
    'outdated' => 'alert-warning version-status-warning',
    default => 'alert-info'
};

$icon = match($redaxoCheck['status']) {
    'up_to_date' => 'fa-check-circle version-icon-success',
    'critical' => 'fa-exclamation-triangle',
    'outdated' => 'fa-exclamation-circle',
    default => 'fa-info-circle'
};

$dismissible = $redaxoCheck['status'] === 'up_to_date' ? '' : 'alert-dismissible';

echo '<div class="alert ' . $alertClass . ' ' . $dismissible . '" role="alert">';
if ($redaxoCheck['status'] !== 'up_to_date') {
    echo '<button type="button" class="close" data-dismiss="alert" aria-label="Close">';
    echo '<span aria-hidden="true">&times;</span>';
    echo '</button>';
}
echo '<h4><i class="fa ' . $icon . '"></i> ' . $redaxoCheck['title'] . '</h4>';
echo '<p>' . $redaxoCheck['message'] . '</p>';
if (isset($redaxoCheck['details'])) {
    $detailsText = '';
    if (is_array($redaxoCheck['details'])) {
        $allDetails = [];
        if (!empty($redaxoCheck['details']['critical_issues'])) {
            $allDetails = array_merge($allDetails, $redaxoCheck['details']['critical_issues']);
        }
        if (!empty($redaxoCheck['details']['warnings'])) {
            $allDetails = array_merge($allDetails, $redaxoCheck['details']['warnings']);
        }
        $detailsText = implode(', ', $allDetails);
    } else {
        $detailsText = $redaxoCheck['details'];
    }
    if (!empty($detailsText)) {
        echo '<p><strong>Details:</strong> ' . $detailsText . '</p>';
    }
}
echo '</div>';

// Wartungsempfehlung basierend auf Admin-Freigaben und System-Status
$nextMaintenanceInfo = '';
$adminReleases = [];
$nextMaintenanceDate = null;

// Sammle alle Admin-Freigaben mit Ablaufdaten
$checkTypes = ['database', 'php_config', 'server_status', 'security_settings'];
foreach ($checkTypes as $checkType) {
    if ($advisor->isCheckReleased($checkType)) {
        $releaseTimestamp = $addon->getConfig("admin_release_{$checkType}", 0);
        $releaseDays = $addon->getConfig('admin_release_days', 30);
        $expiryTimestamp = $releaseTimestamp + ($releaseDays * 24 * 60 * 60);
        $adminReleases[$checkType] = $expiryTimestamp;
    }
}

// Finde das nächste Ablaufdatum
if (!empty($adminReleases)) {
    $nextMaintenanceDate = min($adminReleases);
    $daysUntilMaintenance = ceil(($nextMaintenanceDate - time()) / (24 * 60 * 60));
    
    if ($daysUntilMaintenance > 0) {
        $nextMaintenanceInfo = $addon->i18n('upkeep_dashboard_next_system_check_recommended') . ': <strong>' . date('d.m.Y', $nextMaintenanceDate) . '</strong> (' . $addon->i18n('upkeep_dashboard_in_days', $daysUntilMaintenance) . ')';
    } else {
        $nextMaintenanceInfo = $addon->i18n('upkeep_dashboard_system_check_overdue');
    }
} else {
    // Keine Admin-Freigaben aktiv - Standard-Empfehlung
    $lastMaintenanceCheck = $addon->getConfig('last_maintenance_info', time());
    $daysSinceLastInfo = floor((time() - $lastMaintenanceCheck) / (24 * 60 * 60));
    
    if ($daysSinceLastInfo >= 30) {
        $nextMaintenanceInfo = $addon->i18n('upkeep_dashboard_regular_system_check_recommended');
        // Aktualisiere Timestamp damit Info nicht täglich erscheint
        $addon->setConfig('last_maintenance_info', time());
    }
}

// Zeige Wartungsempfehlung an
if (!empty($nextMaintenanceInfo)) {
    echo '<div class="alert alert-info" role="alert">';
    echo '<h4><i class="fa fa-calendar"></i> ' . $addon->i18n('upkeep_dashboard_maintenance_recommendation') . '</h4>';
    echo '<p>' . $nextMaintenanceInfo . '</p>';

    echo '</div>';
}

// Debug Admin-Freigaben (nur im Debug-Modus)
if (rex::isDebugMode()) {
    $debugInfo = '';
    $debugInfo .= 'Database Released: ' . ($advisor->isCheckReleased('database') ? 'JA' : 'NEIN') . '<br>';
    $debugInfo .= 'PHP Config Released: ' . ($advisor->isCheckReleased('php_config') ? 'JA' : 'NEIN') . '<br>';
    $debugInfo .= 'Server Status Released: ' . ($advisor->isCheckReleased('server_status') ? 'JA' : 'NEIN') . '<br>';
    $debugInfo .= 'Security Settings Released: ' . ($advisor->isCheckReleased('security_settings') ? 'JA' : 'NEIN') . '<br>';
    $debugInfo .= 'Current Time: ' . date('Y-m-d H:i:s') . '<br>';

    echo '<div class="alert alert-info"><strong>Debug Admin-Freigaben:</strong><br>' . $debugInfo . '</div>';
}

// System Status Dashboard
$content = '<div class="row">';

// System Health Card
$systemHealth = $advisor->checkSystemHealth();
$healthClass = match($systemHealth['status']) {
    'healthy' => 'success',
    'warning' => 'warning', 
    'critical' => 'danger',
    default => 'default'
};

$healthIcon = match($systemHealth['status']) {
    'healthy' => 'fa-heart',
    'warning' => 'fa-exclamation-triangle',
    'critical' => 'fa-times-circle',
    default => 'fa-question-circle'
};

$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . $healthClass . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa ' . $healthIcon . ' fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . $systemHealth['score'] . '%</div>';
$content .= '<div>' . $addon->i18n('upkeep_dashboard_system_health') . '</div>';
$content .= '</div></div></div>';
$content .= '<div class="panel-footer"><span class="pull-left">' . $systemHealth['message'] . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-info-circle"></i></span><div class="clearfix"></div></div>';
$content .= '</div></div>';

// Database Status Card - mit Admin-Freigabe-Prüfung
$databaseStatus = $advisor->checkDatabaseStatus();
$dbReleased = $advisor->isCheckReleased('database');

// Status anpassen wenn Admin-Freigabe aktiv ist
if ($dbReleased && $databaseStatus['status'] !== 'healthy') {
    $dbClass = 'info';
    $dbIcon = 'fa-database';
    $dbDisplayStatus = 'GEPRÜFT ✓';
    $dbMessage = $addon->i18n('upkeep_dashboard_checked_and_approved');
} else {
    $dbClass = match($databaseStatus['status']) {
        'healthy' => 'success',
        'warning' => 'warning',
        'critical' => 'danger',
        default => 'danger'
    };
    $dbIcon = match($databaseStatus['status']) {
        'healthy' => 'fa-database',
        'warning' => 'fa-exclamation-circle',
        'critical' => 'fa-exclamation-triangle',
        default => 'fa-times-circle'
    };
    
    $dbDisplayStatus = match($databaseStatus['status']) {
        'healthy' => 'OK',
        'warning' => 'UPDATE',
        'critical' => 'KRITISCH',
        'error' => 'FEHLER',
        default => 'PRÜFEN'
    };
    $dbMessage = $databaseStatus['message'];
}

$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . $dbClass . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa ' . $dbIcon . ' fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . $dbDisplayStatus . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_dashboard_database') . '</div>';
$content .= '</div></div></div>';
$content .= '<div class="panel-footer"><span class="pull-left">' . $dbMessage . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-database"></i></span><div class="clearfix"></div></div>';
$content .= '</div></div>';

// Dateisicherheit Card - vereinfacht
$filePermissions = $advisor->checkFilePermissions();
$permClass = $filePermissions['status'] === 'secure' ? 'success' : 'warning';
$permIcon = $filePermissions['status'] === 'secure' ? 'fa-lock' : 'fa-unlock';

$permMessage = $filePermissions['status'] === 'secure' ? $addon->i18n('upkeep_file_security_configured') : $addon->i18n('upkeep_file_security_needs_review');

$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . $permClass . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa ' . $permIcon . ' fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . ($filePermissions['status'] === 'secure' ? 'OK' : 'PRÜFEN') . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_dashboard_file_security') . '</div>';
$content .= '</div></div></div>';
$content .= '<div class="panel-footer"><span class="pull-left">' . $permMessage . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-shield"></i></span><div class="clearfix"></div></div>';
$content .= '</div></div>';

// Server Konfiguration Card - mit Admin-Freigabe-Prüfung
$phpConfig = $advisor->checkPhpConfiguration();
$phpReleased = $advisor->isCheckReleased('php_config');
$serverStatusReleased = $advisor->isCheckReleased('server_status');

// Detailliertere PHP-Statusprüfung für Dashboard
if ($phpConfig['status'] === 'optimal') {
    // Alles OK - Grün
    $phpClass = 'success';
    $serverMessage = 'Server Konfiguration optimal';
} elseif ($phpReleased || $serverStatusReleased) {
    // Admin hat Freigabe erteilt - Grün
    $phpClass = 'success';
    $serverMessage = $addon->i18n('upkeep_dashboard_checked_and_approved');
} else {
    // Probleme vorhanden - Rot oder Orange je nach Schwere
    $serverMessage = match($phpConfig['status']) {
        'warning' => count($phpConfig['issues'] ?? []) > 0 ? 'Server Version veraltet - Update erforderlich' : 'Server Einstellungen überprüfen',
        'error' => 'Server Version kritisch veraltet - Sofortiges Update erforderlich',
        default => 'Server Status überprüfen'
    };
    
    // Bei kritischen PHP-Problemen Rot, sonst Orange
    $phpClass = 'danger'; // Standard: Rot für alle Probleme
    if ($phpConfig['status'] === 'warning' && count($phpConfig['issues'] ?? []) === 0) {
        $phpClass = 'warning'; // Nur bei harmlosen Warnings Orange
    }
}

$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . $phpClass . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa fa-server fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . ($phpConfig['status'] === 'optimal' ? 'OK' : ($phpReleased ? 'GEPRÜFT ✓' : 'PRÜFEN')) . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_dashboard_server_setup') . '</div>';
$content .= '</div></div></div>';
$content .= '<div class="panel-footer"><span class="pull-left">' . $serverMessage . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-server"></i></span><div class="clearfix"></div></div>';
$content .= '</div></div>';

$content .= '</div>'; // Ende row

$fragment = new rex_fragment();
$fragment->setVar('title', '<i class="fa fa-tachometer"></i> ' . $addon->i18n('upkeep_dashboard_system_status') . ' <small>' . $addon->i18n('upkeep_dashboard_core_system_checks') . '</small>', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Security Checks Section
$securityContent = '<div class="row">';

// Mail Security Card - ohne Links
$mailSecurityStatus = $advisor->getMailSecurityStatus();
$mailClass = $mailSecurityStatus['active'] ? 'success' : 'info';
$mailIcon = $mailSecurityStatus['active'] ? 'fa-envelope-o' : 'fa-envelope';

$mailMessage = $mailSecurityStatus['active'] ? $addon->i18n('upkeep_dashboard_email_protection_active') : $addon->i18n('upkeep_dashboard_email_protection_configure');

$securityContent .= '<div class="col-lg-3 col-md-6">';
$securityContent .= '<div class="panel panel-' . $mailClass . '">';
$securityContent .= '<div class="panel-heading">';
$securityContent .= '<div class="row">';
$securityContent .= '<div class="col-xs-3"><i class="fa ' . $mailIcon . ' fa-5x"></i></div>';
$securityContent .= '<div class="col-xs-9 text-right">';
$securityContent .= '<div class="huge">' . ($mailSecurityStatus['active'] ? 'AKTIV' : 'SETUP') . '</div>';
$securityContent .= '<div>' . $addon->i18n('upkeep_dashboard_mail_protection') . '</div>';
$securityContent .= '</div></div></div>';
$securityContent .= '<div class="panel-footer"><span class="pull-left">' . $mailMessage . '</span>';
$securityContent .= '<span class="pull-right"><i class="fa fa-info-circle"></i></span><div class="clearfix"></div></div>';
$securityContent .= '</div></div>';

// E-Mail Konfiguration Card - Vereinfacht
$phpmailerStatus = $advisor->checkPhpMailerConfig();
$phpmailerClass = match($phpmailerStatus['status']) {
    'configured' => 'success',
    'partial' => 'warning',
    'missing' => 'warning',
    'warning' => 'warning',
    default => 'default'
};

// Benutzerfreundliche Meldung ohne technische Details
$emailMessage = match($phpmailerStatus['status']) {
    'configured' => $addon->i18n('upkeep_email_configuration_ok'),
    'partial' => $addon->i18n('upkeep_dashboard_email_settings_check'),
    'missing' => $addon->i18n('upkeep_dashboard_email_settings_check'),
    'warning' => $addon->i18n('upkeep_dashboard_email_settings_check'),
    default => $addon->i18n('upkeep_dashboard_email_status_unknown')
};

$securityContent .= '<div class="col-lg-3 col-md-6">';
$securityContent .= '<div class="panel panel-' . $phpmailerClass . '">';
$securityContent .= '<div class="panel-heading">';
$securityContent .= '<div class="row">';
$securityContent .= '<div class="col-xs-3"><i class="fa fa-envelope-square fa-5x"></i></div>';
$securityContent .= '<div class="col-xs-9 text-right">';
$securityContent .= '<div class="huge">' . ($phpmailerStatus['status'] === 'configured' ? 'OK' : 'PRÜFEN') . '</div>';
$securityContent .= '<div>E-Mail System</div>';
$securityContent .= '</div></div></div>';
$securityContent .= '<div class="panel-footer"><span class="pull-left">' . $emailMessage . '</span>';
$securityContent .= '<span class="pull-right"><i class="fa fa-cog"></i></span><div class="clearfix"></div></div>';
$securityContent .= '</div></div>';

// Sicherheits-Konfiguration Card - mit Admin-Freigabe-Prüfung
$securityHeaders = $advisor->checkSecurityHeaders();
$securityReleased = $advisor->isCheckReleased('security_settings');

// Status basierend auf Sicherheitsstatus und Admin-Freigabe
if ($securityHeaders['status'] === 'secure') {
    // Alles OK - Grün
    $headersClass = 'success';
    $headersIcon = 'fa-shield';
    $securityMessage = 'Sicherheitseinstellungen aktiv';
} elseif ($securityReleased) {
    // Admin hat Freigabe erteilt - Grün
    $headersClass = 'success';
    $headersIcon = 'fa-shield';
    $securityMessage = $addon->i18n('upkeep_dashboard_checked_and_approved');
} else {
    // Probleme vorhanden - Orange/Rot
    $headersClass = 'warning';
    $headersIcon = 'fa-exclamation-triangle';
    $securityMessage = 'Sicherheitseinstellungen überprüfen';
}

$securityContent .= '<div class="col-lg-3 col-md-6">';
$securityContent .= '<div class="panel panel-' . $headersClass . '">';
$securityContent .= '<div class="panel-heading">';
$securityContent .= '<div class="row">';
$securityContent .= '<div class="col-xs-3"><i class="fa ' . $headersIcon . ' fa-5x"></i></div>';
$securityContent .= '<div class="col-xs-9 text-right">';
$securityContent .= '<div class="huge">' . ($securityHeaders['status'] === 'secure' ? 'OK' : ($securityReleased ? 'GEPRÜFT ✓' : 'PRÜFEN')) . '</div>';
$securityContent .= '<div>' . $addon->i18n('upkeep_dashboard_security') . '</div>';
$securityContent .= '</div></div></div>';
$securityContent .= '<div class="panel-footer"><span class="pull-left">' . $securityMessage . '</span>';
$securityContent .= '<span class="pull-right"><i class="fa fa-shield"></i></span><div class="clearfix"></div></div>';
$securityContent .= '</div></div>';

// Addon Security Card
$addonSecurity = $advisor->checkAddonSecurity();
$addonClass = $addonSecurity['status'] === 'secure' ? 'success' : 'info';

$securityContent .= '<div class="col-lg-3 col-md-6">';
$securityContent .= '<div class="panel panel-' . $addonClass . '">';
$securityContent .= '<div class="panel-heading">';
$securityContent .= '<div class="row">';
$securityContent .= '<div class="col-xs-3"><i class="fa fa-puzzle-piece fa-5x"></i></div>';
$securityContent .= '<div class="col-xs-9 text-right">';
$securityContent .= '<div class="huge">' . count($addonSecurity['addons']) . '</div>';
$securityContent .= '<div>' . $addon->i18n('upkeep_dashboard_addons') . '</div>';
$securityContent .= '</div></div></div>';
$securityContent .= '<div class="panel-footer"><span class="pull-left">' . $addonSecurity['message'] . '</span>';
$securityContent .= '<span class="pull-right"><i class="fa fa-puzzle-piece"></i></span><div class="clearfix"></div></div>';
$securityContent .= '</div></div>';

$securityContent .= '</div>'; // Ende row

$fragment = new rex_fragment();
$fragment->setVar('title', '<i class="fa fa-shield"></i> ' . $addon->i18n('upkeep_dashboard_security_checks') . ' <small>' . $addon->i18n('upkeep_dashboard_security_assessment_monitoring') . '</small>', false);
$fragment->setVar('body', $securityContent, false);
echo $fragment->parse('core/page/section.php');



// System Status Panel - Vereinfacht ohne technische Details
$actionsContent = '<div class="row">';
$actionsContent .= '<div class="col-lg-12">';
$actionsContent .= '<div class="panel panel-default">';
$actionsContent .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-info-circle"></i> System Status</h3></div>';
$actionsContent .= '<div class="panel-body">';

// Einfache Statistiken ohne technische Details
$actionsContent .= '<div class="row">';
$actionsContent .= '<div class="col-md-3 text-center">';
$actionsContent .= '<h4>' . $ipsStats['blocked_ips'] . '</h4>';
$actionsContent .= '<p class="text-muted">Blockierte Zugriffe</p>';
$actionsContent .= '</div>';
$actionsContent .= '<div class="col-md-3 text-center">';
$actionsContent .= '<h4>' . $ipsStats['threats_today'] . '</h4>';
$actionsContent .= '<p class="text-muted">Bedrohungen heute</p>';
$actionsContent .= '</div>';
$actionsContent .= '<div class="col-md-3 text-center">';
$actionsContent .= '<h4>' . ($mailStats['threats_24h'] ?? 0) . '</h4>';
$actionsContent .= '<p class="text-muted">E-Mail Bedrohungen</p>';
$actionsContent .= '</div>';
$actionsContent .= '<div class="col-md-3 text-center">';
$actionsContent .= '<h4>' . ($ipsActive ? 'Aktiv' : 'Inaktiv') . '</h4>';
$actionsContent .= '<p class="text-muted">Sicherheitssystem</p>';
$actionsContent .= '</div>';
$actionsContent .= '</div>';

// Wartungsstatus separat prüfen
$maintenanceCheck = $advisor->runAllChecks();
$maintenanceStatus = $maintenanceCheck['checks']['maintenance_status'] ?? null;

// Zeige Wartungsnachricht IMMER an, wenn Wartung erforderlich ist
if ($maintenanceStatus && $maintenanceStatus['status'] === 'error') {
    echo '<div class="alert alert-danger" role="alert">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_dashboard_maintenance_required') . '</h4>';
    
    // Zeige alle Wartungsnachrichten
    $maintenanceDetails = $maintenanceStatus['details'];
    if (!empty($maintenanceDetails['maintenance_message'])) {
        echo '<p><strong>' . $addon->i18n('upkeep_maintenance_message') . ':</strong> ' . $maintenanceDetails['maintenance_message'] . '</p>';
    }
    
    if (!empty($maintenanceDetails['maintenance_contact'])) {
        echo '<p><strong>' . $addon->i18n('upkeep_dashboard_contact_technical_maintainer', $maintenanceDetails['maintenance_contact']) . '</strong></p>';
    }
    
    echo '<p>' . $addon->i18n('upkeep_maintenance_system_unavailable') . '</p>';
    echo '</div>';
}

$actionsContent .= '</div>';
$actionsContent .= '</div>';
$actionsContent .= '</div>';
$actionsContent .= '</div>'; // Ende row

$fragment = new rex_fragment();
$fragment->setVar('title', '<i class="fa fa-tachometer"></i> ' . $addon->i18n('upkeep_dashboard_system_overview'), false);
$fragment->setVar('body', $actionsContent, false);
echo $fragment->parse('core/page/section.php');