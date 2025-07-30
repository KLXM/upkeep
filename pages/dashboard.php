<?php
/**
 * Interaktives Dashboard für das Upkeep AddOn
 */

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// AJAX-Handler
$func = rex_request('func', 'string', '');
if (rex_request::isXmlHttpRequest() && !empty($func)) {
    include __DIR__ . '/dashboard_ajax.php';
    return;
}

// Live-Statistiken abrufen
$stats = IntrusionPrevention::getStatistics();

// System-Info
$phpVersion = PHP_VERSION;
$rexVersion = rex::getVersion();
$memoryUsage = round(memory_get_usage(true) / 1024 / 1024, 1);
$memoryLimit = ini_get('memory_limit');

// Status aller Upkeep-Module
$ipsActive = IntrusionPrevention::isActive();
$rateLimitActive = IntrusionPrevention::isRateLimitingEnabled();
$frontendMaintenanceActive = $addon->getConfig('frontend_active', false);
$backendMaintenanceActive = $addon->getConfig('backend_active', false);
$domainRedirectsActive = $addon->getConfig('domain_mapping_enabled', false);

// Redirect-Statistiken
$sql = rex_sql::factory();
$sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_domain_mapping') . " WHERE status = 1");
$activeRedirects = (int) $sql->getValue('count');

// Wartungsmodus IP-Zählungen
$allowedIps = $addon->getConfig('allowed_ips', '');
$allowedIpCount = !empty(trim($allowedIps)) ? count(array_filter(explode("\n", $allowedIps))) : 0;

// Aktuelle Uhrzeit für Auto-Refresh
$currentTime = date('H:i:s');

// Dashboard Assets einbinden
rex_view::addCssFile($addon->getAssetsUrl('dashboard.css'));
rex_view::addJsFile($addon->getAssetsUrl('dashboard.js'));

?>

<div id="upkeep-dashboard" class="upkeep-dashboard">
    <!-- Header mit Live-Status -->
    <div class="panel panel-default dashboard-header">
        <div class="panel-body">
            <div class="row">
                <div class="col-md-8">
                    <h1 class="dashboard-title">
                        <i class="rex-icon fa-dashboard"></i> 
                        Upkeep Dashboard
                        <small class="text-muted">Live System Monitor</small>
                    </h1>
                </div>
                <div class="col-md-4 text-right">
                    <div class="dashboard-controls">
                        <span class="live-time" id="live-time"><?= $currentTime ?></span>
                        <button class="btn btn-xs btn-success" id="auto-refresh" data-toggle="tooltip" title="Auto-Refresh (30s)">
                            <i class="rex-icon fa-refresh"></i> Live
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- System Status Cards -->
    <div class="row dashboard-cards">
        <!-- IPS Status -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-<?= $ipsActive ? 'success' : 'warning' ?> status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-shield-alt"></i>
                    </div>
                    <div class="status-content">
                        <h3>IPS</h3>
                        <p class="status-text"><?= $ipsActive ? 'Aktiv' : 'Inaktiv' ?></p>
                        <div class="status-indicator <?= $ipsActive ? 'active' : 'inactive' ?>"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Frontend Wartung -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-<?= $frontendMaintenanceActive ? 'warning' : 'success' ?> status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-globe"></i>
                    </div>
                    <div class="status-content">
                        <h3>Frontend</h3>
                        <p class="status-text"><?= $frontendMaintenanceActive ? 'Wartung' : 'Online' ?></p>
                        <div class="status-indicator <?= $frontendMaintenanceActive ? 'maintenance' : 'active' ?>"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Backend Wartung -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-<?= $backendMaintenanceActive ? 'warning' : 'success' ?> status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-users"></i>
                    </div>
                    <div class="status-content">
                        <h3>Backend</h3>
                        <p class="status-text"><?= $backendMaintenanceActive ? 'Wartung' : 'Online' ?></p>
                        <div class="status-indicator <?= $backendMaintenanceActive ? 'maintenance' : 'active' ?>"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Domain Redirects -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-<?= $domainRedirectsActive ? 'info' : 'default' ?> status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-share"></i>
                    </div>
                    <div class="status-content">
                        <h3><?= $activeRedirects ?></h3>
                        <p class="status-text">Redirects</p>
                        <div class="status-indicator <?= $domainRedirectsActive ? 'active' : 'inactive' ?>"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Security Status Cards -->
    <div class="row dashboard-cards">
        <!-- Gesperrte IPs -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-danger status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-ban"></i>
                    </div>
                    <div class="status-content">
                        <h3 id="blocked-ips-count"><?= $stats['blocked_ips'] ?></h3>
                        <p class="status-text">Gesperrte IPs</p>
                        <small class="text-muted">Aktive Sperren</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Bedrohungen Heute -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-warning status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-exclamation-triangle"></i>
                    </div>
                    <div class="status-content">
                        <h3 id="threats-today-count"><?= $stats['threats_today'] ?></h3>
                        <p class="status-text">Bedrohungen</p>
                        <small class="text-muted">Heute</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- Erlaubte IPs -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-success status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-check-circle"></i>
                    </div>
                    <div class="status-content">
                        <h3 id="allowed-ips-count"><?= $allowedIpCount ?></h3>
                        <p class="status-text">Erlaubte IPs</p>
                        <small class="text-muted">Wartungsmodus</small>
                    </div>
                </div>
            </div>
        </div>

        <!-- System Performance -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-info status-card">
                <div class="panel-body">
                    <div class="status-icon">
                        <i class="rex-icon fa-tachometer"></i>
                    </div>
                    <div class="status-content">
                        <h3><?= $memoryUsage ?>MB</h3>
                        <p class="status-text">RAM Nutzung</p>
                        <small class="text-muted">von <?= $memoryLimit ?></small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Status-Übersicht mit Hinweisen -->
    <div class="row">
        <div class="col-md-12">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-info-circle"></i> 
                        System-Status & Hinweise
                    </h3>
                </div>
                <div class="panel-body">
                    <div class="row">
                        <!-- Wartungsmodus Hinweise -->
                        <div class="col-md-6">
                            <?php if ($frontendMaintenanceActive || $backendMaintenanceActive): ?>
                            <div class="alert alert-warning">
                                <i class="rex-icon fa-wrench"></i>
                                <strong>Wartungsmodus aktiv:</strong><br>
                                <?php if ($frontendMaintenanceActive): ?>
                                • Frontend ist für Besucher gesperrt<br>
                                <?php endif; ?>
                                <?php if ($backendMaintenanceActive): ?>
                                • Backend ist nur für Admins zugänglich<br>
                                <?php endif; ?>
                                <?php if ($allowedIpCount > 0): ?>
                                • <?= $allowedIpCount ?> IP<?= $allowedIpCount > 1 ? 's' : '' ?> haben weiterhin Zugriff
                                <?php endif; ?>
                            </div>
                            <?php else: ?>
                            <div class="alert alert-success">
                                <i class="rex-icon fa-check-circle"></i>
                                <strong>System läuft normal:</strong><br>
                                • Frontend ist öffentlich zugänglich<br>
                                • Backend ist für alle Benutzer verfügbar
                            </div>
                            <?php endif; ?>
                        </div>

                        <!-- Sicherheits-Hinweise -->
                        <div class="col-md-6">
                            <?php if ($ipsActive): ?>
                            <div class="alert alert-info">
                                <i class="rex-icon fa-shield"></i>
                                <strong>Sicherheit aktiv:</strong><br>
                                • Intrusion Prevention System läuft<br>
                                <?php if ($rateLimitActive): ?>
                                • Rate-Limiting ist aktiviert<br>
                                <?php endif; ?>
                                <?php if ($stats['blocked_ips'] > 0): ?>
                                • <?= $stats['blocked_ips'] ?> IP<?= $stats['blocked_ips'] > 1 ? 's' : '' ?> aktuell gesperrt
                                <?php endif; ?>
                            </div>
                            <?php else: ?>
                            <div class="alert alert-danger">
                                <i class="rex-icon fa-exclamation-triangle"></i>
                                <strong>Sicherheitswarnung:</strong><br>
                                • IPS ist deaktiviert!<br>
                                • Website ist ungeschützt vor Angriffen<br>
                                • Sofortige Aktivierung empfohlen
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Domain-Redirects Info -->
                    <?php if ($domainRedirectsActive && $activeRedirects > 0): ?>
                    <div class="row">
                        <div class="col-md-12">
                            <div class="alert alert-info">
                                <i class="rex-icon fa-share"></i>
                                <strong>Domain-Redirects:</strong>
                                <?= $activeRedirects ?> aktive Weiterleitung<?= $activeRedirects > 1 ? 'en' : '' ?> 
                                - <a href="<?= rex_url::backendPage('upkeep/domains') ?>" class="alert-link">Verwalten</a>
                                | <a href="<?= rex_url::backendPage('upkeep/domain_mapping') ?>" class="alert-link">URL-Redirects</a>
                            </div>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Charts und Aktivitäten -->
    <div class="row">
        <!-- Bedrohungs-Trends -->
        <div class="col-md-8">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-line-chart"></i> 
                        Sicherheits-Aktivitäten (7 Tage)
                    </h3>
                </div>
                <div class="panel-body">
                    <div id="threat-chart" class="chart-container">
                        <canvas id="threatChart" height="300"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Top Bedrohungen -->
        <div class="col-md-4">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-list"></i> 
                        Top Bedrohungstypen
                    </h3>
                </div>
                <div class="panel-body">
                    <div class="threat-list">
                        <?php if (!empty($stats['top_threats'])): ?>
                            <?php foreach ($stats['top_threats'] as $threat): ?>
                            <div class="threat-item">
                                <div class="threat-name"><?= rex_escape($threat['type']) ?></div>
                                <div class="threat-count">
                                    <span class="badge"><?= $threat['count'] ?></span>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <p class="text-muted">
                                <i class="rex-icon fa-check-circle"></i> 
                                Keine Bedrohungen diese Woche
                            </p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Letzte Aktivitäten -->
    <div class="row">
        <div class="col-md-12">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-clock-o"></i> 
                        Letzte Sicherheitsereignisse
                        <div class="pull-right">
                            <button class="btn btn-xs btn-default" id="refresh-activities">
                                <i class="rex-icon fa-refresh"></i> Aktualisieren
                            </button>
                        </div>
                    </h3>
                </div>
                <div class="panel-body">
                    <div id="recent-activities" class="activity-feed">
                        <!-- Wird via AJAX geladen -->
                        <div class="text-center">
                            <i class="rex-icon fa-spinner fa-spin"></i> Lade Aktivitäten...
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="row">
        <div class="col-md-12">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-flash"></i> 
                        Quick Actions
                    </h3>
                </div>
                <div class="panel-body">
                    <div class="btn-toolbar" role="toolbar">
                        <div class="btn-group" role="group">
                            <a href="<?= rex_url::backendPage('upkeep/ips/threats') ?>" class="btn btn-primary">
                                <i class="rex-icon fa-list"></i> Bedrohungsliste
                            </a>
                            <a href="<?= rex_url::backendPage('upkeep/ips/blocked') ?>" class="btn btn-danger">
                                <i class="rex-icon fa-ban"></i> Gesperrte IPs
                            </a>
                            <a href="<?= rex_url::backendPage('upkeep/ips/positivliste') ?>" class="btn btn-success">
                                <i class="rex-icon fa-check"></i> Positivliste
                            </a>
                        </div>
                        <div class="btn-group" role="group">
                            <a href="<?= rex_url::backendPage('upkeep/ips/patterns') ?>" class="btn btn-info">
                                <i class="rex-icon fa-code"></i> Patterns
                            </a>
                            <a href="<?= rex_url::backendPage('upkeep/frontend') ?>" class="btn btn-default">
                                <i class="rex-icon fa-globe"></i> Frontend
                            </a>
                            <a href="<?= rex_url::backendPage('upkeep/backend') ?>" class="btn btn-default">
                                <i class="rex-icon fa-users"></i> Backend
                            </a>
                            <a href="<?= rex_url::backendPage('upkeep/domains') ?>" class="btn btn-default">
                                <i class="rex-icon fa-share"></i> Domains
                            </a>
                            </a>
                        </div>
                        <div class="btn-group" role="group">
                            <a href="<?= rex_url::backendPage('upkeep/domains') ?>" class="btn btn-default">
                                <i class="rex-icon fa-sitemap"></i> Domains
                            </a>
                            <a href="<?= rex_url::backendPage('upkeep/domain_mapping') ?>" class="btn btn-default">
                                <i class="rex-icon fa-share"></i> Redirects
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Dashboard JavaScript wird über rex_view::addJsFile geladen -->
<script>
// Dashboard-spezifische Konfiguration
if (typeof UpkeepDashboard !== 'undefined') {
    // Weitere Konfiguration hier falls nötig
    console.log('Upkeep Dashboard initialisiert');
}
</script>
