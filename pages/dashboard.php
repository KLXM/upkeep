<?php
/**
 * Interaktives Dashboard für das Upkeep AddOn
 */

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Live-Statistiken abrufen
try {
    $stats = IntrusionPrevention::getStatistics();
} catch (Exception $e) {
    // Fallback wenn Tabellen noch nicht existieren
    $stats = [
        'blocked_ips' => 0,
        'threats_today' => 0,
        'threats_week' => 0,
        'top_threats' => []
    ];
}

// System-Info
$phpVersion = PHP_VERSION;
$rexVersion = rex::getVersion();
$memoryUsage = round(memory_get_usage(true) / 1024 / 1024, 1);
$memoryLimit = ini_get('memory_limit');

// Status aller Upkeep-Module
$ipsActive = IntrusionPrevention::isActive();
$rateLimitActive = IntrusionPrevention::isRateLimitingEnabled();
$monitorOnlyActive = $addon->getConfig('ips_monitor_only', false);
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

// Sicherheitsbedrohungen nach Typ der letzten 7 Tage abrufen
function getSecurityThreatsByType() {
    try {
        $sql = rex_sql::factory();
        $sql->setQuery("
            SELECT 
                threat_type,
                severity,
                COUNT(*) as count,
                SUM(CASE WHEN action_taken IN ('permanent_block', 'temporary_block') THEN 1 ELSE 0 END) as blocked_count,
                MAX(created_at) as last_occurrence
            FROM " . rex::getTable('upkeep_ips_threat_log') . " 
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY threat_type, severity
            ORDER BY count DESC, severity DESC
        ");
        
        $threatTypes = [];
        while ($sql->hasNext()) {
            $threatTypes[] = [
                'threat_type' => $sql->getValue('threat_type'),
                'severity' => $sql->getValue('severity'),
                'count' => (int) $sql->getValue('count'),
                'blocked_count' => (int) $sql->getValue('blocked_count'),
                'last_occurrence' => $sql->getValue('last_occurrence')
            ];
            $sql->next();
        }
        return $threatTypes;
    } catch (Exception $e) {
        // Debug: Log the error
        if (rex_addon::get('upkeep')->getConfig('ips_debug_mode', false)) {
            rex_logger::factory()->log('error', 'Dashboard getSecurityThreatsByType failed: ' . $e->getMessage());
        }
        return [];
    }
}

// Heute gesperrte IPs nach Ländern abrufen
function getThreatsByCountry() {
    try {
        // Prüfe ob GeoIP verfügbar ist
        if (!class_exists('KLXM\Upkeep\GeoIP')) {
            rex_logger::factory()->log('debug', 'Dashboard: GeoIP-Klasse nicht verfügbar');
            return [];
        }
        
        // Hole alle gesperrten IPs (aktive Sperrungen)
        $sql = rex_sql::factory();
        rex_logger::factory()->log('debug', 'Dashboard: Suche nach allen aktiven gesperrten IPs');
        
        $sql->setQuery('
            SELECT DISTINCT ip_address 
            FROM ' . rex::getTable('upkeep_ips_blocked_ips') . '
            ORDER BY ip_address
        ');
        
        $results = $sql->getArray();
        rex_logger::factory()->log('debug', 'Dashboard: Gefundene gesperrte IPs: ' . count($results));
        
        if (empty($results)) {
            // Prüfe ob überhaupt Einträge in der Tabelle sind
            $sql->setQuery('SELECT COUNT(*) as total FROM ' . rex::getTable('upkeep_ips_blocked_ips'));
            $total = $sql->getValue('total');
            rex_logger::factory()->log('debug', 'Dashboard: Gesamt Einträge in blocked_ips Tabelle: ' . $total);
            return [];
        }
        
        $countries = [];
        
        foreach ($results as $result) {
            $ip = $result['ip_address'];
            rex_logger::factory()->log('debug', 'Dashboard: Verarbeite IP: ' . $ip);
            
            $country = \KLXM\Upkeep\IntrusionPrevention::getCountryByIp($ip);
            $countryCode = $country['code'];
            rex_logger::factory()->log('debug', 'Dashboard: Land für IP ' . $ip . ': ' . $country['name'] . ' (' . $countryCode . ')');
            
            if (!isset($countries[$countryCode])) {
                $countries[$countryCode] = [
                    'code' => $countryCode,
                    'name' => $country['name'],
                    'blocked_count' => 0,
                    'unique_ips' => 0,
                    'last_blocked' => null,
                    'ips' => []
                ];
            }
            
            $countries[$countryCode]['blocked_count']++;
            $countries[$countryCode]['unique_ips']++;
            $countries[$countryCode]['ips'][] = $ip;
        }
        
        // Sortiere nach Anzahl gesperrter IPs
        uasort($countries, function($a, $b) {
            return $b['blocked_count'] <=> $a['blocked_count'];
        });
        
        rex_logger::factory()->log('debug', 'Dashboard: Anzahl Länder gefunden: ' . count($countries));
        
        return array_values($countries);
    } catch (\Exception $e) {
        rex_logger::factory()->log('error', 'Dashboard getThreatsByCountry failed: ' . $e->getMessage(), []);
        return [];
    }
}

$threatsByType = getSecurityThreatsByType();
$threatsByCountry = getThreatsByCountry();

// Dashboard Assets einbinden
rex_view::addCssFile($addon->getAssetsUrl('dashboard.css'));
rex_view::addJsFile($addon->getAssetsUrl('dashboard.js'));

?>

<div id="upkeep-dashboard" class="upkeep-dashboard">
    <!-- Header -->
    <div class="panel panel-default dashboard-header">
        <div class="panel-body">
            <div class="row">
                <div class="col-md-12">
                    <h1 class="dashboard-title">
                        <i class="rex-icon fa-dashboard"></i> 
                        Upkeep Dashboard
                        <small class="text-muted">System Monitor</small>
                    </h1>
                </div>
            </div>
        </div>
    </div>

    <!-- System Status Cards -->
    <div class="row dashboard-cards">
        <!-- IPS Status -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/ips') ?>" class="status-card-link">
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
            </a>
        </div>

        <!-- Frontend Wartung -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/frontend') ?>" class="status-card-link">
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
            </a>
        </div>

        <!-- Backend Wartung -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/backend') ?>" class="status-card-link">
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
            </a>
        </div>

        <!-- Domain Redirects -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/domains') ?>" class="status-card-link">
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
            </a>
        </div>
    </div>

    <!-- Security Status Cards -->
    <div class="row dashboard-cards">
        <!-- Gesperrte IPs -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/ips/blocked') ?>" class="status-card-link">
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
            </a>
        </div>

        <!-- Bedrohungen Heute -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/ips/threats') ?>" class="status-card-link">
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
            </a>
        </div>

        <!-- Erlaubte IPs -->
        <div class="col-md-3 col-sm-6">
            <a href="<?= rex_url::backendPage('upkeep/ips/positivliste') ?>" class="status-card-link">
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
            </a>
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
                                <?php if ($monitorOnlyActive): ?>
                                • <span class="label label-warning">Monitor-Only Modus</span> - Nur Logging, kein Blocking<br>
                                <?php endif; ?>
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

    <!-- Sicherheits-Bedrohungstypen -->
    <div class="row">
        <!-- Bedrohungstypen-Statistik -->
        <div class="col-md-8">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-shield"></i> 
                        Sicherheits-Bedrohungen nach Typ (7 Tage)
                        <small class="pull-right text-muted"><?= count($threatsByType) ?> Typen</small>
                    </h3>
                </div>
                <div class="panel-body">
                    <?php 
                    // Debug: Zeige Anzahl gefundener Bedrohungstypen
                    if ($addon->getConfig('ips_debug_mode', false) && count($threatsByType) === 0): 
                        echo '<div class="alert alert-info"><strong>Debug:</strong> Keine Bedrohungstypen gefunden. Stats zeigen aber ' . $stats['threats_today'] . ' Bedrohungen heute.</div>';
                    endif;
                    ?>
                    <?php if (!empty($threatsByType)): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th>Bedrohungstyp</th>
                                        <th class="text-center">Severity</th>
                                        <th class="text-center">Erkannt</th>
                                        <th class="text-center">Gesperrt</th>
                                        <th class="text-center">Letzter Vorfall</th>
                                        <th class="text-center">Aktionen</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($threatsByType as $threat): ?>
                                        <tr>
                                            <td>
                                                <strong><?= rex_escape($threat['threat_type']) ?></strong>
                                            </td>
                                            <td class="text-center">
                                                <span class="label label-<?= $threat['severity'] === 'critical' ? 'danger' : ($threat['severity'] === 'high' ? 'warning' : ($threat['severity'] === 'medium' ? 'info' : 'default')) ?>">
                                                    <?= rex_escape(ucfirst($threat['severity'])) ?>
                                                </span>
                                            </td>
                                            <td class="text-center">
                                                <span class="badge badge-warning"><?= $threat['count'] ?></span>
                                            </td>
                                            <td class="text-center">
                                                <?php if ($threat['blocked_count'] > 0): ?>
                                                    <span class="badge badge-danger"><?= $threat['blocked_count'] ?></span>
                                                <?php else: ?>
                                                    <span class="text-muted">0</span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="text-center">
                                                <small class="text-muted">
                                                    <?= date('d.m H:i', strtotime($threat['last_occurrence'])) ?>
                                                </small>
                                            </td>
                                            <td class="text-center">
                                                <a href="<?= rex_url::backendPage('upkeep/ips/threats', ['threat_type' => $threat['threat_type']]) ?>" 
                                                   class="btn btn-xs btn-info" title="Details anzeigen">
                                                    <i class="rex-icon fa-search"></i>
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <div class="text-center" style="margin-top: 15px;">
                            <a href="<?= rex_url::backendPage('upkeep/ips/threats') ?>" class="btn btn-default">
                                <i class="rex-icon fa-list"></i> Detaillierte Bedrohungsliste
                            </a>
                        </div>
                    <?php else: ?>
                        <div class="text-center text-muted" style="padding: 40px;">
                            <i class="rex-icon fa-check-circle" style="font-size: 48px; color: #5cb85c;"></i>
                            <h4>Keine Sicherheitsereignisse</h4>
                            <p>In den letzten 7 Tagen wurden keine Bedrohungen erkannt.</p>
                        </div>
                    <?php endif; ?>
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

    <!-- Bedrohungen nach Ländern -->
    <div class="row dashboard-section">
        <div class="col-md-12">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">
                        <i class="rex-icon fa-globe"></i> 
                        Gesperrte IPs nach Ländern
                        <?php if (!empty($threatsByCountry)): ?>
                            <small class="text-muted"><?= count($threatsByCountry) ?> Länder</small>
                        <?php endif; ?>
                    </h3>
                </div>
                <div class="panel-body">
                    <?php if (!empty($threatsByCountry)): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover dashboard-table">
                                <thead>
                                    <tr>
                                        <th><i class="rex-icon fa-flag"></i> Land</th>
                                        <th class="text-center"><i class="rex-icon fa-ban"></i> Sperrungen</th>
                                        <th class="text-center"><i class="rex-icon fa-globe"></i> IPs</th>
                                        <th class="text-center"><i class="rex-icon fa-clock-o"></i> Letzte Sperrung</th>
                                        <th class="text-center"><i class="rex-icon fa-cog"></i> Aktionen</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach (array_slice($threatsByCountry, 0, 10) as $country): ?>
                                        <tr>
                                            <td>
                                                <strong><?= rex_escape($country['name']) ?></strong>
                                                <small class="text-muted">(<?= rex_escape($country['code']) ?>)</small>
                                            </td>
                                            <td class="text-center">
                                                <span class="badge badge-warning"><?= $country['blocked_count'] ?></span>
                                            </td>
                                            <td class="text-center">
                                                <span class="badge badge-info"><?= $country['unique_ips'] ?></span>
                                            </td>
                                            <td class="text-center">
                                                <?php if ($country['last_blocked']): ?>
                                                    <small class="text-muted">
                                                        <?= date('d.m H:i', strtotime($country['last_blocked'])) ?>
                                                    </small>
                                                <?php else: ?>
                                                    <small class="text-muted">-</small>
                                                <?php endif; ?>
                                            </td>
                                            <td class="text-center">
                                                <a href="<?= rex_url::backendPage('upkeep/ips/blocked', ['country' => $country['code']]) ?>" 
                                                   class="btn btn-xs btn-info" title="Gesperrte IPs anzeigen">
                                                    <i class="rex-icon fa-search"></i>
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php if (count($threatsByCountry) > 10): ?>
                            <div class="text-center" style="margin-top: 15px;">
                                <a href="<?= rex_url::backendPage('upkeep/ips/blocked', ['view' => 'countries']) ?>" class="btn btn-default">
                                    <i class="rex-icon fa-globe"></i> Alle <?= count($threatsByCountry) ?> Länder anzeigen
                                </a>
                            </div>
                        <?php endif; ?>
                    <?php else: ?>
                        <div class="text-center text-muted" style="padding: 40px;">
                            <i class="rex-icon fa-check-circle" style="font-size: 48px; color: #5cb85c;"></i>
                            <h4>Keine gesperrten IPs</h4>
                            <p>Aktuell sind keine IPs gesperrt oder die GeoIP-Datenbank ist nicht verfügbar.</p>
                            <?php if (class_exists('KLXM\Upkeep\GeoIP')): ?>
                                <?php $geoStatus = KLXM\Upkeep\IntrusionPrevention::getGeoDatabaseStatus(); ?>
                                <?php if (!$geoStatus['available']): ?>
                                    <a href="<?= rex_url::backendPage('upkeep/ips/settings', ['action' => 'update_geo']) ?>" class="btn btn-sm btn-primary">
                                        <i class="rex-icon fa-download"></i> GeoIP-Datenbank installieren
                                    </a>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
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
