<?php
/**
 * Interaktives Dashboard für das Upkeep AddOn
 */

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');
$user = rex::getUser();

// Sicherheits-Check für User
if (!$user) {
            echo rex_view::error($addon->i18n('upkeep_dashboard_no_user'));
    return;
}

// Handle Toggle Requests
if (rex_post('toggle_action', 'string')) {
    $action = rex_post('toggle_action', 'string');
    $user = rex::getUser();
    $success = false;
    $message = '';
    
    switch ($action) {
        case 'toggle_frontend':
            if ($user->hasPerm('upkeep[frontend]') || $user->isAdmin()) {
                $current = $addon->getConfig('frontend_active', false);
                $addon->setConfig('frontend_active', !$current);
                $success = true;
                $message = $addon->i18n('upkeep_dashboard_frontend_maintenance_toggled', $addon->i18n(!$current ? 'upkeep_dashboard_activated' : 'upkeep_dashboard_deactivated'));
            }
            break;
            
        case 'toggle_backend':
            if ($user->isAdmin()) {
                $current = $addon->getConfig('backend_active', false);
                $addon->setConfig('backend_active', !$current);
                $success = true;
                $message = $addon->i18n('upkeep_dashboard_backend_maintenance_toggled', $addon->i18n(!$current ? 'upkeep_dashboard_activated' : 'upkeep_dashboard_deactivated'));
            }
            break;
            
        case 'toggle_domain_mapping':
            if ($user->hasPerm('upkeep[domain_mapping]') || $user->isAdmin()) {
                $current = $addon->getConfig('domain_mapping_active', false);
                $addon->setConfig('domain_mapping_active', !$current);
                $success = true;
                $message = $addon->i18n('upkeep_dashboard_domain_redirects_toggled', $addon->i18n(!$current ? 'upkeep_dashboard_activated' : 'upkeep_dashboard_deactivated'));
            }
            break;
    }
    
    if ($success) {
        rex_delete_cache();
        echo rex_view::success($message);
    } else {
        echo rex_view::error($addon->i18n('upkeep_dashboard_no_permission'));
    }
}

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
$domainMappingSystemActive = $addon->getConfig('domain_mapping_active', false);

// Domain-Mapping Statistiken
$sql = rex_sql::factory();
$sql->setQuery("SELECT COUNT(*) as total_count FROM " . rex::getTable('upkeep_domain_mapping'));
$totalRedirects = (int) $sql->getValue('total_count');

$sql->setQuery("SELECT COUNT(*) as active_count FROM " . rex::getTable('upkeep_domain_mapping') . " WHERE status = 1");
$activeRedirects = (int) $sql->getValue('active_count');

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
        
        $sql->setQuery('
            SELECT DISTINCT ip_address 
            FROM ' . rex::getTable('upkeep_ips_blocked_ips') . '
            ORDER BY ip_address
        ');
        
        $results = $sql->getArray();
        
        if (empty($results)) {
            // Prüfe ob überhaupt Einträge in der Tabelle sind
            $sql->setQuery('SELECT COUNT(*) as total FROM ' . rex::getTable('upkeep_ips_blocked_ips'));
            $total = $sql->getValue('total');
            return [];
        }
        
        $countries = [];
        
        foreach ($results as $result) {
            $ip = $result['ip_address'];
            
            
            $country = \KLXM\Upkeep\IntrusionPrevention::getCountryByIp($ip);
            $countryCode = $country['code'];
            
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
            <div class="panel panel-<?= $frontendMaintenanceActive ? 'warning' : 'success' ?> status-card">
                <div class="panel-body">
                    <?php if ($user->hasPerm('upkeep[frontend]') || $user->isAdmin()): ?>
                    <form method="post" style="position:absolute; top:10px; right:10px;">
                        <input type="hidden" name="toggle_action" value="toggle_frontend">
                        <button type="submit" class="btn btn-xs <?= $frontendMaintenanceActive ? 'btn-success' : 'btn-warning' ?>" title="<?= $frontendMaintenanceActive ? $addon->i18n('upkeep_dashboard_frontend_activate') : $addon->i18n('upkeep_dashboard_frontend_maintenance') ?>">
                            <i class="rex-icon fa-<?= $frontendMaintenanceActive ? 'play' : 'pause' ?>"></i>
                        </button>
                    </form>
                    <?php endif; ?>
                    
                    <a href="<?= rex_url::backendPage('upkeep/maintenance') ?>" class="status-card-content-link">
                        <div class="status-icon">
                            <i class="rex-icon fa-globe"></i>
                        </div>
                        <div class="status-content">
                            <h3>Frontend</h3>
                            <p class="status-text"><?= $frontendMaintenanceActive ? $addon->i18n('upkeep_dashboard_maintenance') : $addon->i18n('upkeep_dashboard_online') ?></p>
                            <div class="status-indicator <?= $frontendMaintenanceActive ? 'maintenance' : 'active' ?>"></div>
                        </div>
                    </a>
                </div>
            </div>
        </div>

        <!-- Backend Wartung -->
        <div class="col-md-3 col-sm-6">
            <div class="panel panel-<?= $backendMaintenanceActive ? 'warning' : 'success' ?> status-card">
                <div class="panel-body">
                    <?php if ($user->isAdmin()): ?>
                    <form method="post" style="position:absolute; top:10px; right:10px;">
                        <input type="hidden" name="toggle_action" value="toggle_backend">
                        <button type="submit" class="btn btn-xs <?= $backendMaintenanceActive ? 'btn-success' : 'btn-warning' ?>" title="<?= $backendMaintenanceActive ? $addon->i18n('upkeep_dashboard_backend_activate') : $addon->i18n('upkeep_dashboard_backend_maintenance') ?>">
                            <i class="rex-icon fa-<?= $backendMaintenanceActive ? 'play' : 'pause' ?>"></i>
                        </button>
                    </form>
                    <?php endif; ?>
                    
                    <a href="<?= rex_url::backendPage('upkeep/maintenance') ?>" class="status-card-content-link">
                        <div class="status-icon">
                            <i class="rex-icon fa-users"></i>
                        </div>
                        <div class="status-content">
                            <h3>Backend</h3>
                            <p class="status-text"><?= $backendMaintenanceActive ? $addon->i18n('upkeep_dashboard_maintenance') : $addon->i18n('upkeep_dashboard_online') ?></p>
                            <div class="status-indicator <?= $backendMaintenanceActive ? 'maintenance' : 'active' ?>"></div>
                        </div>
                    </a>
                </div>
            </div>
        </div>

        <!-- Domain Redirects -->
        <div class="col-md-3 col-sm-6">
            <?php
            // Bestimme Status-Farbe und Text basierend auf System-Status und Redirect-Anzahl
            if (!$domainMappingSystemActive) {
                $panelClass = 'default';
                $statusText = $addon->i18n('upkeep_dashboard_system_inactive');
                $statusIndicator = 'inactive';
            } elseif ($totalRedirects == 0) {
                $panelClass = 'warning';
                $statusText = $addon->i18n('upkeep_dashboard_no_redirects');
                $statusIndicator = 'warning';
            } elseif ($activeRedirects == 0) {
                $panelClass = 'warning';
                $statusText = $addon->i18n('upkeep_dashboard_all_disabled');
                $statusIndicator = 'warning';
            } elseif ($activeRedirects < $totalRedirects) {
                $panelClass = 'info';
                $statusText = $activeRedirects . ' ' . $addon->i18n('upkeep_dashboard_of') . ' ' . $totalRedirects . ' ' . $addon->i18n('upkeep_dashboard_active');
                $statusIndicator = 'partial';
            } else {
                $panelClass = 'success';
                $statusText = $addon->i18n('upkeep_dashboard_all_active');
                $statusIndicator = 'active';
            }
            ?>
            <div class="panel panel-<?= $panelClass ?> status-card">
                <div class="panel-body">
                    <?php if ($user->hasPerm('upkeep[domain_mapping]') || $user->isAdmin()): ?>
                    <form method="post" style="position:absolute; top:10px; right:10px;">
                        <input type="hidden" name="toggle_action" value="toggle_domain_mapping">
                        <button type="submit" class="btn btn-xs <?= $domainMappingSystemActive ? 'btn-warning' : 'btn-success' ?>" title="<?= $domainMappingSystemActive ? $addon->i18n('upkeep_dashboard_domain_mapping_deactivate') : $addon->i18n('upkeep_dashboard_domain_mapping_activate') ?>">
                            <i class="rex-icon fa-<?= $domainMappingSystemActive ? 'pause' : 'play' ?>"></i>
                        </button>
                    </form>
                    <?php endif; ?>
                    
                    <a href="<?= rex_url::backendPage('upkeep/domains') ?>" class="status-card-content-link">
                        <div class="status-icon">
                            <i class="rex-icon fa-share"></i>
                        </div>
                        <div class="status-content">
                            <h3><?= $totalRedirects ?></h3>
                            <p class="status-text"><?= $statusText ?></p>
                            <div class="status-indicator <?= $statusIndicator ?>"></div>
                        </div>
                    </a>
                </div>
            </div>
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
                            <p class="status-text"><?= $addon->i18n('upkeep_dashboard_blocked_ips') ?></p>
                            <small class="text-muted"><?= $addon->i18n('upkeep_dashboard_active_blocks') ?></small>
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
                            <p class="status-text"><?= $addon->i18n('upkeep_dashboard_threats') ?></p>
                            <small class="text-muted"><?= $addon->i18n('upkeep_dashboard_today') ?></small>
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
                            <p class="status-text"><?= $addon->i18n('upkeep_dashboard_allowed_ips_title') ?></p>
                            <small class="text-muted"><?= $addon->i18n('upkeep_dashboard_maintenance_mode') ?></small>
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
                        <p class="status-text"><?= $addon->i18n('upkeep_dashboard_ram_usage') ?></p>
                        <small class="text-muted"><?= $addon->i18n('upkeep_dashboard_of') ?> <?= $memoryLimit ?></small>
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
                        <?= $addon->i18n('upkeep_dashboard_system_status') ?>
                    </h3>
                </div>
                <div class="panel-body">
                    <div class="row">
                        <!-- Wartungsmodus Hinweise -->
                        <div class="col-md-6">
                            <?php if ($frontendMaintenanceActive || $backendMaintenanceActive): ?>
                            <div class="alert alert-warning">
                                <i class="rex-icon fa-wrench"></i>
                                <strong><?= $addon->i18n('upkeep_dashboard_maintenance_active') ?>:</strong><br>
                                <?php if ($frontendMaintenanceActive): ?>
                                • <?= $addon->i18n('upkeep_dashboard_frontend_blocked') ?><br>
                                <?php endif; ?>
                                <?php if ($backendMaintenanceActive): ?>
                                • <?= $addon->i18n('upkeep_dashboard_backend_admin_only') ?><br>
                                <?php endif; ?>
                                <?php if ($allowedIpCount > 0): ?>
                                • <?= $addon->i18n('upkeep_dashboard_allowed_ips', $allowedIpCount, $allowedIpCount > 1 ? 's' : '') ?>
                                <?php endif; ?>
                            </div>
                            <?php else: ?>
                            <div class="alert alert-success">
                                <i class="rex-icon fa-check-circle"></i>
                                <strong><?= $addon->i18n('upkeep_dashboard_system_normal') ?>:</strong><br>
                                • <?= $addon->i18n('upkeep_dashboard_frontend_public') ?><br>
                                • <?= $addon->i18n('upkeep_dashboard_backend_available') ?>
                            </div>
                            <?php endif; ?>
                        </div>

                        <!-- Sicherheits-Hinweise -->
                        <div class="col-md-6">
                            <?php if ($ipsActive): ?>
                            <div class="alert alert-info">
                                <i class="rex-icon fa-shield"></i>
                                <strong><?= $addon->i18n('upkeep_dashboard_security_active') ?>:</strong><br>
                                • <?= $addon->i18n('upkeep_dashboard_ips_running') ?><br>
                                <?php if ($monitorOnlyActive): ?>
                                • <span class="label label-warning"><?= $addon->i18n('upkeep_dashboard_monitor_only') ?></span><br>
                                <?php endif; ?>
                                <?php if ($rateLimitActive): ?>
                                • <?= $addon->i18n('upkeep_dashboard_rate_limiting') ?><br>
                                <?php endif; ?>
                                <?php if ($stats['blocked_ips'] > 0): ?>
                                • <?= $addon->i18n('upkeep_dashboard_ips_blocked', $stats['blocked_ips'], $stats['blocked_ips'] > 1 ? 's' : '') ?>
                                <?php endif; ?>
                            </div>
                            <?php else: ?>
                            <div class="alert alert-danger">
                                <i class="rex-icon fa-exclamation-triangle"></i>
                                <strong><?= $addon->i18n('upkeep_dashboard_security_warning') ?>:</strong><br>
                                • <?= $addon->i18n('upkeep_dashboard_ips_deactivated') ?><br>
                                • <?= $addon->i18n('upkeep_dashboard_website_unprotected') ?><br>
                                • <?= $addon->i18n('upkeep_dashboard_activation_recommended') ?>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Domain-Redirects Info -->
                    <?php if ($domainMappingSystemActive && $activeRedirects > 0): ?>
                    <div class="row">
                        <div class="col-md-12">
                            <div class="alert alert-info">
                                <i class="rex-icon fa-share"></i>
                                <strong><?= $addon->i18n('upkeep_dashboard_domain_redirects') ?>:</strong>
                                <?= $addon->i18n('upkeep_dashboard_active_redirects', $activeRedirects, $activeRedirects > 1 ? 'en' : '') ?> 
                                - <a href="<?= rex_url::backendPage('upkeep/domains') ?>" class="alert-link"><?= $addon->i18n('upkeep_dashboard_manage') ?></a>
                                | <a href="<?= rex_url::backendPage('upkeep/domain_mapping') ?>" class="alert-link"><?= $addon->i18n('upkeep_dashboard_url_redirects') ?></a>
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
                        <?= $addon->i18n('upkeep_dashboard_security_threats_title') ?>
                        <small class="pull-right text-muted"><?= $addon->i18n('upkeep_dashboard_types_count', count($threatsByType)) ?></small>
                    </h3>
                </div>
                <div class="panel-body">
                    <?php 
                    // Debug: Zeige Anzahl gefundener Bedrohungstypen
                    if ($addon->getConfig('ips_debug_mode', false) && count($threatsByType) === 0): 
                        echo '<div class="alert alert-info"><strong>' . $addon->i18n('upkeep_dashboard_debug_no_threats', $stats['threats_today']) . '</strong></div>';
                    endif;
                    ?>
                    <?php if (!empty($threatsByType)): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead>
                                    <tr>
                                        <th><?= $addon->i18n('upkeep_dashboard_threat_type') ?></th>
                                        <th class="text-center"><?= $addon->i18n('upkeep_dashboard_severity') ?></th>
                                        <th class="text-center"><?= $addon->i18n('upkeep_dashboard_detected') ?></th>
                                        <th class="text-center"><?= $addon->i18n('upkeep_dashboard_blocked') ?></th>
                                        <th class="text-center"><?= $addon->i18n('upkeep_dashboard_last_incident') ?></th>
                                        <th class="text-center"><?= $addon->i18n('upkeep_dashboard_actions') ?></th>
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
                            <h4><?= $addon->i18n('upkeep_dashboard_no_security_events') ?></h4>
                            <p><?= $addon->i18n('upkeep_dashboard_no_threats_7days') ?></p>
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
                        <?= $addon->i18n('upkeep_dashboard_top_threats') ?>
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
                                <?= $addon->i18n('upkeep_dashboard_no_threats_week') ?>
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
                        <?= $addon->i18n('upkeep_dashboard_blocked_ips_countries') ?>
                        <?php if (!empty($threatsByCountry)): ?>
                            <small class="text-muted"><?= $addon->i18n('upkeep_dashboard_countries_count', count($threatsByCountry)) ?></small>
                        <?php endif; ?>
                    </h3>
                </div>
                <div class="panel-body">
                    <?php if (!empty($threatsByCountry)): ?>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover dashboard-table">
                                <thead>
                                    <tr>
                                        <th><i class="rex-icon fa-flag"></i> <?= $addon->i18n('upkeep_dashboard_country') ?></th>
                                        <th class="text-center"><i class="rex-icon fa-ban"></i> <?= $addon->i18n('upkeep_dashboard_blocks') ?></th>
                                        <th class="text-center"><i class="rex-icon fa-globe"></i> <?= $addon->i18n('upkeep_dashboard_unique_ips') ?></th>
                                        <th class="text-center"><i class="rex-icon fa-clock-o"></i> <?= $addon->i18n('upkeep_dashboard_last_block') ?></th>
                                        <th class="text-center"><i class="rex-icon fa-cog"></i> <?= $addon->i18n('upkeep_dashboard_actions') ?></th>
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
                                                   class="btn btn-xs btn-info" title="<?= $addon->i18n('upkeep_dashboard_show_blocked') ?>">
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
                                    <i class="rex-icon fa-globe"></i> <?= $addon->i18n('upkeep_dashboard_show_all_countries', count($threatsByCountry)) ?>
                                </a>
                            </div>
                        <?php endif; ?>
                    <?php else: ?>
                        <div class="text-center text-muted" style="padding: 40px;">
                            <i class="rex-icon fa-check-circle" style="font-size: 48px; color: #5cb85c;"></i>
                            <h4><?= $addon->i18n('upkeep_dashboard_no_blocked_ips') ?></h4>
                            <p><?= $addon->i18n('upkeep_dashboard_no_blocked_or_geo') ?></p>
                            <?php if (class_exists('KLXM\Upkeep\GeoIP')): ?>
                                <?php $geoStatus = KLXM\Upkeep\IntrusionPrevention::getGeoDatabaseStatus(); ?>
                                <?php if (!$geoStatus['available']): ?>
                                    <a href="<?= rex_url::backendPage('upkeep/ips/settings', ['action' => 'update_geo']) ?>" class="btn btn-sm btn-primary">
                                        <i class="rex-icon fa-download"></i> <?= $addon->i18n('upkeep_dashboard_install_geo') ?>
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
