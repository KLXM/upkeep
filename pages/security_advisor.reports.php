<?php
/**
 * Upkeep AddOn - Security Advisor Detaillierte Berichte
 * 
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

use KLXM\Upkeep\SecurityAdvisor;

$addon = rex_addon::get('upkeep');
$securityAdvisor = new SecurityAdvisor();

// Filter und Aktionen
$filter = rex_request::get('filter', 'string', 'all'); // all, error, warning, success
$action = rex_request::get('action', 'string', '');

// Export-Funktion (einfacher GET-Request)
if ($action === 'export') {
    try {
        error_log('Upkeep Export: Starte Export...');
        $results = $securityAdvisor->runAllChecks();
        exportSecurityReport($results);
        exit;
    } catch (Exception $e) {
        $errorMsg = 'Export-Fehler: ' . $e->getMessage();
        echo rex_view::error($errorMsg);
        error_log('Upkeep Export: ' . $errorMsg);
    }
}

// Sicherheitsprüfung durchführen
$results = $securityAdvisor->runAllChecks();



?>

<!-- Filter und Aktionen -->
<div class="row">
    <div class="col-md-8">
        <div class="btn-group" role="group">
            <a href="<?= rex_url::backendPage('upkeep/security_advisor/reports', ['filter' => 'all']) ?>" 
               class="btn btn-<?= $filter === 'all' ? 'primary' : 'default' ?>">
                <?= $addon->i18n('upkeep_filter_all') ?> (<?= count($results['checks']) ?>)
            </a>
            <a href="<?= rex_url::backendPage('upkeep/security_advisor/reports', ['filter' => 'error']) ?>" 
               class="btn btn-<?= $filter === 'error' ? 'danger' : 'default' ?>">
                <?= $addon->i18n('upkeep_filter_critical') ?> (<?= $results['summary']['critical_issues'] ?>)
            </a>
            <a href="<?= rex_url::backendPage('upkeep/security_advisor/reports', ['filter' => 'warning']) ?>" 
               class="btn btn-<?= $filter === 'warning' ? 'warning' : 'default' ?>">
                <?= $addon->i18n('upkeep_filter_warnings') ?> (<?= $results['summary']['warning_issues'] ?>)
            </a>
            <a href="<?= rex_url::backendPage('upkeep/security_advisor/reports', ['filter' => 'success']) ?>" 
               class="btn btn-<?= $filter === 'success' ? 'success' : 'default' ?>">
                <?= $addon->i18n('upkeep_filter_passed') ?>
            </a>
        </div>
    </div>
    <div class="col-md-4 text-right">
        <!-- Einfacher GET-Link für Export -->
        <a href="<?= rex_url::backendPage('upkeep/security_advisor/reports', ['action' => 'export']) ?>" 
           class="btn btn-default" id="export-btn">
            <i class="rex-icon fa fa-download"></i> 
            <?= $addon->i18n('upkeep_export_report') ?>
        </a>
        
        <a href="<?= rex_url::backendPage('upkeep/security_advisor') ?>" class="btn btn-primary">
            <i class="rex-icon fa fa-arrow-left"></i> 
            <?= $addon->i18n('upkeep_back_to_dashboard') ?>
        </a>
    </div>
</div>

<br>

<!-- Zusammenfassung -->
<div class="row">
    <div class="col-md-12">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-chart-pie"></i> 
                    <?= $addon->i18n('upkeep_security_summary') ?>
                </h3>
            </div>
            <div class="panel-body">
                <div class="row">
                    <div class="col-md-2">
                        <div class="summary-stat">
                            <div class="stat-value text-<?= $results['summary']['status'] === 'success' ? 'success' : 'danger' ?>">
                                <?= $results['summary']['score'] ?>%
                            </div>
                            <div class="stat-label"><?= $addon->i18n('upkeep_overall_score') ?></div>
                        </div>
                    </div>
                    <div class="col-md-2">
                        <div class="summary-stat">
                            <div class="stat-value"><?= $results['summary']['grade'] ?></div>
                            <div class="stat-label"><?= $addon->i18n('upkeep_security_grade') ?></div>
                        </div>
                    </div>
                    <div class="col-md-2">
                        <div class="summary-stat">
                            <div class="stat-value"><?= $results['summary']['total_checks'] ?></div>
                            <div class="stat-label"><?= $addon->i18n('upkeep_total_checks') ?></div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="summary-stat">
                            <div class="stat-value text-danger"><?= $results['summary']['critical_issues'] ?></div>
                            <div class="stat-label"><?= $addon->i18n('upkeep_critical_issues') ?></div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="summary-stat">
                            <div class="stat-value text-warning"><?= $results['summary']['warning_issues'] ?></div>
                            <div class="stat-label"><?= $addon->i18n('upkeep_warning_issues') ?></div>
                        </div>
                    </div>
                </div>
                
                <div class="scan-info">
                    <small class="text-muted">
                        <i class="rex-icon fa fa-clock-o"></i>
                        <?= $addon->i18n('upkeep_scan_completed') ?>: <?= date('d.m.Y H:i:s', $results['timestamp']) ?>
                    </small>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Detaillierte Ergebnisse -->
<div class="row">
    <div class="col-md-12">
        <?php
        $filteredChecks = $results['checks'];
        if ($filter !== 'all') {
            $filteredChecks = array_filter($results['checks'], function($check) use ($filter) {
                return $check['status'] === $filter;
            });
        }
        ?>
        
        <?php foreach ($filteredChecks as $checkKey => $check): ?>
            <div class="panel panel-<?= getCheckPanelClass($check['status']) ?>">
                <div class="panel-heading">
                    <h4 class="panel-title">
                        <a data-toggle="collapse" href="#check-<?= $checkKey ?>">
                            <i class="rex-icon fa fa-<?= getCheckIcon($check['status']) ?>"></i>
                            <?= $check['name'] ?>
                            <span class="pull-right">
                                <span class="severity-badge severity-<?= $check['severity'] ?>">
                                    <?= strtoupper($check['severity']) ?>
                                </span>
                                <span class="score-badge"><?= $check['score'] ?>/10</span>
                                <i class="rex-icon fa fa-chevron-down"></i>
                            </span>
                        </a>
                    </h4>
                </div>
                
                <div id="check-<?= $checkKey ?>" class="panel-collapse collapse">
                    <div class="panel-body">
                        <div class="row">
                            <div class="col-md-8">
                                <h5><?= $addon->i18n('upkeep_description') ?></h5>
                                <p><?= $check['description'] ?></p>
                                
                                <?php if (!empty($check['details'])): ?>
                                    <h5><?= $addon->i18n('upkeep_details') ?></h5>
                                    <div class="check-details">
                                        <?= renderCheckDetails($check['details'], $checkKey) ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                            
                            <div class="col-md-4">
                                <?php if (!empty($check['recommendations'])): ?>
                                    <h5><?= $addon->i18n('upkeep_recommendations') ?></h5>
                                    <ul class="recommendation-list">
                                        <?php foreach ($check['recommendations'] as $recommendation): ?>
                                            <li><i class="rex-icon fa fa-lightbulb-o"></i> <?= $recommendation ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                <?php endif; ?>
                                
                                <?php if ($checkKey === 'live_mode'): ?>
                                    
                                    <?php if ($check['status'] !== 'success'): ?>
                                        <div class="live-mode-actions" style="margin-top: 15px;">
                                            <h5><?= $addon->i18n('upkeep_quick_action') ?></h5>
                                            <button type="button" 
                                                    class="btn btn-warning btn-sm enable-live-mode-btn"
                                                    data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                <i class="rex-icon fa fa-power-off"></i>
                                                <?= $addon->i18n('upkeep_enable_live_mode') ?>
                                            </button>
                                            <div class="help-block" style="margin-top: 5px; font-size: 11px;">
                                                <i class="rex-icon fa fa-exclamation-triangle text-warning"></i>
                                                <strong>Warnung:</strong> <?= $addon->i18n('upkeep_live_mode_warning') ?>
                                            </div>
                                        </div>
                                    <?php else: ?>
                                        <div class="alert alert-success" style="margin-top: 15px;">
                                            <i class="rex-icon fa fa-check"></i>
                                            Live-Mode ist bereits aktiv! 
                                        </div>
                                    <?php endif; ?>
                                <?php endif; ?>
                                
                                <?php if ($checkKey === 'content_security_policy'): ?>
                                    <div class="csp-actions" style="margin-top: 15px;">
                                        <h5><?= $addon->i18n('upkeep_quick_action') ?></h5>
                                        
                                        <?php if ($check['status'] !== 'success'): ?>
                                            <button type="button" 
                                                    class="btn btn-info btn-sm enable-csp-btn"
                                                    data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                <i class="rex-icon fa fa-shield"></i>
                                                Backend-CSP aktivieren
                                            </button>
                                            <div class="help-block" style="margin-top: 5px; font-size: 11px;">
                                                <i class="rex-icon fa fa-info-circle text-info"></i>
                                                <strong>Info:</strong> Schützt nur das REDAXO Backend, nicht das Frontend!
                                            </div>
                                        <?php else: ?>
                                            <button type="button" 
                                                    class="btn btn-warning btn-sm disable-csp-btn"
                                                    data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                <i class="rex-icon fa fa-shield"></i>
                                                Backend-CSP deaktivieren
                                            </button>
                                            <div class="help-block" style="margin-top: 5px; font-size: 11px;">
                                                <i class="rex-icon fa fa-check text-success"></i>
                                                <strong>Aktiv:</strong> Backend-CSP ist derzeit aktiviert und schützt das Backend.
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if ($checkKey === 'session_security'): ?>
                                    <div class="session-security-actions" style="margin-top: 15px;">
                                        <h5><?= $addon->i18n('upkeep_quick_action') ?></h5>
                                        
                                        <?php if ($check['status'] !== 'success'): ?>
                                            <button type="button" 
                                                    class="btn btn-warning btn-sm enable-session-security-btn"
                                                    data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                <i class="rex-icon fa fa-lock"></i>
                                                Session-Sicherheit aktivieren
                                            </button>
                                            <div class="help-block" style="margin-top: 5px; font-size: 11px;">
                                                <i class="rex-icon fa fa-info-circle text-info"></i>
                                                <strong>Info:</strong> Konfiguriert sichere Session-Parameter in der config.yml.
                                            </div>
                                        <?php else: ?>
                                            <div class="alert alert-success" style="margin-top: 15px;">
                                                <i class="rex-icon fa fa-check"></i>
                                                Session-Sicherheit ist bereits konfiguriert!
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>
                                
                                <?php if ($checkKey === 'hsts'): ?>
                                    <div class="https-hsts-actions" style="margin-top: 15px;">
                                        <h5><?= $addon->i18n('upkeep_quick_action') ?></h5>
                                        
                                        <?php 
                                        $currentHttps = $check['details']['current_connection']['is_https'] ?? false;
                                        $backendHttps = $check['details']['redaxo_config']['backend_https'] ?? false;
                                        $frontendHttps = $check['details']['redaxo_config']['frontend_https'] ?? false;
                                        $hstsEnabled = $check['details']['hsts_config']['enabled'] ?? false;
                                        $httpsReadyForHsts = $check['details']['https_ready_for_hsts'] ?? false;
                                        ?>
                                        
                                        <?php if (!$currentHttps): ?>
                                            <div class="alert alert-info" style="margin-top: 15px;">
                                                <i class="rex-icon fa fa-lock"></i>
                                                <strong>Schritt 1:</strong> Sie sind aktuell auf HTTP. Wechseln Sie zu HTTPS für bessere Sicherheit.
                                            </div>
                                        <?php elseif (!$backendHttps && !$frontendHttps): ?>
                                            <div class="alert alert-warning" style="margin-top: 15px;">
                                                <i class="rex-icon fa fa-cog"></i>
                                                <strong>Schritt 2:</strong> HTTPS in REDAXO-Konfiguration aktivieren:
                                            </div>
                                            <div class="btn-group" style="margin-top: 10px;">
                                                <button type="button" class="btn btn-info btn-sm enable-https-backend-btn"
                                                        data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                    <i class="rex-icon fa fa-shield"></i> Backend HTTPS
                                                </button>
                                                <button type="button" class="btn btn-info btn-sm enable-https-frontend-btn"
                                                        data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                    <i class="rex-icon fa fa-globe"></i> Frontend HTTPS
                                                </button>
                                                <button type="button" class="btn btn-primary btn-sm enable-https-both-btn"
                                                        data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                    <i class="rex-icon fa fa-lock"></i> Beide aktivieren
                                                </button>
                                            </div>
                                        <?php elseif ($httpsReadyForHsts && !$hstsEnabled): ?>
                                            <div class="alert alert-success" style="margin-top: 15px;">
                                                <i class="rex-icon fa fa-check"></i>
                                                <strong>HTTPS aktiv!</strong> Jetzt HSTS für zusätzliche Sicherheit aktivieren:
                                            </div>
                                            <button type="button" class="btn btn-info btn-sm enable-hsts-btn"
                                                    data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                <i class="rex-icon fa fa-plus-circle"></i>
                                                HSTS aktivieren (empfohlen)
                                            </button>
                                            <div class="help-block" style="margin-top: 5px; font-size: 11px;">
                                                <i class="rex-icon fa fa-exclamation-triangle text-warning"></i>
                                                <strong>WARNUNG:</strong> HSTS zwingt Browser dauerhaft zu HTTPS! Schwer rückgängig zu machen.
                                            </div>
                                        <?php elseif ($hstsEnabled): ?>
                                            <div class="alert alert-success" style="margin-top: 10px;">
                                                <i class="rex-icon fa fa-check-circle"></i>
                                                <strong>Optimal konfiguriert!</strong> HTTPS und HSTS sind aktiv (<?= $check['details']['hsts_config']['max_age_years'] ?> Jahre)
                                            </div>
                                            <button type="button" class="btn btn-warning btn-sm disable-hsts-btn"
                                                    data-csrf="<?= rex_csrf_token::factory('upkeep-security')->getValue() ?>">
                                                <i class="rex-icon fa fa-times"></i>
                                                HSTS deaktivieren
                                            </button>
                                            <div class="help-block" style="margin-top: 5px; font-size: 11px;">
                                                <i class="rex-icon fa fa-exclamation-triangle text-warning"></i>
                                                <strong>WARNUNG:</strong> Browser können HSTS-Policy noch wochenlang cachen!
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
        
        <?php if (empty($filteredChecks)): ?>
            <div class="alert alert-info">
                <i class="rex-icon fa fa-info-circle"></i>
                <?= $addon->i18n('upkeep_no_checks_found_for_filter') ?>
            </div>
        <?php endif; ?>
    </div>
</div>

<style>
.summary-stat {
    text-align: center;
    padding: 15px;
}

.stat-value {
    font-size: 2em;
    font-weight: bold;
}

.stat-label {
    font-size: 0.9em;
    opacity: 0.7;
    margin-top: 5px;
}

.scan-info {
    margin-top: 20px;
    padding-top: 15px;
    border-top: 1px solid #e5e5e5;
}

.severity-badge {
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.7em;
    font-weight: bold;
}

.severity-badge.severity-high {
    background: #dc3545;
    color: white;
}

.severity-badge.severity-medium {
    background: #ffc107;
    color: #333;
}

.severity-badge.severity-low {
    background: #28a745;
    color: white;
}

.score-badge {
    background: #6c757d;
    color: white;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.8em;
    margin-left: 5px;
}

.check-details {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 5px;
    margin: 10px 0;
}

.check-details pre {
    background: none;
    border: none;
    padding: 0;
    margin: 0;
    font-size: 0.9em;
}

.recommendation-list {
    list-style: none;
    padding: 0;
}

.recommendation-list li {
    padding: 5px 0;
    border-bottom: 1px solid #e5e5e5;
}

.recommendation-list li:last-child {
    border-bottom: none;
}

.recommendation-list i {
    color: #ffc107;
    margin-right: 5px;
}

.panel-title a {
    text-decoration: none;
    color: inherit;
    display: block;
}

.panel-title a:hover {
    text-decoration: none;
    color: inherit;
}

.ssl-cert-details {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
}

.ssl-cert-item {
    background: white;
    padding: 10px;
    border-radius: 5px;
    border: 1px solid #e5e5e5;
    min-width: 200px;
}

.ssl-cert-domain {
    font-weight: bold;
    margin-bottom: 5px;
}

.ssl-cert-status {
    margin-bottom: 5px;
}

.ssl-cert-status.valid {
    color: #28a745;
}

.ssl-cert-status.invalid {
    color: #dc3545;
}

.ssl-cert-status.warning {
    color: #ffc107;
}
</style>

<?php
// Helper-Funktionen

function getCheckPanelClass($status) {
    return match($status) {
        'success' => 'success',
        'warning' => 'warning', 
        'error' => 'danger',
        'info' => 'info',
        default => 'default'
    };
}

function getCheckIcon($status) {
    return match($status) {
        'success' => 'check-circle',
        'warning' => 'exclamation-triangle',
        'error' => 'times-circle', 
        'info' => 'info-circle',
        default => 'question-circle'
    };
}

function renderCheckDetails($details, $checkKey) {
    if ($checkKey === 'ssl_certificates') {
        return renderSslDetails($details);
    } elseif ($checkKey === 'server_headers') {
        return renderHeaderDetails($details);
    } else {
        return renderGenericDetails($details);
    }
}

function renderSslDetails($details) {
    $html = '<div class="ssl-cert-details">';
    foreach ($details as $domain => $cert) {
        $statusClass = $cert['valid'] ? 
            ($cert['days_remaining'] > 30 ? 'valid' : 'warning') : 'invalid';
        
        $html .= '<div class="ssl-cert-item">';
        $html .= '<div class="ssl-cert-domain">' . htmlspecialchars($domain) . '</div>';
        $html .= '<div class="ssl-cert-status ' . $statusClass . '">';
        $html .= $cert['valid'] ? '✓ Gültig' : '✗ Ungültig';
        $html .= '</div>';
        
        if ($cert['valid']) {
            $html .= '<div><small>Läuft ab: ' . $cert['expires'] . '</small></div>';
            $html .= '<div><small>Verbleibend: ' . $cert['days_remaining'] . ' Tage</small></div>';
            $html .= '<div><small>Aussteller: ' . htmlspecialchars($cert['issuer']) . '</small></div>';
        }
        
        if (!empty($cert['errors'])) {
            $html .= '<div class="text-danger"><small>' . implode('<br>', $cert['errors']) . '</small></div>';
        }
        
        $html .= '</div>';
    }
    $html .= '</div>';
    
    return $html;
}

function renderHeaderDetails($details) {
    $html = '<div class="header-details">';
    
    if (!empty($details['headers'])) {
        $html .= '<h6>Aktuelle Header:</h6>';
        $html .= '<pre>' . print_r($details['headers'], true) . '</pre>';
    }
    
    if (!empty($details['issues'])) {
        $html .= '<h6>Probleme:</h6>';
        $html .= '<ul>';
        foreach ($details['issues'] as $issue) {
            $html .= '<li>' . htmlspecialchars($issue) . '</li>';
        }
        $html .= '</ul>';
    }
    
    $html .= '</div>';
    
    return $html;
}

function renderGenericDetails($details) {
    return '<pre>' . print_r($details, true) . '</pre>';
}

function exportSecurityReport($results) {
    try {
        $filename = 'upkeep_security_report_' . date('Y-m-d_H-i-s') . '.json';
        
        error_log('Upkeep Export: Exportiere nach ' . $filename);
        
        // Alle Output-Buffer leeren
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        // Headers für Download setzen
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        // JSON-Export mit schöner Formatierung
        $jsonData = json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        
        if ($jsonData === false) {
            throw new Exception('JSON-Encoding fehlgeschlagen: ' . json_last_error_msg());
        }
        
        // Content-Length für bessere Browser-Kompatibilität
        header('Content-Length: ' . strlen($jsonData));
        
        // Flush headers
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } else {
            flush();
        }
        
        echo $jsonData;
        
        error_log('Upkeep Export: Export erfolgreich, ' . strlen($jsonData) . ' Bytes');
        
    } catch (Exception $e) {
        error_log('Upkeep Export: Fehler - ' . $e->getMessage());
        
        // Buffer leeren für Fehlermeldung
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        // Bei Fehlern HTML-Antwort senden
        header('Content-Type: text/html; charset=utf-8');
        echo rex_view::error('Export-Fehler: ' . $e->getMessage());
    }
}

?>

<script type="text/javascript">
$(document).ready(function() {
    // Live-Mode Aktivierung
    $('.enable-live-mode-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        // Bestätigung mit Warnung anzeigen
        var confirmText = 'WARNUNG: Der Live-Mode kann nur durch manuelle Bearbeitung der config.yml wieder deaktiviert werden!\n\n' +
                         'Möchten Sie den Live-Mode wirklich aktivieren?\n\n' +
                         'Dies wird:\n' +
                         '• Debug-Modus deaktivieren\n' +
                         '• throw_always_exception deaktivieren\n' +
                         '• Cache leeren\n\n' +
                         'Fortfahren?';
        
        if (!confirm(confirmText)) {
            return;
        }
        
        // Button deaktivieren während der Anfrage
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        // AJAX-Anfrage
        $.ajax({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_live_mode',
            data: {
                '_csrf_token': csrf
            },
            method: 'POST',
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    // Erfolg anzeigen
                    $btn.removeClass('btn-warning').addClass('btn-success')
                        .html('<i class="rex-icon fa fa-check"></i> Aktiviert');
                    
                    // Success-Nachricht anzeigen
                    var alertHtml = '<div class="alert alert-success alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Erfolg:</strong> ' + response.message;
                    
                    if (response.warning) {
                        alertHtml += '<br><strong>Wichtiger Hinweis:</strong> ' + response.warning;
                    }
                    
                    alertHtml += '</div>';
                    
                    $('.live-mode-actions').before(alertHtml);
                    
                    // Seite nach 3 Sekunden neu laden um aktuellen Status zu zeigen
                    setTimeout(function() {
                        window.location.reload();
                    }, 3000);
                } else {
                    // Fehler anzeigen
                    $btn.prop('disabled', false).html('<i class="rex-icon fa fa-power-off"></i> Live-Mode aktivieren');
                    
                    var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Fehler:</strong> ' + response.message + '</div>';
                    
                    $('.live-mode-actions').before(alertHtml);
                }
            },
            error: function() {
                // Netzwerk- oder Server-Fehler
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-power-off"></i> Live-Mode aktivieren');
                
                var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                               '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                               '<strong>Fehler:</strong> Verbindungsfehler beim Aktivieren des Live-Modes.</div>';
                
                $('.live-mode-actions').before(alertHtml);
            }
        });
    });
    
    // CSP Aktivierung
    $('.enable-csp-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        // Bestätigung mit Warnung anzeigen
        var confirmText = 'Content Security Policy (CSP) aktivieren?\n\n' +
                         'WARNUNG: CSP kann das Layout und JavaScript-Funktionen Ihrer Website beeinträchtigen!\n\n' +
                         'Dies wird:\n' +
                         '• Strikte Sicherheitsregeln für Scripts und Styles aktivieren\n' +
                         '• Möglicherweise inline CSS/JS blockieren\n' +
                         '• Externe Ressourcen einschränken\n\n' +
                         'Testen Sie Ihre Website gründlich nach der Aktivierung!\n\n' +
                         'Fortfahren?';
        
        if (!confirm(confirmText)) {
            return;
        }
        
        // Button deaktivieren während der Anfrage
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        // AJAX-Anfrage
        $.ajax({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_csp',
            data: {
                '_csrf_token': csrf
            },
            method: 'POST',
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    // Erfolg anzeigen
                    $btn.removeClass('btn-info').addClass('btn-success')
                        .html('<i class="rex-icon fa fa-check"></i> Aktiviert');
                    
                    // Success-Nachricht anzeigen
                    var alertHtml = '<div class="alert alert-success alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Erfolg:</strong> ' + response.message;
                    
                    if (response.warning) {
                        alertHtml += '<br><strong>Wichtiger Hinweis:</strong> ' + response.warning;
                    }
                    
                    alertHtml += '</div>';
                    
                    $('.csp-actions').before(alertHtml);
                    
                    // Seite nach 3 Sekunden neu laden um aktuellen Status zu zeigen
                    setTimeout(function() {
                        window.location.reload();
                    }, 3000);
                } else {
                    // Fehler anzeigen
                    $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> CSP aktivieren');
                    
                    var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Fehler:</strong> ' + response.message + '</div>';
                    
                    $('.csp-actions').before(alertHtml);
                }
            },
            error: function() {
                // Netzwerk- oder Server-Fehler
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> CSP aktivieren');
                
                var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                               '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                               '<strong>Fehler:</strong> Verbindungsfehler beim Aktivieren der CSP.</div>';
                
                $('.csp-actions').before(alertHtml);
            }
        });
    });
    
    // CSP Deaktivierung
    $('.disable-csp-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        // Bestätigung anzeigen
        var confirmText = 'Content Security Policy deaktivieren?\n\n' +
                         'Dies wird:\n' +
                         '• Die CSP-Schutzregeln für das Backend entfernen\n' +
                         '• Das Backend weniger sicher machen\n\n' +
                         'Fortfahren?';
        
        if (!confirm(confirmText)) {
            return;
        }
        
        // Button deaktivieren während der Anfrage
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Deaktiviere...');
        
        // AJAX-Anfrage
        $.ajax({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=disable_csp',
            data: {
                '_csrf_token': csrf
            },
            method: 'POST',
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    // Erfolg anzeigen
                    $btn.removeClass('btn-warning').addClass('btn-secondary')
                        .html('<i class="rex-icon fa fa-check"></i> Deaktiviert');
                    
                    // Success-Nachricht anzeigen
                    var alertHtml = '<div class="alert alert-warning alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Deaktiviert:</strong> ' + response.message + '</div>';
                    
                    $('.csp-actions').before(alertHtml);
                    
                    // Seite nach 3 Sekunden neu laden um aktuellen Status zu zeigen
                    setTimeout(function() {
                        window.location.reload();
                    }, 3000);
                } else {
                    // Fehler anzeigen
                    $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> Backend-CSP deaktivieren');
                    
                    var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Fehler:</strong> ' + response.message + '</div>';
                    
                    $('.csp-actions').before(alertHtml);
                }
            },
            error: function() {
                // Netzwerk- oder Server-Fehler
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> Backend-CSP deaktivieren');
                
                var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                               '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                               '<strong>Fehler:</strong> Verbindungsfehler beim Deaktivieren der CSP.</div>';
                
                $('.csp-actions').before(alertHtml);
            }
        });
    });
    
    // Session Security Aktivierung
    $('.enable-session-security-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        // Bestätigung anzeigen
        var confirmText = 'Session-Sicherheitseinstellungen aktivieren?\n\n' +
                         'Dies wird folgende Einstellungen in der config.yml konfigurieren:\n' +
                         '• session.backend.cookie.httponly = true\n' +
                         '• session.backend.cookie.secure = true (nur für HTTPS)\n' +
                         '• session.backend.cookie.samesite = "Lax"\n\n' +
                         'Die Einstellungen sind sofort nach dem Speichern aktiv.\n\n' +
                         'Fortfahren?';
        
        if (!confirm(confirmText)) {
            return;
        }
        
        // Button deaktivieren während der Anfrage
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        // AJAX-Anfrage
        $.ajax({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_session_security',
            data: {
                '_csrf_token': csrf
            },
            method: 'POST',
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    // Erfolg anzeigen
                    $btn.removeClass('btn-warning').addClass('btn-success')
                        .html('<i class="rex-icon fa fa-check"></i> Aktiviert');
                    
                    // Success-Nachricht anzeigen
                    var alertHtml = '<div class="alert alert-success alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Erfolg:</strong> ' + response.message;
                    
                    if (response.warning) {
                        alertHtml += '<br><strong>Hinweis:</strong> ' + response.warning;
                    }
                    
                    alertHtml += '</div>';
                    
                    $('.session-security-actions').before(alertHtml);
                    
                    // Seite nach 3 Sekunden neu laden um aktuellen Status zu zeigen
                    setTimeout(function() {
                        window.location.reload();
                    }, 3000);
                } else {
                    // Fehler anzeigen
                    $btn.prop('disabled', false).html('<i class="rex-icon fa fa-lock"></i> Session-Sicherheit aktivieren');
                    
                    var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Fehler:</strong> ' + response.message + '</div>';
                    
                    $('.session-security-actions').before(alertHtml);
                }
            },
            error: function() {
                // Netzwerk- oder Server-Fehler
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-lock"></i> Session-Sicherheit aktivieren');
                
                var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                               '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                               '<strong>Fehler:</strong> Verbindungsfehler beim Aktivieren der Session-Sicherheit.</div>';
                
                $('.session-security-actions').before(alertHtml);
            }
        });
    });
    
    // HSTS Aktivierung (optionale Sicherheitsverbesserung)
    $('.enable-hsts-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        // Freundliche Bestätigung statt kritischer Warnung
        var confirmText = '💡 HSTS aktivieren?\n\n' +
                         'HTTP Strict Transport Security (HSTS) ist eine optionale Sicherheitsverbesserung.\n\n' +
                         '✅ VORTEILE:\n' +
                         '• Zusätzlicher Schutz vor Man-in-the-Middle Attacken\n' +
                         '• Browser werden automatisch zu HTTPS geleitet\n' +
                         '• Verbessert die Sicherheitsbewertung\n\n' +
                         '⚠️ WICHTIG ZU WISSEN:\n' +
                         '• Browser cachen HSTS-Policy für längere Zeit\n' +
                         '• HTTPS sollte dauerhaft verfügbar sein\n' +
                         '• Bei SSL-Problemen kann Site temporär unzugänglich werden\n\n' +
                         'HSTS jetzt aktivieren?';
        
        if (!confirm(confirmText)) {
            return;
        }
        
        // Button deaktivieren während der Anfrage
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        // AJAX-Anfrage
        $.ajax({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_hsts',
            data: {
                '_csrf_token': csrf
            },
            method: 'POST',
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    // Erfolg anzeigen
                    $btn.removeClass('btn-danger').addClass('btn-success')
                        .html('<i class="rex-icon fa fa-check"></i> Aktiviert');
                    
                    // Success-Nachricht anzeigen
                    var alertHtml = '<div class="alert alert-success alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>HSTS aktiviert:</strong> ' + response.message;
                    
                    if (response.warning) {
                        alertHtml += '<br><strong>⚠️ KRITISCH:</strong> ' + response.warning;
                    }
                    
                    alertHtml += '</div>';
                    
                    $('.hsts-actions').before(alertHtml);
                    
                    // Seite nach 5 Sekunden neu laden um aktuellen Status zu zeigen
                    setTimeout(function() {
                        window.location.reload();
                    }, 5000);
                } else {
                    // Fehler anzeigen
                    $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> HSTS aktivieren');
                    
                    var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Fehler:</strong> ' + response.message + '</div>';
                    
                    $('.hsts-actions').before(alertHtml);
                }
            },
            error: function() {
                // Netzwerk- oder Server-Fehler
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> HSTS aktivieren');
                
                var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                               '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                               '<strong>Fehler:</strong> Verbindungsfehler beim Aktivieren von HSTS.</div>';
                
                $('.hsts-actions').before(alertHtml);
            }
        });
    });
    
    // HSTS Deaktivierung
    $('.disable-hsts-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        // Bestätigung mit Warnung
        var confirmText = 'HSTS deaktivieren?\n\n' +
                         '⚠️ WICHTIGER HINWEIS:\n' +
                         '• Browser können die HSTS-Policy noch wochenlang cachen\n' +
                         '• Deaktivierung ist nicht sofort wirksam\n' +
                         '• max-age wird auf 0 gesetzt, aber Browser entscheiden selbst\n\n' +
                         'Fortfahren?';
        
        if (!confirm(confirmText)) {
            return;
        }
        
        // Button deaktivieren während der Anfrage
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Deaktiviere...');
        
        // AJAX-Anfrage
        $.ajax({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=disable_hsts',
            data: {
                '_csrf_token': csrf
            },
            method: 'POST',
            dataType: 'json',
            success: function(response) {
                if (response.success) {
                    // Erfolg anzeigen
                    $btn.removeClass('btn-warning').addClass('btn-secondary')
                        .html('<i class="rex-icon fa fa-check"></i> Deaktiviert');
                    
                    // Success-Nachricht anzeigen
                    var alertHtml = '<div class="alert alert-warning alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>HSTS deaktiviert:</strong> ' + response.message;
                    
                    if (response.warning) {
                        alertHtml += '<br><strong>⚠️ Hinweis:</strong> ' + response.warning;
                    }
                    
                    alertHtml += '</div>';
                    
                    $('.hsts-actions').before(alertHtml);
                    
                    // Seite nach 5 Sekunden neu laden um aktuellen Status zu zeigen
                    setTimeout(function() {
                        window.location.reload();
                    }, 5000);
                } else {
                    // Fehler anzeigen
                    $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> HSTS deaktivieren');
                    
                    var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                                   '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                                   '<strong>Fehler:</strong> ' + response.message + '</div>';
                    
                    $('.hsts-actions').before(alertHtml);
                }
            },
            error: function() {
                // Netzwerk- oder Server-Fehler
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> HSTS deaktivieren');
                
                var alertHtml = '<div class="alert alert-danger alert-dismissible">' +
                               '<button type="button" class="close" data-dismiss="alert">&times;</button>' +
                               '<strong>Fehler:</strong> Verbindungsfehler beim Deaktivieren von HSTS.</div>';
                
                $('.hsts-actions').before(alertHtml);
            }
        });
    });
    // HTTPS Backend Aktivierung
    $('.enable-https-backend-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        if (!confirm('HTTPS für Backend aktivieren?\n\nDies setzt use_https: true in der config.yml.\n\nSTELLEN SIE SICHER, dass SSL-Zertifikat installiert ist!')) {
            return;
        }
        
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        $.post({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_https_backend',
            data: { 
                '_csrf_token': csrf
            },
            dataType: 'json'
        }).done(function(response) {
            if (response.success) {
                location.reload();
            } else {
                alert('Fehler: ' + response.message);
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> Backend HTTPS');
            }
        }).fail(function() {
            alert('Fehler beim Aktivieren von Backend HTTPS');
            $btn.prop('disabled', false).html('<i class="rex-icon fa fa-shield"></i> Backend HTTPS');
        });
    });

    // HTTPS Frontend Aktivierung
    $('.enable-https-frontend-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        if (!confirm('HTTPS für Frontend aktivieren?\n\nDies setzt use_https: "frontend" in der config.yml.\n\nSTELLEN SIE SICHER, dass SSL-Zertifikat installiert ist!')) {
            return;
        }
        
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        $.post({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_https_frontend',
            data: { 
                '_csrf_token': csrf
            },
            dataType: 'json'
        }).done(function(response) {
            if (response.success) {
                location.reload();
            } else {
                alert('Fehler: ' + response.message);
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-globe"></i> Frontend HTTPS');
            }
        }).fail(function() {
            alert('Fehler beim Aktivieren von Frontend HTTPS');
            $btn.prop('disabled', false).html('<i class="rex-icon fa fa-globe"></i> Frontend HTTPS');
        });
    });

    // HTTPS Beide Aktivierung
    $('.enable-https-both-btn').on('click', function() {
        var $btn = $(this);
        var csrf = $btn.data('csrf');
        
        if (!confirm('HTTPS für Backend UND Frontend aktivieren?\n\nDies setzt use_https: true in der config.yml.\n\nSTELLEN SIE SICHER, dass SSL-Zertifikat installiert ist!')) {
            return;
        }
        
        $btn.prop('disabled', true).html('<i class="rex-icon fa fa-spinner fa-spin"></i> Aktiviere...');
        
        $.post({
            url: window.location.pathname + '?page=upkeep&api=security_advisor&action=enable_https_both',
            data: { 
                '_csrf_token': csrf
            },
            dataType: 'json'
        }).done(function(response) {
            if (response.success) {
                location.reload();
            } else {
                alert('Fehler: ' + response.message);
                $btn.prop('disabled', false).html('<i class="rex-icon fa fa-lock"></i> Beide aktivieren');
            }
        }).fail(function() {
            alert('Fehler beim Aktivieren von HTTPS');
            $btn.prop('disabled', false).html('<i class="rex-icon fa fa-lock"></i> Beide aktivieren');
        });
    });
});
</script>

<style>
.live-mode-actions {
    border-top: 1px solid #ddd;
    padding-top: 15px;
}

.live-mode-actions .btn {
    width: 100%;
}

.live-mode-actions .help-block {
    color: #856404;
    background-color: #fff3cd;
    border: 1px solid #ffeaa7;
    padding: 8px 12px;
    border-radius: 4px;
    margin-top: 10px;
}

.session-security-actions {
    border-top: 1px solid #ddd;
    padding-top: 15px;
}

.session-security-actions .btn {
    width: 100%;
}

.session-security-actions .help-block {
    color: #0c5460;
    background-color: #d1ecf1;
    border: 1px solid #bee5eb;
    padding: 8px 12px;
    border-radius: 4px;
    margin-top: 10px;
}

.hsts-actions {
    border-top: 1px solid #ddd;
    padding-top: 15px;
}

.hsts-actions .btn {
    width: 100%;
}

.hsts-actions .help-block {
    padding: 8px 12px;
    border-radius: 4px;
    margin-top: 10px;
}

.hsts-actions .btn-danger + .help-block {
    color: #721c24;
    background-color: #f8d7da;
    border: 1px solid #f5c6cb;
}

.hsts-actions .btn-warning + .help-block {
    color: #856404;
    background-color: #fff3cd;
    border: 1px solid #ffeaa7;
}
</style>