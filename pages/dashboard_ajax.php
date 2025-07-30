<?php
/**
 * AJAX-Handler für Dashboard-Funktionen
 */

use KLXM\Upkeep\IntrusionPrevention;

// CSRF-Schutz für AJAX-Requests
if (!rex_request::isXmlHttpRequest()) {
    // Normale Seite laden wenn kein AJAX
    include 'dashboard.php';
    return;
}

$func = rex_request('func', 'string', '');

switch ($func) {
    case 'live_stats':
        $stats = IntrusionPrevention::getStatistics();
        
        // Erweiterte Statistiken
        $addon = rex_addon::get('upkeep');
        $allowedIps = $addon->getConfig('allowed_ips', '');
        $allowedIpCount = !empty(trim($allowedIps)) ? count(array_filter(explode("\n", $allowedIps))) : 0;
        
        $sql = rex_sql::factory();
        $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_domain_mapping') . " WHERE status = 1");
        $activeRedirects = (int) $sql->getValue('count');
        
        $stats['allowed_ips'] = $allowedIpCount;
        $stats['active_redirects'] = $activeRedirects;
        
        header('Content-Type: application/json');
        echo json_encode($stats);
        exit;
        
    case 'recent_activities':
        $activities = getRecentActivities();
        echo renderActivityFeed($activities);
        exit;
        
    case 'toggle_module':
        $module = rex_request('module', 'string', '');
        $enabled = rex_request('enabled', 'int', 0) === 1;
        
        $result = toggleUpkeepModule($module, $enabled);
        
        header('Content-Type: application/json');
        echo json_encode($result);
        exit;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Invalid function']);
        exit;
}

/**
 * Schaltet Upkeep-Module ein/aus
 */
function toggleUpkeepModule(string $module, bool $enabled): array
{
    try {
        $addon = rex_addon::get('upkeep');
        $success = false;
        $message = '';
        
        switch ($module) {
            case 'ips':
                $addon->setConfig('ips_active', $enabled);
                $success = true;
                $message = 'IPS ' . ($enabled ? 'aktiviert' : 'deaktiviert');
                break;
                
            case 'frontend':
                $addon->setConfig('frontend_active', $enabled);
                $success = true;
                $message = 'Frontend-Wartung ' . ($enabled ? 'aktiviert' : 'deaktiviert');
                break;
                
            case 'backend':
                $addon->setConfig('backend_active', $enabled);
                $success = true;
                $message = 'Backend-Wartung ' . ($enabled ? 'aktiviert' : 'deaktiviert');
                break;
                
            case 'redirects':
                $addon->setConfig('domain_mapping_enabled', $enabled);
                $success = true;
                $message = 'Domain-Redirects ' . ($enabled ? 'aktiviert' : 'deaktiviert');
                break;
                
            default:
                $message = 'Unbekanntes Modul: ' . $module;
                break;
        }
        
        if ($success) {
            // Log the change
            rex_logger::factory()->log('info', "Dashboard: {$message} (User: " . rex::getUser()->getLogin() . ")");
        }
        
        return [
            'success' => $success,
            'message' => $message,
            'module' => $module,
            'enabled' => $enabled
        ];
        
    } catch (Exception $e) {
        rex_logger::logException($e);
        return [
            'success' => false,
            'message' => 'Fehler beim Umschalten: ' . $e->getMessage(),
            'module' => $module,
            'enabled' => $enabled
        ];
    }
}

/**
 * Holt die letzten 20 Sicherheitsereignisse
 */
function getRecentActivities(): array
{
    $sql = rex_sql::factory();
    $query = "SELECT * FROM " . rex::getTable('upkeep_ips_threat_log') . " 
              ORDER BY created_at DESC 
              LIMIT 20";
    
    $sql->setQuery($query);
    $activities = [];
    
    while ($sql->hasNext()) {
        $activities[] = [
            'id' => $sql->getValue('id'),
            'ip_address' => $sql->getValue('ip_address'),
            'threat_type' => $sql->getValue('threat_type'),
            'threat_category' => $sql->getValue('threat_category'),
            'severity' => $sql->getValue('severity'),
            'pattern_matched' => $sql->getValue('pattern_matched'),
            'request_uri' => $sql->getValue('request_uri'),
            'user_agent' => $sql->getValue('user_agent'),
            'action_taken' => $sql->getValue('action_taken'),
            'created_at' => $sql->getValue('created_at')
        ];
        $sql->next();
    }
    
    return $activities;
}

/**
 * Rendert die Activity Feed HTML
 */
function renderActivityFeed(array $activities): string
{
    if (empty($activities)) {
        return '<div class="text-center text-muted">
                    <i class="rex-icon fa-check-circle" style="font-size: 2rem; margin-bottom: 10px; opacity: 0.5;"></i><br>
                    Keine aktuellen Sicherheitsereignisse
                </div>';
    }
    
    $html = '';
    foreach ($activities as $activity) {
        $html .= renderActivityItem($activity);
    }
    
    return $html;
}

/**
 * Rendert ein einzelnes Activity Item
 */
function renderActivityItem(array $activity): string
{
    $severityClass = getSeverityClass($activity['severity']);
    $threatIcon = getThreatIcon($activity['threat_type']);
    $timeAgo = getTimeAgo($activity['created_at']);
    $actionText = getActionText($activity['action_taken']);
    
    // Request URI kürzen wenn zu lang
    $shortUri = strlen($activity['request_uri']) > 50 
        ? substr($activity['request_uri'], 0, 47) . '...'
        : $activity['request_uri'];
    
    // User Agent kürzen
    $shortAgent = strlen($activity['user_agent']) > 60 
        ? substr($activity['user_agent'], 0, 57) . '...'
        : $activity['user_agent'];
    
    return '
    <div class="activity-item" data-id="' . $activity['id'] . '">
        <div class="activity-icon ' . $severityClass . '">
            <i class="rex-icon ' . $threatIcon . '"></i>
        </div>
        <div class="activity-content">
            <h4 class="activity-title">
                ' . rex_escape($activity['threat_type']) . ' 
                <small class="text-muted">von ' . rex_escape($activity['ip_address']) . '</small>
            </h4>
            <p class="activity-details">
                <strong>URI:</strong> ' . rex_escape($shortUri) . '<br>
                <strong>Pattern:</strong> ' . rex_escape($activity['pattern_matched']) . '<br>
                <strong>Aktion:</strong> ' . $actionText . '
            </p>
        </div>
        <div class="activity-time">
            ' . $timeAgo . '
        </div>
    </div>';
}

/**
 * Ermittelt CSS-Klasse für Schweregrad
 */
function getSeverityClass(string $severity): string
{
    return match($severity) {
        'critical' => 'severity-critical',
        'high' => 'severity-high', 
        'medium' => 'severity-medium',
        'low' => 'severity-low',
        default => 'severity-medium'
    };
}

/**
 * Ermittelt Icon für Bedrohungstyp
 */
function getThreatIcon(string $threatType): string
{
    return match($threatType) {
        'sql_injection' => 'fa-database',
        'xss' => 'fa-code',
        'file_inclusion' => 'fa-file-text',
        'command_injection' => 'fa-terminal',
        'path_traversal' => 'fa-folder-open',
        'rate_limit' => 'fa-tachometer',
        'scanner' => 'fa-search',
        'bot' => 'fa-robot',
        default => 'fa-exclamation-triangle'
    };
}

/**
 * Berechnet "vor X Zeit" Text
 */
function getTimeAgo(string $datetime): string
{
    $time = strtotime($datetime);
    $diff = time() - $time;
    
    if ($diff < 60) {
        return 'vor ' . $diff . 's';
    } elseif ($diff < 3600) {
        return 'vor ' . round($diff / 60) . 'min';
    } elseif ($diff < 86400) {
        return 'vor ' . round($diff / 3600) . 'h';
    } elseif ($diff < 2592000) {
        return 'vor ' . round($diff / 86400) . 'd';
    } else {
        return date('d.m.Y', $time);
    }
}

/**
 * Übersetzt Aktions-Codes in lesbare Texte
 */
function getActionText(string $action): string
{
    return match($action) {
        'permanent_block' => '<span class="label label-danger">Permanent gesperrt</span>',
        'temporary_block' => '<span class="label label-warning">Temporär gesperrt</span>',
        'logged' => '<span class="label label-info">Protokolliert</span>',
        'captcha' => '<span class="label label-primary">CAPTCHA</span>',
        default => '<span class="label label-default">' . rex_escape($action) . '</span>'
    };
}
