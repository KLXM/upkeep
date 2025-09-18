<?php

use KLXM\Upkeep\MailSecurityFilter;

$error = '';
$success = '';

// Threat-Details anzeigen
$threatId = rex_request('threat_id', 'int', 0);
$showDetails = $threatId > 0;

// Filter-Parameter
$filterType = rex_request('filter_type', 'string', '');
$filterSeverity = rex_request('filter_severity', 'string', '');
$filterIp = rex_request('filter_ip', 'string', '');
$filterDate = rex_request('filter_date', 'string', '');
$page = max(1, rex_request('page', 'int', 1));
$limit = 50;
$offset = ($page - 1) * $limit;

// Error/Success Messages
if ($error) {
    echo rex_view::error($error);
}
if ($success) {
    echo rex_view::success($success);
}

// Threat-Details Modal
if ($showDetails) {
    try {
        $sql = rex_sql::factory();
        $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE id = ? AND threat_type LIKE 'mail_%'", [$threatId]);
        
        if ($sql->getRows() > 0) {
            $threat = [
                'id' => $sql->getValue('id'),
                'ip_address' => $sql->getValue('ip_address'),
                'threat_type' => $sql->getValue('threat_type'),
                'threat_category' => $sql->getValue('threat_category'),
                'pattern_matched' => $sql->getValue('pattern_matched'),
                'severity' => $sql->getValue('severity'),
                'action_taken' => $sql->getValue('action_taken'),
                'request_uri' => $sql->getValue('request_uri'),
                'user_agent' => $sql->getValue('user_agent'),
                'created_at' => $sql->getValue('created_at')
            ];
            
            $content = '<div class="modal fade" id="threatModal" tabindex="-1" role="dialog">';
            $content .= '<div class="modal-dialog modal-lg" role="document">';
            $content .= '<div class="modal-content">';
            $content .= '<div class="modal-header">';
            $content .= '<button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>';
            $content .= '<h4 class="modal-title">Threat Details - ' . rex_escape($threat['threat_type']) . '</h4>';
            $content .= '</div>';
            $content .= '<div class="modal-body">';
            
            $content .= '<dl class="dl-horizontal">';
            $content .= '<dt>Threat ID:</dt><dd>' . $threat['id'] . '</dd>';
            $content .= '<dt>IP-Adresse:</dt><dd><code>' . rex_escape($threat['ip_address']) . '</code></dd>';
            $content .= '<dt>Bedrohungstyp:</dt><dd>' . rex_escape($threat['threat_type']) . '</dd>';
            $content .= '<dt>Kategorie:</dt><dd>' . rex_escape($threat['threat_category']) . '</dd>';
            $content .= '<dt>Schweregrad:</dt><dd><span class="label label-' . match($threat['severity']) {
                'critical' => 'danger',
                'high' => 'warning',
                'medium' => 'info',
                default => 'default'
            } . '">' . rex_escape($threat['severity']) . '</span></dd>';
            $content .= '<dt>Pattern:</dt><dd><code>' . rex_escape($threat['pattern_matched']) . '</code></dd>';
            $content .= '<dt>Aktion:</dt><dd>' . rex_escape($threat['action_taken']) . '</dd>';
            $content .= '<dt>Request URI:</dt><dd><code>' . rex_escape($threat['request_uri']) . '</code></dd>';
            $content .= '<dt>User Agent:</dt><dd><code>' . rex_escape($threat['user_agent']) . '</code></dd>';
            $content .= '<dt>Zeitpunkt:</dt><dd>' . rex_formatter::strftime(strtotime($threat['created_at']), 'datetime') . '</dd>';
            $content .= '</dl>';
            
            $content .= '</div>';
            $content .= '<div class="modal-footer">';
            $content .= '<a href="' . rex_url::currentBackendPage() . '" class="btn btn-default">Schließen</a>';
            $content .= '</div>';
            $content .= '</div>';
            $content .= '</div>';
            $content .= '</div>';
            
            $content .= '<script>jQuery(document).ready(function($) { $("#threatModal").modal("show"); });</script>';
            
            echo $content;
        }
    } catch (Exception $e) {
        echo rex_view::error('Fehler beim Laden der Threat-Details: ' . $e->getMessage());
    }
}

// Filter-Panel
$content = '<form method="get" action="' . rex_url::currentBackendPage() . '">';
$content .= '<input type="hidden" name="page" value="upkeep" />';
$content .= '<input type="hidden" name="subpage" value="mail_security" />';
$content .= '<input type="hidden" name="subsubpage" value="threats" />';

$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-filter"></i> Filter & Suche</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';

$content .= '<div class="col-md-3">';
$content .= '<label>Bedrohungstyp</label>';
$content .= '<select name="filter_type" class="form-control">';
$content .= '<option value="">Alle Typen</option>';

// Threat-Typen laden
try {
    $sql = rex_sql::factory();
    $sql->setQuery("SELECT DISTINCT threat_type FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail_%' ORDER BY threat_type");
    while ($sql->hasNext()) {
        $type = $sql->getValue('threat_type');
        $selected = ($filterType === $type) ? ' selected' : '';
        $displayType = str_replace('mail_', '', $type);
        $displayType = ucwords(str_replace('_', ' ', $displayType));
        $content .= '<option value="' . rex_escape($type) . '"' . $selected . '>' . rex_escape($displayType) . '</option>';
        $sql->next();
    }
} catch (Exception $e) {
    // Ignore
}

$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Schweregrad</label>';
$content .= '<select name="filter_severity" class="form-control">';
$content .= '<option value="">Alle Schweregrade</option>';
$severities = ['low' => 'Niedrig', 'medium' => 'Mittel', 'high' => 'Hoch', 'critical' => 'Kritisch'];
foreach ($severities as $value => $label) {
    $selected = ($filterSeverity === $value) ? ' selected' : '';
    $content .= '<option value="' . $value . '"' . $selected . '>' . $label . '</option>';
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>IP-Adresse</label>';
$content .= '<input type="text" name="filter_ip" class="form-control" placeholder="192.168.1.1" value="' . rex_escape($filterIp) . '" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Datum</label>';
$content .= '<input type="date" name="filter_date" class="form-control" value="' . rex_escape($filterDate) . '" />';
$content .= '</div>';

$content .= '<div class="col-md-3">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<button type="submit" class="btn btn-primary">Filtern</button> ';
$content .= '<a href="' . rex_url::currentBackendPage() . '" class="btn btn-default">Reset</a>';
$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Threats laden mit Filter
$whereConditions = ["threat_type LIKE 'mail_%'"];
$whereParams = [];

if (!empty($filterType)) {
    $whereConditions[] = "threat_type = ?";
    $whereParams[] = $filterType;
}
if (!empty($filterSeverity)) {
    $whereConditions[] = "severity = ?";
    $whereParams[] = $filterSeverity;
}
if (!empty($filterIp)) {
    $whereConditions[] = "ip_address LIKE ?";
    $whereParams[] = '%' . $filterIp . '%';
}
if (!empty($filterDate)) {
    $whereConditions[] = "DATE(created_at) = ?";
    $whereParams[] = $filterDate;
}

$whereClause = 'WHERE ' . implode(' AND ', $whereConditions);

try {
    $sql = rex_sql::factory();
    
    // Gesamtanzahl für Pagination
    $countQuery = "SELECT COUNT(*) as total FROM " . rex::getTable('upkeep_ips_threat_log') . " {$whereClause}";
    $sql->setQuery($countQuery, $whereParams);
    $totalThreats = (int) $sql->getValue('total');
    
    // Threats laden
    $query = "SELECT * FROM " . rex::getTable('upkeep_ips_threat_log') . " {$whereClause} ORDER BY created_at DESC LIMIT {$limit} OFFSET {$offset}";
    $sql->setQuery($query, $whereParams);
    
    $threats = [];
    while ($sql->hasNext()) {
        $threats[] = [
            'id' => (int) $sql->getValue('id'),
            'ip_address' => $sql->getValue('ip_address'),
            'threat_type' => $sql->getValue('threat_type'),
            'threat_category' => $sql->getValue('threat_category'),
            'pattern_matched' => $sql->getValue('pattern_matched'),
            'severity' => $sql->getValue('severity'),
            'action_taken' => $sql->getValue('action_taken'),
            'request_uri' => $sql->getValue('request_uri'),
            'user_agent' => $sql->getValue('user_agent'),
            'created_at' => $sql->getValue('created_at')
        ];
        $sql->next();
    }
    
} catch (Exception $e) {
    $threats = [];
    $totalThreats = 0;
    echo rex_view::error('Fehler beim Laden der Threats: ' . $e->getMessage());
}

// Statistiken Panel
if (!empty($threats)) {
    $content = '<div class="row">';
    
    // Grundstatistiken
    $content .= '<div class="col-md-3">';
    $content .= '<div class="panel panel-info">';
    $content .= '<div class="panel-body text-center">';
    $content .= '<h3>' . $totalThreats . '</h3>';
    $content .= '<p>Gesamt-Threats</p>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
    
    // Schweregrad-Verteilung
    $severityStats = [];
    foreach ($threats as $threat) {
        $severity = $threat['severity'];
        $severityStats[$severity] = ($severityStats[$severity] ?? 0) + 1;
    }
    
    foreach (['critical' => 'Kritisch', 'high' => 'Hoch', 'medium' => 'Mittel'] as $severity => $label) {
        if (isset($severityStats[$severity])) {
            $class = match($severity) {
                'critical' => 'danger',
                'high' => 'warning',
                'medium' => 'info',
                default => 'default'
            };
            
            $content .= '<div class="col-md-3">';
            $content .= '<div class="panel panel-' . $class . '">';
            $content .= '<div class="panel-body text-center">';
            $content .= '<h3>' . $severityStats[$severity] . '</h3>';
            $content .= '<p>' . $label . '</p>';
            $content .= '</div>';
            $content .= '</div>';
            $content .= '</div>';
        }
    }
    
    $content .= '</div>';
    
    $fragment = new rex_fragment();
    $fragment->setVar('title', 'Statistiken', false);
    $fragment->setVar('body', $content, false);
    echo $fragment->parse('core/page/section.php');
}

// Threats-Liste
if (!empty($threats)) {
    $content = '<div class="panel panel-default">';
    $content .= '<div class="panel-heading">';
    $content .= '<h3 class="panel-title"><i class="fa fa-exclamation-triangle"></i> Mail Security Threats (' . $totalThreats . ' gesamt, Seite ' . $page . ')</h3>';
    $content .= '</div>';
    
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr>';
    $content .= '<th>Zeit</th>';
    $content .= '<th>IP-Adresse</th>';
    $content .= '<th>Bedrohungstyp</th>';
    $content .= '<th>Pattern</th>';
    $content .= '<th>Schweregrad</th>';
    $content .= '<th>Aktion</th>';
    $content .= '<th>Details</th>';
    $content .= '</tr>';
    $content .= '</thead>';
    $content .= '<tbody>';
    
    foreach ($threats as $threat) {
        $severityClass = match($threat['severity']) {
            'critical' => 'danger',
            'high' => 'warning',
            'medium' => 'info',
            default => 'default'
        };
        
        $threatTypeDisplay = str_replace('mail_', '', $threat['threat_type']);
        $threatTypeDisplay = ucwords(str_replace('_', ' ', $threatTypeDisplay));
        
        $content .= '<tr>';
        $content .= '<td>' . rex_formatter::strftime(strtotime($threat['created_at']), 'datetime') . '</td>';
        $content .= '<td><code>' . rex_escape($threat['ip_address']) . '</code></td>';
        $content .= '<td>' . rex_escape($threatTypeDisplay) . '</td>';
        $content .= '<td><code>' . rex_escape(substr($threat['pattern_matched'], 0, 50)) . (strlen($threat['pattern_matched']) > 50 ? '...' : '') . '</code></td>';
        $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($threat['severity']) . '</span></td>';
        $content .= '<td>' . rex_escape($threat['action_taken']) . '</td>';
        $content .= '<td><a href="' . rex_url::currentBackendPage(['threat_id' => $threat['id']]) . '" class="btn btn-xs btn-primary">Details</a></td>';
        $content .= '</tr>';
    }
    
    $content .= '</tbody>';
    $content .= '</table>';
    $content .= '</div>';
    
    // Pagination
    if ($totalThreats > $limit) {
        $totalPages = ceil($totalThreats / $limit);
        
        $content .= '<div class="panel-footer">';
        $content .= '<nav aria-label="Threat pagination">';
        $content .= '<ul class="pagination">';
        
        // Previous
        if ($page > 1) {
            $prevParams = array_merge($_GET, ['page' => $page - 1]);
            $content .= '<li><a href="' . rex_url::currentBackendPage($prevParams) . '">&laquo; Zurück</a></li>';
        }
        
        // Pages
        $startPage = max(1, $page - 5);
        $endPage = min($totalPages, $page + 5);
        
        for ($i = $startPage; $i <= $endPage; $i++) {
            $pageParams = array_merge($_GET, ['page' => $i]);
            $activeClass = ($i === $page) ? ' class="active"' : '';
            $content .= '<li' . $activeClass . '><a href="' . rex_url::currentBackendPage($pageParams) . '">' . $i . '</a></li>';
        }
        
        // Next
        if ($page < $totalPages) {
            $nextParams = array_merge($_GET, ['page' => $page + 1]);
            $content .= '<li><a href="' . rex_url::currentBackendPage($nextParams) . '">Weiter &raquo;</a></li>';
        }
        
        $content .= '</ul>';
        $content .= '</nav>';
        $content .= '<p class="text-muted">Zeige ' . (($page - 1) * $limit + 1) . ' - ' . min($page * $limit, $totalThreats) . ' von ' . $totalThreats . ' Threats</p>';
        $content .= '</div>';
    }
    
    $content .= '</div>';
    
} else {
    $content = '<div class="alert alert-info">';
    $content .= '<h4>Keine Threats gefunden</h4>';
    $content .= '<p>Es wurden keine Mail Security Threats gefunden oder Ihre Filter haben keine Ergebnisse geliefert.</p>';
    $content .= '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');