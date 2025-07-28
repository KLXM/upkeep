<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Prüfen ob IPS-Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery("SHOW TABLES LIKE ?", [rex::getTable('upkeep_ips_threat_log')]);
    $tableExists = $sql->getRows() > 0;
} catch (Exception $e) {
    $tableExists = false;
}

if (!$tableExists) {
    echo '<div class="alert alert-warning">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> IPS-Datenbanktabellen fehlen</h4>';
    echo '<p>Die Intrusion Prevention System Tabellen wurden noch nicht erstellt.</p>';
    echo '<p>Bitte installieren Sie das Upkeep AddOn erneut über das Backend.</p>';
    echo '</div>';
    return;
}

// Filter verarbeiten
$ipFilter = rex_get('ip_filter', 'string', '');
$severityFilter = rex_get('severity_filter', 'string', '');
$typeFilter = rex_get('type_filter', 'string', '');
$dateFrom = rex_get('date_from', 'string', '');
$dateTo = rex_get('date_to', 'string', '');

// SQL Query zusammenbauen
$where = [];
$params = [];

if (!empty($ipFilter)) {
    $where[] = 'ip_address LIKE ?';
    $params[] = '%' . $ipFilter . '%';
}

if (!empty($severityFilter)) {
    $where[] = 'severity = ?';
    $params[] = $severityFilter;
}

if (!empty($typeFilter)) {
    $where[] = 'threat_type LIKE ?';
    $params[] = '%' . $typeFilter . '%';
}

if (!empty($dateFrom)) {
    $where[] = 'DATE(created_at) >= ?';
    $params[] = $dateFrom;
}

if (!empty($dateTo)) {
    $where[] = 'DATE(created_at) <= ?';
    $params[] = $dateTo;
}

$whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';

// Paginierung
$page = rex_get('page_num', 'int', 1);
$perPage = 25;
$offset = ($page - 1) * $perPage;

// Gesamtanzahl ermitteln
$countQuery = "SELECT COUNT(*) as total FROM " . rex::getTable('upkeep_ips_threat_log') . " " . $whereClause;
$sql->setQuery($countQuery, $params);
$totalRows = $sql->getValue('total');
$totalPages = ceil($totalRows / $perPage);

// Daten laden
$query = "SELECT * FROM " . rex::getTable('upkeep_ips_threat_log') . " " . $whereClause . " 
          ORDER BY created_at DESC LIMIT {$perPage} OFFSET {$offset}";
$sql->setQuery($query, $params);

// Filter-Formular
echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-filter"></i> ' . $addon->i18n('upkeep_ips_filter');
echo '</div>';
echo '<div class="panel-body">';

echo '<form method="get" class="form-inline">';
echo '<input type="hidden" name="page" value="upkeep">';
echo '<input type="hidden" name="subpage" value="ips">';
echo '<input type="hidden" name="subpage2" value="threats">';

echo '<div class="form-group" style="margin-right: 10px;">';
echo '<label class="sr-only" for="ip_filter">IP-Adresse</label>';
echo '<input type="text" class="form-control" id="ip_filter" name="ip_filter" placeholder="IP-Adresse" value="' . rex_escape($ipFilter) . '">';
echo '</div>';

echo '<div class="form-group" style="margin-right: 10px;">';
echo '<label class="sr-only" for="severity_filter">Schweregrad</label>';
echo '<select class="form-control" id="severity_filter" name="severity_filter">';
echo '<option value="">Alle Schweregrade</option>';
echo '<option value="low"' . ($severityFilter === 'low' ? ' selected' : '') . '>Niedrig</option>';
echo '<option value="medium"' . ($severityFilter === 'medium' ? ' selected' : '') . '>Mittel</option>';
echo '<option value="high"' . ($severityFilter === 'high' ? ' selected' : '') . '>Hoch</option>';
echo '<option value="critical"' . ($severityFilter === 'critical' ? ' selected' : '') . '>Kritisch</option>';
echo '</select>';
echo '</div>';

echo '<div class="form-group" style="margin-right: 10px;">';
echo '<label class="sr-only" for="type_filter">Bedrohungstyp</label>';
echo '<input type="text" class="form-control" id="type_filter" name="type_filter" placeholder="Bedrohungstyp" value="' . rex_escape($typeFilter) . '">';
echo '</div>';

echo '<div class="form-group" style="margin-right: 10px;">';
echo '<label class="sr-only" for="date_from">Von Datum</label>';
echo '<input type="date" class="form-control" id="date_from" name="date_from" value="' . rex_escape($dateFrom) . '">';
echo '</div>';

echo '<div class="form-group" style="margin-right: 10px;">';
echo '<label class="sr-only" for="date_to">Bis Datum</label>';
echo '<input type="date" class="form-control" id="date_to" name="date_to" value="' . rex_escape($dateTo) . '">';
echo '</div>';

echo '<button type="submit" class="btn btn-primary"><i class="fa fa-search"></i> Filter</button>';
echo ' <a href="' . rex_url::currentBackendPage() . '" class="btn btn-default"><i class="fa fa-refresh"></i> Zurücksetzen</a>';

echo '</form>';
echo '</div>';
echo '</div>';

// Statistiken anzeigen
if ($totalRows > 0) {
    echo '<div class="alert alert-info">';
    echo '<i class="fa fa-info-circle"></i> ';
    echo "Zeige {$totalRows} Ergebnisse (" . ($offset + 1) . " - " . min($offset + $perPage, $totalRows) . ")";
    echo '</div>';
}

// Bedrohungslog-Tabelle
echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_ips_threat_log');
echo '</div>';

if ($sql->getRows() > 0) {
    echo '<div class="table-responsive">';
    echo '<table class="table table-striped table-hover">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . $addon->i18n('upkeep_ips_time') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_ip') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_threat_type') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_severity') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_pattern') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_uri') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_action') . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';
    
    while ($sql->hasNext()) {
        $createdAt = $sql->getValue('created_at');
        $ipAddress = $sql->getValue('ip_address');
        $threatType = $sql->getValue('threat_type');
        $severity = $sql->getValue('severity');
        $pattern = $sql->getValue('pattern_matched');
        $requestUri = $sql->getValue('request_uri');
        $actionTaken = $sql->getValue('action_taken');
        
        echo '<tr>';
        echo '<td>' . rex_formatter::date($createdAt, 'datetime') . '</td>';
        echo '<td><span class="label label-default">' . rex_escape($ipAddress) . '</span></td>';
        echo '<td><span class="label label-default">' . rex_escape($threatType) . '</span></td>';
        echo '<td>';
        
        $severityClass = match($severity) {
            'critical' => 'label-danger',
            'high' => 'label-warning',
            'medium' => 'label-info',
            'low' => 'label-default',
            default => 'label-default'
        };
        echo '<span class="label ' . $severityClass . '">' . rex_escape(ucfirst($severity)) . '</span>';
        echo '</td>';
        echo '<td><span class="text-monospace small">' . rex_escape(substr($pattern, 0, 50)) . (strlen($pattern) > 50 ? '...' : '') . '</span></td>';
        echo '<td><span class="text-monospace small">' . rex_escape(substr($requestUri, 0, 100)) . (strlen($requestUri) > 100 ? '...' : '') . '</span></td>';
        echo '<td>';
        
        $actionClass = match($actionTaken) {
            'permanent_block' => 'label-danger',
            'temporary_block' => 'label-warning',
            'logged' => 'label-info',
            default => 'label-default'
        };
        echo '<span class="label ' . $actionClass . '">' . rex_escape($actionTaken) . '</span>';
        echo '</td>';
        echo '</tr>';
        
        $sql->next();
    }
    
    echo '</tbody>';
    echo '</table>';
    echo '</div>';
    
} else {
    echo '<div class="panel-body">';
    echo '<p class="text-muted">' . $addon->i18n('upkeep_ips_no_threats') . '</p>';
    echo '</div>';
}

echo '</div>';
