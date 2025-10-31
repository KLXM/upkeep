<?php

use FriendsOfRedaxo\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

echo rex_view::title($addon->i18n('upkeep_ips_title'));

// Prüfen ob IPS-Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery("SHOW TABLES LIKE ?", [rex::getTable('upkeep_ips_blocked_ips')]);
    $tableExists = $sql->getRows() > 0;
} catch (Exception $e) {
    $tableExists = false;
}

if (!$tableExists) {
    echo '<div class="alert alert-warning">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> IPS-Datenbanktabellen fehlen</h4>';
    echo '<p>Die Intrusion Prevention System Tabellen wurden noch nicht erstellt.</p>';
    echo '<p>Bitte installieren Sie das Upkeep AddOn erneut über das Backend: <strong>AddOns → Upkeep → Reinstall</strong></p>';
    echo '<div style="margin-top: 15px;">';
    echo '<a href="' . rex_url::backendPage('packages') . '" class="btn btn-primary">';
    echo '<i class="fa fa-cog"></i> Zu den AddOns';
    echo '</a>';
    echo '</div>';
    echo '</div>';
    return;
}

$stats = IntrusionPrevention::getStatistics();

// Dashboard Cards
$cards = [];

// Gesperrte IPs
$cards[] = [
    'title' => $addon->i18n('upkeep_ips_blocked_count'),
    'value' => $stats['blocked_ips'],
    'icon' => 'fa-shield',
    'color' => $stats['blocked_ips'] > 0 ? 'danger' : 'success'
];

// Bedrohungen heute
$cards[] = [
    'title' => $addon->i18n('upkeep_ips_threats_today'),
    'value' => $stats['threats_today'],
    'icon' => 'fa-exclamation-triangle',
    'color' => $stats['threats_today'] > 10 ? 'danger' : ($stats['threats_today'] > 0 ? 'warning' : 'success')
];

// Bedrohungen diese Woche
$cards[] = [
    'title' => $addon->i18n('upkeep_ips_threats_week'),
    'value' => $stats['threats_week'],
    'icon' => 'fa-chart-line',
    'color' => $stats['threats_week'] > 50 ? 'danger' : 'info'
];

// Status
$isActive = (bool) $addon->getConfig('ips_active', false);
$cards[] = [
    'title' => $addon->i18n('upkeep_ips_status'),
    'value' => $isActive ? $addon->i18n('upkeep_active') : $addon->i18n('upkeep_inactive'),
    'icon' => $isActive ? 'fa-check-circle' : 'fa-times-circle',
    'color' => $isActive ? 'success' : 'danger'
];

// Dashboard rendern
echo '<div class="row">';
foreach ($cards as $card) {
    echo '<div class="col-sm-6 col-md-3">';
    echo '<div class="panel panel-' . $card['color'] . '">';
    echo '<div class="panel-body">';
    echo '<div class="row">';
    echo '<div class="col-xs-3">';
    echo '<i class="fa ' . $card['icon'] . ' fa-3x"></i>';
    echo '</div>';
    echo '<div class="col-xs-9 text-right">';
    echo '<div class="huge">' . $card['value'] . '</div>';
    echo '<div>' . $card['title'] . '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
}
echo '</div>';

// Top Bedrohungen
if (!empty($stats['top_threats'])) {
    echo '<div class="panel panel-default">';
    echo '<div class="panel-heading">';
    echo '<i class="fa fa-list"></i> ' . $addon->i18n('upkeep_ips_top_threats');
    echo '</div>';
    echo '<div class="panel-body">';
    echo '<div class="table-responsive">';
    echo '<table class="table table-striped">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . $addon->i18n('upkeep_ips_threat_type') . '</th>';
    echo '<th class="text-right">' . $addon->i18n('upkeep_ips_count') . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';
    
    foreach ($stats['top_threats'] as $threat) {
        echo '<tr>';
        echo '<td>' . rex_escape($threat['type']) . '</td>';
        echo '<td class="text-right"><span class="badge">' . $threat['count'] . '</span></td>';
        echo '</tr>';
    }
    
    echo '</tbody>';
    echo '</table>';
    echo '</div>';
    echo '</div>';
    echo '</div>';
}

// Schnellaktionen
echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-cogs"></i> ' . $addon->i18n('upkeep_ips_quick_actions');
echo '</div>';
echo '<div class="panel-body">';

$actions = [
    [
        'url' => rex_url::currentBackendPage(['subpage' => 'threats']),
        'title' => $addon->i18n('upkeep_ips_view_threats'),
        'icon' => 'fa-exclamation-triangle',
        'class' => 'btn-warning'
    ],
    [
        'url' => rex_url::currentBackendPage(['subpage' => 'blocked']),
        'title' => $addon->i18n('upkeep_ips_manage_blocked'),
        'icon' => 'fa-shield',
        'class' => 'btn-danger'
    ],
    [
        'url' => rex_url::currentBackendPage(['subpage' => 'patterns']),
        'title' => $addon->i18n('upkeep_ips_manage_patterns'),
        'icon' => 'fa-code',
        'class' => 'btn-info'
    ],
    [
        'url' => rex_url::currentBackendPage(['subpage' => 'settings']),
        'title' => $addon->i18n('upkeep_ips_settings'),
        'icon' => 'fa-cog',
        'class' => 'btn-default'
    ]
];

foreach ($actions as $action) {
    echo '<a href="' . $action['url'] . '" class="btn ' . $action['class'] . ' btn-lg" style="margin-right: 10px; margin-bottom: 10px;">';
    echo '<i class="' . $action['icon'] . '"></i> ' . $action['title'];
    echo '</a>';
}

echo '</div>';
echo '</div>';

// Systeminfo
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> ' . $addon->i18n('upkeep_ips_system_info');
echo '</div>';
echo '<div class="panel-body">';
echo '<dl class="dl-horizontal">';
echo '<dt>' . $addon->i18n('upkeep_ips_version') . ':</dt>';
echo '<dd>' . $addon->getVersion() . '</dd>';
echo '<dt>' . $addon->i18n('upkeep_ips_patterns_count') . ':</dt>';
echo '<dd>' . count(IntrusionPrevention::getCustomPatterns()) . '</dd>';
echo '<dt>' . $addon->i18n('upkeep_ips_last_update') . ':</dt>';
echo '<dd>' . date('d.m.Y H:i:s') . '</dd>';
echo '</dl>';
echo '</div>';
echo '</div>';


