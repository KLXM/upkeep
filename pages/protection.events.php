<?php

/**
 * Upkeep 3.0 – Schutz: Ereignisse (IPS-Bedrohungsprotokoll).
 *
 * Nur lesend: Filter per GET, keine Zustandsänderungen auf dieser Seite.
 */

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');
$pageKey = 'upkeep/protection/events';
$table = rex::getTable('upkeep_ips_threat_log');
$perPage = 25;
$severities = ['low', 'medium', 'high', 'critical'];

// Filter (GET, validiert)
$ipFilter = mb_substr(trim(rex_get('ip', 'string', '')), 0, 64);
$severityFilter = rex_get('severity', 'string', '');
if (!in_array($severityFilter, $severities, true)) {
    $severityFilter = '';
}
$typeFilter = mb_substr(trim(rex_get('type', 'string', '')), 0, 64);
$isDate = static fn (string $d): bool => (bool) preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) && checkdate((int) substr($d, 5, 2), (int) substr($d, 8, 2), (int) substr($d, 0, 4));
$dateFrom = rex_get('from', 'string', '');
$dateFrom = $isDate($dateFrom) ? $dateFrom : '';
$dateTo = rex_get('to', 'string', '');
$dateTo = $isDate($dateTo) ? $dateTo : '';

$where = [];
$params = [];
if ($ipFilter !== '') {
    $where[] = 'ip_address LIKE ?';
    $params[] = '%' . addcslashes($ipFilter, '%_\\') . '%';
}
if ($severityFilter !== '') {
    $where[] = 'severity = ?';
    $params[] = $severityFilter;
}
if ($typeFilter !== '') {
    $where[] = 'threat_type LIKE ?';
    $params[] = '%' . addcslashes($typeFilter, '%_\\') . '%';
}
if ($dateFrom !== '') {
    $where[] = 'created_at >= ?';
    $params[] = $dateFrom . ' 00:00:00';
}
if ($dateTo !== '') {
    $where[] = 'created_at < ?';
    $params[] = date('Y-m-d', strtotime($dateTo . ' +1 day')) . ' 00:00:00';
}
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';

$total = 0;
$rows = [];
try {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT COUNT(*) AS total FROM ' . $table . $whereSql, $params);
    $total = (int) $sql->getValue('total');
    $pages = max(1, (int) ceil($total / $perPage));
    $current = min(max(1, rex_get('p', 'int', 1)), $pages);
    $offset = ($current - 1) * $perPage;
    $rows = $sql->getArray('SELECT * FROM ' . $table . $whereSql . ' ORDER BY created_at DESC LIMIT ' . (int) $perPage . ' OFFSET ' . (int) $offset, $params);
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

// Länderinfo nur, wenn die GeoIP-Datenbank schon vorhanden ist (kein Download beim Seitenaufruf)
$geoAvailable = is_file(rex_path::addonData('upkeep', 'ip2geo.mmdb'));
$countryCache = [];
$country = static function (string $ip) use ($geoAvailable, &$countryCache): string {
    if (!$geoAvailable || $ip === '') {
        return '';
    }
    if (!array_key_exists($ip, $countryCache)) {
        $countryCache[$ip] = '';
        try {
            $info = IntrusionPrevention::getCountryByIp($ip);
            if (($info['code'] ?? 'UNKNOWN') !== 'UNKNOWN') {
                $countryCache[$ip] = (string) ($info['name'] ?? '');
            }
        } catch (Throwable $e) {
            // Länderinfo ist optional
        }
    }
    return $countryCache[$ip];
};

$severityBadge = static function (string $severity) use ($addon): string {
    $class = match ($severity) {
        'critical' => 'upk-badge--danger',
        'high' => 'upk-badge--warn',
        'medium' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $addon->i18n('upkeep_ips_severity_' . $severity) : ($severity ?: '-');
    return '<span class="upk-badge ' . $class . '">' . rex_escape($label) . '</span>';
};

$actionBadge = static function (string $action): string {
    $class = match ($action) {
        'permanent_block' => 'upk-badge--danger',
        'temporary_block', 'blocked' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    return '<span class="upk-badge ' . $class . '">' . rex_escape($action ?: '-') . '</span>';
};

// Filterformular
$filterParams = array_filter(['ip' => $ipFilter, 'severity' => $severityFilter, 'type' => $typeFilter, 'from' => $dateFrom, 'to' => $dateTo], static fn ($v) => $v !== '');

$filter = '<form class="upk-filter form-inline" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '">';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-ev-ip">' . rex_escape($addon->i18n('upkeep_ips_ip')) . '</label>'
    . '<input type="text" class="form-control" id="upk-ev-ip" name="ip" maxlength="64" placeholder="' . rex_escape($addon->i18n('upkeep_ips_ip')) . '" value="' . rex_escape($ipFilter) . '"></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-ev-sev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label>'
    . '<select class="form-control" id="upk-ev-sev" name="severity"><option value="">' . rex_escape($addon->i18n('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($severityFilter === $sev ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-ev-type">' . rex_escape($addon->i18n('upkeep_ips_threat_type')) . '</label>'
    . '<input type="text" class="form-control" id="upk-ev-type" name="type" maxlength="64" placeholder="' . rex_escape($addon->i18n('upkeep_ips_threat_type')) . '" value="' . rex_escape($typeFilter) . '"></div> ';
$filter .= '<div class="form-group"><label for="upk-ev-from">' . rex_escape($addon->i18n('upkeep_pages_date_from')) . '</label> '
    . '<input type="date" class="form-control" id="upk-ev-from" name="from" value="' . rex_escape($dateFrom) . '"></div> ';
$filter .= '<div class="form-group"><label for="upk-ev-to">' . rex_escape($addon->i18n('upkeep_pages_date_to')) . '</label> '
    . '<input type="date" class="form-control" id="upk-ev-to" name="to" value="' . rex_escape($dateTo) . '"></div> ';
$filter .= '<button type="submit" class="btn btn-default"><i class="rex-icon fa-search"></i> ' . rex_escape($addon->i18n('upkeep_filter')) . '</button> ';
if ($filterParams) {
    $filter .= '<a class="btn btn-link" href="' . rex_url::backendPage($pageKey) . '">' . rex_escape($addon->i18n('upkeep_reset')) . '</a>';
}
$filter .= '</form>';

$toolbar = '<div class="upk-toolbar">'
    . '<span class="upk-muted">' . rex_escape($addon->i18n('upkeep_pages_entries_total', $total)) . '</span> '
    . '<a href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '"><i class="rex-icon fa-cog"></i> ' . rex_escape($addon->i18n('upkeep_pages_settings_link')) . '</a>'
    . '</div>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_ips_no_threats')) . '</p></div>';
} else {
    $body = '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_time')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_ip')) . '</th>';
    if ($geoAvailable) {
        $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_country')) . '</th>';
    }
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_threat_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_pattern')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_uri')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_action')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $ip = (string) $row['ip_address'];
        $pattern = (string) ($row['pattern_matched'] ?? '');
        $uri = (string) ($row['request_uri'] ?? '');
        $time = strtotime((string) $row['created_at']);
        $body .= '<tr>';
        $body .= '<td>' . rex_escape($time ? date('d.m.Y H:i', $time) : '-') . '</td>';
        $body .= '<td><span class="upk-mono">' . rex_escape($ip) . '</span></td>';
        if ($geoAvailable) {
            $body .= '<td><span class="upk-muted">' . rex_escape($country($ip) ?: '-') . '</span></td>';
        }
        $body .= '<td>' . rex_escape((string) $row['threat_type']) . '</td>';
        $body .= '<td>' . $severityBadge((string) $row['severity']) . '</td>';
        $body .= '<td><span class="upk-mono" title="' . rex_escape($pattern) . '">' . rex_escape(mb_strimwidth($pattern, 0, 50, '…')) . '</span></td>';
        $body .= '<td><span class="upk-mono" title="' . rex_escape($uri) . '">' . rex_escape(mb_strimwidth($uri, 0, 80, '…')) . '</span></td>';
        $body .= '<td>' . $actionBadge((string) ($row['action_taken'] ?? '')) . '</td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';

    if ($pages > 1) {
        $link = static fn (int $p): string => rex_url::backendPage($pageKey, $filterParams + ['p' => $p]);
        $body .= '<nav><ul class="pagination pagination-sm">';
        $body .= $current > 1 ? '<li><a href="' . $link($current - 1) . '" aria-label="' . rex_escape($addon->i18n('upkeep_previous')) . '">&laquo;</a></li>' : '<li class="disabled"><span>&laquo;</span></li>';
        for ($i = max(1, $current - 3); $i <= min($pages, $current + 3); ++$i) {
            $body .= $i === $current ? '<li class="active"><span>' . $i . '</span></li>' : '<li><a href="' . $link($i) . '">' . $i . '</a></li>';
        }
        $body .= $current < $pages ? '<li><a href="' . $link($current + 1) . '" aria-label="' . rex_escape($addon->i18n('upkeep_next')) . '">&raquo;</a></li>' : '<li class="disabled"><span>&raquo;</span></li>';
        $body .= '</ul></nav>';
    }
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_ips_threat_log'), false);
$fragment->setVar('body', $toolbar . $filter . $body, false);
echo $fragment->parse('core/page/section.php');
