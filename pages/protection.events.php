<?php

/**
 * Upkeep 3.0 – Schutz: Ereignisse (IPS-Bedrohungsprotokoll).
 *
 * Nur lesend: Filter per GET, keine Zustandsänderungen auf dieser Seite.
 */

use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$isAdmin = rex::requireUser()->isAdmin();
$pageKey = 'upkeep/protection/events';
$table = rex::getTable('upkeep_ips_threat_log');
$perPage = 25;
$severities = ['low', 'medium', 'high', 'critical'];

// Kopf
$ipsOn = (bool) $addon->getConfig('ips_active', false);
$actions = Ui::badge($t($ipsOn ? 'upkeep_list_ips_on' : 'upkeep_list_ips_off'), $ipsOn ? 'ok' : 'muted');
if ($ipsOn && $addon->getConfig('ips_monitor_only', false)) {
    $actions .= ' ' . Ui::badge($t('upkeep_set_ips_monitor_only'), 'info');
}
if ($isAdmin) {
    $actions .= ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '">' . rex_escape($t('upkeep_nav_settings')) . '</a>';
}
echo Ui::hero($t('upkeep_nav_protection_events'), $t('upkeep_list_events_intro'), Ui::icon('fa-shield', 'blue'), $actions);

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
$stats = ['today' => 0, 'week' => 0, 'blocked' => 0];
try {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT COUNT(*) AS total FROM ' . $table . $whereSql, $params);
    $total = (int) $sql->getValue('total');
    $pages = max(1, (int) ceil($total / $perPage));
    $current = min(max(1, rex_get('p', 'int', 1)), $pages);
    $offset = ($current - 1) * $perPage;
    $rows = $sql->getArray('SELECT * FROM ' . $table . $whereSql . ' ORDER BY created_at DESC LIMIT ' . (int) $perPage . ' OFFSET ' . (int) $offset, $params);

    // Kennzahlen (einfache Zählungen)
    $sql->setQuery('SELECT COUNT(*) AS c FROM ' . $table . ' WHERE created_at >= ?', [date('Y-m-d 00:00:00')]);
    $stats['today'] = (int) $sql->getValue('c');
    $sql->setQuery('SELECT COUNT(*) AS c FROM ' . $table . ' WHERE created_at >= ?', [date('Y-m-d 00:00:00', strtotime('-6 days'))]);
    $stats['week'] = (int) $sql->getValue('c');
    $sql->setQuery('SELECT COUNT(*) AS c FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE expires_at IS NULL OR expires_at > NOW()');
    $stats['blocked'] = (int) $sql->getValue('c');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

$stat = static fn (string $title, string $icon, string $color, int $value, string $foot = ''): string => Ui::tile($title, Ui::icon($icon, $color), '<div class="upk-tile-value">' . $value . '</div>', $foot, 'upk-tile--stat');
echo '<div class="upk-tiles upk-tiles--stats">'
    . $stat($t('upkeep_list_stat_today'), 'fa-clock-o', 'blue', $stats['today'])
    . $stat($t('upkeep_list_stat_week'), 'fa-calendar', 'indigo', $stats['week'])
    . $stat($t('upkeep_nav_protection_blocked'), 'fa-ban', 'red', $stats['blocked'], '<a href="' . rex_url::backendPage('upkeep/protection/blocked') . '">' . rex_escape($t('upkeep_list_show')) . '</a>')
    . '</div>';

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

$actionBadge = static function (string $action): string {
    $variant = match ($action) {
        'permanent_block' => 'danger',
        'temporary_block', 'blocked' => 'warn',
        default => 'muted',
    };
    return Ui::badge($action ?: '-', $variant);
};

// Filterleiste
$filterParams = array_filter(['ip' => $ipFilter, 'severity' => $severityFilter, 'type' => $typeFilter, 'from' => $dateFrom, 'to' => $dateTo], static fn ($v) => $v !== '');

$filter = '<form class="upk-group upk-filterbar" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '">';
$filter .= '<label class="sr-only" for="upk-ev-ip">' . rex_escape($t('upkeep_ips_ip')) . '</label>'
    . '<input type="search" class="form-control upk-filterbar-text" id="upk-ev-ip" name="ip" maxlength="64" placeholder="' . rex_escape($t('upkeep_ips_ip')) . '" value="' . rex_escape($ipFilter) . '">';
$filter .= '<label class="sr-only" for="upk-ev-type">' . rex_escape($t('upkeep_ips_threat_type')) . '</label>'
    . '<input type="search" class="form-control upk-filterbar-text" id="upk-ev-type" name="type" maxlength="64" placeholder="' . rex_escape($t('upkeep_ips_threat_type')) . '" value="' . rex_escape($typeFilter) . '">';
$filter .= '<label class="sr-only" for="upk-ev-sev">' . rex_escape($t('upkeep_ips_severity')) . '</label>'
    . '<select class="form-control" id="upk-ev-sev" name="severity"><option value="">' . rex_escape($t('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($severityFilter === $sev ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="upk-filterbar-field" for="upk-ev-from"><span>' . rex_escape($t('upkeep_pages_date_from')) . '</span>'
    . '<input type="date" class="form-control" id="upk-ev-from" name="from" value="' . rex_escape($dateFrom) . '"></label>';
$filter .= '<label class="upk-filterbar-field" for="upk-ev-to"><span>' . rex_escape($t('upkeep_pages_date_to')) . '</span>'
    . '<input type="date" class="form-control" id="upk-ev-to" name="to" value="' . rex_escape($dateTo) . '"></label>';
$filter .= '<span class="upk-filterbar-end">';
if ($filterParams) {
    $filter .= '<a class="upk-filterbar-reset" href="' . rex_url::backendPage($pageKey) . '">' . rex_escape($t('upkeep_reset')) . '</a>';
}
$filter .= '<button type="submit" class="btn btn-primary"><i class="rex-icon fa-search" aria-hidden="true"></i> ' . rex_escape($t('upkeep_filter')) . '</button></span>';
$filter .= '</form>';
echo $filter;

echo Ui::listTitle($t('upkeep_ips_threat_log'), $total);

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t($filterParams ? 'upkeep_pages_no_match' : 'upkeep_ips_no_threats'), $filterParams ? 'fa-filter' : 'fa-check') . '</div>';
    return;
}

$labels = [
    'time' => $t('upkeep_ips_time'),
    'ip' => $t('upkeep_ips_ip'),
    'country' => $t('upkeep_pages_country'),
    'type' => $t('upkeep_ips_threat_type'),
    'severity' => $t('upkeep_ips_severity'),
    'pattern' => $t('upkeep_ips_pattern'),
    'uri' => $t('upkeep_ips_uri'),
    'action' => $t('upkeep_ips_action'),
];
if (!$geoAvailable) {
    unset($labels['country']);
}

$body = '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
foreach ($labels as $label) {
    $body .= '<th scope="col">' . rex_escape($label) . '</th>';
}
$body .= '</tr></thead><tbody>';
foreach ($rows as $row) {
    $ip = (string) $row['ip_address'];
    $pattern = (string) ($row['pattern_matched'] ?? '');
    $uri = (string) ($row['request_uri'] ?? '');
    $time = strtotime((string) $row['created_at']);
    $body .= '<tr>';
    $body .= Ui::td($labels['time'], rex_escape($time ? date('d.m.Y H:i', $time) : '-'), 'upk-nowrap');
    $body .= Ui::td($labels['ip'], '<span class="upk-mono">' . rex_escape($ip) . '</span>');
    if ($geoAvailable) {
        $body .= Ui::td($labels['country'], '<span class="upk-muted">' . rex_escape($country($ip) ?: '-') . '</span>');
    }
    $body .= Ui::td($labels['type'], rex_escape((string) $row['threat_type']));
    $body .= Ui::td($labels['severity'], Ui::severity((string) $row['severity']));
    $body .= Ui::td($labels['pattern'], '<span class="upk-mono" title="' . rex_escape($pattern) . '">' . rex_escape(mb_strimwidth($pattern, 0, 50, '…')) . '</span>');
    $body .= Ui::td($labels['uri'], '<span class="upk-mono" title="' . rex_escape($uri) . '">' . rex_escape(mb_strimwidth($uri, 0, 80, '…')) . '</span>');
    $body .= Ui::td($labels['action'], $actionBadge((string) ($row['action_taken'] ?? '')));
    $body .= '</tr>';
}
$body .= '</tbody></table></div>';

$pager = Ui::pager($current, $pages, static fn (int $p): string => rex_url::backendPage($pageKey, $filterParams + ['p' => $p]));
if ('' !== $pager) {
    $body .= '<div class="upk-group-foot">' . $pager . '</div>';
}
$body .= '</div>';
echo $body;
