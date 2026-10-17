<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Ereignisse (nur lesend).
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

use KLXM\Upkeep\Ui;

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$table = rex::getTable('upkeep_ips_threat_log');
$perPage = 50;
$severities = ['low', 'medium', 'high', 'critical'];

$typeLabel = static fn (string $type): string => ucwords(str_replace('_', ' ', preg_replace('/^mail_/', '', $type)));
$formatTime = static function (?string $value): string {
    $ts = $value ? strtotime($value) : false;
    return $ts ? date('d.m.Y H:i', $ts) : '-';
};

// Detailansicht
$detailId = rex_get('id', 'int', 0);
if ($detailId > 0) {
    try {
        $sql = rex_sql::factory();
        $sql->setQuery('SELECT * FROM ' . $table . ' WHERE id = ? AND threat_type LIKE ?', [$detailId, 'mail\_%']);
        if ($sql->getRows() > 0) {
            $fields = [
                'upkeep_ips_ip_address' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('ip_address')) . '</span>',
                'upkeep_mail_security_threat_type' => rex_escape($typeLabel((string) $sql->getValue('threat_type'))),
                'upkeep_ips_category' => rex_escape((string) $sql->getValue('threat_category')),
                'upkeep_ips_severity' => Ui::severity((string) $sql->getValue('severity')),
                'upkeep_ips_pattern' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('pattern_matched')) . '</span>',
                'upkeep_ips_action' => rex_escape((string) $sql->getValue('action_taken')),
                'upkeep_ips_uri' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('request_uri')) . '</span>',
                'upkeep_mail_events_user_agent' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('user_agent')) . '</span>',
                'upkeep_ips_created_at' => rex_escape($formatTime((string) $sql->getValue('created_at'))),
            ];
            $detailRows = [];
            foreach ($fields as $key => $value) {
                $detailRows[] = '<div class="upk-row upk-row--detail"><div class="upk-row-label"><strong>' . rex_escape($t($key)) . '</strong></div><div class="upk-row-control">' . $value . '</div></div>';
            }
            echo Ui::listTitle($t('upkeep_mail_events_details'))
                . '<div class="upk-group">' . implode('', $detailRows)
                . '<div class="upk-form-actions"><a class="btn btn-default" href="' . $tabUrl() . '">' . rex_escape($t('upkeep_close')) . '</a></div></div>';
        } else {
            echo rex_view::warning(rex_escape($t('upkeep_mail_events_not_found')));
        }
    } catch (rex_sql_exception $e) {
        rex_logger::logException($e);
    }
}

// Filter (GET, validiert)
$filterType = mb_substr(rex_get('type', 'string', ''), 0, 64);
$filterSeverity = rex_get('severity', 'string', '');
$filterSeverity = in_array($filterSeverity, $severities, true) ? $filterSeverity : '';
$filterIp = mb_substr(trim(rex_get('ip', 'string', '')), 0, 64);
$filterDate = rex_get('date', 'string', '');
if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $filterDate) || !checkdate((int) substr($filterDate, 5, 2), (int) substr($filterDate, 8, 2), (int) substr($filterDate, 0, 4))) {
    $filterDate = '';
}

$where = ['threat_type LIKE ?'];
$params = ['mail\_%'];
if ($filterType !== '') {
    $where[] = 'threat_type = ?';
    $params[] = $filterType;
}
if ($filterSeverity !== '') {
    $where[] = 'severity = ?';
    $params[] = $filterSeverity;
}
if ($filterIp !== '') {
    $where[] = 'ip_address LIKE ?';
    $params[] = '%' . addcslashes($filterIp, '%_\\') . '%';
}
if ($filterDate !== '') {
    $where[] = 'created_at >= ? AND created_at < ?';
    $params[] = $filterDate . ' 00:00:00';
    $params[] = date('Y-m-d', strtotime($filterDate . ' +1 day')) . ' 00:00:00';
}
$whereSql = ' WHERE ' . implode(' AND ', $where);

$types = [];
$rows = [];
$total = 0;
try {
    $sql = rex_sql::factory();
    foreach ($sql->getArray('SELECT DISTINCT threat_type FROM ' . $table . ' WHERE threat_type LIKE ? ORDER BY threat_type', ['mail\_%']) as $r) {
        $types[] = (string) $r['threat_type'];
    }
    $sql->setQuery('SELECT COUNT(*) AS total FROM ' . $table . $whereSql, $params);
    $total = (int) $sql->getValue('total');
    $pages = max(1, (int) ceil($total / $perPage));
    $current = min(max(1, rex_get('p', 'int', 1)), $pages);
    $rows = $sql->getArray('SELECT * FROM ' . $table . $whereSql . ' ORDER BY created_at DESC LIMIT ' . (int) $perPage . ' OFFSET ' . (int) (($current - 1) * $perPage), $params);
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

$filterParams = array_filter(['type' => $filterType, 'severity' => $filterSeverity, 'ip' => $filterIp, 'date' => $filterDate], static fn ($v) => $v !== '');

$filter = '<form class="upk-group upk-filterbar" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="events">';
$filter .= '<label class="sr-only" for="upk-me-ip">' . rex_escape($t('upkeep_ips_ip_address')) . '</label><input type="search" class="form-control upk-filterbar-text" id="upk-me-ip" name="ip" maxlength="64" placeholder="' . rex_escape($t('upkeep_ips_ip_address')) . '" value="' . rex_escape($filterIp) . '">';
$filter .= '<label class="sr-only" for="upk-me-type">' . rex_escape($t('upkeep_mail_security_threat_type')) . '</label><select class="form-control" id="upk-me-type" name="type"><option value="">' . rex_escape($t('upkeep_all_types')) . '</option>';
foreach ($types as $type) {
    $filter .= '<option value="' . rex_escape($type) . '"' . ($filterType === $type ? ' selected' : '') . '>' . rex_escape($typeLabel($type)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="sr-only" for="upk-me-sev">' . rex_escape($t('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-me-sev" name="severity"><option value="">' . rex_escape($t('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($filterSeverity === $sev ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="upk-filterbar-field" for="upk-me-date"><span>' . rex_escape($t('upkeep_date')) . '</span><input type="date" class="form-control" id="upk-me-date" name="date" value="' . rex_escape($filterDate) . '"></label>';
$filter .= '<span class="upk-filterbar-end">';
if ($filterParams) {
    $filter .= '<a class="upk-filterbar-reset" href="' . $tabUrl() . '">' . rex_escape($t('upkeep_reset')) . '</a>';
}
$filter .= '<button type="submit" class="btn btn-primary"><i class="rex-icon fa-search" aria-hidden="true"></i> ' . rex_escape($t('upkeep_filter')) . '</button></span>';
$filter .= '</form>';
echo $filter;

echo Ui::listTitle($t('upkeep_mail_security_threats'), $total);

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t($filterParams ? 'upkeep_pages_no_match' : 'upkeep_no_threats_message'), $filterParams ? 'fa-filter' : 'fa-check') . '</div>';
    return;
}

$labels = [
    'time' => $t('upkeep_ips_time'),
    'ip' => $t('upkeep_ips_ip_address'),
    'type' => $t('upkeep_mail_security_threat_type'),
    'pattern' => $t('upkeep_ips_pattern'),
    'severity' => $t('upkeep_ips_severity'),
    'action' => $t('upkeep_ips_action'),
    'actions' => $t('upkeep_details'),
];
$body = '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
foreach ($labels as $key => $label) {
    $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
}
$body .= '</tr></thead><tbody>';
foreach ($rows as $row) {
    $pattern = (string) ($row['pattern_matched'] ?? '');
    $body .= '<tr' . ((int) $row['id'] === $detailId ? ' class="upk-table-current"' : '') . '>';
    $body .= Ui::td($labels['time'], rex_escape($formatTime((string) $row['created_at'])), 'upk-nowrap');
    $body .= Ui::td($labels['ip'], '<span class="upk-mono">' . rex_escape((string) $row['ip_address']) . '</span>');
    $body .= Ui::td($labels['type'], rex_escape($typeLabel((string) $row['threat_type'])));
    $body .= Ui::td($labels['pattern'], '<span class="upk-mono" title="' . rex_escape($pattern) . '">' . rex_escape(mb_strimwidth($pattern, 0, 50, '…')) . '</span>');
    $body .= Ui::td($labels['severity'], Ui::severity((string) $row['severity']));
    $body .= Ui::td($labels['action'], rex_escape((string) ($row['action_taken'] ?? '')));
    $body .= Ui::td($labels['actions'], '<a class="btn btn-xs upk-btn-ghost" href="' . $tabUrl($filterParams + ['id' => (int) $row['id']]) . '">' . rex_escape($t('upkeep_details')) . '</a>', 'upk-actions');
    $body .= '</tr>';
}
$body .= '</tbody></table></div>';
$pager = Ui::pager($current, $pages, static fn (int $p): string => $tabUrl($filterParams + ['p' => $p]));
if ('' !== $pager) {
    $body .= '<div class="upk-group-foot">' . $pager . '</div>';
}
$body .= '</div>';
echo $body;
