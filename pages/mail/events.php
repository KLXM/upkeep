<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Ereignisse (nur lesend).
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

$table = rex::getTable('upkeep_ips_threat_log');
$perPage = 50;
$severities = ['low', 'medium', 'high', 'critical'];

$severityBadge = static function (string $severity) use ($addon): string {
    $class = match ($severity) {
        'critical' => 'upk-badge--danger',
        'high', 'medium' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $addon->i18n('upkeep_ips_severity_' . $severity) : ($severity ?: '-');
    return '<span class="upk-badge ' . $class . '">' . rex_escape($label) . '</span>';
};
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
                'upkeep_ips_severity' => $severityBadge((string) $sql->getValue('severity')),
                'upkeep_ips_pattern' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('pattern_matched')) . '</span>',
                'upkeep_ips_action' => rex_escape((string) $sql->getValue('action_taken')),
                'upkeep_ips_uri' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('request_uri')) . '</span>',
                'upkeep_mail_events_user_agent' => '<span class="upk-mono">' . rex_escape((string) $sql->getValue('user_agent')) . '</span>',
                'upkeep_ips_created_at' => rex_escape($formatTime((string) $sql->getValue('created_at'))),
            ];
            $dl = '<dl class="dl-horizontal">';
            foreach ($fields as $key => $value) {
                $dl .= '<dt>' . rex_escape($addon->i18n($key)) . '</dt><dd>' . $value . '</dd>';
            }
            $dl .= '</dl><p><a class="btn btn-default" href="' . $tabUrl() . '">' . rex_escape($addon->i18n('upkeep_close')) . '</a></p>';

            $fragment = new rex_fragment();
            $fragment->setVar('title', $addon->i18n('upkeep_mail_events_details'), false);
            $fragment->setVar('body', $dl, false);
            echo $fragment->parse('core/page/section.php');
        } else {
            echo rex_view::warning(rex_escape($addon->i18n('upkeep_mail_events_not_found')));
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
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

$filterParams = array_filter(['type' => $filterType, 'severity' => $filterSeverity, 'ip' => $filterIp, 'date' => $filterDate], static fn ($v) => $v !== '');

$filter = '<form class="upk-filter form-inline" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="events">';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-me-type">' . rex_escape($addon->i18n('upkeep_mail_security_threat_type')) . '</label><select class="form-control" id="upk-me-type" name="type"><option value="">' . rex_escape($addon->i18n('upkeep_all_types')) . '</option>';
foreach ($types as $type) {
    $filter .= '<option value="' . rex_escape($type) . '"' . ($filterType === $type ? ' selected' : '') . '>' . rex_escape($typeLabel($type)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-me-sev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-me-sev" name="severity"><option value="">' . rex_escape($addon->i18n('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($filterSeverity === $sev ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-me-ip">' . rex_escape($addon->i18n('upkeep_ips_ip_address')) . '</label><input type="text" class="form-control" id="upk-me-ip" name="ip" maxlength="64" placeholder="' . rex_escape($addon->i18n('upkeep_ips_ip_address')) . '" value="' . rex_escape($filterIp) . '"></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-me-date">' . rex_escape($addon->i18n('upkeep_date')) . '</label><input type="date" class="form-control" id="upk-me-date" name="date" value="' . rex_escape($filterDate) . '"></div> ';
$filter .= '<button type="submit" class="btn btn-default"><i class="rex-icon fa-search"></i> ' . rex_escape($addon->i18n('upkeep_filter')) . '</button> ';
if ($filterParams) {
    $filter .= '<a class="btn btn-link" href="' . $tabUrl() . '">' . rex_escape($addon->i18n('upkeep_reset')) . '</a>';
}
$filter .= '</form>';

$toolbar = '<div class="upk-toolbar"><span class="upk-muted">' . rex_escape($addon->i18n('upkeep_pages_entries_total', $total)) . '</span></div>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_no_threats_message')) . '</p></div>';
} else {
    $body = '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_time')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_ip_address')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_mail_security_threat_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_pattern')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_action')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_details')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $pattern = (string) ($row['pattern_matched'] ?? '');
        $body .= '<tr>';
        $body .= '<td>' . rex_escape($formatTime((string) $row['created_at'])) . '</td>';
        $body .= '<td><span class="upk-mono">' . rex_escape((string) $row['ip_address']) . '</span></td>';
        $body .= '<td>' . rex_escape($typeLabel((string) $row['threat_type'])) . '</td>';
        $body .= '<td><span class="upk-mono" title="' . rex_escape($pattern) . '">' . rex_escape(mb_strimwidth($pattern, 0, 50, '…')) . '</span></td>';
        $body .= '<td>' . $severityBadge((string) $row['severity']) . '</td>';
        $body .= '<td>' . rex_escape((string) ($row['action_taken'] ?? '')) . '</td>';
        $body .= '<td class="upk-actions"><a class="btn btn-default btn-xs" href="' . $tabUrl($filterParams + ['id' => (int) $row['id']]) . '">' . rex_escape($addon->i18n('upkeep_details')) . '</a></td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';

    if ($pages > 1) {
        $link = static fn (int $p): string => $tabUrl($filterParams + ['p' => $p]);
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
$fragment->setVar('title', $addon->i18n('upkeep_mail_security_threats'), false);
$fragment->setVar('body', $toolbar . $filter . $body, false);
echo $fragment->parse('core/page/section.php');
