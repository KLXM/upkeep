<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Blocklist (E-Mail-Adressen, Domains, IP-Adressen, Muster).
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

use KLXM\Upkeep\Ui;

$csrf = rex_csrf_token::factory('upkeep_mail_blocklist');
$table = rex::getTable('upkeep_mail_blocklist');
$severities = ['low', 'medium', 'high', 'critical'];
$types = ['email', 'domain', 'ip', 'pattern'];
$messages = [];

/** Validiert einen Wert passend zum Typ und liefert die normalisierte Form oder null. */
$validate = static function (string $type, string $value): ?string {
    $value = trim($value);
    if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
        return null;
    }
    switch ($type) {
        case 'email':
            return filter_var($value, FILTER_VALIDATE_EMAIL) !== false ? mb_strtolower($value) : null;
        case 'domain':
            $domain = ltrim(mb_strtolower($value), '@');
            $ascii = function_exists('idn_to_ascii') ? idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46) : $domain;
            return $ascii !== false && str_contains($ascii, '.') && filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false ? $domain : null;
        case 'ip':
            // Einzelne IP oder IPv4 mit Platzhaltern (z. B. 192.0.2.*), wie vom Filter unterstützt
            if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
                return $value;
            }
            return preg_match('/^(25[0-5]|2[0-4]\d|1?\d?\d|\*)(\.(25[0-5]|2[0-4]\d|1?\d?\d|\*)){3}$/', $value) && str_contains($value, '*') ? $value : null;
        case 'pattern':
            return $value;
    }
    return null;
};

$hasAction = rex_post('add_blocklist', 'bool') || rex_post('remove_blocklist', 'int', 0) > 0 || rex_post('toggle_blocklist', 'int', 0) > 0 || rex_post('bulk_apply', 'bool');
if ($hasAction) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } elseif (rex_post('add_blocklist', 'bool')) {
        $type = rex_post('blocklist_type', 'string', 'email');
        $type = in_array($type, $types, true) ? $type : 'email';
        $value = $validate($type, rex_post('blocklist_value', 'string', ''));
        $severity = rex_post('blocklist_severity', 'string', 'medium');
        $severity = in_array($severity, $severities, true) ? $severity : 'medium';
        $reason = mb_substr(trim(rex_post('blocklist_reason', 'string', '')), 0, 1000);
        $expiresRaw = trim(rex_post('blocklist_expires', 'string', ''));
        $expiresAt = null;
        $error = null;

        if ($value === null) {
            $error = $addon->i18n('upkeep_mail_blocklist_invalid_' . $type);
        } elseif ($expiresRaw !== '') {
            $dt = DateTime::createFromFormat('Y-m-d\TH:i', $expiresRaw) ?: DateTime::createFromFormat('Y-m-d\TH:i:s', $expiresRaw);
            if (!$dt || $dt->getTimestamp() <= time()) {
                $error = $addon->i18n('upkeep_mail_blocklist_invalid_expiry');
            } else {
                $expiresAt = $dt->format('Y-m-d H:i:s');
            }
        }

        if ($error !== null) {
            $messages[] = rex_view::error(rex_escape($error));
        } else {
            try {
                $now = date('Y-m-d H:i:s');
                $sql = rex_sql::factory();
                $sql->setTable($table);
                $sql->setValue('email_address', $type === 'email' ? $value : '');
                $sql->setValue('domain', $type === 'domain' ? $value : '');
                $sql->setValue('ip_address', $type === 'ip' ? $value : '');
                // Bei IP zusätzlich als Muster speichern (Platzhalter-Abgleich im Filter)
                $sql->setValue('pattern', in_array($type, ['ip', 'pattern'], true) ? $value : '');
                $sql->setValue('blocklist_type', $type);
                $sql->setValue('severity', $severity);
                $sql->setValue('reason', $reason);
                $sql->setValue('expires_at', $expiresAt);
                $sql->setValue('status', 1);
                $sql->setValue('created_at', $now);
                $sql->setValue('updated_at', $now);
                $sql->insert();
                $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_mail_blocklist_added')));
            } catch (rex_sql_exception $e) {
                rex_logger::logException($e);
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
            }
        }
    } elseif (rex_post('remove_blocklist', 'int', 0) > 0) {
        $sql = rex_sql::factory();
        $sql->setQuery('DELETE FROM ' . $table . ' WHERE id = ?', [rex_post('remove_blocklist', 'int')]);
        $messages[] = $sql->getRows() > 0
            ? rex_view::success(rex_escape($addon->i18n('upkeep_mail_blocklist_removed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
    } elseif (rex_post('toggle_blocklist', 'int', 0) > 0) {
        $sql = rex_sql::factory();
        $sql->setQuery('UPDATE ' . $table . ' SET status = 1 - status, updated_at = ? WHERE id = ?', [date('Y-m-d H:i:s'), rex_post('toggle_blocklist', 'int')]);
        $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_mail_blocklist_status_changed')));
    } else {
        $action = rex_post('bulk_action', 'string', '');
        $ids = array_values(array_unique(array_filter(array_map('intval', rex_post('selected_blocklist', 'array', [])), static fn ($v) => $v > 0)));
        if (!in_array($action, ['activate', 'deactivate', 'delete'], true) || !$ids) {
            $messages[] = rex_view::warning(rex_escape($addon->i18n('upkeep_pages_bulk_nothing')));
        } else {
            try {
                $in = implode(',', array_fill(0, count($ids), '?'));
                $sql = rex_sql::factory();
                if ($action === 'delete') {
                    $sql->setQuery('DELETE FROM ' . $table . ' WHERE id IN (' . $in . ')', $ids);
                } else {
                    $sql->setQuery('UPDATE ' . $table . ' SET status = ?, updated_at = ? WHERE id IN (' . $in . ')', array_merge([$action === 'activate' ? 1 : 0, date('Y-m-d H:i:s')], $ids));
                }
                $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_pages_bulk_done', $sql->getRows())));
            } catch (rex_sql_exception $e) {
                rex_logger::logException($e);
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_bulk_action_error')));
            }
        }
    }
}

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$hadError = str_contains(implode('', $messages), 'alert-danger');

echo implode('', $messages);

// Filter (GET)
$filterType = rex_get('type', 'string', '');
$filterType = in_array($filterType, $types, true) ? $filterType : '';
$filterSeverity = rex_get('severity', 'string', '');
$filterSeverity = in_array($filterSeverity, $severities, true) ? $filterSeverity : '';
$filterStatus = rex_get('status', 'string', '');
$filterStatus = in_array($filterStatus, ['0', '1'], true) ? $filterStatus : '';
$filterSearch = mb_substr(trim(rex_get('q', 'string', '')), 0, 100);

$where = [];
$params = [];
if ($filterType !== '') {
    $where[] = 'blocklist_type = ?';
    $params[] = $filterType;
}
if ($filterSeverity !== '') {
    $where[] = 'severity = ?';
    $params[] = $filterSeverity;
}
if ($filterStatus !== '') {
    $where[] = 'status = ?';
    $params[] = (int) $filterStatus;
}
if ($filterSearch !== '') {
    $like = '%' . addcslashes($filterSearch, '%_\\') . '%';
    $where[] = '(email_address LIKE ? OR domain LIKE ? OR ip_address LIKE ? OR pattern LIKE ? OR reason LIKE ?)';
    array_push($params, $like, $like, $like, $like, $like);
}
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';

try {
    $rows = rex_sql::factory()->getArray('SELECT * FROM ' . $table . $whereSql . ' ORDER BY created_at DESC', $params);
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

$typeLabel = static fn (string $v): string => in_array($v, ['email', 'domain', 'ip', 'pattern'], true) ? $t('upkeep_type_' . $v) : $v;

$filterParams = array_filter(['type' => $filterType, 'severity' => $filterSeverity, 'status' => $filterStatus, 'q' => $filterSearch], static fn ($v) => $v !== '');
$listUrl = $tabUrl($filterParams);

$filter = '<form class="upk-group upk-filterbar" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="blocklist">';
$filter .= '<label class="sr-only" for="upk-bl-fq">' . rex_escape($t('upkeep_pages_search')) . '</label><input type="search" class="form-control upk-filterbar-text" id="upk-bl-fq" name="q" maxlength="100" placeholder="' . rex_escape($t('upkeep_pages_search')) . '" value="' . rex_escape($filterSearch) . '">';
$filter .= '<label class="sr-only" for="upk-bl-ftype">' . rex_escape($t('upkeep_ips_type')) . '</label><select class="form-control" id="upk-bl-ftype" name="type"><option value="">' . rex_escape($t('upkeep_all_types')) . '</option>';
foreach ($types as $v) {
    $filter .= '<option value="' . $v . '"' . ($filterType === $v ? ' selected' : '') . '>' . rex_escape($typeLabel($v)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="sr-only" for="upk-bl-fsev">' . rex_escape($t('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-bl-fsev" name="severity"><option value="">' . rex_escape($t('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($filterSeverity === $sev ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="sr-only" for="upk-bl-fstatus">' . rex_escape($t('upkeep_pages_status')) . '</label><select class="form-control" id="upk-bl-fstatus" name="status"><option value="">' . rex_escape($t('upkeep_all_status')) . '</option>'
    . '<option value="1"' . ($filterStatus === '1' ? ' selected' : '') . '>' . rex_escape($t('upkeep_active')) . '</option>'
    . '<option value="0"' . ($filterStatus === '0' ? ' selected' : '') . '>' . rex_escape($t('upkeep_inactive')) . '</option></select>';
$filter .= '<span class="upk-filterbar-end">';
if ($filterParams) {
    $filter .= '<a class="upk-filterbar-reset" href="' . $tabUrl() . '">' . rex_escape($t('upkeep_reset')) . '</a>';
}
$filter .= '<button type="submit" class="btn btn-default"><i class="rex-icon fa-search" aria-hidden="true"></i> ' . rex_escape($t('upkeep_filter')) . '</button></span>';
$filter .= '</form>';
echo $filter;

echo Ui::listTitle($t('upkeep_mail_security_blocklist_entries'), count($rows));

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t($filterParams ? 'upkeep_pages_no_match' : 'upkeep_mail_blocklist_empty'), $filterParams ? 'fa-filter' : 'fa-check') . '</div>';
} else {
    $labels = [
        'select' => $t('upkeep_list_select'),
        'entry' => $t('upkeep_mail_blocklist_entry'),
        'type' => $t('upkeep_ips_type'),
        'severity' => $t('upkeep_ips_severity'),
        'status' => $t('upkeep_pages_status'),
        'reason' => $t('upkeep_reason'),
        'until' => $t('upkeep_valid_until'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = '<form id="upk-bl-rows" action="' . $listUrl . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    $body .= '<th scope="col" class="upk-table-check"><input type="checkbox" data-upk-check-all="upk-bl-rows" aria-label="' . rex_escape($t('upkeep_select_all')) . '"></th>';
    foreach ($labels as $key => $label) {
        if ('select' === $key) {
            continue;
        }
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $identifier = (string) (($row['email_address'] ?? '') ?: (($row['domain'] ?? '') ?: (($row['ip_address'] ?? '') ?: ($row['pattern'] ?? ''))));
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $expired = $expires && $expires < time();
        $on = (int) $row['status'] === 1;
        $statusBadge = $expired ? Ui::badge($t('upkeep_status_expired'), 'warn') : Ui::status($on);
        $reason = (string) ($row['reason'] ?? '');
        $actions = '';
        if (!$expired) {
            $actions .= '<button type="submit" form="upk-bl-rows" class="btn btn-xs upk-btn-ghost" name="toggle_blocklist" value="' . $id . '">' . rex_escape($on ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button> ';
        }
        $actions .= '<button type="submit" form="upk-bl-rows" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="remove_blocklist" value="' . $id . '" data-confirm="' . rex_escape($t('upkeep_delete_blocklist_confirm')) . '"><i class="rex-icon rex-icon-delete" aria-hidden="true"></i> ' . rex_escape($t('upkeep_delete')) . '</button>';
        $body .= '<tr>';
        $body .= Ui::td($labels['select'], '<input type="checkbox" form="upk-bl-rows" name="selected_blocklist[]" value="' . $id . '" aria-label="' . rex_escape($identifier) . '">', 'upk-table-check');
        $body .= Ui::td($labels['entry'], '<span class="upk-mono">' . rex_escape($identifier) . '</span>');
        $body .= Ui::td($labels['type'], rex_escape($typeLabel((string) $row['blocklist_type'])));
        $body .= Ui::td($labels['severity'], Ui::severity((string) $row['severity']));
        $body .= Ui::td($labels['status'], $statusBadge);
        $body .= Ui::td($labels['reason'], '<span class="upk-muted" title="' . rex_escape($reason) . '">' . rex_escape(mb_strimwidth($reason, 0, 50, '…')) . '</span>');
        $body .= Ui::td($labels['until'], rex_escape($expires ? date('d.m.Y H:i', $expires) : $t('upkeep_ips_block_duration_permanent')), 'upk-nowrap');
        $body .= Ui::td($labels['actions'], $actions, 'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';
    $body .= '<div class="upk-group-foot"><div class="upk-bulk">'
        . '<label class="sr-only" for="upk-bl-bulk">' . rex_escape($t('upkeep_bulk_action_select')) . '</label>'
        . '<select class="form-control" id="upk-bl-bulk" name="bulk_action" form="upk-bl-rows">'
        . '<option value="">' . rex_escape($t('upkeep_bulk_action_select')) . '</option>'
        . '<option value="activate">' . rex_escape($t('upkeep_activate')) . '</option>'
        . '<option value="deactivate">' . rex_escape($t('upkeep_deactivate')) . '</option>'
        . '<option value="delete">' . rex_escape($t('upkeep_delete')) . '</option>'
        . '</select>'
        . '<button type="submit" class="btn btn-default" form="upk-bl-rows" name="bulk_apply" value="1" data-confirm="' . rex_escape($t('upkeep_bulk_confirm')) . '">' . rex_escape($t('upkeep_execute')) . '</button>'
        . '</div></div>';
    $body .= '</div>';
    echo $body;
}

// Formular: hinzufügen (ein Wertfeld, Bedeutung je nach Typ)
$posted = rex_post('add_blocklist', 'bool') && $hadError;
$value = static fn (string $name, string $default = ''): string => $posted ? (string) rex_post($name, 'string', $default) : $default;
$selType = $value('blocklist_type', 'email');
$selSev = $value('blocklist_severity', 'medium');
$typeOptions = '';
foreach ($types as $v) {
    $typeOptions .= '<option value="' . $v . '"' . ($v === $selType ? ' selected' : '') . '>' . rex_escape($typeLabel($v)) . '</option>';
}
$sevOptions = '';
foreach ($severities as $sev) {
    $sevOptions .= '<option value="' . $sev . '"' . ($sev === $selSev ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
echo '<details class="upk-group upk-form-details"' . ($posted || (!$rows && !$filterParams) ? ' open' : '') . ' id="upk-form">'
    . '<summary>' . rex_escape($t('upkeep_add_to_blocklist')) . '</summary>'
    . '<form action="' . $listUrl . '" method="post">' . $csrf->getHiddenField()
    . Ui::row($t('upkeep_ips_type'), '<select class="form-control" id="upk-bl-type" name="blocklist_type">' . $typeOptions . '</select>', '', 'upk-bl-type')
    . Ui::row($t('upkeep_mail_blocklist_entry'), '<input type="text" class="form-control upk-mono" id="upk-bl-value" name="blocklist_value" required maxlength="255" placeholder="spam@example.com / example.com / 192.0.2.*" value="' . rex_escape($value('blocklist_value')) . '">', $t('upkeep_mail_blocklist_value_help'), 'upk-bl-value')
    . Ui::row($t('upkeep_ips_severity'), '<select class="form-control" id="upk-bl-sev" name="blocklist_severity">' . $sevOptions . '</select>', '', 'upk-bl-sev')
    . Ui::row($t('upkeep_valid_until'), '<input type="datetime-local" class="form-control" id="upk-bl-expires" name="blocklist_expires" value="' . rex_escape($value('blocklist_expires')) . '">', $t('upkeep_empty_permanent'), 'upk-bl-expires')
    . Ui::row($t('upkeep_reason'), '<input type="text" class="form-control" id="upk-bl-reason" name="blocklist_reason" maxlength="1000" value="' . rex_escape($value('blocklist_reason')) . '">', '', 'upk-bl-reason')
    . '<div class="upk-form-actions"><button type="submit" class="btn btn-primary" name="add_blocklist" value="1"><i class="rex-icon rex-icon-add" aria-hidden="true"></i> ' . rex_escape($t('upkeep_add_to_blocklist')) . '</button></div>'
    . '</form></details>';
