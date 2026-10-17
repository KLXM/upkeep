<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Blocklist (E-Mail-Adressen, Domains, IP-Adressen, Muster).
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

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
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

$typeLabel = static fn (string $t): string => in_array($t, ['email', 'domain', 'ip', 'pattern'], true) ? $addon->i18n('upkeep_type_' . $t) : $t;
$severityBadge = static function (string $severity) use ($addon): string {
    $class = match ($severity) {
        'critical' => 'upk-badge--danger',
        'high', 'medium' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $addon->i18n('upkeep_ips_severity_' . $severity) : ($severity ?: '-');
    return '<span class="upk-badge ' . $class . '">' . rex_escape($label) . '</span>';
};

$filterParams = array_filter(['type' => $filterType, 'severity' => $filterSeverity, 'status' => $filterStatus, 'q' => $filterSearch], static fn ($v) => $v !== '');
$listUrl = $tabUrl($filterParams);

$filter = '<form class="upk-filter form-inline" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="blocklist">';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bl-ftype">' . rex_escape($addon->i18n('upkeep_ips_type')) . '</label><select class="form-control" id="upk-bl-ftype" name="type"><option value="">' . rex_escape($addon->i18n('upkeep_all_types')) . '</option>';
foreach ($types as $t) {
    $filter .= '<option value="' . $t . '"' . ($filterType === $t ? ' selected' : '') . '>' . rex_escape($typeLabel($t)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bl-fsev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-bl-fsev" name="severity"><option value="">' . rex_escape($addon->i18n('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($filterSeverity === $sev ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bl-fstatus">' . rex_escape($addon->i18n('upkeep_pages_status')) . '</label><select class="form-control" id="upk-bl-fstatus" name="status"><option value="">' . rex_escape($addon->i18n('upkeep_all_status')) . '</option>'
    . '<option value="1"' . ($filterStatus === '1' ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_active')) . '</option>'
    . '<option value="0"' . ($filterStatus === '0' ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_inactive')) . '</option></select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bl-fq">' . rex_escape($addon->i18n('upkeep_pages_search')) . '</label><input type="search" class="form-control" id="upk-bl-fq" name="q" maxlength="100" placeholder="' . rex_escape($addon->i18n('upkeep_pages_search')) . '" value="' . rex_escape($filterSearch) . '"></div> ';
$filter .= '<button type="submit" class="btn btn-default"><i class="rex-icon fa-search"></i> ' . rex_escape($addon->i18n('upkeep_filter')) . '</button> ';
if ($filterParams) {
    $filter .= '<a class="btn btn-link" href="' . $tabUrl() . '">' . rex_escape($addon->i18n('upkeep_reset')) . '</a>';
}
$filter .= '</form>';

$toolbar = '<div class="upk-toolbar"><span class="upk-muted">' . rex_escape($addon->i18n('upkeep_pages_entries_total', count($rows))) . '</span></div>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n($filterParams ? 'upkeep_pages_no_match' : 'upkeep_mail_blocklist_empty')) . '</p></div>';
} else {
    $body = '<form id="upk-bl-rows" action="' . $listUrl . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th class="rex-table-icon"><input type="checkbox" data-upk-check-all="upk-bl-rows" aria-label="' . rex_escape($addon->i18n('upkeep_select_all')) . '"></th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_mail_blocklist_entry')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_status')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_reason')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_valid_until')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $identifier = (string) (($row['email_address'] ?? '') ?: (($row['domain'] ?? '') ?: (($row['ip_address'] ?? '') ?: ($row['pattern'] ?? ''))));
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $expired = $expires && $expires < time();
        $on = (int) $row['status'] === 1;
        [$statusClass, $statusText] = $expired
            ? ['upk-badge--warn', $addon->i18n('upkeep_status_expired')]
            : ($on ? ['upk-badge--ok', $addon->i18n('upkeep_active')] : ['upk-badge--muted', $addon->i18n('upkeep_inactive')]);
        $reason = (string) ($row['reason'] ?? '');
        $body .= '<tr>';
        $body .= '<td class="rex-table-icon"><input type="checkbox" form="upk-bl-rows" name="selected_blocklist[]" value="' . $id . '" aria-label="' . rex_escape($identifier) . '"></td>';
        $body .= '<td><span class="upk-mono">' . rex_escape($identifier) . '</span></td>';
        $body .= '<td>' . rex_escape($typeLabel((string) $row['blocklist_type'])) . '</td>';
        $body .= '<td>' . $severityBadge((string) $row['severity']) . '</td>';
        $body .= '<td><span class="upk-badge ' . $statusClass . '">' . rex_escape($statusText) . '</span></td>';
        $body .= '<td><span class="upk-muted" title="' . rex_escape($reason) . '">' . rex_escape(mb_strimwidth($reason, 0, 50, '…')) . '</span></td>';
        $body .= '<td>' . rex_escape($expires ? date('d.m.Y H:i', $expires) : $addon->i18n('upkeep_ips_block_duration_permanent')) . '</td>';
        $body .= '<td class="upk-actions">';
        if (!$expired) {
            $body .= '<button type="submit" form="upk-bl-rows" class="btn btn-default btn-xs" name="toggle_blocklist" value="' . $id . '">' . rex_escape($on ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button> ';
        }
        $body .= '<button type="submit" form="upk-bl-rows" class="btn btn-delete btn-xs" name="remove_blocklist" value="' . $id . '" data-confirm="' . rex_escape($addon->i18n('upkeep_delete_blocklist_confirm')) . '"><i class="rex-icon rex-icon-delete"></i> ' . rex_escape($addon->i18n('upkeep_delete')) . '</button>';
        $body .= '</td></tr>';
    }
    $body .= '</tbody></table></div>';
    $body .= '<div class="upk-toolbar form-inline">'
        . '<label class="sr-only" for="upk-bl-bulk">' . rex_escape($addon->i18n('upkeep_bulk_action_select')) . '</label>'
        . '<select class="form-control" id="upk-bl-bulk" name="bulk_action" form="upk-bl-rows">'
        . '<option value="">' . rex_escape($addon->i18n('upkeep_bulk_action_select')) . '</option>'
        . '<option value="activate">' . rex_escape($addon->i18n('upkeep_activate')) . '</option>'
        . '<option value="deactivate">' . rex_escape($addon->i18n('upkeep_deactivate')) . '</option>'
        . '<option value="delete">' . rex_escape($addon->i18n('upkeep_delete')) . '</option>'
        . '</select> '
        . '<button type="submit" class="btn btn-default" form="upk-bl-rows" name="bulk_apply" value="1" data-confirm="' . rex_escape($addon->i18n('upkeep_bulk_confirm')) . '">' . rex_escape($addon->i18n('upkeep_execute')) . '</button>'
        . '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_mail_security_blocklist_entries'), false);
$fragment->setVar('body', $toolbar . $filter . $body, false);
echo $fragment->parse('core/page/section.php');

// Formular: hinzufügen (ein Wertfeld, Bedeutung je nach Typ)
$typeOptions = '';
foreach ($types as $t) {
    $typeOptions .= '<option value="' . $t . '">' . rex_escape($typeLabel($t)) . '</option>';
}
$sevOptions = '';
foreach ($severities as $sev) {
    $sevOptions .= '<option value="' . $sev . '"' . ($sev === 'medium' ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$form = '<form action="' . $listUrl . '" method="post">' . $csrf->getHiddenField();
$form .= '<div class="row">';
$form .= '<div class="col-sm-2"><div class="form-group"><label for="upk-bl-type">' . rex_escape($addon->i18n('upkeep_ips_type')) . '</label><select class="form-control" id="upk-bl-type" name="blocklist_type">' . $typeOptions . '</select></div></div>';
$form .= '<div class="col-sm-4"><div class="form-group"><label for="upk-bl-value">' . rex_escape($addon->i18n('upkeep_mail_blocklist_entry')) . '</label>'
    . '<input type="text" class="form-control upk-mono" id="upk-bl-value" name="blocklist_value" required maxlength="255" placeholder="spam@example.com / example.com / 192.0.2.*">'
    . '<p class="help-block">' . rex_escape($addon->i18n('upkeep_mail_blocklist_value_help')) . '</p></div></div>';
$form .= '<div class="col-sm-2"><div class="form-group"><label for="upk-bl-sev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-bl-sev" name="blocklist_severity">' . $sevOptions . '</select></div></div>';
$form .= '<div class="col-sm-4"><div class="form-group"><label for="upk-bl-expires">' . rex_escape($addon->i18n('upkeep_valid_until')) . '</label>'
    . '<input type="datetime-local" class="form-control" id="upk-bl-expires" name="blocklist_expires"><p class="help-block">' . rex_escape($addon->i18n('upkeep_empty_permanent')) . '</p></div></div>';
$form .= '</div>';
$form .= '<div class="form-group"><label for="upk-bl-reason">' . rex_escape($addon->i18n('upkeep_reason')) . '</label><input type="text" class="form-control" id="upk-bl-reason" name="blocklist_reason" maxlength="1000"></div>';
$form .= '<button type="submit" class="btn btn-primary" name="add_blocklist" value="1"><i class="rex-icon rex-icon-add"></i> ' . rex_escape($addon->i18n('upkeep_add_to_blocklist')) . '</button>';
$form .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_add_to_blocklist'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');
