<?php

/**
 * Upkeep 3.0 – Schutz: Gesperrte IP-Adressen.
 *
 * Manuell sperren (einzeln oder als Liste), entsperren, Schnellaktionen für auffällige IPs.
 */

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');
$csrf = rex_csrf_token::factory('upkeep_blocked');
$pageKey = 'upkeep/protection/blocked';
$table = rex::getTable('upkeep_ips_blocked_ips');
$perPage = 50;
$durations = ['permanent', '1h', '6h', '24h', '7d', '30d'];
$messages = [];

/** IP-Adresse oder CIDR-Bereich (IPv4/IPv6) prüfen. */
$isIpOrCidr = static function (string $value): bool {
    if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
        return true;
    }
    if (substr_count($value, '/') !== 1) {
        return false;
    }
    [$ip, $bits] = explode('/', $value, 2);
    if ($bits === '' || !ctype_digit($bits)) {
        return false;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return (int) $bits <= 32;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        return (int) $bits <= 128;
    }
    return false;
};

if (rex_post('add_blocked_ip', 'bool') || rex_post('bulk_import_ips', 'bool') || rex_post('unblock_ip', 'string', '') !== '') {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } elseif (rex_post('add_blocked_ip', 'bool')) {
        // Einzelne IP sperren
        $ip = trim(rex_post('ip_address', 'string', ''));
        $duration = rex_post('block_duration', 'string', 'permanent');
        $duration = in_array($duration, $durations, true) ? $duration : 'permanent';
        $reason = mb_substr(trim(rex_post('reason', 'string', '')), 0, 255);

        if ($ip === '') {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_ips_blocked_ip_required')));
        } elseif (!$isIpOrCidr($ip)) {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_invalid_ip')));
        } else {
            try {
                $result = IntrusionPrevention::blockIpManually($ip, $duration, $reason);
                $messages[] = !empty($result['success'])
                    ? rex_view::success(rex_escape((string) ($result['message'] ?? $addon->i18n('upkeep_ips_blocked_added'))))
                    : rex_view::error(rex_escape((string) ($result['message'] ?? $addon->i18n('upkeep_pages_action_failed'))));
            } catch (Throwable $e) {
                rex_logger::logException($e);
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
            }
        }
    } elseif (rex_post('bulk_import_ips', 'bool')) {
        // Liste sperren
        $ipList = rex_post('ip_list', 'string', '');
        $duration = rex_post('bulk_duration', 'string', '24h');
        $duration = in_array($duration, $durations, true) ? $duration : '24h';
        $reason = mb_substr(trim(rex_post('bulk_reason', 'string', '')), 0, 255);

        if (trim($ipList) === '') {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_ips_ip_list_required')));
        } elseif (substr_count($ipList, "\n") > 5000) {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_blocked_bulk_too_many')));
        } else {
            try {
                $results = IntrusionPrevention::processBulkIpImport($ipList, $duration, $reason);
                if (($results['success_count'] ?? 0) > 0) {
                    $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_blocked_bulk_success', (int) $results['success_count'])));
                }
                if (($results['error_count'] ?? 0) > 0) {
                    $list = array_map(static fn ($e) => rex_escape((string) $e), array_slice((array) ($results['errors'] ?? []), 0, 50));
                    $messages[] = rex_view::warning(rex_escape($addon->i18n('upkeep_blocked_bulk_errors', (int) $results['error_count'])) . ($list ? '<br>' . implode('<br>', $list) : ''));
                }
                if (($results['skipped_count'] ?? 0) > 0) {
                    $messages[] = rex_view::info(rex_escape($addon->i18n('upkeep_blocked_bulk_skipped', (int) $results['skipped_count'])));
                }
            } catch (Throwable $e) {
                rex_logger::logException($e);
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
            }
        }
    } else {
        // Entsperren
        $ip = trim(rex_post('unblock_ip', 'string', ''));
        if (!$isIpOrCidr($ip)) {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_invalid_ip')));
        } elseif (IntrusionPrevention::unblockIp($ip)) {
            $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_blocked_unblocked', $ip)));
        } else {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_ips_unblock_error', $ip)));
        }
    }
}

echo implode('', $messages);

$durationOptions = static function (string $selected) use ($addon, $durations): string {
    $html = '';
    foreach ($durations as $d) {
        $html .= '<option value="' . $d . '"' . ($d === $selected ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_block_duration_' . $d)) . '</option>';
    }
    return $html;
};

$severityBadge = static function (string $severity) use ($addon): string {
    $class = match ($severity) {
        'critical' => 'upk-badge--danger',
        'high', 'medium' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $addon->i18n('upkeep_ips_severity_' . $severity) : ($severity ?: '-');
    return '<span class="upk-badge ' . $class . '">' . rex_escape($label) . '</span>';
};

$geoAvailable = is_file(rex_path::addonData('upkeep', 'ip2geo.mmdb'));
$country = static function (string $ip) use ($geoAvailable): string {
    if (!$geoAvailable) {
        return '';
    }
    try {
        $info = IntrusionPrevention::getCountryByIp($ip);
        return ($info['code'] ?? 'UNKNOWN') !== 'UNKNOWN' ? (string) ($info['name'] ?? '') : '';
    } catch (Throwable $e) {
        return '';
    }
};

// Liste der aktiven Sperren
$total = 0;
$rows = [];
try {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT COUNT(*) AS total FROM ' . $table . ' WHERE expires_at IS NULL OR expires_at > NOW()');
    $total = (int) $sql->getValue('total');
    $pages = max(1, (int) ceil($total / $perPage));
    $current = min(max(1, rex_get('p', 'int', 1)), $pages);
    $rows = $sql->getArray('SELECT * FROM ' . $table . ' WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY created_at DESC LIMIT ' . (int) $perPage . ' OFFSET ' . (int) (($current - 1) * $perPage));
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

$toolbar = '<div class="upk-toolbar">'
    . '<span class="upk-muted">' . rex_escape($addon->i18n('upkeep_pages_entries_total', $total)) . '</span> '
    . '<a href="' . rex_url::backendPage('upkeep/protection/allowlist') . '"><i class="rex-icon fa-check"></i> ' . rex_escape($addon->i18n('upkeep_ips_positivliste')) . '</a> '
    . '<a href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '"><i class="rex-icon fa-cog"></i> ' . rex_escape($addon->i18n('upkeep_pages_settings_link')) . '</a>'
    . '</div>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_ips_no_blocked_entries')) . '</p></div>';
} else {
    $body = '<form id="upk-blocked-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_ip')) . '</th>';
    if ($geoAvailable) {
        $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_country')) . '</th>';
    }
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_reason')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_expires')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_created')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $ip = (string) $row['ip_address'];
        $reason = (string) ($row['reason'] ?? '');
        $permanent = ($row['block_type'] ?? '') === 'permanent' || empty($row['expires_at']);
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $created = strtotime((string) $row['created_at']);
        $body .= '<tr>';
        $body .= '<td><span class="upk-mono">' . rex_escape($ip) . '</span></td>';
        if ($geoAvailable) {
            $body .= '<td><span class="upk-muted">' . rex_escape($country($ip) ?: '-') . '</span></td>';
        }
        $body .= '<td><span class="upk-badge ' . ($permanent ? 'upk-badge--danger' : 'upk-badge--warn') . '">' . rex_escape($permanent ? $addon->i18n('upkeep_ips_block_duration_permanent') : $addon->i18n('upkeep_blocked_temporary')) . '</span></td>';
        $body .= '<td>' . $severityBadge((string) ($row['threat_level'] ?? '')) . '</td>';
        $body .= '<td title="' . rex_escape($reason) . '">' . rex_escape(mb_strimwidth($reason, 0, 60, '…')) . '</td>';
        $body .= '<td>' . rex_escape($expires ? date('d.m.Y H:i', $expires) : $addon->i18n('upkeep_ips_block_duration_permanent')) . '</td>';
        $body .= '<td>' . rex_escape($created ? date('d.m.Y H:i', $created) : '-') . '</td>';
        $body .= '<td class="upk-actions"><button type="submit" form="upk-blocked-row" class="btn btn-default btn-xs" name="unblock_ip" value="' . rex_escape($ip) . '" data-confirm="' . rex_escape($addon->i18n('upkeep_ips_confirm_unblock')) . '">'
            . '<i class="rex-icon fa-unlock"></i> ' . rex_escape($addon->i18n('upkeep_blocked_unblock')) . '</button></td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';

    if ($pages > 1) {
        $link = static fn (int $p): string => rex_url::backendPage($pageKey, ['p' => $p]);
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
$fragment->setVar('title', $addon->i18n('upkeep_ips_blocked_entries'), false);
$fragment->setVar('body', $toolbar . $body, false);
echo $fragment->parse('core/page/section.php');

// Schnellaktionen: auffällige IPs der letzten 24 Stunden
$recent = [];
try {
    $recent = IntrusionPrevention::getRecentThreatIps(10);
} catch (Throwable $e) {
    rex_logger::logException($e);
}
if ($recent) {
    $body = '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_blocked_quick_help')) . '</p>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_ip')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_blocked_threat_count')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_blocked_last_threat')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($recent as $item) {
        $ip = (string) ($item['ip'] ?? '');
        if (!$isIpOrCidr($ip)) {
            continue;
        }
        $count = (int) ($item['threat_count'] ?? 0);
        $last = strtotime((string) ($item['last_threat'] ?? ''));
        $body .= '<tr>';
        $body .= '<td><span class="upk-mono">' . rex_escape($ip) . '</span></td>';
        $body .= '<td>' . $count . '</td>';
        $body .= '<td>' . $severityBadge((string) ($item['max_severity'] ?? '')) . '</td>';
        $body .= '<td>' . rex_escape($last ? date('d.m.Y H:i', $last) : '-') . '</td>';
        $body .= '<td class="upk-actions"><form action="' . rex_url::backendPage($pageKey) . '" method="post">'
            . $csrf->getHiddenField()
            . '<input type="hidden" name="ip_address" value="' . rex_escape($ip) . '">'
            . '<input type="hidden" name="block_duration" value="24h">'
            . '<input type="hidden" name="reason" value="' . rex_escape($addon->i18n('upkeep_blocked_quick_reason', $count)) . '">'
            . '<button type="submit" class="btn btn-default btn-xs" name="add_blocked_ip" value="1" data-confirm="' . rex_escape($addon->i18n('upkeep_blocked_quick_confirm', $ip)) . '">'
            . '<i class="rex-icon fa-ban"></i> ' . rex_escape($addon->i18n('upkeep_blocked_quick_button')) . '</button>'
            . '</form></td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';

    $fragment = new rex_fragment();
    $fragment->setVar('title', $addon->i18n('upkeep_blocked_quick_title'), false);
    $fragment->setVar('body', $body, false);
    echo $fragment->parse('core/page/section.php');
}

// Formular: einzelne IP sperren
$form = '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField();
$form .= '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_ips_blocked_help')) . ' ' . rex_escape($addon->i18n('upkeep_blocked_format_help')) . '</p>';
$form .= '<div class="row">';
$form .= '<div class="col-sm-4"><div class="form-group"><label for="upk-block-ip">' . rex_escape($addon->i18n('upkeep_ips_ip_address')) . '</label>'
    . '<input type="text" class="form-control upk-mono" id="upk-block-ip" name="ip_address" required maxlength="64" placeholder="192.0.2.10 / 192.0.2.0/24"></div></div>';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-block-duration">' . rex_escape($addon->i18n('upkeep_ips_block_duration')) . '</label>'
    . '<select class="form-control" id="upk-block-duration" name="block_duration">' . $durationOptions('permanent') . '</select></div></div>';
$form .= '<div class="col-sm-5"><div class="form-group"><label for="upk-block-reason">' . rex_escape($addon->i18n('upkeep_ips_reason')) . '</label>'
    . '<input type="text" class="form-control" id="upk-block-reason" name="reason" maxlength="255" placeholder="' . rex_escape($addon->i18n('upkeep_ips_block_reason_manual')) . '"></div></div>';
$form .= '</div>';
$form .= '<button type="submit" class="btn btn-primary" name="add_blocked_ip" value="1"><i class="rex-icon fa-ban"></i> ' . rex_escape($addon->i18n('upkeep_ips_blocked_add')) . '</button>';
$form .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_ips_blocked_add'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');

// Formular: Liste sperren
$form = '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField();
$form .= '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_blocked_bulk_help')) . '</p>';
$form .= '<div class="row">';
$form .= '<div class="col-sm-6"><div class="form-group"><label for="upk-bulk-list">' . rex_escape($addon->i18n('upkeep_blocked_bulk_list')) . '</label>'
    . '<textarea class="form-control upk-mono" id="upk-bulk-list" name="ip_list" rows="8" required placeholder="192.0.2.10&#10;198.51.100.0/24&#10;# ' . rex_escape($addon->i18n('upkeep_blocked_bulk_comment')) . '&#10;2001:db8::/32"></textarea></div></div>';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-bulk-duration">' . rex_escape($addon->i18n('upkeep_ips_block_duration')) . '</label>'
    . '<select class="form-control" id="upk-bulk-duration" name="bulk_duration">' . $durationOptions('24h') . '</select></div></div>';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-bulk-reason">' . rex_escape($addon->i18n('upkeep_ips_reason')) . '</label>'
    . '<input type="text" class="form-control" id="upk-bulk-reason" name="bulk_reason" maxlength="255"></div></div>';
$form .= '</div>';
$form .= '<button type="submit" class="btn btn-default" name="bulk_import_ips" value="1" data-confirm="' . rex_escape($addon->i18n('upkeep_blocked_bulk_confirm')) . '"><i class="rex-icon fa-upload"></i> ' . rex_escape($addon->i18n('upkeep_blocked_bulk_button')) . '</button>';
$form .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_blocked_bulk_title'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');
