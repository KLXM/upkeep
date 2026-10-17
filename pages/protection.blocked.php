<?php

/**
 * Upkeep 3.0 – Schutz: Gesperrte IP-Adressen.
 *
 * Manuell sperren (einzeln oder als Liste), entsperren, Schnellaktionen für auffällige IPs.
 */

use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\Ui;

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

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$isAdmin = rex::requireUser()->isAdmin();
$hadError = str_contains(implode('', $messages), 'alert-danger');

// Kopf
$ipsOn = (bool) $addon->getConfig('ips_active', false);
$actions = Ui::badge($t($ipsOn ? 'upkeep_list_ips_on' : 'upkeep_list_ips_off'), $ipsOn ? 'ok' : 'muted');
if ($ipsOn && $addon->getConfig('ips_monitor_only', false)) {
    $actions .= ' ' . Ui::badge($t('upkeep_set_ips_monitor_only'), 'info');
}
if ($isAdmin) {
    $actions .= ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '">' . rex_escape($t('upkeep_nav_settings')) . '</a>';
}
echo Ui::hero($t('upkeep_list_blocked_title'), $t('upkeep_list_blocked_intro'), Ui::icon('fa-shield', 'blue'), $actions);

echo implode('', $messages);

$durationOptions = static function (string $selected) use ($t, $durations): string {
    $html = '';
    foreach ($durations as $d) {
        $html .= '<option value="' . $d . '"' . ($d === $selected ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_block_duration_' . $d)) . '</option>';
    }
    return $html;
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
$counts = ['temporary' => 0, 'permanent' => 0];
try {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT COUNT(*) AS total FROM ' . $table . ' WHERE expires_at IS NULL OR expires_at > NOW()');
    $total = (int) $sql->getValue('total');
    $pages = max(1, (int) ceil($total / $perPage));
    $current = min(max(1, rex_get('p', 'int', 1)), $pages);
    $rows = $sql->getArray('SELECT * FROM ' . $table . ' WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY created_at DESC LIMIT ' . (int) $perPage . ' OFFSET ' . (int) (($current - 1) * $perPage));
    $sql->setQuery('SELECT COUNT(*) AS c FROM ' . $table . ' WHERE expires_at IS NULL OR block_type = \'permanent\'');
    $counts['permanent'] = (int) $sql->getValue('c');
    $counts['temporary'] = max(0, $total - $counts['permanent']);
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

// Schnellaktionen: auffällige IPs der letzten 24 Stunden
$recent = [];
try {
    $recent = IntrusionPrevention::getRecentThreatIps(10);
} catch (Throwable $e) {
    rex_logger::logException($e);
}
$recent = array_values(array_filter($recent, static fn ($item) => $isIpOrCidr((string) ($item['ip'] ?? ''))));

$stat = static fn (string $title, string $icon, string $color, int $value): string => Ui::tile($title, Ui::icon($icon, $color), '<div class="upk-tile-value">' . $value . '</div>', '', 'upk-tile--stat');
echo '<div class="upk-tiles upk-tiles--stats">'
    . $stat($t('upkeep_blocked_temporary'), 'fa-clock-o', 'orange', $counts['temporary'])
    . $stat($t('upkeep_ips_block_duration_permanent'), 'fa-ban', 'red', $counts['permanent'])
    . $stat($t('upkeep_blocked_quick_title'), 'fa-exclamation-triangle', 'purple', count($recent))
    . '</div>';

echo Ui::listTitle($t('upkeep_ips_blocked_entries'), $total);

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_ips_no_blocked_entries'), 'fa-check') . '</div>';
} else {
    $labels = [
        'ip' => $t('upkeep_ips_ip'),
        'country' => $t('upkeep_pages_country'),
        'type' => $t('upkeep_ips_type'),
        'severity' => $t('upkeep_ips_severity'),
        'reason' => $t('upkeep_ips_reason'),
        'expires' => $t('upkeep_ips_expires'),
        'created' => $t('upkeep_ips_created'),
        'actions' => $t('upkeep_actions'),
    ];
    if (!$geoAvailable) {
        unset($labels['country']);
    }
    $body = '<form id="upk-blocked-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    foreach ($labels as $key => $label) {
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $ip = (string) $row['ip_address'];
        $reason = (string) ($row['reason'] ?? '');
        $permanent = ($row['block_type'] ?? '') === 'permanent' || empty($row['expires_at']);
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $created = strtotime((string) $row['created_at']);
        $body .= '<tr>';
        $body .= Ui::td($labels['ip'], '<span class="upk-mono">' . rex_escape($ip) . '</span>');
        if ($geoAvailable) {
            $body .= Ui::td($labels['country'], '<span class="upk-muted">' . rex_escape($country($ip) ?: '-') . '</span>');
        }
        $body .= Ui::td($labels['type'], Ui::badge($permanent ? $t('upkeep_ips_block_duration_permanent') : $t('upkeep_blocked_temporary'), $permanent ? 'danger' : 'warn'));
        $body .= Ui::td($labels['severity'], Ui::severity((string) ($row['threat_level'] ?? '')));
        $body .= Ui::td($labels['reason'], '<span title="' . rex_escape($reason) . '">' . rex_escape(mb_strimwidth($reason, 0, 60, '…')) . '</span>');
        $body .= Ui::td($labels['expires'], rex_escape($expires ? date('d.m.Y H:i', $expires) : $t('upkeep_ips_block_duration_permanent')), 'upk-nowrap');
        $body .= Ui::td($labels['created'], rex_escape($created ? date('d.m.Y H:i', $created) : '-'), 'upk-nowrap');
        $body .= Ui::td($labels['actions'], '<button type="submit" form="upk-blocked-row" class="btn btn-xs upk-btn-ghost" name="unblock_ip" value="' . rex_escape($ip) . '" data-confirm="' . rex_escape($t('upkeep_ips_confirm_unblock')) . '">'
            . '<i class="rex-icon fa-unlock" aria-hidden="true"></i> ' . rex_escape($t('upkeep_blocked_unblock')) . '</button>', 'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';
    $pager = Ui::pager($current, $pages, static fn (int $p): string => rex_url::backendPage($pageKey, ['p' => $p]));
    if ('' !== $pager) {
        $body .= '<div class="upk-group-foot">' . $pager . '</div>';
    }
    $body .= '</div>';
    echo $body;
}

// Auffällige IP-Adressen der letzten 24 Stunden
if ($recent) {
    $labels = [
        'ip' => $t('upkeep_ips_ip'),
        'count' => $t('upkeep_blocked_threat_count'),
        'severity' => $t('upkeep_ips_severity'),
        'last' => $t('upkeep_blocked_last_threat'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = Ui::listTitle($t('upkeep_blocked_quick_title'), count($recent));
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    foreach ($labels as $key => $label) {
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';
    foreach ($recent as $item) {
        $ip = (string) ($item['ip'] ?? '');
        $count = (int) ($item['threat_count'] ?? 0);
        $last = strtotime((string) ($item['last_threat'] ?? ''));
        $body .= '<tr>';
        $body .= Ui::td($labels['ip'], '<span class="upk-mono">' . rex_escape($ip) . '</span>');
        $body .= Ui::td($labels['count'], (string) $count);
        $body .= Ui::td($labels['severity'], Ui::severity((string) ($item['max_severity'] ?? '')));
        $body .= Ui::td($labels['last'], rex_escape($last ? date('d.m.Y H:i', $last) : '-'), 'upk-nowrap');
        $body .= Ui::td($labels['actions'], '<form class="upk-inline-form" action="' . rex_url::backendPage($pageKey) . '" method="post">'
            . $csrf->getHiddenField()
            . '<input type="hidden" name="ip_address" value="' . rex_escape($ip) . '">'
            . '<input type="hidden" name="block_duration" value="24h">'
            . '<input type="hidden" name="reason" value="' . rex_escape($t('upkeep_blocked_quick_reason', (string) $count)) . '">'
            . '<button type="submit" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="add_blocked_ip" value="1" data-confirm="' . rex_escape($t('upkeep_blocked_quick_confirm', $ip)) . '">'
            . '<i class="rex-icon fa-ban" aria-hidden="true"></i> ' . rex_escape($t('upkeep_blocked_quick_button')) . '</button>'
            . '</form>', 'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div></div>';
    $body .= '<p class="upk-group-note">' . rex_escape($t('upkeep_blocked_quick_help')) . '</p>';
    echo $body;
}

// Formular: einzelne IP sperren
$postedAdd = rex_post('add_blocked_ip', 'bool') && $hadError;
$value = static fn (string $name, string $default = ''): string => $postedAdd ? (string) rex_post($name, 'string', $default) : $default;
$form = '<details class="upk-group upk-form-details"' . (!$rows || $postedAdd ? ' open' : '') . ' id="upk-form">'
    . '<summary>' . rex_escape($t('upkeep_ips_blocked_add')) . '</summary>'
    . '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField()
    . '<p class="upk-form-intro">' . rex_escape($t('upkeep_blocked_format_help')) . '</p>'
    . Ui::row($t('upkeep_ips_ip_address'), '<input type="text" class="form-control upk-mono" id="upk-block-ip" name="ip_address" required maxlength="64" placeholder="192.0.2.10 / 192.0.2.0/24" value="' . rex_escape($value('ip_address')) . '">', '', 'upk-block-ip')
    . Ui::row($t('upkeep_ips_block_duration'), '<select class="form-control" id="upk-block-duration" name="block_duration">' . $durationOptions($value('block_duration', 'permanent')) . '</select>', '', 'upk-block-duration')
    . Ui::row($t('upkeep_ips_reason'), '<input type="text" class="form-control" id="upk-block-reason" name="reason" maxlength="255" placeholder="' . rex_escape($t('upkeep_ips_block_reason_manual')) . '" value="' . rex_escape($value('reason')) . '">', '', 'upk-block-reason')
    . '<div class="upk-form-actions"><button type="submit" class="btn btn-primary" name="add_blocked_ip" value="1"><i class="rex-icon fa-ban" aria-hidden="true"></i> ' . rex_escape($t('upkeep_ips_blocked_add')) . '</button></div>'
    . '</form></details>';
echo $form;

// Formular: Liste sperren
$postedBulk = rex_post('bulk_import_ips', 'bool') && $hadError;
$form = '<details class="upk-group upk-form-details"' . ($postedBulk ? ' open' : '') . '>'
    . '<summary>' . rex_escape($t('upkeep_blocked_bulk_title')) . '</summary>'
    . '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField()
    . Ui::row($t('upkeep_blocked_bulk_list'), '<textarea class="form-control upk-mono" id="upk-bulk-list" name="ip_list" rows="8" required placeholder="192.0.2.10&#10;198.51.100.0/24&#10;# ' . rex_escape($t('upkeep_blocked_bulk_comment')) . '&#10;2001:db8::/32">' . ($postedBulk ? rex_escape(rex_post('ip_list', 'string', '')) : '') . '</textarea>', $t('upkeep_blocked_bulk_help'), 'upk-bulk-list', '', true)
    . Ui::row($t('upkeep_ips_block_duration'), '<select class="form-control" id="upk-bulk-duration" name="bulk_duration">' . $durationOptions('24h') . '</select>', '', 'upk-bulk-duration')
    . Ui::row($t('upkeep_ips_reason'), '<input type="text" class="form-control" id="upk-bulk-reason" name="bulk_reason" maxlength="255">', '', 'upk-bulk-reason')
    . '<div class="upk-form-actions"><button type="submit" class="btn btn-default" name="bulk_import_ips" value="1" data-confirm="' . rex_escape($t('upkeep_blocked_bulk_confirm')) . '"><i class="rex-icon fa-upload" aria-hidden="true"></i> ' . rex_escape($t('upkeep_blocked_bulk_button')) . '</button></div>'
    . '</form></details>';
echo $form;
