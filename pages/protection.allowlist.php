<?php

/**
 * Upkeep 3.0 – Schutz: Positivliste (vertrauenswürdige IP-Adressen und Bereiche).
 */

use KLXM\Upkeep\ClientIp;
use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$csrf = rex_csrf_token::factory('upkeep_allowlist');
$pageKey = 'upkeep/protection/allowlist';
$table = rex::getTable('upkeep_ips_positivliste');
$categories = ['admin', 'cdn', 'monitoring', 'api', 'trusted'];
$messages = [];

$isIp = static fn (string $v): bool => filter_var($v, FILTER_VALIDATE_IP) !== false;
$isCidr = static function (string $value): bool {
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
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false && (int) $bits <= 128;
};

$hasAction = rex_post('add_allowlist', 'bool') || rex_post('remove_allowlist', 'int', 0) > 0 || rex_post('toggle_allowlist', 'int', 0) > 0;
if ($hasAction) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } elseif (rex_post('add_allowlist', 'bool')) {
        $ip = trim(rex_post('ip_address', 'string', ''));
        $range = trim(rex_post('ip_range', 'string', ''));
        $description = mb_substr(trim(rex_post('description', 'string', '')), 0, 255);
        $category = rex_post('category', 'string', 'trusted');
        $category = in_array($category, $categories, true) ? $category : 'trusted';

        if ($ip === '' && $range === '') {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_ips_positivliste_ip_required')));
        } elseif (($ip !== '' && !$isIp($ip)) || ($range !== '' && !$isCidr($range))) {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_invalid_ip')));
        } elseif (($ip !== '' && ClientIp::isTooWideRange($ip)) || ($range !== '' && ClientIp::isTooWideRange($range))) {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_allowlist_range_too_wide')));
        } elseif (IntrusionPrevention::addToPositivliste($ip, $description, $category, $range !== '' ? $range : null)) {
            $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_ips_positivliste_added')));
        } else {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
        }
    } elseif (rex_post('remove_allowlist', 'int', 0) > 0) {
        $messages[] = IntrusionPrevention::removeFromPositivliste(rex_post('remove_allowlist', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_ips_positivliste_removed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
    } else {
        $id = rex_post('toggle_allowlist', 'int');
        $status = rex_post('new_status', 'int', 0) === 1 ? 1 : 0;
        $messages[] = IntrusionPrevention::updatePositivlisteEntry($id, ['status' => $status])
            ? rex_view::success(rex_escape($addon->i18n('upkeep_ips_status_updated')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
    }
}

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$isAdmin = rex::requireUser()->isAdmin();
$hadError = str_contains(implode('', $messages), 'alert-danger');

// Kopf
$ipsOn = (bool) $addon->getConfig('ips_active', false);
$actions = Ui::badge($t($ipsOn ? 'upkeep_list_ips_on' : 'upkeep_list_ips_off'), $ipsOn ? 'ok' : 'muted');
if ($isAdmin) {
    $actions .= ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '">' . rex_escape($t('upkeep_nav_settings')) . '</a>';
}
echo Ui::hero($t('upkeep_nav_protection_allowlist'), $t('upkeep_list_allowlist_intro'), Ui::icon('fa-shield', 'blue'), $actions);

echo implode('', $messages);

$categoryLabel = static fn (string $c): string => in_array($c, ['admin', 'cdn', 'monitoring', 'api', 'trusted'], true) ? $t('upkeep_ips_category_' . $c) : $c;

$rows = [];
try {
    $rows = rex_sql::factory()->getArray('SELECT * FROM ' . $table . ' ORDER BY created_at DESC');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

// Selbst-Entsperrungen sind nur Markierungen (keine Positivliste) – eigene Liste weiter unten
$unlockRows = array_values(array_filter($rows, static fn (array $r): bool => IntrusionPrevention::SELF_UNLOCK_CATEGORY === (string) ($r['category'] ?? '')));
$rows = array_values(array_filter($rows, static fn (array $r): bool => IntrusionPrevention::SELF_UNLOCK_CATEGORY !== (string) ($r['category'] ?? '')));

echo Ui::listTitle($t('upkeep_ips_positivliste_entries'), count($rows));

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_ips_no_positivliste_entries'), 'fa-check-circle') . '</div>';
} else {
    $labels = [
        'ip' => $t('upkeep_ips_ip_address'),
        'range' => $t('upkeep_ips_ip_range'),
        'description' => $t('upkeep_ips_description'),
        'category' => $t('upkeep_ips_category'),
        'status' => $t('upkeep_pages_status'),
        'created' => $t('upkeep_ips_created_at'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = '<form id="upk-allowlist-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    foreach ($labels as $key => $label) {
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $on = (int) $row['status'] === 1;
        $created = strtotime((string) ($row['created_at'] ?? ''));
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $ip = (string) ($row['ip_address'] ?? '');
        $range = (string) ($row['ip_range'] ?? '');
        $desc = rex_escape((string) ($row['description'] ?? ''));
        if ($expires) {
            $desc .= ' <span class="upk-muted">(' . rex_escape($t('upkeep_allowlist_expires', date('d.m.Y H:i', $expires))) . ')</span>';
        }
        $body .= '<tr>';
        $body .= Ui::td($labels['ip'], '' !== $ip ? '<span class="upk-mono">' . rex_escape($ip) . '</span>' : '<span class="upk-muted">–</span>');
        $body .= Ui::td($labels['range'], '' !== $range ? '<span class="upk-mono">' . rex_escape($range) . '</span>' : '<span class="upk-muted">–</span>');
        $body .= Ui::td($labels['description'], $desc);
        $body .= Ui::td($labels['category'], Ui::badge($categoryLabel((string) ($row['category'] ?? '')), 'muted'));
        $body .= Ui::td($labels['status'], Ui::status($on));
        $body .= Ui::td($labels['created'], rex_escape($created ? date('d.m.Y H:i', $created) : '-'), 'upk-nowrap');
        // Umschalten: eigenes kleines Formular, damit new_status mitgeschickt wird
        $body .= Ui::td($labels['actions'], '<form class="upk-inline-form" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField()
            . '<input type="hidden" name="new_status" value="' . ($on ? 0 : 1) . '">'
            . '<button type="submit" class="btn btn-xs upk-btn-ghost" name="toggle_allowlist" value="' . $id . '">' . rex_escape($on ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button>'
            . '</form> '
            . '<button type="submit" form="upk-allowlist-row" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="remove_allowlist" value="' . $id . '" data-confirm="' . rex_escape($t('upkeep_ips_confirm_remove')) . '">'
            . '<i class="rex-icon rex-icon-delete" aria-hidden="true"></i> ' . rex_escape($t('upkeep_delete')) . '</button>', 'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div></div>';
    echo $body;
}
echo '<p class="upk-group-note">' . rex_escape($t('upkeep_ips_positivliste_help')) . '</p>';

// Selbst entsperrte Adressen: weiter überwacht, keine Positivliste
if ($unlockRows) {
    $ulLabels = [
        'ip' => $t('upkeep_ips_ip_address'),
        'kind' => $t('upkeep_ips_category'),
        'until' => $t('upkeep_allowlist_unlocked_until'),
        'created' => $t('upkeep_ips_created_at'),
        'actions' => $t('upkeep_actions'),
    ];
    echo Ui::listTitle($t('upkeep_allowlist_unlocked_title'), count($unlockRows));
    // Formular für die Löschen-Knöpfe (steht sonst nur bei vorhandenen Positivliste-Einträgen)
    $body = $rows ? '' : '<form id="upk-allowlist-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    foreach ($ulLabels as $key => $label) {
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';
    foreach ($unlockRows as $row) {
        $id = (int) $row['id'];
        $created = strtotime((string) ($row['created_at'] ?? ''));
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $active = $expires && $expires > time() && (int) $row['status'] === 1;
        $until = $expires ? rex_escape(date('d.m.Y H:i', $expires)) : '-';
        if (!$active) {
            $until .= ' <span class="upk-muted">(' . rex_escape($t('upkeep_allowlist_unlocked_expired')) . ')</span>';
        }
        $body .= '<tr>';
        $body .= Ui::td($ulLabels['ip'], '<span class="upk-mono">' . rex_escape((string) ($row['ip_address'] ?? '')) . '</span>');
        $body .= Ui::td($ulLabels['kind'], Ui::badge($t('upkeep_allowlist_unlocked_badge'), 'warn'));
        $body .= Ui::td($ulLabels['until'], $until, 'upk-nowrap');
        $body .= Ui::td($ulLabels['created'], rex_escape($created ? date('d.m.Y H:i', $created) : '-'), 'upk-nowrap');
        $body .= Ui::td($ulLabels['actions'], '<button type="submit" form="upk-allowlist-row" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="remove_allowlist" value="' . $id . '" data-confirm="' . rex_escape($t('upkeep_ips_confirm_remove')) . '">'
            . '<i class="rex-icon rex-icon-delete" aria-hidden="true"></i> ' . rex_escape($t('upkeep_delete')) . '</button>', 'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div></div>';
    echo $body;
    echo '<p class="upk-group-note">' . rex_escape($t('upkeep_allowlist_unlocked_note')) . '</p>';
}

// Formular: hinzufügen
$posted = rex_post('add_allowlist', 'bool') && $hadError;
$value = static fn (string $name, string $default = ''): string => $posted ? (string) rex_post($name, 'string', $default) : $default;
$selectedCategory = $value('category', 'trusted');
$options = '';
foreach ($categories as $c) {
    $options .= '<option value="' . $c . '"' . ($c === $selectedCategory ? ' selected' : '') . '>' . rex_escape($categoryLabel($c)) . '</option>';
}
$help = '<ul class="upk-form-help">';
foreach ($categories as $c) {
    $help .= '<li><strong>' . rex_escape($categoryLabel($c)) . ':</strong> ' . rex_escape($t('upkeep_ips_category_' . $c . '_desc')) . '</li>';
}
$help .= '</ul>';

echo '<details class="upk-group upk-form-details"' . (!$rows || $posted ? ' open' : '') . ' id="upk-form">'
    . '<summary>' . rex_escape($t('upkeep_ips_positivliste_add')) . '</summary>'
    . '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField()
    . Ui::row($t('upkeep_ips_ip_address'), '<input type="text" class="form-control upk-mono" id="upk-al-ip" name="ip_address" maxlength="45" placeholder="192.0.2.10" value="' . rex_escape($value('ip_address')) . '">', '', 'upk-al-ip')
    . Ui::row($t('upkeep_ips_ip_range'), '<input type="text" class="form-control upk-mono" id="upk-al-range" name="ip_range" maxlength="49" placeholder="192.0.2.0/24" value="' . rex_escape($value('ip_range')) . '">', $t('upkeep_ips_ip_range_notice'), 'upk-al-range')
    . Ui::row($t('upkeep_ips_category'), '<select class="form-control" id="upk-al-cat" name="category">' . $options . '</select>', '', 'upk-al-cat')
    . Ui::row($t('upkeep_ips_description'), '<input type="text" class="form-control" id="upk-al-desc" name="description" maxlength="255" value="' . rex_escape($value('description')) . '">', '', 'upk-al-desc')
    . '<div class="upk-row upk-row--stack">' . $help . '</div>'
    . '<div class="upk-form-actions"><button type="submit" class="btn btn-primary" name="add_allowlist" value="1"><i class="rex-icon rex-icon-add" aria-hidden="true"></i> ' . rex_escape($t('upkeep_ips_positivliste_add')) . '</button></div>'
    . '</form></details>';
