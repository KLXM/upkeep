<?php

/**
 * Upkeep 3.0 – Schutz: Positivliste (vertrauenswürdige IP-Adressen und Bereiche).
 */

use KLXM\Upkeep\IntrusionPrevention;

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

echo implode('', $messages);

$categoryLabel = static fn (string $c): string => in_array($c, ['admin', 'cdn', 'monitoring', 'api', 'trusted'], true) ? $addon->i18n('upkeep_ips_category_' . $c) : $c;

$rows = [];
try {
    $rows = rex_sql::factory()->getArray('SELECT * FROM ' . $table . ' ORDER BY created_at DESC');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

$toolbar = '<div class="upk-toolbar">'
    . '<span class="upk-muted">' . rex_escape($addon->i18n('upkeep_pages_entries_total', count($rows))) . '</span> '
    . '<a href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '"><i class="rex-icon fa-cog"></i> ' . rex_escape($addon->i18n('upkeep_pages_settings_link')) . '</a>'
    . '</div>';
$intro = '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_ips_positivliste_help')) . '</p>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_ips_no_positivliste_entries')) . '</p></div>';
} else {
    $body = '<form id="upk-allowlist-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_ip_address')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_ip_range')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_description')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_category')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_status')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_created_at')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $on = (int) $row['status'] === 1;
        $created = strtotime((string) ($row['created_at'] ?? ''));
        $expires = !empty($row['expires_at']) ? strtotime((string) $row['expires_at']) : false;
        $body .= '<tr>';
        $body .= '<td><span class="upk-mono">' . rex_escape((string) ($row['ip_address'] ?? '')) . '</span></td>';
        $body .= '<td><span class="upk-mono">' . rex_escape((string) ($row['ip_range'] ?? '')) . '</span></td>';
        $body .= '<td>' . rex_escape((string) ($row['description'] ?? ''));
        if ($expires) {
            $body .= ' <span class="upk-muted">(' . rex_escape($addon->i18n('upkeep_allowlist_expires', date('d.m.Y H:i', $expires))) . ')</span>';
        }
        $body .= '</td>';
        $body .= '<td><span class="upk-badge upk-badge--muted">' . rex_escape($categoryLabel((string) ($row['category'] ?? ''))) . '</span></td>';
        $body .= '<td><span class="upk-badge ' . ($on ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($on ? $addon->i18n('upkeep_active') : $addon->i18n('upkeep_inactive')) . '</span></td>';
        $body .= '<td>' . rex_escape($created ? date('d.m.Y H:i', $created) : '-') . '</td>';
        $body .= '<td class="upk-actions">';
        // Umschalten: eigenes kleines Formular, damit new_status mitgeschickt wird
        $body .= '<form class="upk-inline-form" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField()
            . '<input type="hidden" name="new_status" value="' . ($on ? 0 : 1) . '">'
            . '<button type="submit" class="btn btn-default btn-xs" name="toggle_allowlist" value="' . $id . '">' . rex_escape($on ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button>'
            . '</form> ';
        $body .= '<button type="submit" form="upk-allowlist-row" class="btn btn-delete btn-xs" name="remove_allowlist" value="' . $id . '" data-confirm="' . rex_escape($addon->i18n('upkeep_ips_confirm_remove')) . '">'
            . '<i class="rex-icon rex-icon-delete"></i> ' . rex_escape($addon->i18n('upkeep_delete')) . '</button>';
        $body .= '</td></tr>';
    }
    $body .= '</tbody></table></div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_ips_positivliste_entries'), false);
$fragment->setVar('body', $toolbar . $intro . $body, false);
echo $fragment->parse('core/page/section.php');

// Formular: hinzufügen
$options = '';
foreach ($categories as $c) {
    $options .= '<option value="' . $c . '"' . ($c === 'trusted' ? ' selected' : '') . '>' . rex_escape($categoryLabel($c)) . '</option>';
}
$help = '<ul class="upk-muted">';
foreach ($categories as $c) {
    $help .= '<li><strong>' . rex_escape($categoryLabel($c)) . ':</strong> ' . rex_escape($addon->i18n('upkeep_ips_category_' . $c . '_desc')) . '</li>';
}
$help .= '</ul>';

$form = '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField();
$form .= '<div class="row">';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-al-ip">' . rex_escape($addon->i18n('upkeep_ips_ip_address')) . '</label>'
    . '<input type="text" class="form-control upk-mono" id="upk-al-ip" name="ip_address" maxlength="45" placeholder="192.0.2.10"></div></div>';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-al-range">' . rex_escape($addon->i18n('upkeep_ips_ip_range')) . '</label>'
    . '<input type="text" class="form-control upk-mono" id="upk-al-range" name="ip_range" maxlength="49" placeholder="192.0.2.0/24">'
    . '<p class="help-block">' . rex_escape($addon->i18n('upkeep_ips_ip_range_notice')) . '</p></div></div>';
$form .= '<div class="col-sm-2"><div class="form-group"><label for="upk-al-cat">' . rex_escape($addon->i18n('upkeep_ips_category')) . '</label>'
    . '<select class="form-control" id="upk-al-cat" name="category">' . $options . '</select></div></div>';
$form .= '<div class="col-sm-4"><div class="form-group"><label for="upk-al-desc">' . rex_escape($addon->i18n('upkeep_ips_description')) . '</label>'
    . '<input type="text" class="form-control" id="upk-al-desc" name="description" maxlength="255"></div></div>';
$form .= '</div>';
$form .= '<button type="submit" class="btn btn-primary" name="add_allowlist" value="1"><i class="rex-icon rex-icon-add"></i> ' . rex_escape($addon->i18n('upkeep_ips_positivliste_add')) . '</button>';
$form .= '</form>';
$form .= $help;

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_ips_positivliste_add'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');
