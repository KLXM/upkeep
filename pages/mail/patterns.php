<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Standard-Muster (nur aktivieren/deaktivieren).
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

use KLXM\Upkeep\MailSecurityFilter;

$csrf = rex_csrf_token::factory('upkeep_mail_patterns');
$table = rex::getTable('upkeep_mail_default_patterns');

if (rex_post('toggle_pattern', 'int', 0) > 0) {
    if (!$csrf->isValid()) {
        echo rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        echo MailSecurityFilter::toggleDefaultPatternStatus(rex_post('toggle_pattern', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_ips_pattern_status_changed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_ips_pattern_status_error')));
    }
}

$filterCategory = mb_substr(rex_get('category', 'string', ''), 0, 100);

try {
    $sql = rex_sql::factory();
    $categories = array_map(static fn ($r) => (string) $r['category'], $sql->getArray('SELECT DISTINCT category FROM ' . $table . ' ORDER BY category'));
    if ($filterCategory !== '' && !in_array($filterCategory, $categories, true)) {
        $filterCategory = '';
    }
    $rows = $filterCategory !== ''
        ? $sql->getArray('SELECT * FROM ' . $table . ' WHERE category = ? ORDER BY category, pattern', [$filterCategory])
        : $sql->getArray('SELECT * FROM ' . $table . ' ORDER BY category, pattern');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

$severityBadge = static function (string $severity) use ($addon): string {
    $class = match ($severity) {
        'critical' => 'upk-badge--danger',
        'high', 'medium' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $addon->i18n('upkeep_ips_severity_' . $severity) : ($severity ?: '-');
    return '<span class="upk-badge ' . $class . '">' . rex_escape($label) . '</span>';
};

$filterParams = $filterCategory !== '' ? ['category' => $filterCategory] : [];

$filter = '<form class="upk-filter form-inline" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="patterns">';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-mp-cat">' . rex_escape($addon->i18n('upkeep_category')) . '</label><select class="form-control" id="upk-mp-cat" name="category"><option value="">' . rex_escape($addon->i18n('upkeep_all_categories')) . '</option>';
foreach ($categories as $cat) {
    $filter .= '<option value="' . rex_escape($cat) . '"' . ($filterCategory === $cat ? ' selected' : '') . '>' . rex_escape($cat) . '</option>';
}
$filter .= '</select></div> <button type="submit" class="btn btn-default"><i class="rex-icon fa-search"></i> ' . rex_escape($addon->i18n('upkeep_filter')) . '</button>';
if ($filterParams) {
    $filter .= ' <a class="btn btn-link" href="' . $tabUrl() . '">' . rex_escape($addon->i18n('upkeep_reset')) . '</a>';
}
$filter .= '</form>';

$intro = '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_mail_patterns_help')) . '</p>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_ips_no_default_patterns')) . '</p></div>';
} else {
    $body = '<form id="upk-mp-rows" action="' . $tabUrl($filterParams) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pattern')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_description')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_status')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    $currentCategory = null;
    foreach ($rows as $row) {
        $category = (string) $row['category'];
        if ($category !== $currentCategory) {
            $body .= '<tr class="upk-group-row"><th colspan="6">' . rex_escape($category) . '</th></tr>';
            $currentCategory = $category;
        }
        $on = (int) $row['status'] === 1;
        $body .= '<tr>';
        $body .= '<td><span class="upk-mono">' . rex_escape((string) $row['pattern']) . '</span></td>';
        $body .= '<td>' . rex_escape((string) ($row['description'] ?? '')) . '</td>';
        $body .= '<td>' . $severityBadge((string) $row['severity']) . '</td>';
        $body .= '<td>' . rex_escape((int) $row['is_regex'] ? $addon->i18n('upkeep_type_regex') : $addon->i18n('upkeep_type_text')) . '</td>';
        $body .= '<td><span class="upk-badge ' . ($on ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($on ? $addon->i18n('upkeep_active') : $addon->i18n('upkeep_inactive')) . '</span></td>';
        $body .= '<td class="upk-actions"><button type="submit" form="upk-mp-rows" class="btn btn-default btn-xs" name="toggle_pattern" value="' . (int) $row['id'] . '">'
            . rex_escape($on ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button></td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_mail_tab_patterns'), false);
$fragment->setVar('body', $intro . $filter . $body, false);
echo $fragment->parse('core/page/section.php');
