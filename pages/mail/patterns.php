<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Standard-Muster (nur aktivieren/deaktivieren).
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

use KLXM\Upkeep\MailSecurityFilter;
use KLXM\Upkeep\Ui;

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
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
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

$filterParams = $filterCategory !== '' ? ['category' => $filterCategory] : [];

$filter = '<form class="upk-group upk-filterbar" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="patterns">';
$filter .= '<label class="sr-only" for="upk-mp-cat">' . rex_escape($t('upkeep_category')) . '</label><select class="form-control" id="upk-mp-cat" name="category"><option value="">' . rex_escape($t('upkeep_all_categories')) . '</option>';
foreach ($categories as $cat) {
    $filter .= '<option value="' . rex_escape($cat) . '"' . ($filterCategory === $cat ? ' selected' : '') . '>' . rex_escape($cat) . '</option>';
}
$filter .= '</select><span class="upk-filterbar-end">';
if ($filterParams) {
    $filter .= '<a class="upk-filterbar-reset" href="' . $tabUrl() . '">' . rex_escape($t('upkeep_reset')) . '</a>';
}
$filter .= '<button type="submit" class="btn btn-primary"><i class="rex-icon fa-search" aria-hidden="true"></i> ' . rex_escape($t('upkeep_filter')) . '</button></span>';
$filter .= '</form>';
echo $filter;

echo Ui::listTitle($t('upkeep_mail_tab_patterns'), count($rows));

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_ips_no_default_patterns'), 'fa-code') . '</div>';
    return;
}

$labels = [
    'pattern' => $t('upkeep_pattern'),
    'description' => $t('upkeep_description'),
    'severity' => $t('upkeep_ips_severity'),
    'type' => $t('upkeep_ips_type'),
    'status' => $t('upkeep_pages_status'),
    'actions' => $t('upkeep_actions'),
];
$body = '<form id="upk-mp-rows" action="' . $tabUrl($filterParams) . '" method="post">' . $csrf->getHiddenField() . '</form>';
$body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
foreach ($labels as $key => $label) {
    $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
}
$body .= '</tr></thead><tbody>';
$currentCategory = null;
foreach ($rows as $row) {
    $category = (string) $row['category'];
    if ($category !== $currentCategory) {
        $body .= '<tr class="upk-table-group"><th colspan="6" scope="colgroup">' . rex_escape($category) . '</th></tr>';
        $currentCategory = $category;
    }
    $on = (int) $row['status'] === 1;
    $body .= '<tr>';
    $body .= Ui::td($labels['pattern'], '<span class="upk-mono">' . rex_escape((string) $row['pattern']) . '</span>');
    $body .= Ui::td($labels['description'], rex_escape((string) ($row['description'] ?? '')));
    $body .= Ui::td($labels['severity'], Ui::severity((string) $row['severity']));
    $body .= Ui::td($labels['type'], rex_escape((int) $row['is_regex'] ? $t('upkeep_type_regex') : $t('upkeep_type_text')));
    $body .= Ui::td($labels['status'], Ui::status($on));
    $body .= Ui::td($labels['actions'], '<button type="submit" form="upk-mp-rows" class="btn btn-xs upk-btn-ghost" name="toggle_pattern" value="' . (int) $row['id'] . '">'
        . rex_escape($on ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button>', 'upk-actions');
    $body .= '</tr>';
}
$body .= '</tbody></table></div></div>';
$body .= '<p class="upk-group-note">' . rex_escape($t('upkeep_mail_patterns_help')) . '</p>';
echo $body;
