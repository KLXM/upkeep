<?php

/**
 * Formularschutz: abgewehrte Einsendungen der YForm-Formulare im Frontend.
 */

use KLXM\Upkeep\FormProtection;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$isAdmin = rex::requireUser()->isAdmin();
$t = static fn (string $key, string ...$args) => rex_i18n::rawMsg($key, ...$args);
$reasonLabel = static function (string $code) use ($t): string {
    $key = 'upkeep_form_protection_reason_' . $code;
    return rex_i18n::hasMsg($key) ? $t($key) : $code;
};

$active = (bool) $addon->getConfig('form_protection_active', false);
$yform = rex_addon::get('yform')->isAvailable();

// Status
$status = $active
    ? Ui::badge($t('upkeep_dash_on'), 'ok') . ' ' . Ui::badge($t('strict' === $addon->getConfig('form_protection_level', 'normal') ? 'upkeep_set_form_level_strict' : 'upkeep_set_form_level_normal'), 'info')
    : Ui::badge($t('upkeep_dash_off'));
$head = '<div class="upk-hero"><div class="upk-hero-main">' . Ui::icon('fa-wpforms', 'green')
    . '<div><h2>' . rex_escape($t('upkeep_set_section_forms')) . '</h2><p>' . rex_escape($t('upkeep_forms_page_intro')) . '</p></div></div>'
    . '<div class="upk-hero-actions">' . $status
    . ($isAdmin ? ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'forms']) . '">' . rex_escape($t('upkeep_nav_settings')) . '</a>' : '')
    . '</div></div>';
echo $head;

if (!$yform) {
    echo rex_view::info(rex_escape($t('upkeep_forms_no_yform')));
    return;
}

$stats = FormProtection::getStats(30);
$recent = FormProtection::getRecent(50);

// Kennzahlen
$tiles = [];
$tiles[] = Ui::tile($t('upkeep_forms_tile_total'), Ui::icon('fa-ban', 'green'), '<div class="upk-tile-value">' . (int) $stats['total'] . ' <small>' . rex_escape($t('upkeep_forms_last_30')) . '</small></div>');

$reasons = '';
foreach (array_slice($stats['by_reason'], 0, 5, true) as $code => $count) {
    $reasons .= '<li><span>' . rex_escape($reasonLabel((string) $code)) . '</span><span>' . (int) $count . '</span></li>';
}
$tiles[] = Ui::tile($t('upkeep_forms_tile_reasons'), Ui::icon('fa-search', 'blue'), '' !== $reasons ? '<ul class="upk-facts">' . $reasons . '</ul>' : '<p class="upk-tile-text">' . rex_escape($t('upkeep_forms_none')) . '</p>');

$forms = '';
foreach (array_slice($stats['by_form'], 0, 5, true) as $name => $count) {
    $forms .= '<li><span class="upk-mono">' . rex_escape((string) $name) . '</span><span>' . (int) $count . '</span></li>';
}
$tiles[] = Ui::tile($t('upkeep_forms_tile_forms'), Ui::icon('fa-list-alt', 'teal'), '' !== $forms ? '<ul class="upk-facts">' . $forms . '</ul>' : '<p class="upk-tile-text">' . rex_escape($t('upkeep_forms_none')) . '</p>');

// Verlauf der letzten 30 Tage als schlichte Balken
$max = max(1, ...array_values($stats['by_day']));
$bars = '<div class="upk-bars" role="img" aria-label="' . rex_escape($t('upkeep_forms_chart_label')) . '">';
foreach ($stats['by_day'] as $day => $count) {
    $bars .= '<span title="' . rex_escape(rex_formatter::intlDate(strtotime($day), IntlDateFormatter::MEDIUM) . ': ' . $count) . '" style="--h:' . round(100 * $count / $max) . '%"></span>';
}
$bars .= '</div>';
$tiles[] = Ui::tile($t('upkeep_forms_tile_chart'), Ui::icon('fa-bar-chart', 'purple'), $bars, '', 'upk-tile--wide');

echo '<div class="upk-tiles">' . implode('', $tiles) . '</div>';

// Letzte Einsendungen
if (!$recent) {
    echo Ui::group($t('upkeep_forms_recent'), ['<div class="upk-empty"><i class="rex-icon fa fa-check"></i>' . rex_escape($t('upkeep_forms_none')) . '</div>']);
    return;
}
$rows = '';
foreach ($recent as $entry) {
    $codes = array_filter(explode(',', $entry['reasons']));
    $badges = implode(' ', array_map(static fn ($c) => Ui::badge($reasonLabel($c), 'muted'), $codes));
    $rows .= '<tr>'
        . '<td>' . rex_escape(Ui::date((int) strtotime($entry['created_at']))) . '</td>'
        . '<td class="upk-mono">' . rex_escape($entry['form_name']) . '</td>'
        . '<td>' . $badges . '</td>'
        . '<td>' . (int) $entry['score'] . '</td>'
        . '<td class="upk-mono">' . rex_escape($entry['ip_address']) . '</td>'
        . '<td class="upk-mono">' . rex_escape(mb_strimwidth($entry['url'], 0, 60, '…')) . '</td>'
        . '</tr>';
}
$table = '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>'
    . '<th>' . rex_escape($t('upkeep_forms_col_time')) . '</th><th>' . rex_escape($t('upkeep_forms_col_form')) . '</th>'
    . '<th>' . rex_escape($t('upkeep_form_protection_col_reasons')) . '</th><th>' . rex_escape($t('upkeep_forms_col_score')) . '</th>'
    . '<th>IP</th><th>' . rex_escape($t('upkeep_forms_col_url')) . '</th></tr></thead><tbody>' . $rows . '</tbody></table></div>';

$section = new rex_fragment();
$section->setVar('title', rex_escape($t('upkeep_forms_recent')), false);
$section->setVar('content', $table, false);
echo $section->parse('core/page/section.php');
