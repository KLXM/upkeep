<?php

/**
 * Upkeep 3.0 – Schutz: Statistik (nur Admins).
 *
 * Nur lesend: Treffer, Sperren und Arten im gewählten Zeitraum. Jede Zahl führt,
 * wo es einen passenden Filter gibt, zu den Ereignissen bzw. gesperrten IPs.
 */

use KLXM\Upkeep\ProtectionStats;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);

if (!rex::requireUser()->isAdmin()) {
    echo rex_view::error(rex_escape($t('upkeep_stats_admin_only')));
    return;
}

$pageKey = 'upkeep/protection/stats';
$eventsPage = 'upkeep/protection/events';
$period = ProtectionStats::normalizePeriod(rex_get('period', 'string', ProtectionStats::DEFAULT_PERIOD));
$stats = ProtectionStats::get($period);
$range = $stats['range'];

$numberFormat = str_starts_with(rex_i18n::getLanguage(), 'de') ? [0, ',', '.'] : [0, '.', ','];
$number = static fn (int $v): string => rex_formatter::number($v, $numberFormat);
$pct = static fn (int $part, int $total): string => ($total > 0 ? (($part / $total * 100) > 0 && ($part / $total * 100) < 1 ? '< 1' : (string) round($part / $total * 100)) : '0') . ' %';

// Filter des Zeitraums für die Ereignisse (Tagesgenau – bei 24 h ab gestern)
$periodFilter = ['from' => date('Y-m-d', $range['from_ts']), 'to' => date('Y-m-d')];
$eventsUrl = static fn (array $filter = []): string => rex_url::backendPage($eventsPage, $filter + $periodFilter);

// Kopf
$ipsOn = (bool) $addon->getConfig('ips_active', false);
$actions = Ui::badge($t($ipsOn ? 'upkeep_list_ips_on' : 'upkeep_list_ips_off'), $ipsOn ? 'ok' : 'muted');
if ($ipsOn && $addon->getConfig('ips_monitor_only', false)) {
    $actions .= ' ' . Ui::badge($t('upkeep_set_ips_monitor_only'), 'info');
}
echo Ui::hero($t('upkeep_nav_protection_stats'), $t('upkeep_stats_intro'), Ui::icon('fa-bar-chart', 'indigo'), $actions);

// Zeitraum
$items = [];
foreach (array_keys(ProtectionStats::PERIODS) as $key) {
    $items[$key] = [$t('upkeep_stats_period_' . $key), rex_url::backendPage($pageKey, ['period' => $key])];
}
echo '<div class="upk-stats-toolbar">' . Ui::segmented($items, $period, $t('upkeep_stats_period')) . '</div>';

if (!$stats['ok']) {
    echo rex_view::error(rex_escape($t('upkeep_stats_error')));
    return;
}

$byAction = $stats['by_action'];
$temp = (int) ($byAction['temporary_block'] ?? 0);
$perm = (int) ($byAction['permanent_block'] ?? 0);
$logged = (int) ($byAction['logged'] ?? 0);
$cross = (int) ($byAction['logged_cross_site'] ?? 0);

// ---------- Kacheln ----------
$link = static fn (string $url, string $text, string $label = ''): string => '<a href="' . $url . '"' . ('' !== $label ? ' aria-label="' . rex_escape($label) . '"' : '') . '>' . rex_escape($text) . '</a>';
$tile = static fn (string $title, string $icon, string $color, int $value, string $sub = '', string $foot = ''): string => Ui::tile(
    $title,
    Ui::icon($icon, $color),
    '<div class="upk-tile-value">' . rex_escape($number($value)) . '</div>' . ('' !== $sub ? '<p class="upk-stats-tile-sub">' . rex_escape($sub) . '</p>' : ''),
    $foot,
    'upk-tile--stat',
);
$show = $t('upkeep_list_show');

$tiles = $tile($t('upkeep_stats_tile_hits'), 'fa-crosshairs', 'blue', $stats['hits'], '', $link($eventsUrl(), $show, $t('upkeep_stats_tile_hits') . ': ' . $show));
$tiles .= $tile(
    $t('upkeep_stats_tile_blocks'),
    'fa-ban',
    'red',
    $temp + $perm,
    $t('upkeep_stats_tile_blocks_split', $number($temp), $number($perm)),
    $link($eventsUrl(['action' => 'temporary_block']), $t('upkeep_stats_temporary_short'), $t('upkeep_stats_action_temporary_block'))
    . $link($eventsUrl(['action' => 'permanent_block']), $t('upkeep_stats_permanent_short'), $t('upkeep_stats_action_permanent_block')),
);
$tiles .= $tile($t('upkeep_stats_tile_blocked_now'), 'fa-lock', 'orange', $stats['blocked_now'], '', $link(rex_url::backendPage('upkeep/protection/blocked'), $show, $t('upkeep_stats_tile_blocked_now') . ': ' . $show));
$tiles .= $tile($t('upkeep_stats_tile_unlocks'), 'fa-unlock', 'purple', $stats['self_unlocks'], '', $link(rex_url::backendPage('upkeep/protection/allowlist'), $show, $t('upkeep_stats_tile_unlocks') . ': ' . $show));
$tiles .= $tile(
    $t('upkeep_stats_tile_logged'),
    'fa-eye',
    'teal',
    $logged + $cross,
    $cross > 0 ? $t('upkeep_stats_tile_logged_cross', $number($cross)) : '',
    $link($eventsUrl(['action' => 'logged']), $t('upkeep_stats_logged_short'), $t('upkeep_stats_action_logged'))
    . ($cross > 0 ? $link($eventsUrl(['action' => 'logged_cross_site']), $t('upkeep_stats_cross_short'), $t('upkeep_stats_action_logged_cross_site')) : ''),
);
if (null !== $stats['forms_rejected']) {
    $tiles .= $tile($t('upkeep_stats_tile_forms'), 'fa-wpforms', 'green', (int) $stats['forms_rejected'], '', $link(rex_url::backendPage('upkeep/protection/forms'), $show, $t('upkeep_stats_tile_forms') . ': ' . $show));
}
echo '<div class="upk-tiles upk-tiles--stats upk-stats-tiles">' . $tiles . '</div>';

/**
 * Liste mit waagerechten Balken (wie die Speicherübersicht).
 *
 * @param list<array{label: string, sub?: string, value: int, color: string, icon: string, url?: string}> $rows
 */
$barList = static function (array $rows, int $total, string $footHtml = '') use ($number, $pct): string {
    $max = max(1, ...array_map(static fn ($r) => $r['value'], $rows ?: [['value' => 1]]));
    $html = '<div class="upk-group upk-stats-list">';
    foreach ($rows as $row) {
        $label = rex_escape($row['label']);
        if (!empty($row['url'])) {
            $label = '<a href="' . $row['url'] . '">' . $label . '</a>';
        }
        $html .= '<div class="upk-stats-row upk-stats--' . rex_escape($row['color']) . '">'
            . '<span class="upk-stats-row-icon" aria-hidden="true"><i class="rex-icon fa ' . rex_escape($row['icon']) . '"></i></span>'
            . '<div class="upk-stats-row-main">'
            . '<div class="upk-stats-row-top"><strong>' . $label . '</strong><span class="upk-stats-row-value">' . rex_escape($number($row['value'])) . '</span></div>'
            . '<div class="upk-stats-row-sub"><span>' . (!empty($row['sub']) ? '<span class="upk-mono">' . rex_escape($row['sub']) . '</span>' : '') . '</span><span>' . rex_escape($pct($row['value'], $total)) . '</span></div>'
            . '<span class="upk-stats-share" aria-hidden="true"><span style="width: ' . rex_escape((string) max(1, round($row['value'] / $max * 100, 1))) . '%"></span></span>'
            . '</div></div>';
    }
    if ('' !== $footHtml) {
        $html .= '<div class="upk-stats-list-foot">' . $footHtml . '</div>';
    }
    return $html . '</div>';
};

// ---------- Aktuelle Sperren nach Herkunft (unabhängig vom Zeitraum) ----------
$sourceList = '';
if ($stats['blocked_now'] > 0) {
    $sourceMeta = [
        'auto' => ['high', 'fa-shield'],
        'manual' => ['manual', 'fa-hand-paper-o'],
        'external' => ['type', 'fa-plug'],
        'after_unlock' => ['critical', 'fa-repeat'],
    ];
    $rows = [];
    foreach ($stats['blocked_by_source'] as $source => $value) {
        $source = (string) $source;
        $known = isset($sourceMeta[$source]);
        $rows[] = [
            'label' => $known ? $t('upkeep_stats_source_' . $source) : $source,
            'value' => $value,
            'color' => $known ? $sourceMeta[$source][0] : 'other',
            'icon' => $known ? $sourceMeta[$source][1] : 'fa-question',
        ];
    }
    $sourceList = Ui::listTitle($t('upkeep_stats_by_source'), $stats['blocked_now'])
        . $barList($rows, $stats['blocked_now'], '<a href="' . rex_url::backendPage('upkeep/protection/blocked') . '">' . rex_escape($t('upkeep_stats_show_blocked')) . '</a>');
}

$hasHits = $stats['hits'] > 0;

if (!$hasHits) {
    echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_stats_empty'), 'fa-check') . '</div>';
    if ('' !== $sourceList) {
        echo '<div class="upk-stats-grid"><section>' . $sourceList . '</section></div>';
    }
} else {
    // ---------- Zeitleiste ----------
    $hourly = $range['hourly'];
    $buckets = $range['buckets'];
    $count = count($buckets);
    $labelEvery = $hourly ? 6 : match (true) {
        $count <= 7 => 1,
        $count <= 30 => 5,
        default => 15,
    };
    $max = max(1, $stats['timeline_max']);
    $sevColor = ['low' => 'low', 'medium' => 'medium', 'high' => 'high', 'critical' => 'critical'];
    $sevLabel = static fn (string $s): string => rex_i18n::rawMsg('upkeep_ips_severity_' . $s);
    $bucketLabel = static fn (int $ts): string => $hourly ? date('H:00', $ts) : date('d.m.', $ts);
    $bucketTitle = static fn (int $ts): string => $hourly ? date('d.m.Y H:00', $ts) : date('d.m.Y', $ts);

    $cols = '';
    $labels = '';
    $i = 0;
    foreach ($buckets as $key => $ts) {
        $values = $stats['timeline'][$key];
        $sum = array_sum($values);
        $parts = [];
        foreach (array_reverse(ProtectionStats::SEVERITIES) as $s) {
            if ($values[$s] > 0) {
                $parts[] = $sevLabel($s) . ' ' . $number($values[$s]);
            }
        }
        $title = $bucketTitle($ts) . ': ' . $number($sum) . ($parts ? ' (' . implode(', ', $parts) . ')' : '');
        $stack = '';
        foreach (ProtectionStats::SEVERITIES as $s) {
            if ($values[$s] > 0) {
                $stack .= '<span class="upk-stats--' . $sevColor[$s] . '" style="flex-grow: ' . $values[$s] . '"></span>';
            }
        }
        $cols .= '<div class="upk-stats-col" title="' . rex_escape($title) . '"><div class="upk-stats-stack" style="height: ' . rex_escape((string) round($sum / $max * 100, 2)) . '%">' . $stack . '</div></div>';
        $labels .= '<span>' . (0 === $i % $labelEvery ? rex_escape($bucketLabel($ts)) : '') . '</span>';
        ++$i;
    }

    $legend = '';
    foreach (ProtectionStats::SEVERITIES as $s) {
        $legend .= '<li><span class="upk-stats-dot upk-stats--' . $s . '" aria-hidden="true"></span>' . rex_escape($sevLabel($s)) . '</li>';
    }

    // Tabelle als Alternative zum Diagramm
    $table = '<table class="upk-table upk-stats-table"><caption class="sr-only">' . rex_escape($t($hourly ? 'upkeep_stats_timeline_hourly' : 'upkeep_stats_timeline_daily')) . '</caption><thead><tr><th scope="col">' . rex_escape($t('upkeep_stats_time')) . '</th>';
    foreach (ProtectionStats::SEVERITIES as $s) {
        $table .= '<th scope="col" class="upk-stats-num">' . rex_escape($sevLabel($s)) . '</th>';
    }
    $table .= '<th scope="col" class="upk-stats-num">' . rex_escape($t('upkeep_stats_total')) . '</th></tr></thead><tbody>';
    foreach (array_reverse($buckets, true) as $key => $ts) {
        $values = $stats['timeline'][$key];
        $sum = array_sum($values);
        if (0 === $sum) {
            continue;
        }
        $day = date('Y-m-d', $ts);
        $table .= '<tr><th scope="row"><a href="' . rex_url::backendPage($eventsPage, ['from' => $day, 'to' => $day]) . '">' . rex_escape($bucketTitle($ts)) . '</a></th>';
        foreach (ProtectionStats::SEVERITIES as $s) {
            $table .= '<td class="upk-stats-num">' . rex_escape($number($values[$s])) . '</td>';
        }
        $table .= '<td class="upk-stats-num"><strong>' . rex_escape($number($sum)) . '</strong></td></tr>';
    }
    $table .= '</tbody></table>';

    echo '<section class="upk-stats-card">'
        . '<div class="upk-stats-card-head"><div><h3>' . rex_escape($t('upkeep_stats_timeline')) . '</h3><p>' . rex_escape($t($hourly ? 'upkeep_stats_timeline_hourly' : 'upkeep_stats_timeline_daily')) . '</p></div>'
        . '<div class="upk-stats-card-total">' . rex_escape($number($stats['hits'])) . '</div></div>'
        . '<div class="upk-stats-chart" role="img" aria-label="' . rex_escape($t('upkeep_stats_timeline_label', $number($stats['hits']), $number($stats['timeline_max']))) . '">'
        . '<div class="upk-stats-axis" aria-hidden="true"><span>' . rex_escape($number($stats['timeline_max'])) . '</span><span>' . rex_escape($number((int) round($stats['timeline_max'] / 2))) . '</span><span>0</span></div>'
        . '<div class="upk-stats-plot"><div class="upk-stats-cols" style="--upk-stats-n: ' . $count . '">' . $cols . '</div>'
        . '<div class="upk-stats-xlabels" aria-hidden="true" style="--upk-stats-n: ' . $count . '">' . $labels . '</div></div>'
        . '</div>'
        . '<ul class="upk-stats-legend">' . $legend . '</ul>'
        . '<details class="upk-stats-details"><summary>' . rex_escape($t('upkeep_stats_timeline_table')) . '</summary><div class="upk-table-wrap">' . $table . '</div></details>'
        . '</section>';

    // ---------- Aufschlüsselungen ----------
    $typeLabel = static function (string $type): string {
        if (str_starts_with($type, 'mail_escalated_')) {
            return rex_i18n::rawMsg('upkeep_stats_type_mail_escalated') . ': ' . substr($type, 15);
        }
        return rex_i18n::hasMsg('upkeep_stats_type_' . $type) ? rex_i18n::rawMsg('upkeep_stats_type_' . $type) : $type;
    };
    $typeIcon = static fn (string $type): string => match (true) {
        str_contains($type, 'user_agent') => 'fa-user-secret',
        str_contains($type, 'rate_limit') => 'fa-tachometer',
        str_starts_with($type, 'form') => 'fa-wpforms',
        str_starts_with($type, 'mail') => 'fa-envelope-o',
        str_starts_with($type, 'custom') => 'fa-code',
        default => 'fa-bug',
    };

    $rows = [];
    foreach ($stats['by_type'] as $type => $value) {
        $type = (string) $type;
        $label = $typeLabel($type);
        $rows[] = ['label' => $label, 'sub' => $label !== $type ? $type : '', 'value' => $value, 'color' => 'type', 'icon' => $typeIcon($type), 'url' => $eventsUrl(['type' => $type])];
    }
    $more = $stats['type_count'] - count($rows);
    $typeList = Ui::listTitle($t('upkeep_stats_by_type'), $stats['type_count'])
        . $barList($rows, $stats['hits'], $more > 0 ? '<span class="upk-muted">' . rex_escape($t('upkeep_stats_by_type_more', (string) $more)) . '</span>' : '');

    $rows = [];
    foreach (array_reverse(ProtectionStats::SEVERITIES) as $s) {
        $rows[] = ['label' => $sevLabel($s), 'value' => $stats['by_severity'][$s] ?? 0, 'color' => $s, 'icon' => 'critical' === $s || 'high' === $s ? 'fa-exclamation-triangle' : ('medium' === $s ? 'fa-exclamation-circle' : 'fa-info-circle'), 'url' => $eventsUrl(['severity' => $s])];
    }
    $sevList = Ui::listTitle($t('upkeep_stats_by_severity')) . $barList($rows, $stats['hits']);

    $actionMeta = [
        'temporary_block' => ['high', 'fa-clock-o'],
        'permanent_block' => ['critical', 'fa-ban'],
        'logged' => ['low', 'fa-eye'],
        'logged_cross_site' => ['cross', 'fa-external-link'],
    ];
    $rows = [];
    foreach ($byAction as $action => $value) {
        $action = (string) $action;
        $known = isset($actionMeta[$action]);
        $rows[] = [
            'label' => $known ? $t('upkeep_stats_action_' . $action) : ('' !== $action ? $action : '–'),
            'value' => $value,
            'color' => $known ? $actionMeta[$action][0] : 'other',
            'icon' => $known ? $actionMeta[$action][1] : 'fa-question',
            'url' => $known ? $eventsUrl(['action' => $action]) : '',
        ];
    }
    $actionList = Ui::listTitle($t('upkeep_stats_by_action')) . $barList($rows, $stats['hits']);

    echo '<div class="upk-stats-grid"><section>' . $typeList . '</section><section>' . $sevList . $actionList . $sourceList . '</section></div>';
}

// ---------- Auffälligste Adressen ----------
if ($stats['top_ips']) {
    $labels = [
        'ip' => $t('upkeep_ips_ip'),
        'hits' => $t('upkeep_stats_hits'),
        'severity' => $t('upkeep_ips_severity'),
        'last' => $t('upkeep_stats_last_seen'),
        'status' => $t('upkeep_stats_status'),
    ];
    $top = '<section class="upk-stats-top">' . Ui::listTitle($t('upkeep_stats_top_ips'), count($stats['top_ips']))
        . '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    foreach ($labels as $key => $label) {
        $top .= '<th scope="col"' . ('hits' === $key ? ' class="upk-stats-num"' : '') . '>' . rex_escape($label) . '</th>';
    }
    $top .= '</tr></thead><tbody>';
    $statusBadge = [
        'blocked' => ['upkeep_stats_status_blocked', 'danger'],
        'unlocked' => ['upkeep_stats_status_unlocked', 'info'],
        'free' => ['upkeep_stats_status_free', 'muted'],
    ];
    foreach ($stats['top_ips'] as $row) {
        $last = strtotime($row['last_seen']);
        [$statusKey, $variant] = $statusBadge[$row['status']];
        $top .= '<tr>'
            . Ui::td($labels['ip'], '<a class="upk-mono" href="' . $eventsUrl(['ip' => $row['ip']]) . '" title="' . rex_escape($t('upkeep_stats_show_events_for', $row['ip'])) . '">' . rex_escape($row['ip']) . '</a>')
            . Ui::td($labels['hits'], rex_escape($number($row['hits'])), 'upk-stats-num')
            . Ui::td($labels['severity'], Ui::severity($row['severity']))
            . Ui::td($labels['last'], rex_escape($last ? date('d.m.Y H:i', $last) : '–'), 'upk-nowrap')
            . Ui::td($labels['status'], Ui::badge($t($statusKey), $variant))
            . '</tr>';
    }
    $top .= '</tbody></table></div></div></section>';
    echo $top;
}
