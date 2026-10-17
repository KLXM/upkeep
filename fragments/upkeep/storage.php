<?php

/**
 * Speicherübersicht im Stil von macOS (Systemeinstellungen > Allgemein > Speicher):
 * großer Balken mit Lücken zwischen den Bereichen, Legende, darunter die Aufschlüsselung als Liste.
 *
 * Variablen:
 * - report      array   Bericht aus KLXM\Upkeep\Storage::getReport() ([] = noch nicht berechnet)
 * - canRefresh  bool    Darf der Nutzer neu berechnen / Cache leeren (nur Admins)
 * - csrf        rex_csrf_token|string  Token-Objekt oder fertiges Hidden-Field-HTML
 * - action      string  Ziel-URL des Formulars (fertig escaped aus rex_url)
 *
 * @var rex_fragment $this
 * @psalm-scope-this rex_fragment
 */

$report = $this->getVar('report', []);
$report = is_array($report) ? $report : [];
$canRefresh = (bool) $this->getVar('canRefresh', false);
$csrf = $this->getVar('csrf', '');
$action = (string) $this->getVar('action', '');

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$csrfField = $csrf instanceof rex_csrf_token ? $csrf->getHiddenField() : (string) $csrf;
$bytes = static fn ($v): string => rex_formatter::bytes((int) $v, [1]);
$numberFormat = str_starts_with(rex_i18n::getLanguage(), 'de') ? [0, ',', '.'] : [0, '.', ','];
$number = static fn ($v): string => rex_formatter::number((int) $v, $numberFormat);
$pct = static fn (float $v): string => ($v > 0 && $v < 1 ? '< 1' : (string) round($v)) . ' %';

$icons = [
    'images' => 'fa-picture-o',
    'videos' => 'fa-film',
    'documents' => 'fa-file-text-o',
    'audio' => 'fa-music',
    'media_other' => 'fa-folder-o',
    'media_manager' => 'fa-magic',
    'database' => 'fa-database',
    'backups' => 'fa-archive',
    'logs' => 'fa-list-alt',
    'cache' => 'fa-bolt',
    'system' => 'fa-cogs',
];
$cssKey = static fn (string $key): string => preg_replace('/[^a-z0-9_-]/', '', strtolower($key)) ?? 'other';
$label = static fn (string $key): string => rex_i18n::rawMsg('upkeep_storage_cat_' . $key);

$form = static function (string $value, string $text, string $icon, string $class = 'btn-default') use ($canRefresh, $csrfField, $action): string {
    if (!$canRefresh) {
        return '';
    }
    return '<form class="upkeep-storage__form" method="post" action="' . $action . '">'
        . $csrfField
        . '<button type="submit" class="btn ' . rex_escape($class) . ' btn-sm" name="upkeep_storage_action" value="' . rex_escape($value) . '">'
        . '<i class="rex-icon fa ' . rex_escape($icon) . '" aria-hidden="true"></i> ' . rex_escape($text)
        . '</button></form>';
};

// ---------- Noch nicht berechnet ----------
if ([] === $report) {
    ?>
    <div class="upkeep-storage">
        <div class="upkeep-storage__card">
            <div class="upkeep-storage__head">
                <span class="upkeep-storage__drive" aria-hidden="true"><i class="rex-icon fa fa-hdd-o"></i></span>
                <div class="upkeep-storage__head-text">
                    <h3><?= rex_escape($t('upkeep_storage_site')) ?></h3>
                    <p><?= rex_escape($t('upkeep_storage_not_computed')) ?></p>
                </div>
            </div>
            <div class="upkeep-storage__bar upkeep-storage__bar--empty" aria-hidden="true"></div>
            <div class="upkeep-storage__footer">
                <span class="upkeep-storage__time"><?= rex_escape($canRefresh ? '' : $t('upkeep_storage_not_computed_editor')) ?></span>
                <?= $form('refresh', $t('upkeep_storage_compute_now'), 'fa-calculator', 'btn-primary') ?>
            </div>
        </div>
    </div>
    <?php
    return;
}

// ---------- Daten aufbereiten ----------
$categories = array_values(array_filter((array) ($report['categories'] ?? []), static fn ($c): bool => is_array($c) && isset($c['key'])));
usort($categories, static fn ($a, $b) => ((int) $b['bytes']) <=> ((int) $a['bytes']));
$used = array_values(array_filter($categories, static fn ($c) => (int) $c['bytes'] > 0));
$empty = array_values(array_filter($categories, static fn ($c) => (int) $c['bytes'] <= 0));
$total = max(0, (int) ($report['total_bytes'] ?? 0));
$disk = is_array($report['disk'] ?? null) && (int) ($report['disk']['total'] ?? 0) > 0 ? $report['disk'] : null;
$media = is_array($report['media'] ?? null) ? $report['media'] : [];
$database = is_array($report['database'] ?? null) ? $report['database'] : [];
$computedAt = (int) ($report['computed_at'] ?? 0);

$user = rex::getUser();
$mediaLinks = rex_addon::get('mediapool')->isAvailable() && $user && $user->getComplexPerm('media')->hasMediaPerm();

$countText = static function (array $cat) use ($t, $number): string {
    $unit = 'database' === $cat['key'] ? 'table' : 'file';
    return $t('upkeep_storage_count_' . $unit . (1 === (int) $cat['count'] ? '' : 's'), $number($cat['count']));
};

// Untertitel: belegt + freier Platz auf dem Server (wenn bekannt)
$subtitle = $t('upkeep_storage_used', $bytes($total));
if ($disk) {
    $subtitle .= ' · ' . $t('upkeep_storage_disk_free', $bytes($disk['free']), $bytes($disk['total']));
}
?>
<div class="upkeep-storage">

    <div class="upkeep-storage__card">
        <div class="upkeep-storage__head">
            <span class="upkeep-storage__drive" aria-hidden="true"><i class="rex-icon fa fa-hdd-o"></i></span>
            <div class="upkeep-storage__head-text">
                <h3><?= rex_escape($t('upkeep_storage_site')) ?></h3>
                <p><?= rex_escape($subtitle) ?></p>
            </div>
            <div class="upkeep-storage__head-total"><?= rex_escape($bytes($total)) ?></div>
        </div>

        <div class="upkeep-storage__bar" role="img" aria-label="<?= rex_escape($t('upkeep_storage_bar_label', $bytes($total))) ?>">
            <?php foreach ($used as $cat): ?>
                <?php $share = $total > 0 ? (int) $cat['bytes'] / $total * 100 : 0; ?>
                <span class="upkeep-storage__seg upkeep-storage--<?= rex_escape($cssKey((string) $cat['key'])) ?>"
                      style="flex-grow: <?= rex_escape((string) round($share * 10, 3)) ?>"
                      title="<?= rex_escape($label((string) $cat['key']) . ': ' . $bytes($cat['bytes']) . ' (' . $pct($share) . ')') ?>"></span>
            <?php endforeach ?>
        </div>

        <ul class="upkeep-storage__legend">
            <?php foreach ($used as $cat): ?>
                <li><span class="upkeep-storage__dot upkeep-storage--<?= rex_escape($cssKey((string) $cat['key'])) ?>" aria-hidden="true"></span><?= rex_escape($label((string) $cat['key'])) ?></li>
            <?php endforeach ?>
        </ul>

        <?php if ($disk): ?>
            <?php $diskUsed = max(0, (int) $disk['total'] - (int) $disk['free']); $diskShare = min(100, $diskUsed / (int) $disk['total'] * 100); ?>
            <div class="upkeep-storage__server">
                <span><?= rex_escape($t('upkeep_storage_server')) ?></span>
                <span class="upkeep-storage__meter" role="img" aria-label="<?= rex_escape($t('upkeep_storage_disk_used_pct', (string) round($diskShare))) ?>">
                    <span style="width: <?= rex_escape((string) round($diskShare, 1)) ?>%"></span>
                </span>
                <span><?= rex_escape($t('upkeep_storage_disk', $bytes($diskUsed), $bytes($disk['total']), $bytes($disk['free']))) ?></span>
            </div>
        <?php endif ?>
    </div>

    <?php if (!empty($report['partial'])): ?>
        <p class="upkeep-storage__note"><i class="rex-icon fa fa-clock-o" aria-hidden="true"></i> <?= rex_escape($t('upkeep_storage_partial')) ?></p>
    <?php endif ?>
    <?php if ((int) ($media['missing'] ?? 0) > 0): ?>
        <p class="upkeep-storage__note"><i class="rex-icon fa fa-exclamation-triangle" aria-hidden="true"></i> <?= rex_escape($t('upkeep_storage_media_missing', $number($media['missing']))) ?></p>
    <?php endif ?>

    <h3 class="upk-group-title"><?= rex_escape($t('upkeep_storage_breakdown')) ?></h3>
    <div class="upk-group">
        <?php foreach ($used as $cat): ?>
            <?php $key = (string) $cat['key']; $share = $total > 0 ? (int) $cat['bytes'] / $total * 100 : 0; ?>
            <div class="upkeep-storage__row">
                <span class="upkeep-storage__icon upkeep-storage--<?= rex_escape($cssKey($key)) ?>" aria-hidden="true"><i class="rex-icon fa <?= rex_escape($icons[$key] ?? 'fa-folder-o') ?>"></i></span>
                <div class="upkeep-storage__row-main">
                    <div class="upkeep-storage__row-top">
                        <strong><?= rex_escape($label($key)) ?></strong>
                        <span class="upkeep-storage__row-size"><?= rex_escape($bytes($cat['bytes'])) ?><?= !empty($cat['partial']) ? ' +' : '' ?></span>
                    </div>
                    <div class="upkeep-storage__row-sub">
                        <span><?= rex_escape($countText($cat)) ?></span>
                        <span><?= rex_escape($pct($share)) ?></span>
                    </div>
                    <span class="upkeep-storage__share upkeep-storage--<?= rex_escape($cssKey($key)) ?>"><span style="width: <?= rex_escape((string) max(1, round($share, 1))) ?>%"></span></span>
                </div>
            </div>
        <?php endforeach ?>
    </div>
    <?php if ($empty): ?>
        <details class="upk-group upkeep-storage__empty">
            <summary><?= rex_escape($t('upkeep_storage_empty_categories', (string) count($empty))) ?></summary>
            <?php foreach ($empty as $cat): ?>
                <?php $key = (string) $cat['key']; ?>
                <div class="upkeep-storage__row upkeep-storage__row--zero">
                    <span class="upkeep-storage__icon upkeep-storage--<?= rex_escape($cssKey($key)) ?>" aria-hidden="true"><i class="rex-icon fa <?= rex_escape($icons[$key] ?? 'fa-folder-o') ?>"></i></span>
                    <div class="upkeep-storage__row-main"><div class="upkeep-storage__row-top"><strong><?= rex_escape($label($key)) ?></strong><span class="upkeep-storage__row-size"><?= rex_escape($bytes(0)) ?></span></div></div>
                </div>
            <?php endforeach ?>
        </details>
    <?php endif ?>

    <?php if (!empty($media['top']) || !empty($database['top'])): ?>
        <div class="upkeep-storage__details">
            <?php if (!empty($media['top'])): ?>
                <?php $max = max(1, ...array_map(static fn ($f) => (int) $f['bytes'], $media['top'])); ?>
                <section>
                    <h3 class="upk-group-title"><?= rex_escape($t('upkeep_storage_top_media')) ?></h3>
                    <div class="upk-group">
                        <?php foreach ($media['top'] as $file): ?>
                            <?php
                            $name = (string) ($file['title'] ?? '') !== '' ? (string) $file['title'] : (string) $file['filename'];
                            $cat = $cssKey((string) ($file['category'] ?? 'media_other'));
                            ?>
                            <div class="upkeep-storage__row upkeep-storage__row--compact">
                                <span class="upkeep-storage__icon upkeep-storage--<?= rex_escape($cat) ?>" aria-hidden="true"><i class="rex-icon fa <?= rex_escape($icons[$cat] ?? 'fa-file-o') ?>"></i></span>
                                <div class="upkeep-storage__row-main">
                                    <div class="upkeep-storage__row-top">
                                        <span class="upkeep-storage__name">
                                            <?php if ($mediaLinks): ?><a href="<?= rex_url::backendPage('mediapool/media', ['file_id' => (int) $file['id']]) ?>"><?= rex_escape($name) ?></a><?php else: ?><?= rex_escape($name) ?><?php endif ?>
                                        </span>
                                        <span class="upkeep-storage__row-size"><?= rex_escape($bytes($file['bytes'])) ?></span>
                                    </div>
                                    <?php if ($name !== (string) $file['filename']): ?>
                                        <div class="upkeep-storage__row-sub"><span class="upk-mono"><?= rex_escape((string) $file['filename']) ?></span></div>
                                    <?php endif ?>
                                    <span class="upkeep-storage__share upkeep-storage--<?= rex_escape($cat) ?>"><span style="width: <?= rex_escape((string) max(1, round((int) $file['bytes'] / $max * 100, 1))) ?>%"></span></span>
                                </div>
                            </div>
                        <?php endforeach ?>
                    </div>
                </section>
            <?php endif ?>
            <?php if (!empty($database['top'])): ?>
                <?php $max = max(1, ...array_map(static fn ($tb) => (int) $tb['bytes'], $database['top'])); ?>
                <section>
                    <h3 class="upk-group-title"><?= rex_escape($t('upkeep_storage_top_tables')) ?></h3>
                    <div class="upk-group">
                        <?php foreach ($database['top'] as $table): ?>
                            <div class="upkeep-storage__row upkeep-storage__row--compact">
                                <span class="upkeep-storage__icon upkeep-storage--database" aria-hidden="true"><i class="rex-icon fa fa-table"></i></span>
                                <div class="upkeep-storage__row-main">
                                    <div class="upkeep-storage__row-top">
                                        <span class="upkeep-storage__name upk-mono"><?= rex_escape((string) $table['name']) ?></span>
                                        <span class="upkeep-storage__row-size"><?= rex_escape($bytes($table['bytes'])) ?></span>
                                    </div>
                                    <div class="upkeep-storage__row-sub"><span><?= rex_escape($t('upkeep_storage_rows', $number($table['rows']))) ?></span></div>
                                    <span class="upkeep-storage__share upkeep-storage--database"><span style="width: <?= rex_escape((string) max(1, round((int) $table['bytes'] / $max * 100, 1))) ?>%"></span></span>
                                </div>
                            </div>
                        <?php endforeach ?>
                    </div>
                </section>
            <?php endif ?>
        </div>
    <?php endif ?>

    <div class="upkeep-storage__footer">
        <span class="upkeep-storage__time"><?= rex_escape($t('upkeep_storage_computed_at', rex_formatter::intlDateTime($computedAt, [IntlDateFormatter::MEDIUM, IntlDateFormatter::SHORT]))) ?></span>
        <?php if ($canRefresh): ?>
            <span class="upkeep-storage__actions">
                <?php foreach ($categories as $cat): ?>
                    <?php if ('media_manager' === $cat['key'] && (int) $cat['bytes'] > 0 && rex_addon::get('media_manager')->isAvailable()): ?>
                        <?= $form('clear_media_cache', $t('upkeep_storage_clear_media_cache'), 'fa-eraser') ?>
                    <?php endif ?>
                <?php endforeach ?>
                <?= $form('refresh', $t('upkeep_storage_refresh'), 'fa-refresh') ?>
            </span>
        <?php endif ?>
    </div>
</div>
