<?php

/**
 * Speicherübersicht (Balken + Legende + große Dateien).
 *
 * Variablen:
 * - report      array   Bericht aus KLXM\Upkeep\Storage::getReport() ([] = noch nicht berechnet)
 * - canRefresh  bool    Darf der Nutzer neu berechnen / Cache leeren (nur Admins)
 * - csrf        rex_csrf_token|string  Token-Objekt oder fertiges Hidden-Field-HTML
 * - action      string  Ziel-URL des Formulars
 *
 * @var rex_fragment $this
 * @psalm-scope-this rex_fragment
 */

$report = $this->getVar('report', []);
$report = is_array($report) ? $report : [];
$canRefresh = (bool) $this->getVar('canRefresh', false);
$csrf = $this->getVar('csrf', '');
$action = (string) $this->getVar('action', '');

$csrfField = $csrf instanceof rex_csrf_token ? $csrf->getHiddenField() : (string) $csrf;
$bytes = static fn ($v): string => rex_formatter::bytes((int) $v, [1]);
$numberFormat = str_starts_with(rex_i18n::getLanguage(), 'de') ? [0, ',', '.'] : [0, '.', ','];
$number = static fn ($v): string => rex_formatter::number((int) $v, $numberFormat);

$form = static function (string $value, string $label, string $icon, string $class = 'btn-default') use ($canRefresh, $csrfField, $action): string {
    if (!$canRefresh) {
        return '';
    }
    return '<form class="upkeep-storage__form" method="post" action="' . rex_escape($action) . '">'
        . $csrfField
        . '<button type="submit" class="btn ' . rex_escape($class) . ' btn-sm" name="upkeep_storage_action" value="' . rex_escape($value) . '">'
        . '<i class="rex-icon ' . rex_escape($icon) . '" aria-hidden="true"></i> ' . rex_escape($label)
        . '</button></form>';
};

if ([] === $report) {
    ?>
    <div class="upkeep-storage upkeep-storage--empty">
        <div class="upkeep-storage__bar upkeep-storage__bar--empty" aria-hidden="true"></div>
        <p class="upkeep-storage__empty-text"><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_not_computed')) ?></p>
        <?php if ($canRefresh): ?>
            <?= $form('refresh', rex_i18n::rawMsg('upkeep_storage_compute_now'), 'fa fa-calculator', 'btn-primary') ?>
        <?php else: ?>
            <p class="upkeep-storage__hint"><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_not_computed_editor')) ?></p>
        <?php endif ?>
    </div>
    <?php
    return;
}

$categories = array_values(array_filter(
    (array) ($report['categories'] ?? []),
    static fn ($c): bool => is_array($c) && isset($c['key']),
));
$total = max(0, (int) ($report['total_bytes'] ?? 0));
$disk = is_array($report['disk'] ?? null) ? $report['disk'] : null;
$media = is_array($report['media'] ?? null) ? $report['media'] : [];
$database = is_array($report['database'] ?? null) ? $report['database'] : [];
$computedAt = (int) ($report['computed_at'] ?? 0);

$user = rex::getUser();
$mediaLinks = rex_addon::get('mediapool')->isAvailable() && $user && $user->getComplexPerm('media')->hasMediaPerm();

$label = static fn (string $key): string => rex_i18n::rawMsg('upkeep_storage_cat_' . $key);
$cssKey = static fn (string $key): string => preg_replace('/[^a-z0-9_-]/', '', strtolower($key)) ?? 'other';
?>
<div class="upkeep-storage">
    <div class="upkeep-storage__head">
        <div class="upkeep-storage__total">
            <span class="upkeep-storage__total-value"><?= rex_escape($bytes($total)) ?></span>
            <span class="upkeep-storage__total-label"><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_total')) ?></span>
        </div>
        <?php if ($disk && (int) $disk['total'] > 0): ?>
            <?php
            $diskUsed = max(0, (int) $disk['total'] - (int) $disk['free']);
            $diskPct = min(100, round($diskUsed / (int) $disk['total'] * 100, 1));
            ?>
            <div class="upkeep-storage__disk">
                <span><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_disk', $bytes($diskUsed), $bytes($disk['total']), $bytes($disk['free']))) ?></span>
                <span class="upkeep-storage__disk-meter" role="img" aria-label="<?= rex_escape(rex_i18n::rawMsg('upkeep_storage_disk_used_pct', (string) $diskPct)) ?>">
                    <span style="width: <?= rex_escape((string) $diskPct) ?>%"></span>
                </span>
            </div>
        <?php endif ?>
    </div>

    <div class="upkeep-storage__bar" role="img" aria-label="<?= rex_escape(rex_i18n::rawMsg('upkeep_storage_bar_label', $bytes($total))) ?>">
        <?php foreach ($categories as $cat): ?>
            <?php if ((int) $cat['bytes'] <= 0 || $total <= 0) {
                continue;
            } ?>
            <span class="upkeep-storage__seg upkeep-storage--<?= rex_escape($cssKey((string) $cat['key'])) ?>"
                  style="flex-grow: <?= rex_escape((string) round((int) $cat['bytes'] / $total * 1000, 3)) ?>"
                  title="<?= rex_escape($label((string) $cat['key']) . ': ' . $bytes($cat['bytes'])) ?>"></span>
        <?php endforeach ?>
    </div>

    <ul class="upkeep-storage__legend">
        <?php foreach ($categories as $cat): ?>
            <?php $key = (string) $cat['key']; ?>
            <li class="upkeep-storage__item<?= (int) $cat['bytes'] <= 0 ? ' upkeep-storage__item--zero' : '' ?>">
                <span class="upkeep-storage__dot upkeep-storage--<?= rex_escape($cssKey($key)) ?>" aria-hidden="true"></span>
                <span class="upkeep-storage__label"><?= rex_escape($label($key)) ?></span>
                <span class="upkeep-storage__size"><?= rex_escape($bytes($cat['bytes'])) ?><?= !empty($cat['partial']) ? ' <span class="upkeep-storage__approx" title="' . rex_escape(rex_i18n::rawMsg('upkeep_storage_partial_item')) . '">+</span>' : '' ?></span>
                <span class="upkeep-storage__count">
                    <?= rex_escape(rex_i18n::rawMsg('upkeep_storage_count_' . ('database' === $key ? 'table' : 'file') . (1 === (int) $cat['count'] ? '' : 's'), $number($cat['count']))) ?>
                </span>
            </li>
        <?php endforeach ?>
    </ul>

    <?php if (!empty($report['partial'])): ?>
        <p class="upkeep-storage__note upkeep-storage__note--warning">
            <i class="rex-icon fa fa-clock-o" aria-hidden="true"></i>
            <?= rex_escape(rex_i18n::rawMsg('upkeep_storage_partial')) ?>
        </p>
    <?php endif ?>
    <?php if ((int) ($media['missing'] ?? 0) > 0): ?>
        <p class="upkeep-storage__note upkeep-storage__note--warning">
            <i class="rex-icon fa fa-exclamation-triangle" aria-hidden="true"></i>
            <?= rex_escape(rex_i18n::rawMsg('upkeep_storage_media_missing', $number($media['missing']))) ?>
        </p>
    <?php endif ?>

    <?php if (!empty($media['top']) || !empty($database['top'])): ?>
        <div class="upkeep-storage__details">
            <?php if (!empty($media['top'])): ?>
                <section class="upkeep-storage__group">
                    <h4 class="upkeep-storage__group-title"><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_top_media')) ?></h4>
                    <ol class="upkeep-storage__list">
                        <?php foreach ($media['top'] as $file): ?>
                            <?php
                            $name = (string) ($file['title'] ?? '') !== '' ? (string) $file['title'] : (string) $file['filename'];
                            ?>
                            <li>
                                <span class="upkeep-storage__dot upkeep-storage--<?= rex_escape($cssKey((string) ($file['category'] ?? 'media_other'))) ?>" aria-hidden="true"></span>
                                <span class="upkeep-storage__file">
                                    <?php if ($mediaLinks): ?>
                                        <a href="<?= rex_url::backendPage('mediapool/media', ['file_id' => (int) $file['id']]) ?>"><?= rex_escape($name) ?></a>
                                    <?php else: ?>
                                        <?= rex_escape($name) ?>
                                    <?php endif ?>
                                    <?php if ($name !== (string) $file['filename']): ?>
                                        <small><?= rex_escape((string) $file['filename']) ?></small>
                                    <?php endif ?>
                                </span>
                                <span class="upkeep-storage__size"><?= rex_escape($bytes($file['bytes'])) ?></span>
                            </li>
                        <?php endforeach ?>
                    </ol>
                </section>
            <?php endif ?>
            <?php if (!empty($database['top'])): ?>
                <section class="upkeep-storage__group">
                    <h4 class="upkeep-storage__group-title"><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_top_tables')) ?></h4>
                    <ol class="upkeep-storage__list">
                        <?php foreach ($database['top'] as $table): ?>
                            <li>
                                <span class="upkeep-storage__dot upkeep-storage--database" aria-hidden="true"></span>
                                <span class="upkeep-storage__file">
                                    <code><?= rex_escape((string) $table['name']) ?></code>
                                    <small><?= rex_escape(rex_i18n::rawMsg('upkeep_storage_rows', $number($table['rows']))) ?></small>
                                </span>
                                <span class="upkeep-storage__size"><?= rex_escape($bytes($table['bytes'])) ?></span>
                            </li>
                        <?php endforeach ?>
                    </ol>
                </section>
            <?php endif ?>
        </div>
    <?php endif ?>

    <div class="upkeep-storage__footer">
        <span class="upkeep-storage__time">
            <?= rex_escape(rex_i18n::rawMsg('upkeep_storage_computed_at', rex_formatter::intlDateTime($computedAt, [IntlDateFormatter::MEDIUM, IntlDateFormatter::SHORT]))) ?>
        </span>
        <?php if ($canRefresh): ?>
            <span class="upkeep-storage__actions">
                <?php foreach ($categories as $cat): ?>
                    <?php if ('media_manager' === $cat['key'] && (int) $cat['bytes'] > 0 && rex_addon::get('media_manager')->isAvailable()): ?>
                        <?= $form('clear_media_cache', rex_i18n::rawMsg('upkeep_storage_clear_media_cache'), 'fa fa-eraser') ?>
                    <?php endif ?>
                <?php endforeach ?>
                <?= $form('refresh', rex_i18n::rawMsg('upkeep_storage_refresh'), 'fa fa-refresh') ?>
            </span>
        <?php endif ?>
    </div>
</div>
