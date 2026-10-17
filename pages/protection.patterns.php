<?php

/**
 * Upkeep 3.0 – Schutz: Muster (eigene Muster und Standard-Muster des IPS).
 *
 * Tabs: ?tab=custom (eigene Muster, anlegen/bearbeiten/löschen) und ?tab=default
 * (mitgelieferte Muster, nur aktivieren/deaktivieren).
 */

use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$csrf = rex_csrf_token::factory('upkeep_patterns');
$pageKey = 'upkeep/protection/patterns';
$severities = ['low', 'medium', 'high', 'critical'];
$tab = rex_request('tab', 'string', 'custom') === 'default' ? 'default' : 'custom';
$messages = [];

$regexValid = static function (string $pattern): bool {
    if (class_exists(\KLXM\Upkeep\PatternValidator::class)) {
        return \KLXM\Upkeep\PatternValidator::isValid($pattern);
    }
    return @preg_match($pattern, '') !== false;
};

$url = static fn (array $params = []): string => rex_url::backendPage($pageKey, ['tab' => $tab] + $params);

// --- Aktionen -------------------------------------------------------------
$editId = rex_get('edit', 'int', 0);
$formData = null;
$hasAction = rex_post('save_pattern', 'bool') || rex_post('toggle_custom', 'int', 0) > 0 || rex_post('delete_custom', 'int', 0) > 0 || rex_post('toggle_default', 'int', 0) > 0;

if ($hasAction) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } elseif (rex_post('save_pattern', 'bool')) {
        $id = rex_post('id', 'int', 0);
        $formData = [
            'id' => $id,
            'pattern' => trim(rex_post('pattern', 'string', '')),
            'description' => mb_substr(trim(rex_post('description', 'string', '')), 0, 1000),
            'severity' => rex_post('severity', 'string', 'medium'),
            'is_regex' => rex_post('is_regex', 'bool', false),
            'status' => $id > 0 ? rex_post('status', 'bool', false) : true,
        ];
        if (!in_array($formData['severity'], $severities, true)) {
            $formData['severity'] = 'medium';
        }
        $error = null;
        if ($formData['pattern'] === '') {
            $error = $addon->i18n('upkeep_ips_pattern_empty');
        } elseif (strlen($formData['pattern']) > 500) {
            $error = $addon->i18n('upkeep_patterns_too_long');
        } elseif ($formData['is_regex'] && !$regexValid($formData['pattern'])) {
            $error = $addon->i18n('upkeep_patterns_invalid_regex');
        }

        if ($error !== null) {
            $messages[] = rex_view::error(rex_escape($error));
            $editId = $id;
        } elseif ($id > 0) {
            $ok = false;
            try {
                if (method_exists(IntrusionPrevention::class, 'updateCustomPattern')) {
                    $ok = (bool) IntrusionPrevention::updateCustomPattern($id, $formData['pattern'], $formData['description'], $formData['severity'], $formData['is_regex'], $formData['status']);
                } else {
                    $sql = rex_sql::factory();
                    $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
                    $sql->setWhere(['id' => $id]);
                    $sql->setValue('pattern', $formData['pattern']);
                    $sql->setValue('description', $formData['description']);
                    $sql->setValue('severity', $formData['severity']);
                    $sql->setValue('is_regex', $formData['is_regex'] ? 1 : 0);
                    $sql->setValue('status', $formData['status'] ? 1 : 0);
                    $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                    $sql->update();
                    $ok = true;
                }
            } catch (Throwable $e) {
                rex_logger::logException($e);
            }
            if ($ok) {
                $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_ips_pattern_updated')));
                $formData = null;
                $editId = 0;
            } else {
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_ips_pattern_update_error')));
                $editId = $id;
            }
        } elseif (IntrusionPrevention::addCustomPattern($formData['pattern'], $formData['description'], $formData['severity'], $formData['is_regex'])) {
            $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_ips_pattern_added')));
            $formData = null;
        } else {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_ips_pattern_add_error')));
        }
    } elseif (rex_post('toggle_custom', 'int', 0) > 0) {
        $messages[] = IntrusionPrevention::toggleCustomPatternStatus(rex_post('toggle_custom', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_ips_pattern_status_changed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_ips_pattern_status_error')));
    } elseif (rex_post('delete_custom', 'int', 0) > 0) {
        $messages[] = IntrusionPrevention::removeCustomPattern(rex_post('delete_custom', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_ips_pattern_deleted')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_ips_pattern_delete_error')));
    } else {
        $messages[] = IntrusionPrevention::toggleDefaultPatternStatus(rex_post('toggle_default', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_ips_pattern_status_changed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_ips_pattern_status_error')));
    }
}

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$isAdmin = rex::requireUser()->isAdmin();

// Kopf
$ipsOn = (bool) $addon->getConfig('ips_active', false);
$actions = Ui::badge($t($ipsOn ? 'upkeep_list_ips_on' : 'upkeep_list_ips_off'), $ipsOn ? 'ok' : 'muted');
if ($isAdmin) {
    $actions .= ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '">' . rex_escape($t('upkeep_nav_settings')) . '</a>';
}
echo Ui::hero($t('upkeep_nav_protection_patterns'), $t('upkeep_list_patterns_intro'), Ui::icon('fa-shield', 'blue'), $actions);

// --- Umschalter -----------------------------------------------------------
echo Ui::segmented([
    'custom' => [$t('upkeep_list_patterns_custom'), rex_url::backendPage($pageKey, ['tab' => 'custom'])],
    'default' => [$t('upkeep_list_patterns_default'), rex_url::backendPage($pageKey, ['tab' => 'default'])],
], $tab, $t('upkeep_nav_protection_patterns'));

echo implode('', $messages);

$typeText = static fn (array $row): string => rex_escape((int) $row['is_regex'] ? $t('upkeep_type_regex') : $t('upkeep_type_text'));
$thead = static function (array $labels): string {
    $html = '<thead><tr>';
    foreach ($labels as $key => $label) {
        $html .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    return $html . '</tr></thead>';
};

// --- Standard-Muster ------------------------------------------------------
if ($tab === 'default') {
    try {
        $rows = rex_sql::factory()->getArray('SELECT * FROM ' . rex::getTable('upkeep_ips_default_patterns') . ' ORDER BY category, pattern');
    } catch (rex_sql_exception $e) {
        rex_logger::logException($e);
        echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
        return;
    }

    echo Ui::listTitle($t('upkeep_list_patterns_default'), count($rows));
    if (!$rows) {
        echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_ips_no_default_patterns'), 'fa-code') . '</div>';
        return;
    }
    $labels = [
        'pattern' => $t('upkeep_ips_pattern'),
        'description' => $t('upkeep_ips_description'),
        'severity' => $t('upkeep_ips_severity'),
        'type' => $t('upkeep_ips_type'),
        'status' => $t('upkeep_pages_status'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = '<form id="upk-patterns-default" action="' . $url() . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table">' . $thead($labels) . '<tbody>';
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
        $body .= Ui::td($labels['type'], $typeText($row));
        $body .= Ui::td($labels['status'], Ui::status($on));
        $body .= Ui::td($labels['actions'], '<button type="submit" form="upk-patterns-default" class="btn btn-xs upk-btn-ghost" name="toggle_default" value="' . (int) $row['id'] . '">'
            . rex_escape($on ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button>', 'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div></div>';
    $body .= '<p class="upk-group-note">' . rex_escape($t('upkeep_ips_default_patterns_explanation')) . '</p>';
    echo $body;
    return;
}

// --- Eigene Muster --------------------------------------------------------
try {
    $rows = rex_sql::factory()->getArray('SELECT * FROM ' . rex::getTable('upkeep_ips_custom_patterns') . ' ORDER BY created_at DESC');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

if ($editId > 0 && $formData === null) {
    $formData = IntrusionPrevention::getCustomPattern($editId);
    if ($formData === null) {
        $editId = 0;
    }
}

echo Ui::listTitle($t('upkeep_list_patterns_custom'), count($rows));
if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_ips_no_patterns'), 'fa-code') . '</div>';
} else {
    $labels = [
        'pattern' => $t('upkeep_ips_pattern'),
        'description' => $t('upkeep_ips_description'),
        'severity' => $t('upkeep_ips_severity'),
        'type' => $t('upkeep_ips_type'),
        'status' => $t('upkeep_pages_status'),
        'created' => $t('upkeep_ips_created'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = '<form id="upk-patterns-custom" action="' . $url() . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table">' . $thead($labels) . '<tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $on = (int) $row['status'] === 1;
        $created = strtotime((string) $row['created_at']);
        $body .= '<tr' . ($id === $editId ? ' class="upk-table-current"' : '') . '>';
        $body .= Ui::td($labels['pattern'], '<span class="upk-mono">' . rex_escape((string) $row['pattern']) . '</span>');
        $body .= Ui::td($labels['description'], rex_escape((string) ($row['description'] ?? '')));
        $body .= Ui::td($labels['severity'], Ui::severity((string) $row['severity']));
        $body .= Ui::td($labels['type'], $typeText($row));
        $body .= Ui::td($labels['status'], Ui::status($on));
        $body .= Ui::td($labels['created'], rex_escape($created ? date('d.m.Y H:i', $created) : '-'), 'upk-nowrap');
        $body .= Ui::td($labels['actions'],
            '<a class="btn btn-xs upk-btn-ghost" href="' . $url(['edit' => $id]) . '#upk-form"><i class="rex-icon rex-icon-edit" aria-hidden="true"></i> ' . rex_escape($t('upkeep_edit')) . '</a> '
            . '<button type="submit" form="upk-patterns-custom" class="btn btn-xs upk-btn-ghost" name="toggle_custom" value="' . $id . '">' . rex_escape($on ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button> '
            . '<button type="submit" form="upk-patterns-custom" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="delete_custom" value="' . $id . '" data-confirm="' . rex_escape($t('upkeep_patterns_delete_confirm')) . '"><i class="rex-icon rex-icon-delete" aria-hidden="true"></i> ' . rex_escape($t('upkeep_delete')) . '</button>',
            'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div></div>';
    echo $body;
}

// Formular: anlegen / bearbeiten
$isEdit = $editId > 0 && $formData !== null;
$current = $formData ?? ['pattern' => '', 'description' => '', 'severity' => 'medium', 'is_regex' => false, 'status' => true];
$options = '';
foreach ($severities as $sev) {
    $options .= '<option value="' . $sev . '"' . (($current['severity'] ?? 'medium') === $sev ? ' selected' : '') . '>'
        . rex_escape($t('upkeep_ips_severity_' . $sev) . ' – ' . $t('upkeep_ips_severity_' . $sev . '_tooltip')) . '</option>';
}

$form = '<details class="upk-group upk-form-details"' . (!$rows || $formData !== null ? ' open' : '') . ' id="upk-form">'
    . '<summary>' . rex_escape($isEdit ? $t('upkeep_patterns_edit') : $t('upkeep_patterns_add')) . '</summary>'
    . '<form action="' . $url() . '" method="post">' . $csrf->getHiddenField();
if ($isEdit) {
    $form .= '<input type="hidden" name="id" value="' . (int) $editId . '">';
}
$form .= Ui::row($t('upkeep_ips_pattern'), '<input type="text" class="form-control upk-mono" id="upk-pat-pattern" name="pattern" required maxlength="500" value="' . rex_escape((string) ($current['pattern'] ?? '')) . '">', $t('upkeep_ips_pattern_tooltip'), 'upk-pat-pattern');
$form .= Ui::row($t('upkeep_ips_description'), '<input type="text" class="form-control" id="upk-pat-desc" name="description" maxlength="1000" value="' . rex_escape((string) ($current['description'] ?? '')) . '">', '', 'upk-pat-desc');
$form .= Ui::row($t('upkeep_ips_severity'), '<select class="form-control" id="upk-pat-sev" name="severity">' . $options . '</select>', '', 'upk-pat-sev');
$form .= Ui::row($t('upkeep_patterns_is_regex_label'), Ui::switch('is_regex', !empty($current['is_regex']), 'upk-pat-regex'), $t('upkeep_ips_pattern_note_regex') . ' ' . $t('upkeep_ips_pattern_note_test'), 'upk-pat-regex');
if ($isEdit) {
    $form .= Ui::row($t('upkeep_active'), Ui::switch('status', !empty($current['status']), 'upk-pat-status'), '', 'upk-pat-status');
}
$form .= '<div class="upk-form-actions">';
if ($isEdit) {
    $form .= '<a class="btn btn-abort" href="' . $url() . '">' . rex_escape($t('upkeep_cancel')) . '</a>';
}
$form .= '<button type="submit" class="btn btn-save" name="save_pattern" value="1">' . rex_escape($isEdit ? $t('upkeep_update') : $t('upkeep_add')) . '</button></div>';
$form .= '</form></details>';
echo $form;
