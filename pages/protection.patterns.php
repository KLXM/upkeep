<?php

/**
 * Upkeep 3.0 – Schutz: Muster (eigene Muster und Standard-Muster des IPS).
 *
 * Tabs: ?tab=custom (eigene Muster, anlegen/bearbeiten/löschen) und ?tab=default
 * (mitgelieferte Muster, nur aktivieren/deaktivieren).
 */

use KLXM\Upkeep\IntrusionPrevention;

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

$severityBadge = static function (string $severity) use ($addon): string {
    $class = match ($severity) {
        'critical' => 'upk-badge--danger',
        'high', 'medium' => 'upk-badge--warn',
        default => 'upk-badge--muted',
    };
    $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $addon->i18n('upkeep_ips_severity_' . $severity) : ($severity ?: '-');
    return '<span class="upk-badge ' . $class . '">' . rex_escape($label) . '</span>';
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

// --- Tabs -----------------------------------------------------------------
$tabs = ['custom' => $addon->i18n('upkeep_ips_custom_patterns'), 'default' => $addon->i18n('upkeep_ips_default_patterns')];
echo '<div class="upk-tabs"><ul class="nav nav-tabs">';
foreach ($tabs as $key => $label) {
    echo '<li' . ($key === $tab ? ' class="active"' : '') . '><a href="' . rex_url::backendPage($pageKey, ['tab' => $key]) . '">' . rex_escape($label) . '</a></li>';
}
echo '</ul></div>';

echo implode('', $messages);

$toolbar = '<div class="upk-toolbar"><a href="' . rex_url::backendPage('upkeep/settings', ['section' => 'ips']) . '"><i class="rex-icon fa-cog"></i> ' . rex_escape($addon->i18n('upkeep_pages_settings_link')) . '</a></div>';

// --- Standard-Muster ------------------------------------------------------
if ($tab === 'default') {
    try {
        $rows = rex_sql::factory()->getArray('SELECT * FROM ' . rex::getTable('upkeep_ips_default_patterns') . ' ORDER BY category, pattern');
    } catch (rex_sql_exception $e) {
        rex_logger::logException($e);
        echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
        return;
    }

    $body = $toolbar . '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_ips_default_patterns_explanation')) . '</p>';
    if (!$rows) {
        $body .= '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_ips_no_default_patterns')) . '</p></div>';
    } else {
        $body .= '<form id="upk-patterns-default" action="' . $url() . '" method="post">' . $csrf->getHiddenField() . '</form>';
        $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
        $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_pattern')) . '</th>';
        $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_description')) . '</th>';
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
            $body .= '<td class="upk-actions"><button type="submit" form="upk-patterns-default" class="btn btn-default btn-xs" name="toggle_default" value="' . (int) $row['id'] . '">'
                . rex_escape($on ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button></td>';
            $body .= '</tr>';
        }
        $body .= '</tbody></table></div>';
    }

    $fragment = new rex_fragment();
    $fragment->setVar('title', $addon->i18n('upkeep_ips_default_patterns'), false);
    $fragment->setVar('body', $body, false);
    echo $fragment->parse('core/page/section.php');
    return;
}

// --- Eigene Muster --------------------------------------------------------
try {
    $rows = rex_sql::factory()->getArray('SELECT * FROM ' . rex::getTable('upkeep_ips_custom_patterns') . ' ORDER BY created_at DESC');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

if ($editId > 0 && $formData === null) {
    $formData = IntrusionPrevention::getCustomPattern($editId);
    if ($formData === null) {
        $editId = 0;
    }
}

if (!$rows) {
    $body = $toolbar . '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_ips_no_patterns')) . '</p></div>';
} else {
    $body = $toolbar . '<form id="upk-patterns-custom" action="' . $url() . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_pattern')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_description')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_status')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_created')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $on = (int) $row['status'] === 1;
        $created = strtotime((string) $row['created_at']);
        $body .= '<tr>';
        $body .= '<td><span class="upk-mono">' . rex_escape((string) $row['pattern']) . '</span></td>';
        $body .= '<td>' . rex_escape((string) ($row['description'] ?? '')) . '</td>';
        $body .= '<td>' . $severityBadge((string) $row['severity']) . '</td>';
        $body .= '<td>' . rex_escape((int) $row['is_regex'] ? $addon->i18n('upkeep_type_regex') : $addon->i18n('upkeep_type_text')) . '</td>';
        $body .= '<td><span class="upk-badge ' . ($on ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($on ? $addon->i18n('upkeep_active') : $addon->i18n('upkeep_inactive')) . '</span></td>';
        $body .= '<td>' . rex_escape($created ? date('d.m.Y H:i', $created) : '-') . '</td>';
        $body .= '<td class="upk-actions">';
        $body .= '<a class="btn btn-default btn-xs" href="' . $url(['edit' => $id]) . '"><i class="rex-icon rex-icon-edit"></i> ' . rex_escape($addon->i18n('upkeep_edit')) . '</a> ';
        $body .= '<button type="submit" form="upk-patterns-custom" class="btn btn-default btn-xs" name="toggle_custom" value="' . $id . '">' . rex_escape($on ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button> ';
        $body .= '<button type="submit" form="upk-patterns-custom" class="btn btn-delete btn-xs" name="delete_custom" value="' . $id . '" data-confirm="' . rex_escape($addon->i18n('upkeep_patterns_delete_confirm')) . '"><i class="rex-icon rex-icon-delete"></i> ' . rex_escape($addon->i18n('upkeep_delete')) . '</button>';
        $body .= '</td></tr>';
    }
    $body .= '</tbody></table></div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_ips_custom_patterns'), false);
$fragment->setVar('body', $body, false);
echo $fragment->parse('core/page/section.php');

// Formular: anlegen / bearbeiten
$isEdit = $editId > 0 && $formData !== null;
$current = $formData ?? ['pattern' => '', 'description' => '', 'severity' => 'medium', 'is_regex' => false, 'status' => true];
$options = '';
foreach ($severities as $sev) {
    $options .= '<option value="' . $sev . '"' . (($current['severity'] ?? 'medium') === $sev ? ' selected' : '') . '>'
        . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev) . ' – ' . $addon->i18n('upkeep_ips_severity_' . $sev . '_tooltip')) . '</option>';
}

$form = '<form action="' . $url() . '" method="post">' . $csrf->getHiddenField();
if ($isEdit) {
    $form .= '<input type="hidden" name="id" value="' . (int) $editId . '">';
}
$form .= '<div class="row">';
$form .= '<div class="col-sm-5"><div class="form-group"><label for="upk-pat-pattern">' . rex_escape($addon->i18n('upkeep_ips_pattern')) . '</label>'
    . '<input type="text" class="form-control upk-mono" id="upk-pat-pattern" name="pattern" required maxlength="500" value="' . rex_escape((string) ($current['pattern'] ?? '')) . '">'
    . '<p class="help-block">' . rex_escape($addon->i18n('upkeep_ips_pattern_tooltip')) . '</p></div></div>';
$form .= '<div class="col-sm-4"><div class="form-group"><label for="upk-pat-desc">' . rex_escape($addon->i18n('upkeep_ips_description')) . '</label>'
    . '<input type="text" class="form-control" id="upk-pat-desc" name="description" maxlength="1000" value="' . rex_escape((string) ($current['description'] ?? '')) . '"></div></div>';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-pat-sev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label>'
    . '<select class="form-control" id="upk-pat-sev" name="severity">' . $options . '</select></div></div>';
$form .= '</div>';
$form .= '<div class="checkbox"><label><input type="checkbox" name="is_regex" value="1"' . (!empty($current['is_regex']) ? ' checked' : '') . '> ' . rex_escape($addon->i18n('upkeep_patterns_is_regex_label')) . '</label></div>';
if ($isEdit) {
    $form .= '<div class="checkbox"><label><input type="checkbox" name="status" value="1"' . (!empty($current['status']) ? ' checked' : '') . '> ' . rex_escape($addon->i18n('upkeep_active')) . '</label></div>';
}
$form .= '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_ips_pattern_note_regex')) . ' ' . rex_escape($addon->i18n('upkeep_ips_pattern_note_test')) . '</p>';
$form .= '<button type="submit" class="btn btn-save" name="save_pattern" value="1">' . rex_escape($isEdit ? $addon->i18n('upkeep_update') : $addon->i18n('upkeep_add')) . '</button>';
if ($isEdit) {
    $form .= ' <a class="btn btn-abort" href="' . $url() . '">' . rex_escape($addon->i18n('upkeep_cancel')) . '</a>';
}
$form .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $isEdit ? $addon->i18n('upkeep_patterns_edit') : $addon->i18n('upkeep_patterns_add'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');
