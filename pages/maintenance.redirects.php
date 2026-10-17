<?php

/**
 * Upkeep 3.0 – Weiterleitungen (Domain-Mapping).
 *
 * Liste, Anlegen, Bearbeiten und Löschen von Domain-/Pfad-Weiterleitungen.
 * Der globale Schalter liegt in den Einstellungen (Abschnitt "redirects").
 */

use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$csrf = rex_csrf_token::factory('upkeep_redirects');
$pageKey = 'upkeep/maintenance/redirects';
$table = rex::getTable('upkeep_domain_mapping');
$allowedCodes = [301, 302, 303, 307, 308];

$func = rex_request('func', 'string', '');
$id = rex_request('id', 'int', 0);
$messages = [];

/**
 * Normalisiert und prüft einen Hostnamen (IDN-fähig). Liefert die ASCII-Form oder null.
 */
$normalizeHost = static function (string $host): ?string {
    $host = rtrim(mb_strtolower(trim($host)), '.');
    if ($host === '' || strlen($host) > 253 || preg_match('/[\s\/\\\\?#@:]/', $host)) {
        return null;
    }
    $ascii = $host;
    if (function_exists('idn_to_ascii')) {
        $converted = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($converted === false) {
            return null;
        }
        $ascii = $converted;
    }
    if (filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false || !str_contains($ascii, '.')) {
        // localhost und IP-Adressen als Ziel zulassen
        if ($ascii !== 'localhost' && filter_var(trim($ascii, '[]'), FILTER_VALIDATE_IP) === false) {
            return null;
        }
    }
    return $ascii;
};

// Löschen (nur POST)
if (rex_post('delete_mapping', 'int', 0) > 0) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        $sql = rex_sql::factory();
        $sql->setQuery('DELETE FROM ' . $table . ' WHERE id = ?', [rex_post('delete_mapping', 'int')]);
        $messages[] = $sql->getRows() > 0
            ? rex_view::success($addon->i18n('upkeep_domain_mapping_deleted'))
            : rex_view::error($addon->i18n('upkeep_domain_mapping_delete_error'));
    }
    $func = '';
}

// Status umschalten (nur POST)
if (rex_post('toggle_mapping', 'int', 0) > 0) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        $sql = rex_sql::factory();
        $sql->setQuery('UPDATE ' . $table . ' SET status = 1 - status, updatedate = ? WHERE id = ?', [date('Y-m-d H:i:s'), rex_post('toggle_mapping', 'int')]);
        $messages[] = rex_view::success($addon->i18n('upkeep_redirects_status_changed'));
    }
    $func = '';
}

// Speichern
$data = [];
if (rex_post('save', 'bool')) {
    $data = [
        'id' => rex_post('id', 'int', 0),
        'source_domain' => trim(rex_post('source_domain', 'string', '')),
        'source_path' => trim(rex_post('source_path', 'string', '')),
        'target_url' => trim(rex_post('target_url', 'string', '')),
        'redirect_code' => rex_post('redirect_code', 'int', 301),
        'is_wildcard' => rex_post('is_wildcard', 'bool', false) ? 1 : 0,
        'status' => rex_post('status', 'int', 0) === 1 ? 1 : 0,
        'description' => trim(rex_post('description', 'string', '')),
    ];
    $func = $data['id'] > 0 ? 'edit' : 'add';
    $id = $data['id'];
    $errors = [];

    if (!$csrf->isValid()) {
        $errors[] = rex_i18n::msg('csrf_token_invalid');
    }

    // Quell-Domain
    if ($data['source_domain'] === '') {
        $errors[] = $addon->i18n('upkeep_domain_mapping_source_required');
    } else {
        $domain = mb_strtolower($data['source_domain']);
        if (str_starts_with($domain, 'www.')) {
            $domain = substr($domain, 4);
        }
        if ($normalizeHost($domain) === null) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_domain');
        }
        // Gespeichert wird die eingegebene (ggf. IDN-)Form ohne www.
        $data['source_domain'] = $domain;
    }

    // Quell-Pfad
    $path = $data['source_path'];
    if ($data['is_wildcard'] && $path === '') {
        $errors[] = $addon->i18n('upkeep_domain_mapping_source_path_required');
    } elseif ($path !== '') {
        if (str_contains($path, '..') || str_contains($path, '\\') || preg_match('/[\s?#]/', $path)) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_path_security');
        }
        if (!str_starts_with($path, '/')) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_path_start');
        }
        if ($data['is_wildcard']) {
            // Genau ein Stern, und zwar als abschließendes "/*"
            if (!str_ends_with($path, '/*') || substr_count($path, '*') !== 1) {
                $errors[] = $addon->i18n('upkeep_domain_mapping_wildcard_ending');
            }
        } elseif (str_contains($path, '*')) {
            $errors[] = $addon->i18n('upkeep_redirects_star_without_wildcard');
        }
    }
    if (strlen($path) > 255) {
        $errors[] = $addon->i18n('upkeep_redirects_path_too_long');
    }

    // Ziel-URL
    $target = $data['target_url'];
    if ($target === '') {
        $errors[] = $addon->i18n('upkeep_domain_mapping_target_required');
    } else {
        $starCount = substr_count($target, '*');
        if ($starCount > 1 || ($starCount === 1 && !$data['is_wildcard'])) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_wildcard_url');
        }
        $testUrl = str_replace('*', 'x', $target);
        $parts = parse_url($testUrl);
        $scheme = is_array($parts) ? strtolower($parts['scheme'] ?? '') : '';
        if (preg_match('/[\x00-\x20\x7f]/', $target)) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_target_url');
        } elseif (!in_array($scheme, ['http', 'https'], true)) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_url_schema_required');
        } elseif (!isset($parts['host']) || isset($parts['user']) || isset($parts['pass']) || $normalizeHost((string) $parts['host']) === null) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_target_url');
        } else {
            // Stern nur im Pfad/Query, nie im Host-Teil
            $schemePos = strpos($target, '://');
            $authority = (string) strtok(substr($target, $schemePos === false ? 0 : $schemePos + 3), '/?#');
            if (str_contains($authority, '*')) {
                $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_wildcard_url');
            }
        }
    }

    if (!in_array($data['redirect_code'], $allowedCodes, true)) {
        $data['redirect_code'] = 301;
    }
    if (mb_strlen($data['description']) > 1000) {
        $data['description'] = mb_substr($data['description'], 0, 1000);
    }

    // Duplikat Domain + Pfad
    if (!$errors) {
        $sql = rex_sql::factory();
        $query = 'SELECT id FROM ' . $table . ' WHERE source_domain = ? AND COALESCE(source_path, \'\') = ?';
        $params = [$data['source_domain'], $path];
        if ($data['id'] > 0) {
            $query .= ' AND id != ?';
            $params[] = $data['id'];
        }
        $sql->setQuery($query, $params);
        if ($sql->getRows() > 0) {
            $errors[] = $addon->i18n('upkeep_redirects_duplicate');
        }
    }

    if (!$errors) {
        try {
            $now = date('Y-m-d H:i:s');
            $sql = rex_sql::factory();
            $sql->setTable($table);
            $sql->setValue('source_domain', $data['source_domain']);
            $sql->setValue('source_path', $path === '' ? null : $path);
            $sql->setValue('target_url', $target);
            $sql->setValue('redirect_code', $data['redirect_code']);
            $sql->setValue('is_wildcard', $data['is_wildcard']);
            $sql->setValue('status', $data['status']);
            $sql->setValue('description', $data['description']);
            $sql->setValue('updatedate', $now);
            if ($data['id'] > 0) {
                $sql->setWhere(['id' => $data['id']]);
                $sql->update();
            } else {
                $sql->setValue('createdate', $now);
                $sql->insert();
            }
            $messages[] = rex_view::success($addon->i18n('upkeep_domain_mapping_saved'));
            $func = '';
            $data = [];
        } catch (rex_sql_exception $e) {
            rex_logger::logException($e);
            $messages[] = rex_view::error($addon->i18n('upkeep_domain_mapping_save_error'));
        }
    } else {
        $messages[] = rex_view::error(
            rex_escape($addon->i18n('upkeep_domain_mapping_save_error')) . ':<br>' . implode('<br>', array_map('rex_escape', $errors))
        );
    }
}

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$isAdmin = rex::requireUser()->isAdmin();

// Kopf
$active = (bool) $addon->getConfig('domain_mapping_active', false);
$actions = Ui::badge($t($active ? 'upkeep_redirects_module_on' : 'upkeep_redirects_module_off'), $active ? 'ok' : 'muted');
if ($isAdmin) {
    $actions .= ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'redirects']) . '">' . rex_escape($t('upkeep_nav_settings')) . '</a>';
}
echo Ui::hero($t('upkeep_redirects_title'), $t('upkeep_set_section_redirects_desc'), Ui::icon('fa-share', 'indigo'), $actions);

echo implode('', $messages);

// Formulardaten
if ($func === 'edit' && !$data) {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT * FROM ' . $table . ' WHERE id = ?', [$id]);
    if ($sql->getRows() === 0) {
        echo rex_view::error(rex_escape($t('upkeep_redirects_not_found')));
        $func = '';
    } else {
        foreach (['id', 'source_domain', 'source_path', 'target_url', 'redirect_code', 'is_wildcard', 'status', 'description'] as $col) {
            $data[$col] = $sql->getValue($col);
        }
    }
}
if ($func !== 'edit') {
    if ($func !== 'add') {
        $data = [];
    }
    if (!isset($data['status'])) {
        $data['status'] = 1;
    }
}
$isEdit = $func === 'edit';

// Liste
$rows = [];
try {
    $rows = rex_sql::factory()->getArray('SELECT * FROM ' . $table . ' ORDER BY source_domain, source_path');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
}

echo Ui::listTitle($t('upkeep_redirects_title'), count($rows));

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t('upkeep_domain_mapping_no_entries'), 'fa-share') . '</div>';
} else {
    $labels = [
        'domain' => $t('upkeep_domain_mapping_source_domain'),
        'path' => $t('upkeep_domain_mapping_source_path'),
        'target' => $t('upkeep_domain_mapping_target_url'),
        'code' => $t('upkeep_redirects_code_short'),
        'status' => $t('upkeep_domain_mapping_status'),
        'description' => $t('upkeep_domain_mapping_description_field'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = '<form id="upk-redirects-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    foreach ($labels as $key => $label) {
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';

    foreach ($rows as $row) {
        $rowId = (int) $row['id'];
        $path = (string) ($row['source_path'] ?? '');
        $target = (string) $row['target_url'];
        $desc = (string) ($row['description'] ?? '');
        $isOn = (int) $row['status'] === 1;

        $body .= '<tr' . ($isEdit && $rowId === (int) $id ? ' class="upk-table-current"' : '') . '>';
        $body .= Ui::td($labels['domain'], rex_escape((string) $row['source_domain']), 'upk-nowrap');
        $body .= Ui::td($labels['path'], ($path === ''
            ? '<span class="upk-muted">' . rex_escape($t('upkeep_redirects_domain_only')) . '</span>'
            : '<span class="upk-mono">' . rex_escape($path) . '</span>')
            . ((int) $row['is_wildcard'] ? ' ' . Ui::badge($t('upkeep_redirects_wildcard_badge'), 'info') : ''));
        $body .= Ui::td($labels['target'], '<span class="upk-mono" title="' . rex_escape($target) . '">' . rex_escape(mb_strimwidth($target, 0, 60, '…')) . '</span>');
        $body .= Ui::td($labels['code'], (string) (int) $row['redirect_code']);
        $body .= Ui::td($labels['status'], Ui::status($isOn));
        $body .= Ui::td($labels['description'], '<span class="upk-muted" title="' . rex_escape($desc) . '">' . rex_escape(mb_strimwidth($desc, 0, 40, '…')) . '</span>');
        $body .= Ui::td($labels['actions'],
            '<a class="btn btn-xs upk-btn-ghost" href="' . rex_url::backendPage($pageKey, ['func' => 'edit', 'id' => $rowId]) . '#upk-form"><i class="rex-icon rex-icon-edit" aria-hidden="true"></i> ' . rex_escape($t('upkeep_edit')) . '</a> '
            . '<button type="submit" form="upk-redirects-row" class="btn btn-xs upk-btn-ghost" name="toggle_mapping" value="' . $rowId . '">'
            . rex_escape($isOn ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button> '
            . '<button type="submit" form="upk-redirects-row" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="delete_mapping" value="' . $rowId . '" data-confirm="' . rex_escape($t('upkeep_redirects_delete_confirm')) . '">'
            . '<i class="rex-icon rex-icon-delete" aria-hidden="true"></i> ' . rex_escape($t('upkeep_delete')) . '</button>',
            'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div></div>';
    echo $body;
}
echo '<p class="upk-group-note">' . rex_escape($t('upkeep_redirects_domain_note')) . '</p>';

// Formular: anlegen / bearbeiten
$codeOptions = '';
foreach ($allowedCodes as $code) {
    $codeOptions .= '<option value="' . $code . '"' . ((int) ($data['redirect_code'] ?? 301) === $code ? ' selected' : '') . '>' . $code . ' – ' . rex_escape($t('upkeep_redirects_code_' . $code)) . '</option>';
}

$form = '<details class="upk-group upk-form-details"' . (!$rows || $func === 'add' || $isEdit ? ' open' : '') . ' id="upk-form">'
    . '<summary>' . rex_escape($isEdit ? $t('upkeep_domain_mapping_edit') : $t('upkeep_domain_mapping_add')) . '</summary>'
    . '<form action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField()
    . '<input type="hidden" name="func" value="' . ($isEdit ? 'edit' : 'add') . '">';
if ($isEdit) {
    $form .= '<input type="hidden" name="id" value="' . (int) $id . '">';
}
$form .= Ui::row($t('upkeep_domain_mapping_source_domain'), '<input class="form-control" type="text" id="upk-source-domain" name="source_domain" value="' . rex_escape((string) ($data['source_domain'] ?? '')) . '" required maxlength="253" placeholder="alte-domain.de">', $t('upkeep_redirects_domain_note'), 'upk-source-domain');
$form .= Ui::row($t('upkeep_domain_mapping_source_path'), '<input class="form-control upk-mono" type="text" id="upk-source-path" name="source_path" value="' . rex_escape((string) ($data['source_path'] ?? '')) . '" maxlength="255" placeholder="/pfad/zur/seite">', $t('upkeep_redirects_path_note'), 'upk-source-path');
$form .= Ui::row($t('upkeep_redirects_wildcard_label'), Ui::switch('is_wildcard', !empty($data['is_wildcard']), 'upk-is-wildcard'), $t('upkeep_domain_mapping_wildcard_note'), 'upk-is-wildcard');
$form .= Ui::row($t('upkeep_domain_mapping_target_url'), '<input class="form-control upk-mono" type="url" id="upk-target-url" name="target_url" value="' . rex_escape((string) ($data['target_url'] ?? '')) . '" required maxlength="2000" placeholder="https://neue-domain.de/">', $t('upkeep_redirects_target_note'), 'upk-target-url');
$form .= Ui::row($t('upkeep_domain_mapping_redirect_code'), '<select class="form-control" id="upk-redirect-code" name="redirect_code">' . $codeOptions . '</select>', '', 'upk-redirect-code');
$form .= Ui::row($t('upkeep_domain_mapping_description_field'), '<textarea class="form-control" id="upk-description" name="description" rows="2" maxlength="1000">' . rex_escape((string) ($data['description'] ?? '')) . '</textarea>', '', 'upk-description');
$form .= Ui::row($t('upkeep_redirects_status_label'), Ui::switch('status', !empty($data['status']), 'upk-status'), '', 'upk-status');
$form .= '<div class="upk-form-actions">';
if ($isEdit || $func === 'add') {
    $form .= '<a class="btn btn-abort" href="' . rex_url::backendPage($pageKey) . '">' . rex_escape(rex_i18n::rawMsg('form_abort')) . '</a>';
}
$form .= '<button class="btn btn-save" type="submit" name="save" value="1">' . rex_escape(rex_i18n::rawMsg('form_save')) . '</button></div>';
$form .= '</form></details>';
echo $form;
