<?php

/**
 * Upkeep 3.0 – Weiterleitungen (Domain-Mapping).
 *
 * Liste, Anlegen, Bearbeiten und Löschen von Domain-/Pfad-Weiterleitungen.
 * Der globale Schalter liegt in den Einstellungen (Abschnitt "redirects").
 */

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

echo implode('', $messages);

// Formular
if ($func === 'add' || $func === 'edit') {
    if ($func === 'edit' && !$data) {
        $sql = rex_sql::factory();
        $sql->setQuery('SELECT * FROM ' . $table . ' WHERE id = ?', [$id]);
        if ($sql->getRows() === 0) {
            echo rex_view::error($addon->i18n('upkeep_redirects_not_found'));
            $func = '';
        } else {
            foreach (['id', 'source_domain', 'source_path', 'target_url', 'redirect_code', 'is_wildcard', 'status', 'description'] as $col) {
                $data[$col] = $sql->getValue($col);
            }
        }
    }
    if ($func === 'add' && !isset($data['status'])) {
        $data['status'] = 1;
    }
}

if ($func === 'add' || $func === 'edit') {
    $formElements = [];

    $n = [];
    $n['label'] = '<label for="upk-source-domain">' . $addon->i18n('upkeep_domain_mapping_source_domain') . '</label>';
    $n['field'] = '<input class="form-control" type="text" id="upk-source-domain" name="source_domain" value="' . rex_escape((string) ($data['source_domain'] ?? '')) . '" required maxlength="253" placeholder="alte-domain.de">';
    $n['note'] = rex_escape($addon->i18n('upkeep_redirects_domain_note'));
    $formElements[] = $n;

    $n = [];
    $n['label'] = '<label for="upk-source-path">' . $addon->i18n('upkeep_domain_mapping_source_path') . '</label>';
    $n['field'] = '<input class="form-control upk-mono" type="text" id="upk-source-path" name="source_path" value="' . rex_escape((string) ($data['source_path'] ?? '')) . '" maxlength="255" placeholder="/pfad/zur/seite">';
    $n['note'] = rex_escape($addon->i18n('upkeep_redirects_path_note'));
    $formElements[] = $n;

    $n = [];
    $n['label'] = '<label for="upk-is-wildcard">' . $addon->i18n('upkeep_domain_mapping_is_wildcard') . '</label>';
    $n['field'] = '<div class="checkbox"><label><input type="checkbox" id="upk-is-wildcard" name="is_wildcard" value="1"' . (!empty($data['is_wildcard']) ? ' checked' : '') . '> ' . rex_escape($addon->i18n('upkeep_redirects_wildcard_label')) . '</label></div>';
    $n['note'] = rex_escape($addon->i18n('upkeep_domain_mapping_wildcard_note'));
    $formElements[] = $n;

    $n = [];
    $n['label'] = '<label for="upk-target-url">' . $addon->i18n('upkeep_domain_mapping_target_url') . '</label>';
    $n['field'] = '<input class="form-control upk-mono" type="url" id="upk-target-url" name="target_url" value="' . rex_escape((string) ($data['target_url'] ?? '')) . '" required maxlength="2000" placeholder="https://neue-domain.de/">';
    $n['note'] = rex_escape($addon->i18n('upkeep_redirects_target_note'));
    $formElements[] = $n;

    $select = new rex_select();
    $select->setId('upk-redirect-code');
    $select->setName('redirect_code');
    $select->setAttribute('class', 'form-control');
    foreach ($allowedCodes as $code) {
        $select->addOption($code . ' - ' . $addon->i18n('upkeep_redirects_code_' . $code), $code);
    }
    $select->setSelected((int) ($data['redirect_code'] ?? 301));
    $n = [];
    $n['label'] = '<label for="upk-redirect-code">' . $addon->i18n('upkeep_domain_mapping_redirect_code') . '</label>';
    $n['field'] = $select->get();
    $formElements[] = $n;

    $n = [];
    $n['label'] = '<label for="upk-description">' . $addon->i18n('upkeep_domain_mapping_description_field') . '</label>';
    $n['field'] = '<textarea class="form-control" id="upk-description" name="description" rows="3" maxlength="1000">' . rex_escape((string) ($data['description'] ?? '')) . '</textarea>';
    $formElements[] = $n;

    $n = [];
    $n['label'] = '<label for="upk-status">' . $addon->i18n('upkeep_domain_mapping_status') . '</label>';
    $n['field'] = '<div class="checkbox"><label><input type="checkbox" id="upk-status" name="status" value="1"' . (!empty($data['status']) ? ' checked' : '') . '> ' . rex_escape($addon->i18n('upkeep_redirects_status_label')) . '</label></div>';
    $formElements[] = $n;

    $fragment = new rex_fragment();
    $fragment->setVar('elements', $formElements, false);
    $form = $fragment->parse('core/form/form.php');

    $buttons = [
        ['field' => '<button class="btn btn-save rex-form-aligned" type="submit" name="save" value="1">' . rex_i18n::msg('form_save') . '</button>'],
        ['field' => '<a class="btn btn-abort" href="' . rex_url::backendPage($pageKey) . '">' . rex_i18n::msg('form_abort') . '</a>'],
    ];
    $fragment = new rex_fragment();
    $fragment->setVar('elements', $buttons, false);
    $buttonHtml = $fragment->parse('core/form/submit.php');

    $fragment = new rex_fragment();
    $fragment->setVar('class', 'edit', false);
    $fragment->setVar('title', $func === 'add' ? $addon->i18n('upkeep_domain_mapping_add') : $addon->i18n('upkeep_domain_mapping_edit'), false);
    $fragment->setVar('body', $form, false);
    $fragment->setVar('buttons', $buttonHtml, false);

    echo '<form action="' . rex_url::backendPage($pageKey) . '" method="post">';
    echo $csrf->getHiddenField();
    echo '<input type="hidden" name="func" value="' . rex_escape($func) . '">';
    if ($func === 'edit') {
        echo '<input type="hidden" name="id" value="' . (int) $id . '">';
    }
    echo $fragment->parse('core/page/section.php');
    echo '</form>';
    return;
}

// Liste
$active = (bool) $addon->getConfig('domain_mapping_active', false);
$settingsUrl = rex_url::backendPage('upkeep/settings', ['section' => 'redirects']);

$toolbar = '<div class="upk-toolbar">';
$toolbar .= '<a class="btn btn-primary" href="' . rex_url::backendPage($pageKey, ['func' => 'add']) . '"><i class="rex-icon rex-icon-add"></i> ' . rex_escape($addon->i18n('upkeep_domain_mapping_add')) . '</a>';
$toolbar .= ' <span class="upk-badge ' . ($active ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($active ? $addon->i18n('upkeep_redirects_module_on') : $addon->i18n('upkeep_redirects_module_off')) . '</span>';
$toolbar .= ' <a href="' . $settingsUrl . '"><i class="rex-icon fa-cog"></i> ' . rex_escape($addon->i18n('upkeep_pages_settings_link')) . '</a>';
$toolbar .= '</div>';

$sql = rex_sql::factory();
$rows = [];
try {
    $rows = $sql->getArray('SELECT * FROM ' . $table . ' ORDER BY source_domain, source_path');
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
}

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n('upkeep_domain_mapping_no_entries')) . '</p>'
        . '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_domain_mapping_help_text')) . '</p></div>';
} else {
    $body = '<form id="upk-redirects-row" action="' . rex_url::backendPage($pageKey) . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover">';
    $body .= '<thead><tr>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_domain_mapping_source_domain')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_domain_mapping_source_path')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_domain_mapping_target_url')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_redirects_code_short')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_domain_mapping_status')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_domain_mapping_description_field')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';

    foreach ($rows as $row) {
        $rowId = (int) $row['id'];
        $path = (string) ($row['source_path'] ?? '');
        $target = (string) $row['target_url'];
        $desc = (string) ($row['description'] ?? '');
        $isOn = (int) $row['status'] === 1;

        $body .= '<tr>';
        $body .= '<td>' . rex_escape((string) $row['source_domain']) . '</td>';
        $body .= '<td>' . ($path === ''
            ? '<span class="upk-muted">' . rex_escape($addon->i18n('upkeep_redirects_domain_only')) . '</span>'
            : '<span class="upk-mono">' . rex_escape($path) . '</span>')
            . ((int) $row['is_wildcard'] ? ' <span class="upk-badge upk-badge--muted">' . rex_escape($addon->i18n('upkeep_redirects_wildcard_badge')) . '</span>' : '')
            . '</td>';
        $body .= '<td><span class="upk-mono" title="' . rex_escape($target) . '">' . rex_escape(mb_strimwidth($target, 0, 60, '…')) . '</span></td>';
        $body .= '<td>' . (int) $row['redirect_code'] . '</td>';
        $body .= '<td><span class="upk-badge ' . ($isOn ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($isOn ? $addon->i18n('upkeep_active') : $addon->i18n('upkeep_inactive')) . '</span></td>';
        $body .= '<td><span class="upk-muted" title="' . rex_escape($desc) . '">' . rex_escape(mb_strimwidth($desc, 0, 40, '…')) . '</span></td>';
        $body .= '<td class="upk-actions">';
        $body .= '<a class="btn btn-default btn-xs" href="' . rex_url::backendPage($pageKey, ['func' => 'edit', 'id' => $rowId]) . '"><i class="rex-icon rex-icon-edit"></i> ' . rex_escape($addon->i18n('upkeep_edit')) . '</a> ';
        $body .= '<button type="submit" form="upk-redirects-row" class="btn btn-default btn-xs" name="toggle_mapping" value="' . $rowId . '">'
            . rex_escape($isOn ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button> ';
        $body .= '<button type="submit" form="upk-redirects-row" class="btn btn-delete btn-xs" name="delete_mapping" value="' . $rowId . '" data-confirm="' . rex_escape($addon->i18n('upkeep_redirects_delete_confirm')) . '">'
            . '<i class="rex-icon rex-icon-delete"></i> ' . rex_escape($addon->i18n('upkeep_delete')) . '</button>';
        $body .= '</td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_redirects_title'), false);
$fragment->setVar('body', $toolbar . $body, false);
echo $fragment->parse('core/page/section.php');
