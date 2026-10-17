<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Badwords.
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

use KLXM\Upkeep\MailSecurityFilter;

$csrf = rex_csrf_token::factory('upkeep_mail_badwords');
$table = rex::getTable('upkeep_mail_badwords');
$severities = ['low', 'medium', 'high', 'critical'];
$baseCategories = ['general', 'profanity', 'pharmaceutical', 'financial_fraud', 'security', 'spam', 'phishing'];
$messages = [];

$regexValid = static function (string $pattern): bool {
    if (class_exists(\KLXM\Upkeep\PatternValidator::class)) {
        return \KLXM\Upkeep\PatternValidator::isValid($pattern);
    }
    return @preg_match($pattern, '') !== false;
};
$cleanCategory = static function (string $category): string {
    $category = strtolower(trim($category));
    $category = preg_replace('/[^a-z0-9_\-]/', '_', $category) ?? '';
    return $category === '' ? 'general' : substr($category, 0, 100);
};
$cleanSeverity = static fn (string $s, string $default = 'medium'): string => in_array($s, ['low', 'medium', 'high', 'critical'], true) ? $s : $default;

/** Setzt den Status eines Badwords gezielt (über die Umschalt-Funktion der Bibliothek). */
$setStatus = static function (int $id, bool $active) use ($table): bool {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT status FROM ' . $table . ' WHERE id = ?', [$id]);
    if ($sql->getRows() === 0) {
        return false;
    }
    if ((bool) $sql->getValue('status') === $active) {
        return false;
    }
    return MailSecurityFilter::toggleBadwordStatus($id);
};

$editId = rex_get('edit', 'int', 0);
$formData = null;

$hasAction = rex_post('save_badword', 'bool') || rex_post('remove_badword', 'int', 0) > 0 || rex_post('toggle_badword', 'int', 0) > 0
    || rex_post('bulk_apply', 'bool') || rex_post('import_badwords', 'bool');

if ($hasAction) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } elseif (rex_post('save_badword', 'bool')) {
        $id = rex_post('id', 'int', 0);
        $formData = [
            'id' => $id,
            'pattern' => trim(rex_post('badword_pattern', 'string', '')),
            'severity' => $cleanSeverity(rex_post('badword_severity', 'string', 'medium')),
            'category' => $cleanCategory(rex_post('badword_category', 'string', 'general')),
            'is_regex' => rex_post('badword_is_regex', 'bool', false),
            'description' => mb_substr(trim(rex_post('badword_description', 'string', '')), 0, 1000),
            'status' => $id > 0 ? rex_post('badword_status', 'bool', false) : true,
        ];
        $error = null;
        if ($formData['pattern'] === '') {
            $error = $addon->i18n('upkeep_mail_security_pattern_required');
        } elseif (strlen($formData['pattern']) > 500) {
            $error = $addon->i18n('upkeep_patterns_too_long');
        } elseif ($formData['is_regex'] && !$regexValid($formData['pattern'])) {
            $error = $addon->i18n('upkeep_patterns_invalid_regex');
        }

        if ($error !== null) {
            $messages[] = rex_view::error(rex_escape($error));
            $editId = $id;
        } elseif ($id > 0) {
            if (MailSecurityFilter::updateBadword($id, $formData['pattern'], $formData['description'], $formData['category'], $formData['severity'], $formData['status'])) {
                // is_regex wird von updateBadword nicht gesetzt
                try {
                    rex_sql::factory()->setQuery('UPDATE ' . $table . ' SET is_regex = ? WHERE id = ? AND is_editable = 1', [$formData['is_regex'] ? 1 : 0, $id]);
                } catch (rex_sql_exception $e) {
                    rex_logger::logException($e);
                }
                $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_mail_badwords_updated')));
                $formData = null;
                $editId = 0;
            } else {
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
                $editId = $id;
            }
        } elseif (MailSecurityFilter::addBadword($formData['pattern'], $formData['severity'], $formData['category'], $formData['is_regex'], $formData['description'])) {
            $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_mail_security_badword_added')));
            $formData = null;
        } else {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_mail_security_badword_add_error')));
        }
    } elseif (rex_post('remove_badword', 'int', 0) > 0) {
        $messages[] = MailSecurityFilter::removeBadword(rex_post('remove_badword', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_mail_security_badword_removed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_mail_security_badword_remove_error')));
    } elseif (rex_post('toggle_badword', 'int', 0) > 0) {
        $messages[] = MailSecurityFilter::toggleBadwordStatus(rex_post('toggle_badword', 'int'))
            ? rex_view::success(rex_escape($addon->i18n('upkeep_mail_security_badword_status_changed')))
            : rex_view::error(rex_escape($addon->i18n('upkeep_pages_action_failed')));
    } elseif (rex_post('bulk_apply', 'bool')) {
        $action = rex_post('bulk_action', 'string', '');
        $ids = array_filter(array_map('intval', rex_post('selected_badwords', 'array', [])), static fn ($v) => $v > 0);
        if (!in_array($action, ['activate', 'deactivate', 'delete'], true) || !$ids) {
            $messages[] = rex_view::warning(rex_escape($addon->i18n('upkeep_pages_bulk_nothing')));
        } else {
            $count = 0;
            try {
                foreach (array_unique($ids) as $id) {
                    $ok = match ($action) {
                        'delete' => MailSecurityFilter::removeBadword($id),
                        'activate' => $setStatus($id, true),
                        'deactivate' => $setStatus($id, false),
                    };
                    $count += $ok ? 1 : 0;
                }
                $messages[] = rex_view::success(rex_escape($addon->i18n('upkeep_pages_bulk_done', $count)));
            } catch (Throwable $e) {
                rex_logger::logException($e);
                $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_bulk_action_error')));
            }
        }
    } else {
        // Import: eine Zeile pro Badword, optional pattern|severity|category|description
        $importData = rex_post('import_data', 'string', '');
        $importSeverity = $cleanSeverity(rex_post('import_severity', 'string', 'medium'));
        $importCategory = $cleanCategory(rex_post('import_category', 'string', 'imported'));
        $lines = array_slice(array_filter(array_map('trim', preg_split('/\R/', $importData) ?: [])), 0, 5000);
        if (!$lines) {
            $messages[] = rex_view::error(rex_escape($addon->i18n('upkeep_mail_badwords_import_empty')));
        } else {
            $imported = 0;
            $failed = 0;
            foreach ($lines as $line) {
                if (str_starts_with($line, '#') || str_starts_with($line, '//')) {
                    continue;
                }
                $parts = array_map('trim', explode('|', $line));
                $pattern = $parts[0];
                if ($pattern === '' || strlen($pattern) > 500) {
                    ++$failed;
                    continue;
                }
                $ok = MailSecurityFilter::addBadword(
                    $pattern,
                    isset($parts[1]) && $parts[1] !== '' ? $cleanSeverity($parts[1], $importSeverity) : $importSeverity,
                    isset($parts[2]) && $parts[2] !== '' ? $cleanCategory($parts[2]) : $importCategory,
                    false,
                    mb_substr($parts[3] ?? '', 0, 1000),
                );
                $ok ? ++$imported : ++$failed;
            }
            $messages[] = $imported > 0
                ? rex_view::success(rex_escape($addon->i18n('upkeep_mail_badwords_import_result', $imported, $failed)))
                : rex_view::error(rex_escape($addon->i18n('upkeep_mail_badwords_import_result', $imported, $failed)));
        }
    }
}

echo implode('', $messages);

// Filter (GET)
$filterCategory = mb_substr(rex_get('category', 'string', ''), 0, 100);
$filterSeverity = rex_get('severity', 'string', '');
$filterSeverity = in_array($filterSeverity, $severities, true) ? $filterSeverity : '';
$filterStatus = rex_get('status', 'string', '');
$filterStatus = in_array($filterStatus, ['0', '1'], true) ? $filterStatus : '';
$filterSearch = mb_substr(trim(rex_get('q', 'string', '')), 0, 100);

$where = [];
$params = [];
if ($filterCategory !== '') {
    $where[] = 'category = ?';
    $params[] = $filterCategory;
}
if ($filterSeverity !== '') {
    $where[] = 'severity = ?';
    $params[] = $filterSeverity;
}
if ($filterStatus !== '') {
    $where[] = 'status = ?';
    $params[] = (int) $filterStatus;
}
if ($filterSearch !== '') {
    $like = '%' . addcslashes($filterSearch, '%_\\') . '%';
    $where[] = '(pattern LIKE ? OR description LIKE ?)';
    $params[] = $like;
    $params[] = $like;
}
$whereSql = $where ? ' WHERE ' . implode(' AND ', $where) : '';

try {
    $sql = rex_sql::factory();
    $rows = $sql->getArray('SELECT * FROM ' . $table . $whereSql . ' ORDER BY FIELD(severity, \'critical\', \'high\', \'medium\', \'low\'), category, pattern', $params);
    $categories = array_map(static fn ($r) => (string) $r['category'], $sql->getArray('SELECT DISTINCT category FROM ' . $table . ' ORDER BY category'));
} catch (rex_sql_exception $e) {
    rex_logger::logException($e);
    echo rex_view::error($addon->i18n('upkeep_pages_table_missing'));
    return;
}

$categoryLabel = static function (string $c) use ($addon, $baseCategories): string {
    return in_array($c, $baseCategories, true) ? $addon->i18n('upkeep_category_' . $c) : $c;
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

$filterParams = array_filter(['category' => $filterCategory, 'severity' => $filterSeverity, 'status' => $filterStatus, 'q' => $filterSearch], static fn ($v) => $v !== '');

$filter = '<form class="upk-filter form-inline" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="badwords">';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bw-fcat">' . rex_escape($addon->i18n('upkeep_category')) . '</label><select class="form-control" id="upk-bw-fcat" name="category"><option value="">' . rex_escape($addon->i18n('upkeep_all_categories')) . '</option>';
foreach ($categories as $cat) {
    $filter .= '<option value="' . rex_escape($cat) . '"' . ($filterCategory === $cat ? ' selected' : '') . '>' . rex_escape($categoryLabel($cat)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bw-fsev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-bw-fsev" name="severity"><option value="">' . rex_escape($addon->i18n('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($filterSeverity === $sev ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bw-fstatus">' . rex_escape($addon->i18n('upkeep_pages_status')) . '</label><select class="form-control" id="upk-bw-fstatus" name="status"><option value="">' . rex_escape($addon->i18n('upkeep_all_status')) . '</option>'
    . '<option value="1"' . ($filterStatus === '1' ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_active')) . '</option>'
    . '<option value="0"' . ($filterStatus === '0' ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_inactive')) . '</option></select></div> ';
$filter .= '<div class="form-group"><label class="sr-only" for="upk-bw-fq">' . rex_escape($addon->i18n('upkeep_pages_search')) . '</label><input type="search" class="form-control" id="upk-bw-fq" name="q" maxlength="100" placeholder="' . rex_escape($addon->i18n('upkeep_pages_search')) . '" value="' . rex_escape($filterSearch) . '"></div> ';
$filter .= '<button type="submit" class="btn btn-default"><i class="rex-icon fa-search"></i> ' . rex_escape($addon->i18n('upkeep_filter')) . '</button> ';
if ($filterParams) {
    $filter .= '<a class="btn btn-link" href="' . $tabUrl() . '">' . rex_escape($addon->i18n('upkeep_reset')) . '</a>';
}
$filter .= '</form>';

$listUrl = $tabUrl($filterParams);
$toolbar = '<div class="upk-toolbar"><span class="upk-muted">' . rex_escape($addon->i18n('upkeep_pages_entries_total', count($rows))) . '</span></div>';

if (!$rows) {
    $body = '<div class="upk-empty"><p>' . rex_escape($addon->i18n($filterParams ? 'upkeep_pages_no_match' : 'upkeep_mail_badwords_empty')) . '</p></div>';
} else {
    $body = '<form id="upk-bw-rows" action="' . $listUrl . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="table-responsive"><table class="table table-striped table-hover"><thead><tr>';
    $body .= '<th class="rex-table-icon"><input type="checkbox" data-upk-check-all="upk-bw-rows" aria-label="' . rex_escape($addon->i18n('upkeep_select_all')) . '"></th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pattern')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_category')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_ips_type')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_pages_status')) . '</th>';
    $body .= '<th>' . rex_escape($addon->i18n('upkeep_description')) . '</th>';
    $body .= '<th class="upk-actions">' . rex_escape($addon->i18n('upkeep_actions')) . '</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $on = (int) $row['status'] === 1;
        $desc = (string) ($row['description'] ?? '');
        $body .= '<tr>';
        $body .= '<td class="rex-table-icon"><input type="checkbox" form="upk-bw-rows" name="selected_badwords[]" value="' . $id . '" aria-label="' . rex_escape((string) $row['pattern']) . '"></td>';
        $body .= '<td><span class="upk-mono">' . rex_escape((string) $row['pattern']) . '</span></td>';
        $body .= '<td>' . rex_escape($categoryLabel((string) $row['category'])) . '</td>';
        $body .= '<td>' . $severityBadge((string) $row['severity']) . '</td>';
        $body .= '<td>' . rex_escape((int) $row['is_regex'] ? $addon->i18n('upkeep_type_regex') : $addon->i18n('upkeep_type_text')) . '</td>';
        $body .= '<td><span class="upk-badge ' . ($on ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($on ? $addon->i18n('upkeep_active') : $addon->i18n('upkeep_inactive')) . '</span></td>';
        $body .= '<td><span class="upk-muted" title="' . rex_escape($desc) . '">' . rex_escape(mb_strimwidth($desc, 0, 50, '…')) . '</span></td>';
        $body .= '<td class="upk-actions">';
        $body .= '<a class="btn btn-default btn-xs" href="' . $tabUrl($filterParams + ['edit' => $id]) . '"><i class="rex-icon rex-icon-edit"></i> ' . rex_escape($addon->i18n('upkeep_edit')) . '</a> ';
        $body .= '<button type="submit" form="upk-bw-rows" class="btn btn-default btn-xs" name="toggle_badword" value="' . $id . '">' . rex_escape($on ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '</button> ';
        $body .= '<button type="submit" form="upk-bw-rows" class="btn btn-delete btn-xs" name="remove_badword" value="' . $id . '" data-confirm="' . rex_escape($addon->i18n('upkeep_delete_badword_confirm')) . '"><i class="rex-icon rex-icon-delete"></i> ' . rex_escape($addon->i18n('upkeep_delete')) . '</button>';
        $body .= '</td></tr>';
    }
    $body .= '</tbody></table></div>';

    $body .= '<div class="upk-toolbar form-inline">'
        . '<label class="sr-only" for="upk-bw-bulk">' . rex_escape($addon->i18n('upkeep_bulk_action_select')) . '</label>'
        . '<select class="form-control" id="upk-bw-bulk" name="bulk_action" form="upk-bw-rows">'
        . '<option value="">' . rex_escape($addon->i18n('upkeep_bulk_action_select')) . '</option>'
        . '<option value="activate">' . rex_escape($addon->i18n('upkeep_activate')) . '</option>'
        . '<option value="deactivate">' . rex_escape($addon->i18n('upkeep_deactivate')) . '</option>'
        . '<option value="delete">' . rex_escape($addon->i18n('upkeep_delete')) . '</option>'
        . '</select> '
        . '<button type="submit" class="btn btn-default" form="upk-bw-rows" name="bulk_apply" value="1" data-confirm="' . rex_escape($addon->i18n('upkeep_bulk_confirm')) . '">' . rex_escape($addon->i18n('upkeep_execute')) . '</button>'
        . '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_mail_security_badwords'), false);
$fragment->setVar('body', $toolbar . $filter . $body, false);
echo $fragment->parse('core/page/section.php');

// Formular: anlegen / bearbeiten
if ($editId > 0 && $formData === null) {
    $sql = rex_sql::factory();
    $sql->setQuery('SELECT * FROM ' . $table . ' WHERE id = ?', [$editId]);
    if ($sql->getRows() > 0) {
        $formData = [
            'pattern' => (string) $sql->getValue('pattern'),
            'severity' => (string) $sql->getValue('severity'),
            'category' => (string) $sql->getValue('category'),
            'is_regex' => (bool) $sql->getValue('is_regex'),
            'description' => (string) $sql->getValue('description'),
            'status' => (bool) $sql->getValue('status'),
            'is_editable' => (bool) $sql->getValue('is_editable'),
        ];
    } else {
        $editId = 0;
    }
}
$isEdit = $editId > 0 && $formData !== null;
$current = $formData ?? ['pattern' => '', 'severity' => 'medium', 'category' => 'general', 'is_regex' => false, 'description' => '', 'status' => true];

$sevOptions = '';
foreach ($severities as $sev) {
    $sevOptions .= '<option value="' . $sev . '"' . ($current['severity'] === $sev ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$catOptions = '';
foreach (array_unique(array_merge($baseCategories, $categories)) as $cat) {
    $catOptions .= '<option value="' . rex_escape($cat) . '"' . ($current['category'] === $cat ? ' selected' : '') . '>' . rex_escape($categoryLabel($cat)) . '</option>';
}

$form = '<form action="' . $listUrl . '" method="post">' . $csrf->getHiddenField();
if ($isEdit) {
    $form .= '<input type="hidden" name="id" value="' . (int) $editId . '">';
    if (isset($current['is_editable']) && !$current['is_editable']) {
        $form .= '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_mail_badwords_not_editable')) . '</p>';
    }
}
$form .= '<div class="row">';
$form .= '<div class="col-sm-5"><div class="form-group"><label for="upk-bw-pattern">' . rex_escape($addon->i18n('upkeep_pattern')) . '</label>'
    . '<input type="text" class="form-control upk-mono" id="upk-bw-pattern" name="badword_pattern" required maxlength="500" value="' . rex_escape((string) $current['pattern']) . '" placeholder="' . rex_escape($addon->i18n('upkeep_pattern_example')) . '"></div></div>';
$form .= '<div class="col-sm-3"><div class="form-group"><label for="upk-bw-sev">' . rex_escape($addon->i18n('upkeep_ips_severity')) . '</label>'
    . '<select class="form-control" id="upk-bw-sev" name="badword_severity">' . $sevOptions . '</select></div></div>';
$form .= '<div class="col-sm-4"><div class="form-group"><label for="upk-bw-cat">' . rex_escape($addon->i18n('upkeep_category')) . '</label>'
    . '<select class="form-control" id="upk-bw-cat" name="badword_category">' . $catOptions . '</select></div></div>';
$form .= '</div>';
$form .= '<div class="form-group"><label for="upk-bw-desc">' . rex_escape($addon->i18n('upkeep_description')) . '</label>'
    . '<input type="text" class="form-control" id="upk-bw-desc" name="badword_description" maxlength="1000" value="' . rex_escape((string) $current['description']) . '"></div>';
$form .= '<div class="checkbox"><label><input type="checkbox" name="badword_is_regex" value="1"' . (!empty($current['is_regex']) ? ' checked' : '') . '> ' . rex_escape($addon->i18n('upkeep_patterns_is_regex_label')) . '</label></div>';
if ($isEdit) {
    $form .= '<div class="checkbox"><label><input type="checkbox" name="badword_status" value="1"' . (!empty($current['status']) ? ' checked' : '') . '> ' . rex_escape($addon->i18n('upkeep_active')) . '</label></div>';
}
$form .= '<button type="submit" class="btn btn-save" name="save_badword" value="1">' . rex_escape($isEdit ? $addon->i18n('upkeep_update') : $addon->i18n('upkeep_add')) . '</button>';
if ($isEdit) {
    $form .= ' <a class="btn btn-abort" href="' . $listUrl . '">' . rex_escape($addon->i18n('upkeep_cancel')) . '</a>';
}
$form .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $isEdit ? $addon->i18n('upkeep_mail_badwords_edit') : $addon->i18n('upkeep_mail_badwords_add'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');

// Formular: Import
$sevOptions = '';
foreach ($severities as $sev) {
    $sevOptions .= '<option value="' . $sev . '"' . ($sev === 'medium' ? ' selected' : '') . '>' . rex_escape($addon->i18n('upkeep_ips_severity_' . $sev)) . '</option>';
}
$form = '<form action="' . $listUrl . '" method="post">' . $csrf->getHiddenField();
$form .= '<p class="upk-muted">' . rex_escape($addon->i18n('upkeep_import_help')) . ' ' . rex_escape($addon->i18n('upkeep_import_format')) . '</p>';
$form .= '<div class="row">';
$form .= '<div class="col-sm-8"><div class="form-group"><label for="upk-bw-import">' . rex_escape($addon->i18n('upkeep_import_data_label')) . '</label>'
    . '<textarea class="form-control upk-mono" id="upk-bw-import" name="import_data" rows="6" required></textarea></div></div>';
$form .= '<div class="col-sm-4">'
    . '<div class="form-group"><label for="upk-bw-isev">' . rex_escape($addon->i18n('upkeep_default_severity')) . '</label><select class="form-control" id="upk-bw-isev" name="import_severity">' . $sevOptions . '</select></div>'
    . '<div class="form-group"><label for="upk-bw-icat">' . rex_escape($addon->i18n('upkeep_default_category')) . '</label><input type="text" class="form-control" id="upk-bw-icat" name="import_category" maxlength="100" value="imported"></div>'
    . '</div>';
$form .= '</div>';
$form .= '<button type="submit" class="btn btn-default" name="import_badwords" value="1"><i class="rex-icon fa-upload"></i> ' . rex_escape($addon->i18n('upkeep_import')) . '</button>';
$form .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_mail_badwords_import_title'), false);
$fragment->setVar('body', $form, false);
echo $fragment->parse('core/page/section.php');
