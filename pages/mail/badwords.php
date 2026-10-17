<?php

/**
 * Upkeep 3.0 – E-Mail-Sicherheit: Badwords.
 *
 * Eingebunden von pages/protection.mail.php ($addon, $pageKey, $tab, $tabUrl).
 */

use KLXM\Upkeep\MailSecurityFilter;
use KLXM\Upkeep\Ui;

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

$t = static fn (string $key, string ...$args): string => rex_i18n::rawMsg($key, ...$args);
$hadError = str_contains(implode('', $messages), 'alert-danger');

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
    echo rex_view::error(rex_escape($t('upkeep_pages_table_missing')));
    return;
}

$categoryLabel = static function (string $c) use ($t, $baseCategories): string {
    return in_array($c, $baseCategories, true) ? $t('upkeep_category_' . $c) : $c;
};

$filterParams = array_filter(['category' => $filterCategory, 'severity' => $filterSeverity, 'status' => $filterStatus, 'q' => $filterSearch], static fn ($v) => $v !== '');

$filter = '<form class="upk-group upk-filterbar" method="get" action="' . rex_url::backendController() . '">';
$filter .= '<input type="hidden" name="page" value="' . rex_escape($pageKey) . '"><input type="hidden" name="tab" value="badwords">';
$filter .= '<label class="sr-only" for="upk-bw-fq">' . rex_escape($t('upkeep_pages_search')) . '</label><input type="search" class="form-control upk-filterbar-text" id="upk-bw-fq" name="q" maxlength="100" placeholder="' . rex_escape($t('upkeep_pages_search')) . '" value="' . rex_escape($filterSearch) . '">';
$filter .= '<label class="sr-only" for="upk-bw-fcat">' . rex_escape($t('upkeep_category')) . '</label><select class="form-control" id="upk-bw-fcat" name="category"><option value="">' . rex_escape($t('upkeep_all_categories')) . '</option>';
foreach ($categories as $cat) {
    $filter .= '<option value="' . rex_escape($cat) . '"' . ($filterCategory === $cat ? ' selected' : '') . '>' . rex_escape($categoryLabel($cat)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="sr-only" for="upk-bw-fsev">' . rex_escape($t('upkeep_ips_severity')) . '</label><select class="form-control" id="upk-bw-fsev" name="severity"><option value="">' . rex_escape($t('upkeep_filter_all_severities')) . '</option>';
foreach ($severities as $sev) {
    $filter .= '<option value="' . $sev . '"' . ($filterSeverity === $sev ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
$filter .= '</select>';
$filter .= '<label class="sr-only" for="upk-bw-fstatus">' . rex_escape($t('upkeep_pages_status')) . '</label><select class="form-control" id="upk-bw-fstatus" name="status"><option value="">' . rex_escape($t('upkeep_all_status')) . '</option>'
    . '<option value="1"' . ($filterStatus === '1' ? ' selected' : '') . '>' . rex_escape($t('upkeep_active')) . '</option>'
    . '<option value="0"' . ($filterStatus === '0' ? ' selected' : '') . '>' . rex_escape($t('upkeep_inactive')) . '</option></select>';
$filter .= '<span class="upk-filterbar-end">';
if ($filterParams) {
    $filter .= '<a class="upk-filterbar-reset" href="' . $tabUrl() . '">' . rex_escape($t('upkeep_reset')) . '</a>';
}
$filter .= '<button type="submit" class="btn btn-default"><i class="rex-icon fa-search" aria-hidden="true"></i> ' . rex_escape($t('upkeep_filter')) . '</button></span>';
$filter .= '</form>';
echo $filter;

$listUrl = $tabUrl($filterParams);
echo Ui::listTitle($t('upkeep_mail_security_badwords'), count($rows));

if (!$rows) {
    echo '<div class="upk-group">' . Ui::emptyState($t($filterParams ? 'upkeep_pages_no_match' : 'upkeep_mail_badwords_empty'), $filterParams ? 'fa-filter' : 'fa-check') . '</div>';
} else {
    $labels = [
        'select' => $t('upkeep_list_select'),
        'pattern' => $t('upkeep_pattern'),
        'category' => $t('upkeep_category'),
        'severity' => $t('upkeep_ips_severity'),
        'type' => $t('upkeep_ips_type'),
        'status' => $t('upkeep_pages_status'),
        'description' => $t('upkeep_description'),
        'actions' => $t('upkeep_actions'),
    ];
    $body = '<form id="upk-bw-rows" action="' . $listUrl . '" method="post">' . $csrf->getHiddenField() . '</form>';
    $body .= '<div class="upk-group upk-group--table"><div class="upk-table-wrap"><table class="upk-table"><thead><tr>';
    $body .= '<th scope="col" class="upk-table-check"><input type="checkbox" data-upk-check-all="upk-bw-rows" aria-label="' . rex_escape($t('upkeep_select_all')) . '"></th>';
    foreach ($labels as $key => $label) {
        if ('select' === $key) {
            continue;
        }
        $body .= '<th scope="col"' . ('actions' === $key ? ' class="upk-actions"' : '') . '>' . ('actions' === $key ? '<span class="sr-only">' . rex_escape($label) . '</span>' : rex_escape($label)) . '</th>';
    }
    $body .= '</tr></thead><tbody>';
    foreach ($rows as $row) {
        $id = (int) $row['id'];
        $on = (int) $row['status'] === 1;
        $desc = (string) ($row['description'] ?? '');
        $body .= '<tr' . ($id === $editId ? ' class="upk-table-current"' : '') . '>';
        $body .= Ui::td($labels['select'], '<input type="checkbox" form="upk-bw-rows" name="selected_badwords[]" value="' . $id . '" aria-label="' . rex_escape((string) $row['pattern']) . '">', 'upk-table-check');
        $body .= Ui::td($labels['pattern'], '<span class="upk-mono">' . rex_escape((string) $row['pattern']) . '</span>');
        $body .= Ui::td($labels['category'], rex_escape($categoryLabel((string) $row['category'])));
        $body .= Ui::td($labels['severity'], Ui::severity((string) $row['severity']));
        $body .= Ui::td($labels['type'], rex_escape((int) $row['is_regex'] ? $t('upkeep_type_regex') : $t('upkeep_type_text')));
        $body .= Ui::td($labels['status'], Ui::status($on));
        $body .= Ui::td($labels['description'], '<span class="upk-muted" title="' . rex_escape($desc) . '">' . rex_escape(mb_strimwidth($desc, 0, 50, '…')) . '</span>');
        $body .= Ui::td($labels['actions'],
            '<a class="btn btn-xs upk-btn-ghost" href="' . $tabUrl($filterParams + ['edit' => $id]) . '#upk-form"><i class="rex-icon rex-icon-edit" aria-hidden="true"></i> ' . rex_escape($t('upkeep_edit')) . '</a> '
            . '<button type="submit" form="upk-bw-rows" class="btn btn-xs upk-btn-ghost" name="toggle_badword" value="' . $id . '">' . rex_escape($on ? $t('upkeep_deactivate') : $t('upkeep_activate')) . '</button> '
            . '<button type="submit" form="upk-bw-rows" class="btn btn-xs upk-btn-ghost upk-btn-ghost--danger" name="remove_badword" value="' . $id . '" data-confirm="' . rex_escape($t('upkeep_delete_badword_confirm')) . '"><i class="rex-icon rex-icon-delete" aria-hidden="true"></i> ' . rex_escape($t('upkeep_delete')) . '</button>',
            'upk-actions');
        $body .= '</tr>';
    }
    $body .= '</tbody></table></div>';

    $body .= '<div class="upk-group-foot"><div class="upk-bulk">'
        . '<label class="sr-only" for="upk-bw-bulk">' . rex_escape($t('upkeep_bulk_action_select')) . '</label>'
        . '<select class="form-control" id="upk-bw-bulk" name="bulk_action" form="upk-bw-rows">'
        . '<option value="">' . rex_escape($t('upkeep_bulk_action_select')) . '</option>'
        . '<option value="activate">' . rex_escape($t('upkeep_activate')) . '</option>'
        . '<option value="deactivate">' . rex_escape($t('upkeep_deactivate')) . '</option>'
        . '<option value="delete">' . rex_escape($t('upkeep_delete')) . '</option>'
        . '</select>'
        . '<button type="submit" class="btn btn-default" form="upk-bw-rows" name="bulk_apply" value="1" data-confirm="' . rex_escape($t('upkeep_bulk_confirm')) . '">' . rex_escape($t('upkeep_execute')) . '</button>'
        . '</div></div>';
    $body .= '</div>';
    echo $body;
}

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
    $sevOptions .= '<option value="' . $sev . '"' . ($current['severity'] === $sev ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
$catOptions = '';
foreach (array_unique(array_merge($baseCategories, $categories)) as $cat) {
    $catOptions .= '<option value="' . rex_escape($cat) . '"' . ($current['category'] === $cat ? ' selected' : '') . '>' . rex_escape($categoryLabel($cat)) . '</option>';
}

$form = '<details class="upk-group upk-form-details"' . ($formData !== null || (!$rows && !$filterParams) ? ' open' : '') . ' id="upk-form">'
    . '<summary>' . rex_escape($isEdit ? $t('upkeep_mail_badwords_edit') : $t('upkeep_mail_badwords_add')) . '</summary>'
    . '<form action="' . $listUrl . '" method="post">' . $csrf->getHiddenField();
if ($isEdit) {
    $form .= '<input type="hidden" name="id" value="' . (int) $editId . '">';
    if (isset($current['is_editable']) && !$current['is_editable']) {
        $form .= '<p class="upk-form-intro">' . rex_escape($t('upkeep_mail_badwords_not_editable')) . '</p>';
    }
}
$form .= Ui::row($t('upkeep_pattern'), '<input type="text" class="form-control upk-mono" id="upk-bw-pattern" name="badword_pattern" required maxlength="500" value="' . rex_escape((string) $current['pattern']) . '" placeholder="' . rex_escape($t('upkeep_pattern_example')) . '">', '', 'upk-bw-pattern');
$form .= Ui::row($t('upkeep_ips_severity'), '<select class="form-control" id="upk-bw-sev" name="badword_severity">' . $sevOptions . '</select>', '', 'upk-bw-sev');
$form .= Ui::row($t('upkeep_category'), '<select class="form-control" id="upk-bw-cat" name="badword_category">' . $catOptions . '</select>', '', 'upk-bw-cat');
$form .= Ui::row($t('upkeep_description'), '<input type="text" class="form-control" id="upk-bw-desc" name="badword_description" maxlength="1000" value="' . rex_escape((string) $current['description']) . '">', '', 'upk-bw-desc');
$form .= Ui::row($t('upkeep_patterns_is_regex_label'), Ui::switch('badword_is_regex', !empty($current['is_regex']), 'upk-bw-regex'), '', 'upk-bw-regex');
if ($isEdit) {
    $form .= Ui::row($t('upkeep_active'), Ui::switch('badword_status', !empty($current['status']), 'upk-bw-status'), '', 'upk-bw-status');
}
$form .= '<div class="upk-form-actions">';
if ($isEdit) {
    $form .= '<a class="btn btn-abort" href="' . $listUrl . '">' . rex_escape($t('upkeep_cancel')) . '</a>';
}
$form .= '<button type="submit" class="btn btn-save" name="save_badword" value="1">' . rex_escape($isEdit ? $t('upkeep_update') : $t('upkeep_add')) . '</button></div>';
$form .= '</form></details>';
echo $form;

// Formular: Import
$postedImport = rex_post('import_badwords', 'bool') && $hadError;
$sevOptions = '';
foreach ($severities as $sev) {
    $sevOptions .= '<option value="' . $sev . '"' . ($sev === 'medium' ? ' selected' : '') . '>' . rex_escape($t('upkeep_ips_severity_' . $sev)) . '</option>';
}
echo '<details class="upk-group upk-form-details"' . ($postedImport ? ' open' : '') . '>'
    . '<summary>' . rex_escape($t('upkeep_mail_badwords_import_title')) . '</summary>'
    . '<form action="' . $listUrl . '" method="post">' . $csrf->getHiddenField()
    . Ui::row($t('upkeep_import_data_label'), '<textarea class="form-control upk-mono" id="upk-bw-import" name="import_data" rows="6" required>' . ($postedImport ? rex_escape(rex_post('import_data', 'string', '')) : '') . '</textarea>', $t('upkeep_import_help') . ' ' . $t('upkeep_import_format'), 'upk-bw-import', '', true)
    . Ui::row($t('upkeep_default_severity'), '<select class="form-control" id="upk-bw-isev" name="import_severity">' . $sevOptions . '</select>', '', 'upk-bw-isev')
    . Ui::row($t('upkeep_default_category'), '<input type="text" class="form-control" id="upk-bw-icat" name="import_category" maxlength="100" value="imported">', '', 'upk-bw-icat')
    . '<div class="upk-form-actions"><button type="submit" class="btn btn-default" name="import_badwords" value="1"><i class="rex-icon fa-upload" aria-hidden="true"></i> ' . rex_escape($t('upkeep_import')) . '</button></div>'
    . '</form></details>';
