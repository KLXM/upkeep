<?php

use FriendsOfRedaxo\Upkeep\MailSecurityFilter;

$error = '';
$success = '';
$addon = rex_addon::get('upkeep');

// Badword hinzufügen
if (rex_post('add-badword', 'string') === '1') {
    $pattern = trim(rex_post('badword_pattern', 'string', ''));
    $severity = rex_post('badword_severity', 'string', 'medium');
    $category = rex_post('badword_category', 'string', 'general');
    $isRegex = (bool) rex_post('badword_is_regex', 'int', 0);
    $description = trim(rex_post('badword_description', 'string', ''));
    
    if (!empty($pattern)) {
        // Bei RegEx: Syntax validieren
        if ($isRegex && @preg_match($pattern, '') === false) {
            $error = $addon->i18n('upkeep_mail_security_invalid_regex');
        } else {
            if (MailSecurityFilter::addBadword($pattern, $severity, $category, $isRegex, $description)) {
                $success = $addon->i18n('upkeep_mail_security_badword_added');
            } else {
                $error = $addon->i18n('upkeep_mail_security_badword_add_error');
            }
        }
    } else {
        $error = $addon->i18n('upkeep_mail_security_pattern_required');
    }
}

// Badword entfernen
if (rex_post('remove-badword', 'int') > 0) {
    $badwordId = rex_post('remove-badword', 'int');
    if (MailSecurityFilter::removeBadword($badwordId)) {
        $success = $addon->i18n('upkeep_mail_security_badword_removed');
    } else {
        $error = $addon->i18n('upkeep_mail_security_badword_remove_error');
    }
}

// Badword-Status ändern
if (rex_post('toggle-badword', 'int') > 0) {
    $badwordId = rex_post('toggle-badword', 'int');
    
    if (MailSecurityFilter::toggleBadwordStatus($badwordId)) {
        $success = $addon->i18n('upkeep_mail_security_badword_status_changed');
    } else {
        $error = $addon->i18n('upkeep_mail_security_status_change_error');
    }
}

// Badword bearbeiten
if (rex_post('edit-badword', 'string') === '1') {
    $id = rex_post('id', 'int');
    $pattern = trim(rex_post('badword_pattern', 'string', ''));
    $severity = rex_post('badword_severity', 'string', 'medium');
    $category = rex_post('badword_category', 'string', 'general');
    $isRegex = (bool) rex_post('badword_is_regex', 'int', 0);
    $description = trim(rex_post('badword_description', 'string', ''));
    $status = (bool) rex_post('badword_status', 'int', 1);
    
    if (!empty($pattern) && $id > 0) {
        // Bei RegEx: Syntax validieren
        if ($isRegex && @preg_match($pattern, '') === false) {
            $error = $addon->i18n('upkeep_mail_security_invalid_regex');
        } else {
            if (MailSecurityFilter::updateBadword($id, $pattern, $description, $category, $severity, $status)) {
                $success = $addon->i18n('upkeep_mail_security_badword_updated');
            } else {
                $error = $addon->i18n('upkeep_mail_security_badword_update_error');
            }
        }
    } else {
        $error = $addon->i18n('upkeep_mail_security_pattern_required');
    }
}

// Bulk-Aktionen
if (rex_post('bulk-action', 'string') && rex_post('selected-badwords', 'array')) {
    $action = rex_post('bulk-action', 'string');
    $selectedIds = rex_post('selected-badwords', 'array');
    $affectedCount = 0;
    
    try {
        foreach ($selectedIds as $id) {
            $id = (int) $id;
            if ($id > 0) {
                switch ($action) {
                    case 'delete':
                        if (MailSecurityFilter::removeBadword($id)) {
                            $affectedCount++;
                        }
                        break;
                    case 'activate':
                        // Status auf aktiv setzen
                        $sql = rex_sql::factory();
                        $sql->setQuery("SELECT status FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [$id]);
                        if ($sql->getRows() > 0 && !(bool)$sql->getValue('status')) {
                            if (MailSecurityFilter::toggleBadwordStatus($id)) {
                                $affectedCount++;
                            }
                        }
                        break;
                    case 'deactivate':
                        // Status auf inaktiv setzen
                        $sql = rex_sql::factory();
                        $sql->setQuery("SELECT status FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [$id]);
                        if ($sql->getRows() > 0 && (bool)$sql->getValue('status')) {
                            if (MailSecurityFilter::toggleBadwordStatus($id)) {
                                $affectedCount++;
                            }
                        }
                        break;
                }
            }
        }
        
        $actionNames = [
            'delete' => $addon->i18n('upkeep_deleted'),
            'activate' => $addon->i18n('upkeep_activated'),
            'deactivate' => $addon->i18n('upkeep_deactivated')
        ];
        
        $success = $affectedCount . ' ' . $addon->i18n('upkeep_badwords_processed') . ' ' . ($actionNames[$action] ?? $addon->i18n('upkeep_modified')) . '.';
        
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_bulk_action_error') . ' ' . $e->getMessage();
    }
}

// Import von Badwords aus Datei
if (rex_post('import-badwords', 'string') === '1') {
    $importData = trim(rex_post('import_data', 'string', ''));
    $importSeverity = rex_post('import_severity', 'string', 'medium');
    $importCategory = rex_post('import_category', 'string', 'imported');
    
    if (!empty($importData)) {
        $lines = array_filter(array_map('trim', explode("\n", $importData)));
        $imported = 0;
        $errors = 0;
        
        foreach ($lines as $line) {
            // Skip Kommentare und leere Zeilen
            if (empty($line) || str_starts_with($line, '#') || str_starts_with($line, '//')) {
                continue;
            }
            
            // Format: pattern|severity|category|description oder nur pattern
            $parts = explode('|', $line);
            $pattern = trim($parts[0]);
            $severity = isset($parts[1]) ? trim($parts[1]) : $importSeverity;
            $category = isset($parts[2]) ? trim($parts[2]) : $importCategory;
            $description = isset($parts[3]) ? trim($parts[3]) : 'Imported badword';
            
            if (!empty($pattern)) {
                if (MailSecurityFilter::addBadword($pattern, $severity, $category, false, $description)) {
                    $imported++;
                } else {
                    $errors++;
                }
            }
        }
        
        if ($imported > 0) {
            $success = $imported . ' ' . $addon->i18n('upkeep_mail_security_badwords_imported');
            if ($errors > 0) {
                $success .= ' (' . $errors . ' ' . $addon->i18n('upkeep_mail_security_errors_occurred') . ')';
            }
        } else {
            $error = $addon->i18n('upkeep_mail_security_no_badwords_imported') . ' ' . ($errors > 0 ? $errors . ' ' . $addon->i18n('upkeep_mail_security_errors_occurred') : '');
        }
    } else {
        $error = $addon->i18n('upkeep_mail_security_import_data_empty');
    }
}

// Error/Success Messages
if ($error) {
    echo rex_view::error($error);
}
if ($success) {
    echo rex_view::success($success);
}

// Zu bearbeitendes Badword laden, falls action=edit
$editBadword = null;
if (rex_get('action') === 'edit' && rex_get('id', 'int') > 0) {
    $sql = rex_sql::factory();
    $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [rex_get('id', 'int')]);
    
    if ($sql->getRows() > 0) {
        $editBadword = [
            'id' => (int) $sql->getValue('id'),
            'pattern' => $sql->getValue('pattern'),
            'description' => $sql->getValue('description'),
            'category' => $sql->getValue('category'),
            'severity' => $sql->getValue('severity'),
            'is_regex' => (bool) $sql->getValue('is_regex'),
            'status' => (bool) $sql->getValue('status'),
            'is_default' => (bool) $sql->getValue('is_default'),
            'is_editable' => (bool) $sql->getValue('is_editable')
        ];
    }
}

// Filter-Parameter
$filterCategory = rex_request('filter_category', 'string', '');
$filterSeverity = rex_request('filter_severity', 'string', '');
$filterStatus = rex_request('filter_status', 'string', '');
$filterSearch = rex_request('filter_search', 'string', '');

// Badwords laden mit Filter
$whereConditions = [];
$whereParams = [];

if (!empty($filterCategory)) {
    $whereConditions[] = "category = ?";
    $whereParams[] = $filterCategory;
}
if (!empty($filterSeverity)) {
    $whereConditions[] = "severity = ?";
    $whereParams[] = $filterSeverity;
}
if (!empty($filterStatus)) {
    $whereConditions[] = "status = ?";
    $whereParams[] = (int) $filterStatus;
}
if (!empty($filterSearch)) {
    $whereConditions[] = "(pattern LIKE ? OR description LIKE ?)";
    $whereParams[] = '%' . $filterSearch . '%';
    $whereParams[] = '%' . $filterSearch . '%';
}

$whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';

try {
    $sql = rex_sql::factory();
    $query = "SELECT * FROM " . rex::getTable('upkeep_mail_badwords') . " {$whereClause} ORDER BY severity DESC, category, pattern";
    $sql->setQuery($query, $whereParams);
    
    $badwords = [];
    while ($sql->hasNext()) {
        $badwords[] = [
            'id' => (int) $sql->getValue('id'),
            'pattern' => $sql->getValue('pattern'),
            'severity' => $sql->getValue('severity'),
            'category' => $sql->getValue('category'),
            'is_regex' => (bool) $sql->getValue('is_regex'),
            'status' => (bool) $sql->getValue('status'),
            'description' => $sql->getValue('description'),
            'created_at' => $sql->getValue('created_at'),
            'updated_at' => $sql->getValue('updated_at')
        ];
        $sql->next();
    }
    
    // Kategorien für Filter laden
    $sql->setQuery("SELECT DISTINCT category FROM " . rex::getTable('upkeep_mail_badwords') . " ORDER BY category");
    $categories = [];
    while ($sql->hasNext()) {
        $categories[] = $sql->getValue('category');
        $sql->next();
    }
    
} catch (Exception $e) {
    $badwords = [];
    $categories = [];
    echo rex_view::error('Fehler beim Laden der Badwords: ' . $e->getMessage());
}

// Filter-Panel
$content = '<form method="get" action="' . rex_url::currentBackendPage() . '">';
$content .= '<input type="hidden" name="page" value="upkeep" />';
$content .= '<input type="hidden" name="subpage" value="mail_security" />';
$content .= '<input type="hidden" name="subsubpage" value="badwords" />';

$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-filter"></i> ' . $addon->i18n('upkeep_filter_search') . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-3">';
$content .= '<select name="filter_category" class="form-control">';
$content .= '<option value="">' . $addon->i18n('upkeep_all_categories') . '</option>';
foreach ($categories as $cat) {
    $selected = ($filterCategory === $cat) ? ' selected' : '';
    $content .= '<option value="' . rex_escape($cat) . '"' . $selected . '>' . rex_escape($cat) . '</option>';
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<select name="filter_severity" class="form-control">';
$content .= '<option value="">' . $addon->i18n('upkeep_all_severities') . '</option>';
$severities = [
    'low' => $addon->i18n('upkeep_severity_low'),
    'medium' => $addon->i18n('upkeep_severity_medium'),
    'high' => $addon->i18n('upkeep_severity_high'),
    'critical' => $addon->i18n('upkeep_severity_critical')
];
foreach ($severities as $value => $label) {
    $selected = ($filterSeverity === $value) ? ' selected' : '';
    $content .= '<option value="' . $value . '"' . $selected . '>' . $label . '</option>';
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<select name="filter_status" class="form-control">';
$content .= '<option value="">' . $addon->i18n('upkeep_all_status') . '</option>';
$content .= '<option value="1"' . ($filterStatus === '1' ? ' selected' : '') . '>' . $addon->i18n('upkeep_status_active') . '</option>';
$content .= '<option value="0"' . ($filterStatus === '0' ? ' selected' : '') . '>' . $addon->i18n('upkeep_status_inactive') . '</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-3">';
$content .= '<input type="text" name="filter_search" class="form-control" placeholder="' . $addon->i18n('upkeep_search_pattern_description') . '" value="' . rex_escape($filterSearch) . '" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<button type="submit" class="btn btn-primary">' . $addon->i18n('upkeep_filter') . '</button> ';
$content .= '<a href="' . rex_url::currentBackendPage() . '" class="btn btn-default">' . $addon->i18n('upkeep_reset') . '</a>';
$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Badword hinzufügen/bearbeiten Panel
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
if ($editBadword) {
    $content .= '<input type="hidden" name="edit-badword" value="1" />';
    $content .= '<input type="hidden" name="id" value="' . $editBadword['id'] . '" />';
} else {
    $content .= '<input type="hidden" name="add-badword" value="1" />';
}

$content .= '<div class="panel panel-success">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa ' . ($editBadword ? 'fa-edit' : 'fa-plus') . '"></i> ' . ($editBadword ? $addon->i18n('upkeep_mail_security_edit_badword') : $addon->i18n('upkeep_mail_security_add_badword')) . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-4">';
$content .= '<label>' . $addon->i18n('upkeep_pattern') . ' *</label>';
$content .= '<input type="text" class="form-control" name="badword_pattern" value="' . ($editBadword ? htmlspecialchars($editBadword['pattern']) : '') . '" placeholder="' . $addon->i18n('upkeep_pattern_example') . '" required />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_severity') . '</label>';
$content .= '<select class="form-control" name="badword_severity">';
$currentSeverity = $editBadword ? $editBadword['severity'] : 'medium';
$content .= '<option value="low"' . ($currentSeverity === 'low' ? ' selected' : '') . '>' . $addon->i18n('upkeep_severity_low') . '</option>';
$content .= '<option value="medium"' . ($currentSeverity === 'medium' ? ' selected' : '') . '>' . $addon->i18n('upkeep_severity_medium') . '</option>';
$content .= '<option value="high"' . ($currentSeverity === 'high' ? ' selected' : '') . '>' . $addon->i18n('upkeep_severity_high') . '</option>';
$content .= '<option value="critical"' . ($currentSeverity === 'critical' ? ' selected' : '') . '>' . $addon->i18n('upkeep_severity_critical') . '</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_category') . '</label>';
$content .= '<select class="form-control" name="badword_category">';
$currentCategory = $editBadword ? $editBadword['category'] : 'general';
$content .= '<option value="general"' . ($currentCategory === 'general' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_general') . '</option>';
$content .= '<option value="profanity"' . ($currentCategory === 'profanity' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_profanity') . '</option>';
$content .= '<option value="pharmaceutical"' . ($currentCategory === 'pharmaceutical' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_pharmaceutical') . '</option>';
$content .= '<option value="financial_fraud"' . ($currentCategory === 'financial_fraud' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_financial_fraud') . '</option>';
$content .= '<option value="security"' . ($currentCategory === 'security' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_security') . '</option>';
$content .= '<option value="spam"' . ($currentCategory === 'spam' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_spam') . '</option>';
$content .= '<option value="phishing"' . ($currentCategory === 'phishing' ? ' selected' : '') . '>' . $addon->i18n('upkeep_category_phishing') . '</option>';
foreach ($categories as $cat) {
    if (!in_array($cat, ['general', 'profanity', 'pharmaceutical', 'financial_fraud', 'security', 'spam', 'phishing'])) {
        $content .= '<option value="' . rex_escape($cat) . '"' . ($currentCategory === $cat ? ' selected' : '') . '>' . rex_escape($cat) . '</option>';
    }
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<label class="checkbox-inline">';
$isRegexChecked = isset($editBadword) && $editBadword['is_regex'] ? ' checked' : '';
$content .= '<input type="checkbox" name="badword_is_regex" value="1"' . $isRegexChecked . ' /> ' . $addon->i18n('upkeep_regex');
$content .= '</label>';

if ($editBadword) {
    $content .= '<br><br>';
    $content .= '<label class="checkbox-inline">';
    $statusChecked = isset($editBadword) && $editBadword['status'] ? ' checked' : '';
    $content .= '<input type="checkbox" name="badword_status" value="1"' . $statusChecked . ' /> ' . $addon->i18n('upkeep_status_active');
    $content .= '</label>';
}
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>&nbsp;</label><br>';
if ($editBadword) {
    $content .= '<button type="submit" class="btn btn-success">' . $addon->i18n('upkeep_update') . '</button> ';
    $content .= '<a href="' . rex_url::currentBackendPage() . '" class="btn btn-default">' . $addon->i18n('upkeep_cancel') . '</a>';
} else {
    $content .= '<button type="submit" class="btn btn-success">' . $addon->i18n('upkeep_add') . '</button>';
}
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="row" style="margin-top: 15px;">';
$content .= '<div class="col-md-12">';
$content .= '<label>' . $addon->i18n('upkeep_description') . '</label>';
$content .= '<input type="text" class="form-control" name="badword_description" value="' . ($editBadword ? htmlspecialchars($editBadword['description']) : '') . '" placeholder="' . $addon->i18n('upkeep_badword_description_placeholder') . '" />';
$content .= '</div>';
$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Import-Panel
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="import-badwords" value="1" />';

$content .= '<div class="panel panel-info">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-upload"></i> ' . $addon->i18n('upkeep_mail_security_import_badwords') . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-8">';
$content .= '<label>' . $addon->i18n('upkeep_import_data_label') . '</label>';
$content .= '<textarea class="form-control" name="import_data" rows="6" placeholder="' . $addon->i18n('upkeep_import_placeholder') . '&#10;' . $addon->i18n('upkeep_import_with_details') . '&#10;' . $addon->i18n('upkeep_import_format') . '"></textarea>';
$content .= '<small class="help-block">' . $addon->i18n('upkeep_import_help') . '</small>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_default_severity') . '</label>';
$content .= '<select class="form-control" name="import_severity">';
$content .= '<option value="low">' . $addon->i18n('upkeep_severity_low') . '</option>';
$content .= '<option value="medium" selected>' . $addon->i18n('upkeep_severity_medium') . '</option>';
$content .= '<option value="high">' . $addon->i18n('upkeep_severity_high') . '</option>';
$content .= '<option value="critical">' . $addon->i18n('upkeep_severity_critical') . '</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_default_category') . '</label>';
$content .= '<input type="text" class="form-control" name="import_category" value="imported" />';
$content .= '<br>';
$content .= '<button type="submit" class="btn btn-info">' . $addon->i18n('upkeep_import') . '</button>';
$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Badwords-Liste
if (!empty($badwords)) {
    $content = '<form action="' . rex_url::currentBackendPage() . '" method="post" id="badwords-form">';
    
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading">';
    $content .= '<h3 class="panel-title"><i class="fa fa-list"></i> ' . $addon->i18n('upkeep_badwords') . ' (' . count($badwords) . ' ' . $addon->i18n('upkeep_found') . ')</h3>';
    $content .= '</div>';
    
    $content .= '<div class="panel-body">';
    
    // Bulk-Aktionen
    $content .= '<div class="row" style="margin-bottom: 15px;">';
    $content .= '<div class="col-md-6">';
    $content .= '<div class="input-group">';
    $content .= '<select name="bulk-action" class="form-control">';
    $content .= '<option value="">' . $addon->i18n('upkeep_bulk_action_select') . '</option>';
    $content .= '<option value="activate">' . $addon->i18n('upkeep_bulk_activate_all') . '</option>';
    $content .= '<option value="deactivate">' . $addon->i18n('upkeep_bulk_deactivate_all') . '</option>';
    $content .= '<option value="delete">' . $addon->i18n('upkeep_bulk_delete_all') . '</option>';
    $content .= '</select>';
    $content .= '<span class="input-group-btn">';
    $content .= '<button type="submit" class="btn btn-default" onclick="return confirm(\'' . $addon->i18n('upkeep_bulk_confirm') . '\')">' . $addon->i18n('upkeep_execute') . '</button>';
    $content .= '</span>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '<div class="col-md-6 text-right">';
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#badwords-form input[type=checkbox]\').prop(\'checked\', true)">' . $addon->i18n('upkeep_select_all') . '</button> ';
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#badwords-form input[type=checkbox]\').prop(\'checked\', false)">' . $addon->i18n('upkeep_deselect_all') . '</button>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr>';
    $content .= '<th width="30"><input type="checkbox" id="select-all" /></th>';
    $content .= '<th>' . $addon->i18n('upkeep_pattern') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_category') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_severity') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_type') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_status') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_description') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_created') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_actions') . '</th>';
    $content .= '</tr>';
    $content .= '</thead>';
    $content .= '<tbody>';
    
    foreach ($badwords as $badword) {
        $severityClass = match($badword['severity']) {
            'critical' => 'danger',
            'high' => 'warning',
            'medium' => 'info',
            default => 'default'
        };
        
        $statusClass = $badword['status'] ? 'success' : 'default';
        $statusText = $badword['status'] ? $addon->i18n('upkeep_status_active') : $addon->i18n('upkeep_status_inactive');
        
        $content .= '<tr' . (!$badword['status'] ? ' class="text-muted"' : '') . '>';
        $content .= '<td><input type="checkbox" name="selected-badwords[]" value="' . $badword['id'] . '" /></td>';
        $content .= '<td><code>' . rex_escape($badword['pattern']) . '</code></td>';
        $content .= '<td><span class="label label-default">' . rex_escape($badword['category']) . '</span></td>';
        $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($badword['severity']) . '</span></td>';
        $content .= '<td>' . ($badword['is_regex'] ? '<span class="label label-primary">' . $addon->i18n('upkeep_type_regex') . '</span>' : '<span class="label label-default">' . $addon->i18n('upkeep_type_text') . '</span>') . '</td>';
        $content .= '<td><span class="label label-' . $statusClass . '">' . $statusText . '</span></td>';
        $content .= '<td>' . rex_escape(substr($badword['description'] ?? '', 0, 50)) . (strlen($badword['description'] ?? '') > 50 ? '...' : '') . '</td>';
        $content .= '<td>' . rex_formatter::strftime(strtotime($badword['created_at']), 'date') . '</td>';
        $content .= '<td>';
        
        // Bearbeiten-Button
        $content .= '<a href="' . rex_url::currentBackendPage(['action' => 'edit', 'id' => $badword['id']]) . '" class="btn btn-xs btn-success" title="' . $addon->i18n('upkeep_edit') . '">';
        $content .= '<i class="fa fa-edit"></i>';
        $content .= '</a> ';
        
        // Status-Toggle
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="toggle-badword" value="' . $badword['id'] . '" />';
        $content .= '<input type="hidden" name="current-status" value="' . ($badword['status'] ? 1 : 0) . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-' . ($badword['status'] ? 'warning' : 'success') . '" title="' . ($badword['status'] ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '">';
        $content .= '<i class="fa fa-' . ($badword['status'] ? 'pause' : 'play') . '"></i>';
        $content .= '</button>';
        $content .= '</form> ';
        
        // Löschen
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="remove-badword" value="' . $badword['id'] . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-danger" onclick="return confirm(\'' . $addon->i18n('upkeep_delete_badword_confirm') . '\')" title="' . $addon->i18n('upkeep_delete') . '">';
        $content .= '<i class="fa fa-trash"></i>';
        $content .= '</button>';
        $content .= '</form>';
        
        $content .= '</td>';
        $content .= '</tr>';
    }
    
    $content .= '</tbody>';
    $content .= '</table>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</form>';
    
    // JavaScript für Select All
    $content .= '<script>
    jQuery(document).ready(function($) {
        $("#select-all").change(function() {
            $("#badwords-form input[type=checkbox]").prop("checked", this.checked);
        });
    });
    </script>';
    
} else {
    $content = '<div class="alert alert-info">';
    $content .= '<h4>' . $addon->i18n('upkeep_no_badwords_found') . '</h4>';
    $content .= '<p>' . $addon->i18n('upkeep_no_badwords_configured') . '</p>';
    $content .= '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');