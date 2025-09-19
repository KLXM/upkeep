<?php

use KLXM\Upkeep\MailSecurityFilter;

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
            $error = $addon->i18n('upkeep_mail_badwords_regex_invalid');
        } else {
            if (MailSecurityFilter::addBadword($pattern, $severity, $category, $isRegex, $description)) {
                $success = $addon->i18n('upkeep_mail_badwords_add_success');
            } else {
                $error = $addon->i18n('upkeep_mail_badwords_add_error');
            }
        }
    } else {
        $error = $addon->i18n('upkeep_mail_badwords_pattern_empty');
    }
}

// Badword entfernen
if (rex_post('remove-badword', 'int') > 0) {
    $badwordId = rex_post('remove-badword', 'int');
    if (MailSecurityFilter::removeBadword($badwordId)) {
        $success = $addon->i18n('upkeep_mail_badwords_remove_success');
    } else {
        $error = $addon->i18n('upkeep_mail_badwords_remove_error');
    }
}

// Badword-Status ändern
if (rex_post('toggle-badword', 'int') > 0) {
    $badwordId = rex_post('toggle-badword', 'int');
    $currentStatus = rex_post('current-status', 'int', 1);
    $newStatus = $currentStatus ? 0 : 1;
    
    try {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_mail_badwords'));
        $sql->setWhere(['id' => $badwordId]);
        $sql->setValue('status', $newStatus);
        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
        $sql->update();
        
        $success = $addon->i18n('upkeep_mail_badwords_status_changed');
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_mail_badwords_status_error', $e->getMessage());
    }
}

// Bulk-Aktionen
if (rex_post('bulk-action', 'string') && rex_post('selected-badwords', 'array')) {
    $action = rex_post('bulk-action', 'string');
    $selectedIds = rex_post('selected-badwords', 'array');
    $affectedCount = 0;
    
    try {
        $sql = rex_sql::factory();
        
        foreach ($selectedIds as $id) {
            $id = (int) $id;
            if ($id > 0) {
                switch ($action) {
                    case 'delete':
                        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [$id]);
                        $affectedCount++;
                        break;
                    case 'activate':
                        $sql->setTable(rex::getTable('upkeep_mail_badwords'));
                        $sql->setWhere(['id' => $id]);
                        $sql->setValue('status', 1);
                        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                        $sql->update();
                        $affectedCount++;
                        break;
                    case 'deactivate':
                        $sql->setTable(rex::getTable('upkeep_mail_badwords'));
                        $sql->setWhere(['id' => $id]);
                        $sql->setValue('status', 0);
                        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                        $sql->update();
                        $affectedCount++;
                        break;
                }
            }
        }
        
        $actionNames = [
            'delete' => $addon->i18n('upkeep_mail_badwords_bulk_deleted'),
            'activate' => $addon->i18n('upkeep_mail_badwords_bulk_activated'),
            'deactivate' => $addon->i18n('upkeep_mail_badwords_bulk_deactivated')
        ];
        
        $success = $addon->i18n('upkeep_mail_badwords_bulk_success', $affectedCount, ($actionNames[$action] ?? $addon->i18n('upkeep_mail_badwords_bulk_processed')));
        
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_mail_badwords_bulk_error', $e->getMessage());
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
            $success = $addon->i18n('upkeep_mail_badwords_import_success', $imported);
            if ($errors > 0) {
                $success .= ' ' . $addon->i18n('upkeep_mail_badwords_import_errors', $errors);
            }
        } else {
            $errorMsg = $errors > 0 ? $addon->i18n('upkeep_mail_badwords_import_error_count', $errors) : '';
            $error = $addon->i18n('upkeep_mail_badwords_import_no_success', $errorMsg);
        }
    } else {
        $error = $addon->i18n('upkeep_mail_badwords_import_data_empty');
    }
}

// Error/Success Messages
if ($error) {
    echo rex_view::error($error);
}
if ($success) {
    echo rex_view::success($success);
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
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-filter"></i> Filter & Suche</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-3">';
$content .= '<select name="filter_category" class="form-control">';
$content .= '<option value="">Alle Kategorien</option>';
foreach ($categories as $cat) {
    $selected = ($filterCategory === $cat) ? ' selected' : '';
    $content .= '<option value="' . rex_escape($cat) . '"' . $selected . '>' . rex_escape($cat) . '</option>';
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<select name="filter_severity" class="form-control">';
$content .= '<option value="">Alle Schweregrade</option>';
$severities = ['low' => 'Niedrig', 'medium' => 'Mittel', 'high' => 'Hoch', 'critical' => 'Kritisch'];
foreach ($severities as $value => $label) {
    $selected = ($filterSeverity === $value) ? ' selected' : '';
    $content .= '<option value="' . $value . '"' . $selected . '>' . $label . '</option>';
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<select name="filter_status" class="form-control">';
$content .= '<option value="">Alle Status</option>';
$content .= '<option value="1"' . ($filterStatus === '1' ? ' selected' : '') . '>Aktiv</option>';
$content .= '<option value="0"' . ($filterStatus === '0' ? ' selected' : '') . '>Inaktiv</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-3">';
$content .= '<input type="text" name="filter_search" class="form-control" placeholder="Suche in Pattern/Beschreibung" value="' . rex_escape($filterSearch) . '" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<button type="submit" class="btn btn-primary">Filtern</button> ';
$content .= '<a href="' . rex_url::currentBackendPage() . '" class="btn btn-default">Reset</a>';
$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Badword hinzufügen Panel
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="add-badword" value="1" />';

$content .= '<div class="panel panel-success">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-plus"></i> Neues Badword hinzufügen</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-4">';
$content .= '<label>Pattern *</label>';
$content .= '<input type="text" class="form-control" name="badword_pattern" placeholder="z.B. viagra oder /spam.{0,20}mail/i" required />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Schweregrad</label>';
$content .= '<select class="form-control" name="badword_severity">';
$content .= '<option value="low">Niedrig</option>';
$content .= '<option value="medium" selected>Mittel</option>';
$content .= '<option value="high">Hoch</option>';
$content .= '<option value="critical">Kritisch</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Kategorie</label>';
$content .= '<select class="form-control" name="badword_category">';
$content .= '<option value="general">Allgemein</option>';
$content .= '<option value="profanity">Profanity</option>';
$content .= '<option value="pharmaceutical">Pharma</option>';
$content .= '<option value="financial_fraud">Finanzbetrug</option>';
$content .= '<option value="security">Sicherheit</option>';
$content .= '<option value="spam">Spam</option>';
$content .= '<option value="phishing">Phishing</option>';
foreach ($categories as $cat) {
    if (!in_array($cat, ['general', 'profanity', 'pharmaceutical', 'financial_fraud', 'security', 'spam', 'phishing'])) {
        $content .= '<option value="' . rex_escape($cat) . '">' . rex_escape($cat) . '</option>';
    }
}
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<label class="checkbox-inline">';
$content .= '<input type="checkbox" name="badword_is_regex" value="1" /> RegEx';
$content .= '</label>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<button type="submit" class="btn btn-success">Hinzufügen</button>';
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="row" style="margin-top: 15px;">';
$content .= '<div class="col-md-12">';
$content .= '<label>Beschreibung</label>';
$content .= '<input type="text" class="form-control" name="badword_description" placeholder="Optionale Beschreibung des Badwords" />';
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
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-upload"></i> Badwords importieren</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-8">';
$content .= '<label>Import-Daten (ein Pattern pro Zeile)</label>';
$content .= '<textarea class="form-control" name="import_data" rows="6" placeholder="viagra&#10;cialis&#10;spam mail&#10;oder mit Details:&#10;bitcoin scam|critical|financial_fraud|Cryptocurrency fraud"></textarea>';
$content .= '<small class="help-block">Format: <code>pattern</code> oder <code>pattern|severity|category|description</code></small>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Standard-Schweregrad</label>';
$content .= '<select class="form-control" name="import_severity">';
$content .= '<option value="low">Niedrig</option>';
$content .= '<option value="medium" selected>Mittel</option>';
$content .= '<option value="high">Hoch</option>';
$content .= '<option value="critical">Kritisch</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Standard-Kategorie</label>';
$content .= '<input type="text" class="form-control" name="import_category" value="imported" />';
$content .= '<br>';
$content .= '<button type="submit" class="btn btn-info">Importieren</button>';
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
    $content .= '<h3 class="panel-title"><i class="fa fa-list"></i> Badwords (' . count($badwords) . ' gefunden)</h3>';
    $content .= '</div>';
    
    $content .= '<div class="panel-body">';
    
    // Bulk-Aktionen
    $content .= '<div class="row" style="margin-bottom: 15px;">';
    $content .= '<div class="col-md-6">';
    $content .= '<div class="input-group">';
    $content .= '<select name="bulk-action" class="form-control">';
    $content .= '<option value="">Bulk-Aktion wählen...</option>';
    $content .= '<option value="activate">Alle aktivieren</option>';
    $content .= '<option value="deactivate">Alle deaktivieren</option>';
    $content .= '<option value="delete">Alle löschen</option>';
    $content .= '</select>';
    $content .= '<span class="input-group-btn">';
    $content .= '<button type="submit" class="btn btn-default" onclick="return confirm(\'Bulk-Aktion wirklich ausführen?\')">Ausführen</button>';
    $content .= '</span>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '<div class="col-md-6 text-right">';
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#badwords-form input[type=checkbox]\').prop(\'checked\', true)">Alle auswählen</button> ';
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#badwords-form input[type=checkbox]\').prop(\'checked\', false)">Alle abwählen</button>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr>';
    $content .= '<th width="30"><input type="checkbox" id="select-all" /></th>';
    $content .= '<th>Pattern</th>';
    $content .= '<th>Kategorie</th>';
    $content .= '<th>Schweregrad</th>';
    $content .= '<th>Typ</th>';
    $content .= '<th>Status</th>';
    $content .= '<th>Beschreibung</th>';
    $content .= '<th>Erstellt</th>';
    $content .= '<th>Aktionen</th>';
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
        $statusText = $badword['status'] ? 'Aktiv' : 'Inaktiv';
        
        $content .= '<tr' . (!$badword['status'] ? ' class="text-muted"' : '') . '>';
        $content .= '<td><input type="checkbox" name="selected-badwords[]" value="' . $badword['id'] . '" /></td>';
        $content .= '<td><code>' . rex_escape($badword['pattern']) . '</code></td>';
        $content .= '<td><span class="label label-default">' . rex_escape($badword['category']) . '</span></td>';
        $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($badword['severity']) . '</span></td>';
        $content .= '<td>' . ($badword['is_regex'] ? '<span class="label label-primary">RegEx</span>' : '<span class="label label-default">Text</span>') . '</td>';
        $content .= '<td><span class="label label-' . $statusClass . '">' . $statusText . '</span></td>';
        $content .= '<td>' . rex_escape(substr($badword['description'] ?? '', 0, 50)) . (strlen($badword['description'] ?? '') > 50 ? '...' : '') . '</td>';
        $content .= '<td>' . rex_formatter::strftime(strtotime($badword['created_at']), 'date') . '</td>';
        $content .= '<td>';
        
        // Status-Toggle
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="toggle-badword" value="' . $badword['id'] . '" />';
        $content .= '<input type="hidden" name="current-status" value="' . ($badword['status'] ? 1 : 0) . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-' . ($badword['status'] ? 'warning' : 'success') . '" title="' . ($badword['status'] ? 'Deaktivieren' : 'Aktivieren') . '">';
        $content .= '<i class="fa fa-' . ($badword['status'] ? 'pause' : 'play') . '"></i>';
        $content .= '</button>';
        $content .= '</form> ';
        
        // Löschen
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="remove-badword" value="' . $badword['id'] . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-danger" onclick="return confirm(\'Badword wirklich löschen?\')" title="Löschen">';
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
    $content .= '<h4>Keine Badwords gefunden</h4>';
    $content .= '<p>Es wurden noch keine Badwords konfiguriert oder Ihre Filter haben keine Ergebnisse geliefert.</p>';
    $content .= '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');