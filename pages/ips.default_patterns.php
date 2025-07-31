<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Prüfen ob IPS-Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery("SHOW TABLES LIKE ?", [rex::getTable('upkeep_ips_default_patterns')]);
    $tableExists = $sql->getRows() > 0;
} catch (Exception $e) {
    $tableExists = false;
}

if (!$tableExists) {
    echo '<div class="alert alert-warning">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_ips_table_missing') . '</h4>';
    echo '<p>' . $addon->i18n('upkeep_ips_table_missing_text') . '</p>';
    echo '<p>' . $addon->i18n('upkeep_ips_reinstall_required') . '</p>';
    echo '</div>';
    return;
}

// Pattern-Status umschalten
if (rex_get('action') === 'toggle' && rex_get('id', 'int')) {
    if (IntrusionPrevention::toggleDefaultPatternStatus(rex_get('id', 'int'))) {
        echo rex_view::success($addon->i18n('upkeep_ips_pattern_status_changed'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_pattern_status_error'));
    }
}

// Pattern bearbeiten
if (rex_post('edit_pattern', 'bool')) {
    $id = rex_post('id', 'int');
    $pattern = rex_post('pattern', 'string');
    $description = rex_post('description', 'string');
    $severity = rex_post('severity', 'string', 'medium');
    $isRegex = rex_post('is_regex', 'bool');
    $status = rex_post('status', 'bool', true);
    
    if (!empty($pattern) && $id > 0) {
        if (IntrusionPrevention::updateDefaultPattern($id, $pattern, $description, $severity, $isRegex, $status)) {
            echo rex_view::success($addon->i18n('upkeep_ips_pattern_updated'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_ips_pattern_update_error'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_pattern_empty'));
    }
}

// Bestehende Standard-Patterns laden
$sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_default_patterns') . " ORDER BY category, pattern");

// Prüfen ob Pattern bearbeitet werden soll
$editPattern = null;
if (rex_get('action') === 'edit' && rex_get('id', 'int')) {
    $editPatternId = rex_get('id', 'int');
    $editSql = rex_sql::factory();
    $editSql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_default_patterns') . " WHERE id = ?", [$editPatternId]);
    if ($editSql->getRows() > 0) {
        $editPattern = [
            'id' => $editSql->getValue('id'),
            'category' => $editSql->getValue('category'),
            'pattern' => $editSql->getValue('pattern'),
            'description' => $editSql->getValue('description'),
            'severity' => $editSql->getValue('severity'),
            'is_regex' => (bool) $editSql->getValue('is_regex'),
            'status' => (bool) $editSql->getValue('status'),
            'is_default' => (bool) $editSql->getValue('is_default')
        ];
    }
}

// Bearbeitungsformular (nur wenn Pattern bearbeitet wird)
if ($editPattern) {
    echo '<div class="panel panel-default">';
    echo '<div class="panel-heading">';
    echo '<i class="fa fa-edit"></i> ' . $addon->i18n('upkeep_ips_edit_default_pattern');
    echo '</div>';
    echo '<div class="panel-body">';

    $form = '<form method="post">';
    $form .= '<input type="hidden" name="edit_pattern" value="1">';
    $form .= '<input type="hidden" name="id" value="' . $editPattern['id'] . '">';
    $form .= '<div class="row">';

    $form .= '<div class="col-md-3">';
    $form .= '<div class="form-group">';
    $form .= '<label for="category">' . $addon->i18n('upkeep_ips_category') . '</label>';
    $form .= '<input type="text" class="form-control" id="category" name="category" value="' . rex_escape($editPattern['category']) . '" readonly>';
    $form .= '<small class="help-block text-muted">' . $addon->i18n('upkeep_ips_category_readonly') . '</small>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-3">';
    $form .= '<div class="form-group">';
    $form .= '<label for="pattern">' . $addon->i18n('upkeep_ips_pattern') . ' ';
    $form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_pattern_tooltip') . '" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '<input type="text" class="form-control" id="pattern" name="pattern" value="' . rex_escape($editPattern['pattern']) . '" required>';
    $form .= '<small class="help-block">' . $addon->i18n('upkeep_ips_pattern_help') . '</small>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-3">';
    $form .= '<div class="form-group">';
    $form .= '<label for="description">' . $addon->i18n('upkeep_ips_description') . ' ';
    $form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_description_tooltip') . '" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '<input type="text" class="form-control" id="description" name="description" value="' . rex_escape($editPattern['description']) . '">';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-2">';
    $form .= '<div class="form-group">';
    $form .= '<label for="severity">' . $addon->i18n('upkeep_ips_severity') . ' ';
    $form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_severity_tooltip') . '" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '<select class="form-control selectpicker" id="severity" name="severity" data-style="btn-default">';
    $currentSeverity = $editPattern['severity'];
    $form .= '<option value="low"' . ($currentSeverity === 'low' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_low_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_low') . ' (Log only)</option>';
    $form .= '<option value="medium"' . ($currentSeverity === 'medium' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_medium_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_medium') . ' (15min)</option>';
    $form .= '<option value="high"' . ($currentSeverity === 'high' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_high_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_high') . ' (1h)</option>';
    $form .= '<option value="critical"' . ($currentSeverity === 'critical' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_critical_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_critical') . ' (Permanent)</option>';
    $form .= '</select>';
    $form .= '<small class="help-block text-muted">' . $addon->i18n('upkeep_ips_severity_help') . '</small>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-1">';
    $form .= '<div class="form-group">';
    $form .= '<label>&nbsp;</label><br>';
    $form .= '<div class="checkbox">';
    $isRegexChecked = $editPattern['is_regex'] ? ' checked' : '';
    $form .= '<label>';
    $form .= '<input type="checkbox" name="is_regex" value="1"' . $isRegexChecked . '> ' . $addon->i18n('upkeep_ips_is_regex') . ' ';
    $form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_is_regex_tooltip') . '" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '</div>';
    $form .= '<div class="checkbox">';
    $statusChecked = $editPattern['status'] ? ' checked' : '';
    $form .= '<label>';
    $form .= '<input type="checkbox" name="status" value="1"' . $statusChecked . '> ' . $addon->i18n('upkeep_active') . ' ';
    $form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_pattern_status_tooltip') . '" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '</div>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '</div>';

    $form .= '<div class="form-group">';
    $form .= '<button type="submit" class="btn btn-success" title="' . $addon->i18n('upkeep_update') . '">';
    $form .= '<i class="fa fa-save"></i> ' . $addon->i18n('upkeep_update');
    $form .= '</button>';
    $form .= ' <a href="' . rex_url::currentBackendPage() . '" class="btn btn-default" title="' . $addon->i18n('upkeep_cancel') . '">';
    $form .= '<i class="fa fa-times"></i> ' . $addon->i18n('upkeep_cancel');
    $form .= '</a>';
    $form .= '</div>';

    $form .= '</form>';

    echo $form;
    echo '</div>';
    echo '</div>';
}

// Standard-Patterns anzeigen
echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-list"></i> ' . $addon->i18n('upkeep_ips_default_patterns');
if (!$editPattern) {
    echo ' <small class="text-muted">(' . $addon->i18n('upkeep_ips_default_patterns_info') . ')</small>';
}
echo '</div>';

if ($sql->getRows() > 0) {
    echo '<div class="table-responsive">';
    echo '<table class="table table-striped table-hover">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . $addon->i18n('upkeep_ips_category') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_pattern') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_description') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_severity') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_type') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_status') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_default') . '</th>';
    echo '<th class="text-center">' . $addon->i18n('upkeep_actions') . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';

    $currentCategory = '';
    while ($sql->hasNext()) {
        $id = $sql->getValue('id');
        $category = $sql->getValue('category');
        $pattern = $sql->getValue('pattern');
        $description = $sql->getValue('description');
        $severity = $sql->getValue('severity');
        $isRegex = (bool) $sql->getValue('is_regex');
        $status = (bool) $sql->getValue('status');
        $isDefault = (bool) $sql->getValue('is_default');
        $createdAt = $sql->getValue('created_at');

        // Kategorie-Gruppierung
        if ($category !== $currentCategory) {
            echo '<tr class="info">';
            echo '<td colspan="8"><strong>' . rex_escape($category) . '</strong></td>';
            echo '</tr>';
            $currentCategory = $category;
        }

        echo '<tr>';
        echo '<td><small class="text-muted">' . rex_escape($category) . '</small></td>';
        echo '<td><span class="text-monospace text-primary">' . rex_escape($pattern) . '</span></td>';
        echo '<td>' . rex_escape($description ?: '-') . '</td>';
        echo '<td>';
        
        // Severity-Badge
        $severityClass = match($severity) {
            'low' => 'label-default',
            'medium' => 'label-warning',
            'high' => 'label-danger',
            'critical' => 'label-danger'
        };
        echo '<span class="label ' . $severityClass . '">' . $addon->i18n('upkeep_ips_severity_' . $severity) . '</span>';
        echo '</td>';
        echo '<td>';
        echo $isRegex ? '<span class="label label-info">RegEx</span>' : '<span class="label label-default">String</span>';
        echo '</td>';
        echo '<td>';
        echo $status ? '<span class="label label-success">' . $addon->i18n('upkeep_active') . '</span>' : '<span class="label label-danger">' . $addon->i18n('upkeep_inactive') . '</span>';
        echo '</td>';
        echo '<td>';
        echo $isDefault ? '<span class="label label-primary">' . $addon->i18n('upkeep_yes') . '</span>' : '<span class="label label-default">' . $addon->i18n('upkeep_no') . '</span>';
        echo '</td>';
        echo '<td class="text-center">';
        
        // Bearbeiten-Button
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'edit', 'id' => $id]) . '" class="btn btn-xs btn-primary" title="' . $addon->i18n('upkeep_edit') . '">';
        echo '<i class="fa fa-pencil"></i>';
        echo '</a> ';
        
        // Status Toggle-Button
        $toggleTitle = $status ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate');
        $toggleIcon = $status ? 'fa-toggle-on' : 'fa-toggle-off';
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'toggle', 'id' => $id]) . '" class="btn btn-xs btn-default" title="' . $toggleTitle . '">';
        echo '<i class="fa ' . $toggleIcon . '"></i>';
        echo '</a>';
        
        echo '</td>';
        echo '</tr>';

        $sql->next();
    }

    echo '</tbody>';
    echo '</table>';
    echo '</div>';
} else {
    echo '<div class="panel-body">';
    echo '<p class="text-muted">' . $addon->i18n('upkeep_ips_no_default_patterns') . '</p>';
    echo '</div>';
}

echo '</div>';

// Hinweise und Dokumentation
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> ' . $addon->i18n('upkeep_ips_default_patterns_help');
echo '</div>';
echo '<div class="panel-body">';

echo '<div class="alert alert-info">';
echo '<h5><i class="fa fa-lightbulb-o"></i> ' . $addon->i18n('upkeep_ips_what_are_default_patterns') . '</h5>';
echo '<p>' . $addon->i18n('upkeep_ips_default_patterns_explanation') . '</p>';
echo '</div>';

echo '<h4>' . $addon->i18n('upkeep_ips_pattern_categories') . '</h4>';
echo '<ul>';
echo '<li><strong>immediate_block</strong> - ' . $addon->i18n('upkeep_ips_category_immediate_block') . '</li>';
echo '<li><strong>wordpress/typo3/drupal/joomla</strong> - ' . $addon->i18n('upkeep_ips_category_cms') . '</li>';
echo '<li><strong>admin_panels</strong> - ' . $addon->i18n('upkeep_ips_category_admin_panels') . '</li>';
echo '<li><strong>config_files</strong> - ' . $addon->i18n('upkeep_ips_category_config_files') . '</li>';
echo '<li><strong>shells</strong> - ' . $addon->i18n('upkeep_ips_category_shells') . '</li>';
echo '<li><strong>sql_injection</strong> - ' . $addon->i18n('upkeep_ips_category_sql_injection') . '</li>';
echo '</ul>';

echo '<div class="alert alert-warning">';
echo '<h5><i class="fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_ips_editing_warning') . '</h5>';
echo '<ul class="mb-0">';
echo '<li>' . $addon->i18n('upkeep_ips_editing_warning_1') . '</li>';
echo '<li>' . $addon->i18n('upkeep_ips_editing_warning_2') . '</li>';
echo '<li>' . $addon->i18n('upkeep_ips_editing_warning_3') . '</li>';
echo '</ul>';
echo '</div>';

echo '</div>';
echo '</div>';

// JavaScript für Tooltips
echo '<script>
$(document).ready(function() {
    $("[data-toggle=\"tooltip\"]").tooltip();
});
</script>';
