<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Prüfen ob IPS-Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery("SHOW TABLES LIKE ?", [rex::getTable('upkeep_ips_custom_patterns')]);
    $tableExists = $sql->getRows() > 0;
} catch (Exception $e) {
    $tableExists = false;
}

if (!$tableExists) {
    echo '<div class="alert alert-warning">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> IPS-Datenbanktabellen fehlen</h4>';
    echo '<p>Die Intrusion Prevention System Tabellen wurden noch nicht erstellt.</p>';
    echo '<p>Bitte installieren Sie das Upkeep AddOn erneut über das Backend: <strong>AddOns → Upkeep → Reinstall</strong></p>';
    echo '</div>';
    return;
}

// Pattern hinzufügen
if (rex_post('add_pattern', 'bool')) {
    $pattern = rex_post('pattern', 'string');
    $description = rex_post('description', 'string');
    $severity = rex_post('severity', 'string', 'medium');
    $isRegex = rex_post('is_regex', 'bool');
    
    if (!empty($pattern)) {
        if (IntrusionPrevention::addCustomPattern($pattern, $description, $severity, $isRegex)) {
            echo rex_view::success($addon->i18n('upkeep_ips_pattern_added'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_ips_pattern_add_error'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_pattern_empty'));
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
        if (IntrusionPrevention::updateCustomPattern($id, $pattern, $description, $severity, $isRegex, $status)) {
            echo rex_view::success($addon->i18n('upkeep_ips_pattern_updated'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_ips_pattern_update_error'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_pattern_empty'));
    }
}

// Pattern Status umschalten
if (rex_get('action') === 'toggle' && rex_get('id', 'int')) {
    if (IntrusionPrevention::toggleCustomPatternStatus(rex_get('id', 'int'))) {
        echo rex_view::success($addon->i18n('upkeep_ips_pattern_status_changed'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_pattern_status_error'));
    }
}

// Pattern löschen
if (rex_get('action') === 'delete' && rex_get('id', 'int')) {
    if (IntrusionPrevention::removeCustomPattern(rex_get('id', 'int'))) {
        echo rex_view::success($addon->i18n('upkeep_ips_pattern_deleted'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_pattern_delete_error'));
    }
}

// Bestehende Patterns laden
$sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_custom_patterns') . " ORDER BY created_at DESC");

// Prüfen ob Pattern bearbeitet werden soll
$editPattern = null;
if (rex_get('action') === 'edit' && rex_get('id', 'int')) {
    $editPattern = IntrusionPrevention::getCustomPattern(rex_get('id', 'int'));
}

// Formular für neues Pattern
echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
if ($editPattern) {
    echo '<i class="fa fa-edit"></i> ' . $addon->i18n('upkeep_ips_edit_pattern');
} else {
    echo '<i class="fa fa-plus"></i> ' . $addon->i18n('upkeep_ips_add_pattern');
}
echo '</div>';
echo '<div class="panel-body">';

$form = '<form method="post">';
if ($editPattern) {
    $form .= '<input type="hidden" name="edit_pattern" value="1">';
    $form .= '<input type="hidden" name="id" value="' . $editPattern['id'] . '">';
} else {
    $form .= '<input type="hidden" name="add_pattern" value="1">';
}
$form .= '<div class="row">';

$form .= '<div class="col-md-4">';
$form .= '<div class="form-group">';
$form .= '<label for="pattern">' . $addon->i18n('upkeep_ips_pattern') . ' ';
$form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_pattern_tooltip') . '" data-toggle="tooltip"></i>';
$form .= '</label>';
$form .= '<input type="text" class="form-control" id="pattern" name="pattern" value="' . rex_escape($editPattern['pattern'] ?? '') . '" required>';
$form .= '<small class="help-block">' . $addon->i18n('upkeep_ips_pattern_help') . '</small>';
$form .= '</div>';
$form .= '</div>';

$form .= '<div class="col-md-3">';
$form .= '<div class="form-group">';
$form .= '<label for="description">' . $addon->i18n('upkeep_ips_description') . ' ';
$form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_description_tooltip') . '" data-toggle="tooltip"></i>';
$form .= '</label>';
$form .= '<input type="text" class="form-control" id="description" name="description" value="' . rex_escape($editPattern['description'] ?? '') . '">';
$form .= '</div>';
$form .= '</div>';

$form .= '<div class="col-md-2">';
$form .= '<div class="form-group">';
$form .= '<label for="severity">' . $addon->i18n('upkeep_ips_severity') . ' ';
$form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_severity_tooltip') . '" data-toggle="tooltip"></i>';
$form .= '</label>';
$form .= '<select class="form-control selectpicker" id="severity" name="severity" data-style="btn-default">';
$currentSeverity = $editPattern['severity'] ?? 'medium';
$form .= '<option value="low"' . ($currentSeverity === 'low' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_low_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_low') . ' (Log only)</option>';
$form .= '<option value="medium"' . ($currentSeverity === 'medium' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_medium_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_medium') . ' (15min)</option>';
$form .= '<option value="high"' . ($currentSeverity === 'high' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_high_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_high') . ' (1h)</option>';
$form .= '<option value="critical"' . ($currentSeverity === 'critical' ? ' selected' : '') . ' title="' . $addon->i18n('upkeep_ips_severity_critical_tooltip') . '">' . $addon->i18n('upkeep_ips_severity_critical') . ' (Permanent)</option>';
$form .= '</select>';
$form .= '<small class="help-block text-muted">' . $addon->i18n('upkeep_ips_severity_help') . '</small>';
$form .= '</div>';
$form .= '</div>';

$form .= '<div class="col-md-2">';
$form .= '<div class="form-group">';
$form .= '<label>&nbsp;</label><br>';
$form .= '<div class="checkbox">';
$isRegexChecked = isset($editPattern) && $editPattern['is_regex'] ? ' checked' : '';
$form .= '<label>';
$form .= '<input type="checkbox" name="is_regex" value="1"' . $isRegexChecked . '> ' . $addon->i18n('upkeep_ips_is_regex') . ' ';
$form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_is_regex_tooltip') . '" data-toggle="tooltip"></i>';
$form .= '</label>';
$form .= '</div>';
if ($editPattern) {
    $form .= '<div class="checkbox">';
    $statusChecked = isset($editPattern) && $editPattern['status'] ? ' checked' : '';
    $form .= '<label>';
    $form .= '<input type="checkbox" name="status" value="1"' . $statusChecked . '> ' . $addon->i18n('upkeep_active') . ' ';
    $form .= '<i class="fa fa-question-circle text-info" title="' . $addon->i18n('upkeep_ips_pattern_status_tooltip') . '" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '</div>';
}
$form .= '</div>';
$form .= '</div>';

$form .= '<div class="col-md-1">';
$form .= '<div class="form-group">';
$form .= '<label>&nbsp;</label><br>';
if ($editPattern) {
    $form .= '<button type="submit" class="btn btn-success" title="' . $addon->i18n('upkeep_update') . '">';
    $form .= '<i class="fa fa-save"></i>';
    $form .= '</button>';
    $form .= ' <a href="' . rex_url::currentBackendPage() . '" class="btn btn-default" title="' . $addon->i18n('upkeep_cancel') . '">';
    $form .= '<i class="fa fa-times"></i>';
    $form .= '</a>';
} else {
    $form .= '<button type="submit" class="btn btn-primary" title="' . $addon->i18n('upkeep_add') . '">';
    $form .= '<i class="fa fa-plus"></i>';
    $form .= '</button>';
}
$form .= '</div>';
$form .= '</div>';

$form .= '</div>';
$form .= '</form>';

echo $form;
echo '</div>';
echo '</div>';

// Bestehende Patterns
echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-list"></i> ' . $addon->i18n('upkeep_ips_custom_patterns');
echo '</div>';

if ($sql->getRows() > 0) {
    echo '<div class="table-responsive">';
    echo '<table class="table table-striped table-hover">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . $addon->i18n('upkeep_ips_pattern') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_description') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_severity') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_type') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_status') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_created') . '</th>';
    echo '<th class="text-center">' . $addon->i18n('upkeep_actions') . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';
    
    while ($sql->hasNext()) {
        $id = $sql->getValue('id');
        $pattern = $sql->getValue('pattern');
        $description = $sql->getValue('description');
        $severity = $sql->getValue('severity');
        $isRegex = $sql->getValue('is_regex');
        $status = $sql->getValue('status');
        $createdAt = $sql->getValue('created_at');
        
        echo '<tr>';
        echo '<td><span class="text-monospace" style="background:#f8f9fa; padding:2px 4px; border-radius:3px;">' . rex_escape($pattern) . '</span></td>';
        echo '<td>' . rex_escape($description) . '</td>';
        echo '<td>';
        $severityClass = match($severity) {
            'critical' => 'label-danger',
            'high' => 'label-warning',
            'medium' => 'label-info',
            'low' => 'label-default',
            default => 'label-default'
        };
        echo '<span class="label ' . $severityClass . '">' . $addon->i18n('upkeep_ips_severity_' . $severity) . '</span>';
        echo '</td>';
        echo '<td>';
        echo $isRegex ? '<span class="label label-info">RegEx</span>' : '<span class="label label-default">String</span>';
        echo '</td>';
        echo '<td>';
        echo $status ? '<span class="label label-success">' . $addon->i18n('upkeep_active') . '</span>' : '<span class="label label-danger">' . $addon->i18n('upkeep_inactive') . '</span>';
        echo '</td>';
        echo '<td>' . date('d.m.Y H:i', strtotime($createdAt)) . '</td>';
        echo '<td class="text-center">';
        
        // Bearbeiten-Button
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'edit', 'id' => $id]) . '" class="btn btn-xs btn-success" title="' . $addon->i18n('upkeep_edit') . '">';
        echo '<i class="fa fa-edit"></i>';
        echo '</a> ';
        
        // Status umschalten
        $toggleTitle = $status ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate');
        $toggleIcon = $status ? 'fa-pause' : 'fa-play';
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'toggle', 'id' => $id]) . '" class="btn btn-xs btn-warning" title="' . $toggleTitle . '">';
        echo '<i class="fa ' . $toggleIcon . '"></i>';
        echo '</a> ';
        
        // Löschen-Button
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'delete', 'id' => $id]) . '" class="btn btn-xs btn-danger" onclick="return confirm(\'' . $addon->i18n('upkeep_ips_delete_confirm') . '\')" title="' . $addon->i18n('upkeep_delete') . '">';
        echo '<i class="fa fa-trash"></i>';
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
    echo '<p class="text-muted">' . $addon->i18n('upkeep_ips_no_patterns') . '</p>';
    echo '</div>';
}

echo '</div>';

// Beispiele und Hilfe
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> ' . $addon->i18n('upkeep_ips_pattern_examples');
echo '</div>';
echo '<div class="panel-body">';

// Schweregrade Erklärung
echo '<div class="alert alert-info">';
echo '<h4><i class="fa fa-shield"></i> Schweregrade und ihre Auswirkungen</h4>';
echo '<div class="row">';
echo '<div class="col-md-3">';
echo '<span class="label label-default">LOW</span><br>';
echo '<small><strong>Nur Protokollierung</strong><br>Keine Sperrung, nur Logging für Analyse</small>';
echo '</div>';
echo '<div class="col-md-3">';
echo '<span class="label label-info">MEDIUM</span><br>';
echo '<small><strong>15 Minuten Sperrung</strong><br>Temporäre Blockierung bei verdächtigen Aktivitäten</small>';
echo '</div>';
echo '<div class="col-md-3">';
echo '<span class="label label-warning">HIGH</span><br>';
echo '<small><strong>1 Stunde Sperrung</strong><br>Längere Blockierung bei Angriffsversuchen</small>';
echo '</div>';
echo '<div class="col-md-3">';
echo '<span class="label label-danger">CRITICAL</span><br>';
echo '<small><strong>Permanente Sperrung</strong><br>Dauerhafte Blockierung bei schweren Bedrohungen</small>';
echo '</div>';
echo '</div>';
echo '</div>';

echo '<h4>' . $addon->i18n('upkeep_ips_string_patterns') . '</h4>';
echo '<ul>';
echo '<li><span class="text-monospace text-primary">/evil.php</span> - Blockiert Zugriffe auf evil.php</li>';
echo '<li><span class="text-monospace text-primary">exploit</span> - Blockiert URLs die "exploit" enthalten</li>';
echo '<li><span class="text-monospace text-primary">../../../</span> - Blockiert Path Traversal Versuche</li>';
echo '</ul>';
echo '<h4>' . $addon->i18n('upkeep_ips_regex_patterns') . '</h4>';
echo '<ul>';
echo '<li><span class="text-monospace text-success">/\.(php|asp|jsp)$/</span> - Blockiert Script-Dateien</li>';
echo '<li><span class="text-monospace text-success">/union\s+select/i</span> - SQL Injection Pattern</li>';
echo '<li><span class="text-monospace text-success">/\b(wget|curl)\b/i</span> - Command Injection Tools</li>';
echo '</ul>';

echo '<div class="alert alert-warning">';
echo '<h5><i class="fa fa-exclamation-triangle"></i> Wichtige Hinweise</h5>';
echo '<ul class="mb-0">';
echo '<li><strong>RegEx-Patterns</strong> beginnen und enden mit Schrägstrichen: <code>/pattern/flags</code></li>';
echo '<li><strong>String-Patterns</strong> sind einfache Textsuchen ohne Schrägstriche</li>';
echo '<li><strong>Test vor Aktivierung</strong> empfohlen - falsche Patterns können legitime Benutzer blockieren</li>';
echo '<li><strong>Schweregrad CRITICAL</strong> sollte nur für eindeutige Angriffe verwendet werden</li>';
echo '</ul>';
echo '</div>';

echo '</div>';
echo '</div>';

// JavaScript für Bootstrap Tooltips
echo '<script>';
echo '$(document).ready(function() {';
echo '    $("[data-toggle=\'tooltip\']").tooltip({';
echo '        placement: "top",';
echo '        html: true,';
echo '        container: "body"';
echo '    });';
echo '});';
echo '</script>';
