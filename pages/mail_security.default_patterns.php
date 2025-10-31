<?php

use FriendsOfRedaxo\Upkeep\MailSecurityFilter;

$addon = rex_addon::get('upkeep');

// Prüfen ob Mail Security Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery("SHOW TABLES LIKE ?", [rex::getTable('upkeep_mail_default_patterns')]);
    $tableExists = $sql->getRows() > 0;
} catch (Exception $e) {
    $tableExists = false;
}

if (!$tableExists) {
    echo '<div class="alert alert-warning">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> Mail Security Tabellen fehlen</h4>';
    echo '<p>Die Mail Security Tabellen wurden noch nicht erstellt. Führen Sie eine Neuinstallation des Upkeep AddOns durch.</p>';
    echo '<p>Navigieren Sie zu AddOns > Upkeep > Installieren, um die Tabellen zu erstellen.</p>';
    echo '</div>';
    return;
}

// Pattern-Status umschalten
if (rex_get('action') === 'toggle' && rex_get('id', 'int')) {
    if (MailSecurityFilter::toggleDefaultPatternStatus(rex_get('id', 'int'))) {
        echo rex_view::success('Pattern-Status erfolgreich geändert.');
    } else {
        echo rex_view::error('Fehler beim Ändern des Pattern-Status.');
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
        if (MailSecurityFilter::updateDefaultPattern($id, $pattern, $description, $severity, $isRegex, $status)) {
            echo rex_view::success('Pattern erfolgreich aktualisiert.');
        } else {
            echo rex_view::error('Fehler beim Aktualisieren des Patterns.');
        }
    } else {
        echo rex_view::error('Pattern darf nicht leer sein.');
    }
}

// Bestehende Standard-Patterns laden
$sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_mail_default_patterns') . " ORDER BY category, pattern");

// Prüfen ob Pattern bearbeitet werden soll
$editPattern = null;
if (rex_get('action') === 'edit' && rex_get('id', 'int')) {
    $editPatternId = rex_get('id', 'int');
    $editSql = rex_sql::factory();
    $editSql->setQuery("SELECT * FROM " . rex::getTable('upkeep_mail_default_patterns') . " WHERE id = ?", [$editPatternId]);
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
    echo '<i class="fa fa-edit"></i> Standard-Pattern bearbeiten';
    echo '</div>';
    echo '<div class="panel-body">';

    $form = '<form method="post">';
    $form .= '<input type="hidden" name="edit_pattern" value="1">';
    $form .= '<input type="hidden" name="id" value="' . $editPattern['id'] . '">';
    $form .= '<div class="row">';

    $form .= '<div class="col-md-3">';
    $form .= '<div class="form-group">';
    $form .= '<label for="category">Kategorie</label>';
    $form .= '<input type="text" class="form-control" id="category" name="category" value="' . rex_escape($editPattern['category']) . '" readonly>';
    $form .= '<small class="help-block text-muted">Kategorie kann nicht geändert werden</small>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-3">';
    $form .= '<div class="form-group">';
    $form .= '<label for="pattern">Pattern ';
    $form .= '<i class="fa fa-question-circle text-info" title="Das Pattern, das in E-Mails gesucht werden soll. Bei RegEx-Patterns muss der vollständige Ausdruck angegeben werden." data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '<input type="text" class="form-control" id="pattern" name="pattern" value="' . rex_escape($editPattern['pattern']) . '" required>';
    $form .= '<small class="help-block">RegEx-Patterns müssen mit / beginnen und enden</small>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-3">';
    $form .= '<div class="form-group">';
    $form .= '<label for="description">Beschreibung ';
    $form .= '<i class="fa fa-question-circle text-info" title="Beschreibt, was dieses Pattern erkennt und warum es blockiert wird." data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '<input type="text" class="form-control" id="description" name="description" value="' . rex_escape($editPattern['description']) . '">';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-2">';
    $form .= '<div class="form-group">';
    $form .= '<label for="severity">Schweregrad ';
    $form .= '<i class="fa fa-question-circle text-info" title="Bestimmt die Reaktion auf erkannte Patterns: Low=Log only, Medium=Block, High=Block+Escalate, Critical=Block+IP-Ban" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '<select class="form-control selectpicker" id="severity" name="severity" data-style="btn-default">';
    $currentSeverity = $editPattern['severity'];
    $form .= '<option value="low"' . ($currentSeverity === 'low' ? ' selected' : '') . ' title="Nur Logging, keine Blockierung">Niedrig (Log only)</option>';
    $form .= '<option value="medium"' . ($currentSeverity === 'medium' ? ' selected' : '') . ' title="E-Mail wird blockiert">Mittel (Block)</option>';
    $form .= '<option value="high"' . ($currentSeverity === 'high' ? ' selected' : '') . ' title="E-Mail blockiert + IPS-Eskalation">Hoch (Block+Escalate)</option>';
    $form .= '<option value="critical"' . ($currentSeverity === 'critical' ? ' selected' : '') . ' title="E-Mail blockiert + IP permanent gesperrt">Kritisch (Block+IP-Ban)</option>';
    $form .= '</select>';
    $form .= '<small class="help-block text-muted">Beeinflusst die Blockierungs-Strategie</small>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '<div class="col-md-1">';
    $form .= '<div class="form-group">';
    $form .= '<label>&nbsp;</label><br>';
    $form .= '<div class="checkbox">';
    $isRegexChecked = $editPattern['is_regex'] ? ' checked' : '';
    $form .= '<label>';
    $form .= '<input type="checkbox" name="is_regex" value="1"' . $isRegexChecked . '> RegEx ';
    $form .= '<i class="fa fa-question-circle text-info" title="Aktivieren für reguläre Ausdrücke, deaktivieren für einfache Textsuche" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '</div>';
    $form .= '<div class="checkbox">';
    $statusChecked = $editPattern['status'] ? ' checked' : '';
    $form .= '<label>';
    $form .= '<input type="checkbox" name="status" value="1"' . $statusChecked . '> Aktiv ';
    $form .= '<i class="fa fa-question-circle text-info" title="Deaktivierte Patterns werden nicht mehr geprüft" data-toggle="tooltip"></i>';
    $form .= '</label>';
    $form .= '</div>';
    $form .= '</div>';
    $form .= '</div>';

    $form .= '</div>';

    $form .= '<div class="form-group">';
    $form .= '<button type="submit" class="btn btn-success" title="Änderungen speichern">';
    $form .= '<i class="fa fa-save"></i> Speichern';
    $form .= '</button>';
    $form .= ' <a href="' . rex_url::currentBackendPage() . '" class="btn btn-default" title="Abbrechen">';
    $form .= '<i class="fa fa-times"></i> Abbrechen';
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
echo '<i class="fa fa-list"></i> Mail Security Standard-Patterns';
if (!$editPattern) {
    echo ' <small class="text-muted">(Diese Patterns werden bei der Installation automatisch geladen)</small>';
}
echo '</div>';

if ($sql->getRows() > 0) {
    echo '<div class="table-responsive">';
    echo '<table class="table table-striped table-hover">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>Kategorie</th>';
    echo '<th>Pattern</th>';
    echo '<th>Beschreibung</th>';
    echo '<th>Schweregrad</th>';
    echo '<th>Typ</th>';
    echo '<th>Status</th>';
    echo '<th>Standard</th>';
    echo '<th class="text-center">Aktionen</th>';
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
        echo '<span class="label ' . $severityClass . '">' . ucfirst($severity) . '</span>';
        echo '</td>';
        echo '<td>';
        echo $isRegex ? '<span class="label label-info">RegEx</span>' : '<span class="label label-default">String</span>';
        echo '</td>';
        echo '<td>';
        echo $status ? '<span class="label label-success">Aktiv</span>' : '<span class="label label-danger">Inaktiv</span>';
        echo '</td>';
        echo '<td>';
        echo $isDefault ? '<span class="label label-primary">Ja</span>' : '<span class="label label-default">Nein</span>';
        echo '</td>';
        echo '<td class="text-center">';

        // Bearbeiten-Button
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'edit', 'id' => $id]) . '" class="btn btn-xs btn-primary" title="Bearbeiten">';
        echo '<i class="fa fa-pencil"></i>';
        echo '</a> ';

        // Status Toggle-Button
        $toggleTitle = $status ? 'Deaktivieren' : 'Aktivieren';
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
    echo '<p class="text-muted">Keine Standard-Patterns gefunden. Führen Sie eine Neuinstallation durch.</p>';
    echo '</div>';
}

echo '</div>';

// Hinweise und Dokumentation
echo '<div class="panel panel-info">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-info-circle"></i> Hilfe zu Mail Security Patterns';
echo '</div>';
echo '<div class="panel-body">';

echo '<div class="alert alert-info">';
echo '<h5><i class="fa fa-lightbulb-o"></i> Was sind Standard-Patterns?</h5>';
echo '<p>Standard-Patterns sind vordefinierte Regeln zur Erkennung von schädlichen Inhalten in E-Mails. Sie werden bei der Installation des AddOns automatisch in die Datenbank geladen und können hier angepasst werden.</p>';
echo '</div>';

echo '<h4>Pattern-Kategorien</h4>';
echo '<ul>';
echo '<li><strong>critical_injection</strong> - Kritische Code-Injection (JavaScript, PHP, SQL, Command)</li>';
echo '<li><strong>high_injection</strong> - Hohe Risiko-Injection (Iframe, Object, etc.)</li>';
echo '<li><strong>medium_injection</strong> - Mittlere Risiko-Injection (CSS, Data-URLs)</li>';
echo '<li><strong>high_spam</strong> - Hohes Spam-Risiko (Druckausübung, Versprechen)</li>';
echo '<li><strong>medium_spam</strong> - Mittleres Spam-Risiko (Angebote, Versprechen)</li>';
echo '<li><strong>low_spam</strong> - Niedriges Spam-Risiko (Marketing-Sprache)</li>';
echo '<li><strong>bogus_code</strong> - Obfuscated/verschleierte Code-Injection</li>';
echo '<li><strong>apt_patterns</strong> - Advanced Persistent Threats</li>';
echo '<li><strong>zero_day</strong> - Zero-Day & Emerging Threats</li>';
echo '<li><strong>email_specific</strong> - E-Mail-spezifische Spam-Muster</li>';
echo '</ul>';

echo '<div class="alert alert-warning">';
echo '<h5><i class="fa fa-exclamation-triangle"></i> Wichtige Hinweise</h5>';
echo '<ul class="mb-0">';
echo '<li>Änderungen an Standard-Patterns wirken sich auf alle E-Mail-Prüfungen aus</li>';
echo '<li>Deaktivieren Sie Patterns nur, wenn Sie sicher sind, dass sie False-Positives verursachen</li>';
echo '<li>Bei kritischen Patterns (severity=critical) wird die IP-Adresse automatisch gesperrt</li>';
echo '<li>RegEx-Patterns müssen mit / beginnen und enden, z.B. /pattern/i</li>';
echo '</ul>';
echo '</div>';

echo '<h4>Beispiele für Pattern-Änderungen</h4>';
echo '<ul>';
echo '<li><strong>Spam-Wort hinzufügen:</strong> Pattern: "kostenlose", Severity: medium</li>';
echo '<li><strong>Domain blockieren:</strong> Pattern: "/@spamdomain\.com$/i", Severity: high</li>';
echo '<li><strong>HTML-Injection:</strong> Pattern: "/<script[^>]*src\s*=\s*["\'][^"\']*["\'][^>]*>/i", Severity: critical</li>';
echo '</ul>';

echo '</div>';
echo '</div>';

// JavaScript für Tooltips
echo '<script>
$(document).ready(function() {
    $("[data-toggle=\"tooltip\"]").tooltip();
});
</script>';