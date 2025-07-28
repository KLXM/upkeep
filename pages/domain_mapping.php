<?php
/**
 * Domain Mapping Verwaltung für Upkeep AddOn
 * 
 * Einfache Domain-zu-URL-Zuordnung mit HTTP Status Codes
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();
$func = rex_request('func', 'string');
$id = rex_request('id', 'int');

// Handle global domain mapping activation
if (rex_post('save_global_settings', 'bool')) {
    $domainMappingActive = rex_post('domain_mapping_active', 'bool') ? 1 : 0;
    $addon->setConfig('domain_mapping_active', $domainMappingActive);
    echo rex_view::success('Globale Einstellungen gespeichert.');
}

// Handle form submission
if (rex_post('save', 'bool')) {
    $data = [
        'id' => rex_post('id', 'int'),
        'source_domain' => trim(rex_post('source_domain', 'string')),
        'source_path' => trim(rex_post('source_path', 'string')),
        'target_url' => trim(rex_post('target_url', 'string')),
        'redirect_code' => rex_post('redirect_code', 'int', 301),
        'is_wildcard' => rex_post('is_wildcard', 'bool') ? 1 : 0,
        'status' => rex_post('status', 'bool') ? 1 : 0,
        'description' => trim(rex_post('description', 'string'))
    ];
    
    // Validation
    $errors = [];
    
    if (empty($data['source_domain'])) {
        $errors[] = 'Source Domain ist erforderlich';
    } elseif (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$/', $data['source_domain'])) {
        $errors[] = 'Ungültige Domain';
    }
    
    // Pfad-Validierung für Wildcards
    if (!empty($data['source_path'])) {
        if ($data['is_wildcard'] && !str_ends_with($data['source_path'], '/*')) {
            $errors[] = 'Wildcard-Pfade müssen mit /* enden';
        }
        if (!str_starts_with($data['source_path'], '/')) {
            $errors[] = 'Pfade müssen mit / beginnen';
        }
    }
    
    if (empty($data['target_url'])) {
        $errors[] = 'Target URL ist erforderlich';
    } elseif (!filter_var($data['target_url'], FILTER_VALIDATE_URL) && !str_contains($data['target_url'], '*')) {
        $errors[] = 'Ungültige URL (außer bei Wildcard-URLs mit *)';
    }
    
    // Check for duplicate domain+path combination
    if (empty($errors)) {
        $sql = rex_sql::factory();
        $where = 'source_domain = ? AND source_path = ?';
        $params = [$data['source_domain'], $data['source_path']];
        
        if (!empty($data['id'])) {
            $where .= ' AND id != ?';
            $params[] = $data['id'];
        }
        
        $sql->setQuery('SELECT id FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE ' . $where, $params);
        
        if ($sql->getRows() > 0) {
            $errors[] = 'Diese Domain+Pfad-Kombination ist bereits konfiguriert';
        }
    }
    
    if (empty($errors)) {
        // Save data
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_domain_mapping'));
        $sql->setValue('source_domain', $data['source_domain']);
        $sql->setValue('source_path', $data['source_path']);
        $sql->setValue('target_url', $data['target_url']);
        $sql->setValue('redirect_code', $data['redirect_code']);
        $sql->setValue('is_wildcard', $data['is_wildcard']);
        $sql->setValue('status', $data['status']);
        $sql->setValue('description', $data['description']);
        $sql->setValue('updatedate', date('Y-m-d H:i:s'));
        
        if (!empty($data['id'])) {
            $sql->setWhere(['id' => $data['id']]);
            $sql->update();
        } else {
            $sql->setValue('createdate', date('Y-m-d H:i:s'));
            $sql->insert();
        }
        
        echo rex_view::success('Domain Mapping wurde gespeichert');
        $func = '';
    } else {
        echo rex_view::error('Fehler beim Speichern:<br>' . implode('<br>', $errors));
    }
}

// Handle delete
if ($func == 'delete' && $id > 0) {
    $sql = rex_sql::factory();
    $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE id = ?', [$id]);
    
    if ($sql->getRows() > 0) {
        echo rex_view::success('Domain Mapping wurde gelöscht');
    } else {
        echo rex_view::error('Fehler beim Löschen');
    }
    $func = '';
}

// Show form
if ($func == 'add' || $func == 'edit') {
    $data = [];
    
    if ($func == 'edit' && $id > 0) {
        $sql = rex_sql::factory();
        $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE id = ?', [$id]);
        
        if ($sql->getRows() > 0) {
            $data = [
                'id' => $sql->getValue('id'),
                'source_domain' => $sql->getValue('source_domain'),
                'source_path' => $sql->getValue('source_path'),
                'target_url' => $sql->getValue('target_url'),
                'redirect_code' => $sql->getValue('redirect_code'),
                'is_wildcard' => $sql->getValue('is_wildcard'),
                'status' => $sql->getValue('status'),
                'description' => $sql->getValue('description')
            ];
        } else {
            echo rex_view::error('Eintrag nicht gefunden');
            $func = '';
        }
    }
    
    if ($func == 'add' || $func == 'edit') {
        // Form elements
        $formElements = [];
        
        // Source Domain
        $n = [];
        $n['label'] = '<label for="source_domain">Source Domain</label>';
        $n['field'] = '<input class="form-control" type="text" id="source_domain" name="source_domain" value="' . rex_escape($data['source_domain'] ?? '') . '" required>';
        $n['note'] = 'Domain ohne http(s):// und ohne Pfad (z.B. alt-domain.com)';
        $formElements[] = $n;
        
        // Source Path
        $n = [];
        $n['label'] = '<label for="source_path">Source Path (optional)</label>';
        $n['field'] = '<input class="form-control" type="text" id="source_path" name="source_path" value="' . rex_escape($data['source_path'] ?? '') . '" placeholder="/pfad/zur/seite">';
        $n['note'] = 'Spezifischer Pfad für URL-Matching. Leer lassen für Domain-only Mapping.';
        $formElements[] = $n;
        
        // Wildcard Checkbox
        $n = [];
        $n['label'] = '<label for="is_wildcard">Wildcard Mapping</label>';
        $checked = isset($data['is_wildcard']) && $data['is_wildcard'] ? ' checked="checked"' : '';
        $n['field'] = '<input type="checkbox" id="is_wildcard" name="is_wildcard" value="1"' . $checked . '> Wildcard-Umleitung aktivieren';
        $n['note'] = 'Source Path muss mit /* enden. Target URL kann * enthalten für dynamische Ersetzung.';
        $formElements[] = $n;
        
        // Target URL
        $n = [];
        $n['label'] = '<label for="target_url">Target URL</label>';
        $n['field'] = '<input class="form-control" type="text" id="target_url" name="target_url" value="' . rex_escape($data['target_url'] ?? '') . '" required>';
        $n['note'] = 'Vollständige URL mit http:// oder https://. Bei Wildcards: * wird durch gefangenen Pfad ersetzt.';
        $formElements[] = $n;
        
        // HTTP Status Code
        $n = [];
        $n['label'] = '<label for="redirect_code">HTTP Status Code</label>';
        $select = new rex_select();
        $select->setId('redirect_code');
        $select->setName('redirect_code');
        $select->setAttribute('class', 'form-control');
        $select->addOption('301 - Moved Permanently', 301);
        $select->addOption('302 - Found', 302);
        $select->addOption('303 - See Other', 303);
        $select->addOption('307 - Temporary Redirect', 307);
        $select->addOption('308 - Permanent Redirect', 308);
        $select->setSelected($data['redirect_code'] ?? 301);
        $n['field'] = $select->get();
        $formElements[] = $n;
        
        // Description
        $n = [];
        $n['label'] = '<label for="description">Beschreibung (optional)</label>';
        $n['field'] = '<textarea class="form-control" id="description" name="description" rows="3" placeholder="Beschreibung der Weiterleitung...">' . rex_escape($data['description'] ?? '') . '</textarea>';
        $n['note'] = 'Optionale Beschreibung für bessere Übersicht und Dokumentation.';
        $formElements[] = $n;
        
        // Status
        $n = [];
        $n['label'] = '<label for="status">Aktiv</label>';
        $n['field'] = '<input type="checkbox" id="status" name="status" value="1"' . (($data['status'] ?? 1) ? ' checked' : '') . '>';
        $formElements[] = $n;
        
        // Build form
        $fragment = new rex_fragment();
        $fragment->setVar('elements', $formElements, false);
        $form = $fragment->parse('core/form/form.php');
        
        // Form buttons
        $formElements = [];
        $n = [];
        $n['field'] = '<button class="btn btn-save rex-primary-action" type="submit" name="save" value="1">Speichern</button>';
        $formElements[] = $n;
        
        $n = [];
        $n['field'] = '<a class="btn btn-abort" href="' . rex_url::currentBackendPage() . '">Abbrechen</a>';
        $formElements[] = $n;
        
        $fragment = new rex_fragment();
        $fragment->setVar('elements', $formElements, false);
        $buttons = $fragment->parse('core/form/submit.php');
        
        // Complete form
        $fragment = new rex_fragment();
        $fragment->setVar('class', 'edit', false);
        $fragment->setVar('title', $func == 'add' ? 'Domain Mapping hinzufügen' : 'Domain Mapping bearbeiten', false);
        $fragment->setVar('body', $form, false);
        $fragment->setVar('buttons', $buttons, false);
        $content = $fragment->parse('core/page/section.php');
        
        echo '<form action="' . rex_url::currentBackendPage() . '" method="post">';
        if ($func == 'edit') {
            echo '<input type="hidden" name="id" value="' . $id . '">';
        }
        echo $content;
        echo '</form>';
    }
}

// Show list
if ($func == '') {
    // Global Settings
    $domainMappingActive = $addon->getConfig('domain_mapping_active', false);
    
    $globalForm = '
    <form action="' . rex_url::currentBackendPage() . '" method="post">
        <div class="checkbox">
            <label>
                <input type="checkbox" name="domain_mapping_active" value="1"' . ($domainMappingActive ? ' checked="checked"' : '') . '>
                Domain-Mapping global aktivieren
            </label>
        </div>
        <p class="help-block">Wenn deaktiviert, werden alle Domain-Mappings ignoriert, auch wenn sie als "Aktiv" markiert sind.</p>
        <button class="btn btn-primary" type="submit" name="save_global_settings" value="1">Einstellungen speichern</button>
    </form>';
    
    $fragment = new rex_fragment();
    $fragment->setVar('title', 'Globale Domain-Mapping Einstellungen', false);
    $fragment->setVar('body', $globalForm, false);
    echo $fragment->parse('core/page/section.php');
    
    // Description
    $fragment = new rex_fragment();
    $fragment->setVar('title', 'Domain Mapping', false);
    $fragment->setVar('body', '<p>Hier können Sie Domains auf URLs umleiten. Die Umleitung funktioniert nur, wenn die Domain auch tatsächlich auf diesen Server zeigt.</p>', false);
    echo $fragment->parse('core/page/section.php');
    
    // List
    $list = rex_list::factory('SELECT * FROM ' . rex::getTable('upkeep_domain_mapping') . ' ORDER BY source_domain');
    $list->addTableAttribute('class', 'table-striped');
    
    $list->setNoRowsMessage('Keine Domain Mappings vorhanden');
    
    $list->setColumnLabel('source_domain', 'Domain');
    $list->setColumnLabel('source_path', 'Pfad');
    $list->setColumnLabel('target_url', 'Ziel-URL');
    $list->setColumnLabel('redirect_code', 'HTTP Code');
    $list->setColumnLabel('is_wildcard', 'Wildcard');
    $list->setColumnLabel('status', 'Status');
    $list->setColumnLabel('description', 'Beschreibung');
    
    // Format source_path column
    $list->setColumnFormat('source_path', 'custom', function($params) {
        $path = $params['value'];
        if (empty($path)) {
            return '<em>Domain-only</em>';
        }
        return rex_escape($path);
    });
    
    $list->setColumnFormat('target_url', 'custom', function($params) {
        $url = $params['value'];
        if (strlen($url) > 40) {
            $url = substr($url, 0, 37) . '...';
        }
        return '<a href="' . rex_escape($params['value']) . '" target="_blank">' . rex_escape($url) . '</a>';
    });
    
    $list->setColumnFormat('is_wildcard', 'custom', function($params) {
        return $params['value'] ? '<span class="label label-info">*</span>' : '';
    });
    
    $list->setColumnFormat('status', 'custom', function($params) {
        return $params['value'] ? '<span class="rex-online">Aktiv</span>' : '<span class="rex-offline">Inaktiv</span>';
    });
    
    $list->setColumnFormat('description', 'custom', function($params) {
        $desc = $params['value'];
        if (empty($desc)) {
            return '';
        }
        if (strlen($desc) > 30) {
            $desc = substr($desc, 0, 27) . '...';
        }
        return '<small>' . rex_escape($desc) . '</small>';
    });
    
    $list->addColumn('edit', '<i class="rex-icon rex-icon-edit"></i> ' . rex_i18n::msg('edit'));
    $list->setColumnLayout('edit', array('<th class="rex-table-action" colspan="2">###VALUE###</th>', '<td class="rex-table-action">###VALUE###</td>'));
    $list->setColumnParams('edit', array('func' => 'edit', 'id' => '###id###'));
    
    $list->addColumn('delete', '<i class="rex-icon rex-icon-delete"></i> ' . rex_i18n::msg('delete'));
    $list->setColumnLayout('delete', array('', '<td class="rex-table-action">###VALUE###</td>'));
    $list->setColumnParams('delete', array('func' => 'delete', 'id' => '###id###'));
    $list->addLinkAttribute('delete', 'onclick', 'return confirm(\'Wirklich löschen?\')');
    
    $list->removeColumn('id');
    $list->removeColumn('createdate');
    $list->removeColumn('updatedate');
    
    $content = $list->get();
    
    // Add button
    $content = '<a class="btn btn-primary" href="' . rex_url::currentBackendPage(['func' => 'add']) . '">Domain Mapping hinzufügen</a><br><br>' . $content;
    
    $fragment = new rex_fragment();
    $fragment->setVar('title', 'Domain Mappings', false);
    $fragment->setVar('content', $content, false);
    echo $fragment->parse('core/page/section.php');
}
