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
        'id' => rex_request('id', 'int', 0),
        'source_domain' => trim(rex_request('source_domain', 'string', '')),
        'source_path' => trim(rex_request('source_path', 'string', '')),
        'target_url' => trim(rex_request('target_url', 'string', '')),
        'redirect_code' => rex_request('redirect_code', 'int', 301),
        'is_wildcard' => rex_request('is_wildcard', 'bool', false),
        'status' => rex_request('status', 'bool', true),
        'description' => trim(rex_request('description', 'string', ''))
    ];
    
    // Leere source_path zu NULL normalisieren für konsistente Behandlung
    if ($data['source_path'] === '') {
        $data['source_path'] = null;
    }
    
    // Validation
    $errors = [];
    
    if (empty($data['source_domain'])) {
        $errors[] = $addon->i18n('upkeep_domain_mapping_source_required');
    } elseif (!preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/', $data['source_domain']) || strlen($data['source_domain']) > 253) {
        $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_domain');
    }
    
    // Wildcard-spezifische Validierung
    if ($data['is_wildcard'] && empty($data['source_path'])) {
        $errors[] = $addon->i18n('upkeep_domain_mapping_source_path_required');
    } elseif (!empty($data['source_path'])) {
        // Pfad-Sicherheit: Verhindere Path Traversal
        if (str_contains($data['source_path'], '..') || str_contains($data['source_path'], '\\')) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_path_security');
        }
        
        if ($data['is_wildcard'] && !str_ends_with($data['source_path'], '/*')) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_wildcard_ending');
        }
        if (!str_starts_with($data['source_path'], '/')) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_path_start');
        }
    }
    
    if (empty($data['target_url'])) {
        $errors[] = $addon->i18n('upkeep_domain_mapping_target_required');
    } else {
        // Wildcard-URLs validieren
        if (str_contains($data['target_url'], '*')) {
            // Bei Wildcard-URLs: Prüfe URL-Format ohne das *
            $testUrl = str_replace('*', 'test', $data['target_url']);
            if (!filter_var($testUrl, FILTER_VALIDATE_URL)) {
                $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_wildcard_url');
            }
        } else {
            // Normale URL-Validierung
            if (!filter_var($data['target_url'], FILTER_VALIDATE_URL)) {
                $errors[] = $addon->i18n('upkeep_domain_mapping_invalid_target_url');
            }
        }
        
        // Zusätzliche Sicherheitscheck für erlaubte Schemas
        if (!preg_match('/^https?:\/\//', $data['target_url']) && !str_contains($data['target_url'], '*')) {
            $errors[] = $addon->i18n('upkeep_domain_mapping_url_schema_required');
        }
    }
    
    // Check for duplicate domain+path combination with NULL handling
    if (empty($errors)) {
        $sql = rex_sql::factory();
        
        // Bessere NULL-Behandlung für source_path
        $duplicateQuery = 'SELECT id FROM ' . rex::getTable('upkeep_domain_mapping') . 
                         ' WHERE source_domain = ? AND ' .
                         '(source_path = ? OR (source_path IS NULL AND ? IS NULL) OR (source_path = "" AND ? = ""))';
        $duplicateParams = [$data['source_domain'], $data['source_path'], $data['source_path'], $data['source_path']];
        
        if (!empty($data['id'])) {
            $duplicateQuery .= ' AND id != ?';
            $duplicateParams[] = $data['id'];
        }
        
        $sql->setQuery($duplicateQuery, $duplicateParams);
        
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
        
        echo rex_view::success($addon->i18n('upkeep_domain_mapping_saved'));
        $func = '';
    } else {
        echo rex_view::error($addon->i18n('upkeep_domain_mapping_save_error') . ':<br>' . implode('<br>', $errors));
    }
}

// Handle delete
if ($func == 'delete' && $id > 0) {
    $sql = rex_sql::factory();
    $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE id = ?', [$id]);
    
    if ($sql->getRows() > 0) {
        echo rex_view::success($addon->i18n('upkeep_domain_mapping_deleted'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_domain_mapping_delete_error'));
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
        $n['note'] = $addon->i18n('upkeep_domain_mapping_wildcard_note');
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
        <p class="help-block">' . $addon->i18n('upkeep_domain_mapping_disabled_help') . '</p>
        <button class="btn btn-primary" type="submit" name="save_global_settings" value="1">Einstellungen speichern</button>
    </form>';
    
    $fragment = new rex_fragment();
    $fragment->setVar('title', $addon->i18n('upkeep_domain_mapping_global_settings'), false);
    $fragment->setVar('body', $globalForm, false);
    echo $fragment->parse('core/page/section.php');
    
    // Description
    $fragment = new rex_fragment();
    $fragment->setVar('title', $addon->i18n('upkeep_domain_mapping'), false);
    $fragment->setVar('body', '<p>' . $addon->i18n('upkeep_domain_mapping_help_text') . '</p>', false);
    echo $fragment->parse('core/page/section.php');
    
    // List
    $list = rex_list::factory('SELECT * FROM ' . rex::getTable('upkeep_domain_mapping') . ' ORDER BY source_domain');
    $list->addTableAttribute('class', 'table-striped');
    
    $list->setNoRowsMessage($addon->i18n('upkeep_domain_mapping_no_entries'));
    
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
