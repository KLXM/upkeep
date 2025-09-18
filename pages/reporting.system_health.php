<?php
/**
 * Upkeep AddOn - System Health Configuration
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

$addon = rex_addon::get('upkeep');

echo rex_view::content($addon->i18n('upkeep_system_health_info'));

// Handle form submission
if ('update' == rex_request('func', 'string')) {
    $healthKey = rex_request('system_health_key', 'string');
    
    // Generate key if empty
    if (empty($healthKey)) {
        $healthKey = bin2hex(random_bytes(16));
    }
    
    $addon->setConfig('system_health_key', $healthKey);
    $addon->setConfig('system_health_enabled', rex_request('system_health_enabled', 'int'));
    
    echo rex_view::success($addon->i18n('upkeep_system_health_settings_updated'));
}

// Generate new key action
if ('generate_key' == rex_request('func', 'string')) {
    $newKey = bin2hex(random_bytes(16));
    $addon->setConfig('system_health_key', $newKey);
    echo rex_view::success($addon->i18n('upkeep_system_health_key_generated'));
}

$formElements = [];

// Enable/Disable System Health API
$selEnabled = new rex_select();
$selEnabled->setId('system_health_enabled');
$selEnabled->setName('system_health_enabled');
$selEnabled->setSize(1);
$selEnabled->setAttribute('class', 'form-control selectpicker');
$selEnabled->setSelected($addon->getConfig('system_health_enabled', 0));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selEnabled->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="system_health_enabled">' . rex_escape($addon->i18n('upkeep_system_health_enabled')) . '</label>';
$n['field'] = $selEnabled->get();
$formElements[] = $n;

// Health Key
$currentKey = $addon->getConfig('system_health_key', '');
$n = [];
$n['label'] = '<label for="system_health_key">' . $addon->i18n('upkeep_system_health_key') . '</label>';
$n['field'] = '<div class="input-group">';
$n['field'] .= '<input class="form-control" id="system_health_key" type="text" name="system_health_key" value="' . rex_escape($currentKey) . '" />';
$n['field'] .= '<span class="input-group-btn">';
$n['field'] .= '<button class="btn btn-default" type="submit" name="func" value="generate_key" title="' . $addon->i18n('upkeep_system_health_generate_key') . '">';
$n['field'] .= '<i class="rex-icon fa fa-refresh"></i> ' . $addon->i18n('upkeep_system_health_generate_key') . '</button>';
$n['field'] .= '</span>';
$n['field'] .= '</div>';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_system_health_key_note') . '</p>';
$formElements[] = $n;

// Save button
$n = [];
$n['label'] = '<label></label>';
$n['field'] = '<button class="btn btn-save" type="submit" name="config-submit" value="1" title="' . $addon->i18n('upkeep_save') . '">' . $addon->i18n('upkeep_save') . '</button>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$formElementsView = $fragment->parse('core/form/form.php');

$content = '
<form action="' . rex_url::currentBackendPage() . '" method="post">
    <input type="hidden" name="func" value="update" />
    <fieldset>
        ' . $formElementsView . '
    </fieldset>
</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit');
$fragment->setVar('title', $addon->i18n('upkeep_system_health_settings'));
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// API Usage Information
if ($addon->getConfig('system_health_enabled', 0) && !empty($currentKey)) {
    $baseUrl = rex::getServer() . rex_url::frontendController();
    
    $examples = [];
    
    // Basic JSON
    $examples[] = [
        'title' => 'Basic JSON Status',
        'url' => $baseUrl . '?rex-api-call=upkeep_system_health&health_key=' . $currentKey,
        'description' => 'Returns basic system health information in JSON format'
    ];
    
    // Detailed JSON
    $examples[] = [
        'title' => 'Detailed JSON Status',
        'url' => $baseUrl . '?rex-api-call=upkeep_system_health&health_key=' . $currentKey . '&detailed=1',
        'description' => 'Returns detailed system health information including PHP extensions and database info'
    ];
    
    // Plain Text
    $examples[] = [
        'title' => 'Plain Text Status',
        'url' => $baseUrl . '?rex-api-call=upkeep_system_health&health_key=' . $currentKey . '&format=text',
        'description' => 'Returns system health information in plain text format'
    ];
    
    $content = '<div class="table-responsive"><table class="table table-striped">';
    $content .= '<thead><tr><th>API Endpoint</th><th>Description</th><th>Action</th></tr></thead>';
    $content .= '<tbody>';
    
    foreach ($examples as $example) {
        $content .= '<tr>';
        $content .= '<td><strong>' . rex_escape($example['title']) . '</strong><br>';
        $content .= '<code style="word-break: break-all;">' . rex_escape($example['url']) . '</code></td>';
        $content .= '<td>' . rex_escape($example['description']) . '</td>';
        $content .= '<td><a href="' . rex_escape($example['url']) . '" target="_blank" class="btn btn-xs btn-primary">';
        $content .= '<i class="rex-icon fa fa-external-link"></i> Test</a></td>';
        $content .= '</tr>';
    }
    
    $content .= '</tbody></table></div>';
    
    $fragment = new rex_fragment();
    $fragment->setVar('class', 'info');
    $fragment->setVar('title', $addon->i18n('upkeep_system_health_api_usage'));
    $fragment->setVar('body', $content, false);
    echo $fragment->parse('core/page/section.php');
}

// Information
$info = '<div class="alert alert-info">';
$info .= '<h4><i class="rex-icon fa fa-info-circle"></i> ' . $addon->i18n('upkeep_system_health_info_title') . '</h4>';
$info .= '<p>' . $addon->i18n('upkeep_system_health_info_desc') . '</p>';
$info .= '<ul>';
$info .= '<li><strong>JSON Format:</strong> <code>?rex-api-call=upkeep_system_health&health_key=YOUR_KEY</code></li>';
$info .= '<li><strong>Detailed Info:</strong> <code>&detailed=1</code></li>';
$info .= '<li><strong>Plain Text:</strong> <code>&format=text</code></li>';
$info .= '</ul>';
$info .= '</div>';

echo $info;