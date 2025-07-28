<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Prüfen ob IPS-Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery('SHOW TABLES LIKE "' . rex::getTable('upkeep_ips_positivliste') . '"');
    if (!$sql->getRows()) {
        echo rex_view::error($addon->i18n('upkeep_ips_tables_missing'));
        return;
    }
} catch (Exception $e) {
    echo rex_view::error($addon->i18n('upkeep_ips_error') . ': ' . $e->getMessage());
    return;
}

// IP zur Positivliste hinzufügen
if (rex_post('add_positivliste', 'bool')) {
    $ip = rex_post('ip_address', 'string', '');
    $ipRange = rex_post('ip_range', 'string', '');
    $description = rex_post('description', 'string', '');
    $category = rex_post('category', 'string', 'trusted');
    
    if ($ip || $ipRange) {
        if (IntrusionPrevention::addToPositivliste($ip, $description, $category, $ipRange ?: null)) {
            echo rex_view::success($addon->i18n('upkeep_ips_positivliste_added'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_ips_error_adding'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_positivliste_ip_required'));
    }
}

// IP aus Positivliste entfernen
if (rex_post('remove_positivliste', 'int')) {
    $id = rex_post('remove_positivliste', 'int');
    if (IntrusionPrevention::removeFromPositivliste($id)) {
        echo rex_view::success($addon->i18n('upkeep_ips_positivliste_removed'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_error_removing'));
    }
}

// Status ändern
if (rex_post('toggle_status', 'int')) {
    $id = rex_post('toggle_status', 'int');
    $status = rex_post('new_status', 'int', 0);
    if (IntrusionPrevention::updatePositivlisteEntry($id, ['status' => $status])) {
        echo rex_view::success($addon->i18n('upkeep_ips_status_updated'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_error_updating'));
    }
}

// Positivliste-Einträge laden
$positivlisteEntries = IntrusionPrevention::getPositivlisteEntries();

// Formular-HTML für neue Positivliste-Einträge
$formContent = '<form method="post">';
$formContent .= '<input type="hidden" name="add_positivliste" value="1">';

$formContent .= '<div class="form-group">';
$formContent .= '<label for="ip_address">' . $addon->i18n('upkeep_ips_ip_address') . '</label>';
$formContent .= '<input type="text" class="form-control" id="ip_address" name="ip_address" placeholder="192.168.1.100">';
$formContent .= '</div>';

$formContent .= '<div class="form-group">';
$formContent .= '<label for="ip_range">' . $addon->i18n('upkeep_ips_ip_range') . '</label>';
$formContent .= '<input type="text" class="form-control" id="ip_range" name="ip_range" placeholder="192.168.1.0/24">';
$formContent .= '<p class="help-block">' . $addon->i18n('upkeep_ips_ip_range_notice') . '</p>';
$formContent .= '</div>';

$formContent .= '<div class="form-group">';
$formContent .= '<label for="description">' . $addon->i18n('upkeep_ips_description') . '</label>';
$formContent .= '<textarea class="form-control" id="description" name="description" rows="2"></textarea>';
$formContent .= '</div>';

$formContent .= '<div class="form-group">';
$formContent .= '<label for="category">' . $addon->i18n('upkeep_ips_category') . '</label>';
$formContent .= '<select class="form-control" id="category" name="category">';
$formContent .= '<option value="admin">' . $addon->i18n('upkeep_ips_category_admin') . '</option>';
$formContent .= '<option value="cdn">' . $addon->i18n('upkeep_ips_category_cdn') . '</option>';
$formContent .= '<option value="monitoring">' . $addon->i18n('upkeep_ips_category_monitoring') . '</option>';
$formContent .= '<option value="api">' . $addon->i18n('upkeep_ips_category_api') . '</option>';
$formContent .= '<option value="trusted" selected>' . $addon->i18n('upkeep_ips_category_trusted') . '</option>';
$formContent .= '</select>';
$formContent .= '</div>';

$formContent .= '<button type="submit" class="btn btn-primary">';
$formContent .= '<i class="rex-icon rex-icon-add"></i> ' . $addon->i18n('upkeep_ips_positivliste_add');
$formContent .= '</button>';
$formContent .= '</form>';

echo '<div class="row">';
echo '<div class="col-md-6">';
echo '<div class="rex-panel">';
echo '<header class="rex-panel-header"><h3>' . $addon->i18n('upkeep_ips_positivliste_add') . '</h3></header>';
echo '<div class="rex-panel-body">';
echo $formContent;
echo '</div>';
echo '</div>';
echo '</div>';

echo '<div class="col-md-6">';
echo '<div class="rex-panel">';
echo '<header class="rex-panel-header"><h3>' . $addon->i18n('upkeep_ips_positivliste_info') . '</h3></header>';
echo '<div class="rex-panel-body">';
echo '<p>' . $addon->i18n('upkeep_ips_positivliste_help') . '</p>';
echo '<ul>';
echo '<li><strong>' . $addon->i18n('upkeep_ips_category_admin') . ':</strong> ' . $addon->i18n('upkeep_ips_category_admin_desc') . '</li>';
echo '<li><strong>' . $addon->i18n('upkeep_ips_category_cdn') . ':</strong> ' . $addon->i18n('upkeep_ips_category_cdn_desc') . '</li>';
echo '<li><strong>' . $addon->i18n('upkeep_ips_category_monitoring') . ':</strong> ' . $addon->i18n('upkeep_ips_category_monitoring_desc') . '</li>';
echo '<li><strong>' . $addon->i18n('upkeep_ips_category_api') . ':</strong> ' . $addon->i18n('upkeep_ips_category_api_desc') . '</li>';
echo '<li><strong>' . $addon->i18n('upkeep_ips_category_trusted') . ':</strong> ' . $addon->i18n('upkeep_ips_category_trusted_desc') . '</li>';
echo '</ul>';
echo '</div>';
echo '</div>';
echo '</div>';
echo '</div>';

// Positivliste-Tabelle
if (!empty($positivlisteEntries)) {
    $list = rex_list::factory('SELECT * FROM ' . rex::getTable('upkeep_ips_positivliste') . ' ORDER BY created_at DESC');
    $list->setColumnLabel('id', 'ID');
    $list->setColumnLabel('ip_address', $addon->i18n('upkeep_ips_ip_address'));
    $list->setColumnLabel('ip_range', $addon->i18n('upkeep_ips_ip_range'));
    $list->setColumnLabel('description', $addon->i18n('upkeep_ips_description'));
    $list->setColumnLabel('category', $addon->i18n('upkeep_ips_category'));
    $list->setColumnLabel('status', $addon->i18n('upkeep_ips_status'));
    $list->setColumnLabel('created_at', $addon->i18n('upkeep_ips_created_at'));
    
    // Kategorie formatieren
    $list->setColumnFormat('category', 'custom', function($params) use ($addon) {
        $categories = [
            'admin' => $addon->i18n('upkeep_ips_category_admin'),
            'cdn' => $addon->i18n('upkeep_ips_category_cdn'),
            'monitoring' => $addon->i18n('upkeep_ips_category_monitoring'),
            'api' => $addon->i18n('upkeep_ips_category_api'),
            'trusted' => $addon->i18n('upkeep_ips_category_trusted')
        ];
        $category = $params['list']->getValue('category');
        return '<span class="label label-info">' . ($categories[$category] ?? $category) . '</span>';
    });
    
    // Status formatieren
    $list->setColumnFormat('status', 'custom', function($params) use ($addon) {
        $status = (int) $params['list']->getValue('status');
        $id = $params['list']->getValue('id');
        
        if ($status === 1) {
            $badge = '<span class="label label-success">' . $addon->i18n('upkeep_ips_active') . '</span>';
            $toggle = '<form method="post" style="display:inline;margin-left:5px;">';
            $toggle .= '<input type="hidden" name="toggle_status" value="' . $id . '">';
            $toggle .= '<input type="hidden" name="new_status" value="0">';
            $toggle .= '<button type="submit" class="btn btn-xs btn-warning" title="' . $addon->i18n('upkeep_ips_deactivate') . '">';
            $toggle .= '<i class="rex-icon rex-icon-offline"></i></button>';
            $toggle .= '</form>';
            return $badge . $toggle;
        } else {
            $badge = '<span class="label label-default">' . $addon->i18n('upkeep_ips_inactive') . '</span>';
            $toggle = '<form method="post" style="display:inline;margin-left:5px;">';
            $toggle .= '<input type="hidden" name="toggle_status" value="' . $id . '">';
            $toggle .= '<input type="hidden" name="new_status" value="1">';
            $toggle .= '<button type="submit" class="btn btn-xs btn-success" title="' . $addon->i18n('upkeep_ips_activate') . '">';
            $toggle .= '<i class="rex-icon rex-icon-online"></i></button>';
            $toggle .= '</form>';
            return $badge . $toggle;
        }
    });
    
    // Aktionen hinzufügen
    $list->addColumn('actions', $addon->i18n('upkeep_ips_actions'), -1);
    $list->setColumnFormat('actions', 'custom', function($params) use ($addon) {
        $id = $params['list']->getValue('id');
        $ip = $params['list']->getValue('ip_address');
        
        $actions = '<form method="post" style="display:inline;" onsubmit="return confirm(\'' . $addon->i18n('upkeep_ips_confirm_remove') . '\');">';
        $actions .= '<input type="hidden" name="remove_positivliste" value="' . $id . '">';
        $actions .= '<button type="submit" class="btn btn-xs btn-danger" title="' . $addon->i18n('upkeep_ips_remove') . '">';
        $actions .= '<i class="rex-icon rex-icon-delete"></i></button>';
        $actions .= '</form>';
        
        return $actions;
    });
    
    // Spalten ausblenden
    $list->removeColumn('id');
    $list->removeColumn('updated_at');
    
    echo '<h2>' . $addon->i18n('upkeep_ips_positivliste_entries') . ' (' . count($positivlisteEntries) . ')</h2>';
    echo $list->get();
} else {
    echo rex_view::info($addon->i18n('upkeep_ips_no_positivliste_entries'));
}
