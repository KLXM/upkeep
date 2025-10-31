<?php

use FriendsOfRedaxo\Upkeep\MailSecurityFilter;

$error = '';
$success = '';
$addon = rex_addon::get('upkeep');

// Blocklist-Eintrag hinzufügen
if (rex_post('add-blocklist', 'string') === '1') {
    $email = trim(rex_post('blocklist_email', 'string', ''));
    $domain = trim(rex_post('blocklist_domain', 'string', ''));
    $ip = trim(rex_post('blocklist_ip', 'string', ''));
    $pattern = trim(rex_post('blocklist_pattern', 'string', ''));
    $type = rex_post('blocklist_type', 'string', 'email');
    $severity = rex_post('blocklist_severity', 'string', 'medium');
    $reason = trim(rex_post('blocklist_reason', 'string', ''));
    $expires = rex_post('blocklist_expires', 'string', '');
    
    // Validierung basierend auf Typ
    $isValid = false;
    $targetValue = '';
    
    switch ($type) {
        case 'email':
            if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $isValid = true;
                $targetValue = $email;
            } else {
                $error = $addon->i18n('upkeep_mail_security_invalid_email');
            }
            break;
        case 'domain':
            if (!empty($domain) && preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain)) {
                $isValid = true;
                $targetValue = $domain;
            } else {
                $error = $addon->i18n('upkeep_mail_security_invalid_domain');
            }
            break;
        case 'ip':
            if (!empty($ip) && (filter_var($ip, FILTER_VALIDATE_IP) || preg_match('/^[\d.*]+$/', $ip))) {
                $isValid = true;
                $targetValue = $ip;
            } else {
                $error = $addon->i18n('upkeep_mail_security_invalid_ip');
            }
            break;
        case 'pattern':
            if (!empty($pattern)) {
                $isValid = true;
                $targetValue = $pattern;
            } else {
                $error = $addon->i18n('upkeep_mail_security_pattern_empty');
            }
            break;
    }
    
    if ($isValid) {
        // Ablaufzeit verarbeiten
        $expiresAt = null;
        if (!empty($expires)) {
            $expiresAt = date('Y-m-d H:i:s', strtotime($expires));
        }
        
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
            
            if ($type === 'email') {
                $sql->setValue('email_address', $targetValue);
                $sql->setValue('domain', '');
                $sql->setValue('ip_address', '');
                $sql->setValue('pattern', '');
            } elseif ($type === 'domain') {
                $sql->setValue('email_address', '');
                $sql->setValue('domain', $targetValue);
                $sql->setValue('ip_address', '');
                $sql->setValue('pattern', '');
            } elseif ($type === 'ip') {
                $sql->setValue('email_address', '');
                $sql->setValue('domain', '');
                $sql->setValue('ip_address', $targetValue);
                $sql->setValue('pattern', $targetValue); // Für Pattern-Matching
            } else {
                $sql->setValue('email_address', '');
                $sql->setValue('domain', '');
                $sql->setValue('ip_address', '');
                $sql->setValue('pattern', $targetValue);
            }
            
            $sql->setValue('blocklist_type', $type);
            $sql->setValue('severity', $severity);
            $sql->setValue('reason', $reason);
            $sql->setValue('expires_at', $expiresAt);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            $success = $addon->i18n('upkeep_mail_security_blocklist_entry_added');
        } catch (Exception $e) {
            $error = $addon->i18n('upkeep_mail_security_error_adding') . ' ' . $e->getMessage();
        }
    }
}

// Blocklist-Eintrag entfernen
if (rex_post('remove-blocklist', 'int') > 0) {
    $blocklistId = rex_post('remove-blocklist', 'int');
    
    try {
        $sql = rex_sql::factory();
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_blocklist') . " WHERE id = ?", [$blocklistId]);
        $success = $addon->i18n('upkeep_mail_security_blocklist_entry_removed');
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_mail_security_error_removing') . ' ' . $e->getMessage();
    }
}

// Blocklist-Status ändern
if (rex_post('toggle-blocklist', 'int') > 0) {
    $blocklistId = rex_post('toggle-blocklist', 'int');
    $currentStatus = rex_post('current-status', 'int', 1);
    $newStatus = $currentStatus ? 0 : 1;
    
    try {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
        $sql->setWhere(['id' => $blocklistId]);
        $sql->setValue('status', $newStatus);
        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
        $sql->update();
        
        $success = $addon->i18n('upkeep_mail_security_blocklist_status_changed');
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_mail_security_error_changing_status') . ' ' . $e->getMessage();
    }
}

// Bulk-Aktionen
if (rex_post('bulk-action', 'string') && rex_post('selected-blocklist', 'array')) {
    $action = rex_post('bulk-action', 'string');
    $selectedIds = rex_post('selected-blocklist', 'array');
    $affectedCount = 0;
    
    try {
        $sql = rex_sql::factory();
        
        foreach ($selectedIds as $id) {
            $id = (int) $id;
            if ($id > 0) {
                switch ($action) {
                    case 'delete':
                        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_blocklist') . " WHERE id = ?", [$id]);
                        $affectedCount++;
                        break;
                    case 'activate':
                        $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
                        $sql->setWhere(['id' => $id]);
                        $sql->setValue('status', 1);
                        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                        $sql->update();
                        $affectedCount++;
                        break;
                    case 'deactivate':
                        $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
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
            'delete' => $addon->i18n('upkeep_bulk_deleted'),
            'activate' => $addon->i18n('upkeep_bulk_activated'), 
            'deactivate' => $addon->i18n('upkeep_bulk_deactivated')
        ];
        
        $success = $affectedCount . ' ' . $addon->i18n('upkeep_mail_security_blocklist_entries_processed') . ' ' . ($actionNames[$action] ?? $addon->i18n('upkeep_bulk_modified')) . '.';
        
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_bulk_action_error') . ' ' . $e->getMessage();
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
$filterType = rex_request('filter_type', 'string', '');
$filterSeverity = rex_request('filter_severity', 'string', '');
$filterStatus = rex_request('filter_status', 'string', '');
$filterSearch = rex_request('filter_search', 'string', '');

// Blocklist-Einträge laden mit Filter
$whereConditions = [];
$whereParams = [];

if (!empty($filterType)) {
    $whereConditions[] = "blocklist_type = ?";
    $whereParams[] = $filterType;
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
    $whereConditions[] = "(email_address LIKE ? OR domain LIKE ? OR pattern LIKE ? OR reason LIKE ?)";
    $whereParams[] = '%' . $filterSearch . '%';
    $whereParams[] = '%' . $filterSearch . '%';
    $whereParams[] = '%' . $filterSearch . '%';
    $whereParams[] = '%' . $filterSearch . '%';
}

$whereClause = !empty($whereConditions) ? 'WHERE ' . implode(' AND ', $whereConditions) : '';

try {
    $sql = rex_sql::factory();
    $query = "SELECT * FROM " . rex::getTable('upkeep_mail_blocklist') . " {$whereClause} ORDER BY severity DESC, created_at DESC";
    $sql->setQuery($query, $whereParams);
    
    $blocklistEntries = [];
    while ($sql->hasNext()) {
        $entry = [
            'id' => (int) $sql->getValue('id'),
            'email_address' => $sql->getValue('email_address'),
            'domain' => $sql->getValue('domain'),
            'ip_address' => $sql->getValue('ip_address'),
            'pattern' => $sql->getValue('pattern'),
            'blocklist_type' => $sql->getValue('blocklist_type'),
            'severity' => $sql->getValue('severity'),
            'reason' => $sql->getValue('reason'),
            'expires_at' => $sql->getValue('expires_at'),
            'status' => (bool) $sql->getValue('status'),
            'created_at' => $sql->getValue('created_at'),
            'updated_at' => $sql->getValue('updated_at')
        ];
        
        // Identifier für Anzeige
        $entry['identifier'] = $entry['email_address'] ?: $entry['domain'] ?: $entry['ip_address'] ?: $entry['pattern'];
        
        // Abgelaufen prüfen
        $entry['is_expired'] = false;
        if ($entry['expires_at'] && strtotime($entry['expires_at']) < time()) {
            $entry['is_expired'] = true;
        }
        
        $blocklistEntries[] = $entry;
        $sql->next();
    }
    
} catch (Exception $e) {
    $blocklistEntries = [];
    echo rex_view::error('Fehler beim Laden der Blocklist: ' . $e->getMessage());
}

// Filter-Panel
$content = '<form method="get" action="' . rex_url::currentBackendPage() . '">';
$content .= '<input type="hidden" name="page" value="upkeep" />';
$content .= '<input type="hidden" name="subpage" value="mail_security" />';
$content .= '<input type="hidden" name="subsubpage" value="blocklist" />';

$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-filter"></i> ' . $addon->i18n('upkeep_filter_search') . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-2">';
$content .= '<select name="filter_type" class="form-control">';
$content .= '<option value="">' . $addon->i18n('upkeep_all_types') . '</option>';
$content .= '<option value="email"' . ($filterType === 'email' ? ' selected' : '') . '>' . $addon->i18n('upkeep_type_email') . '</option>';
$content .= '<option value="domain"' . ($filterType === 'domain' ? ' selected' : '') . '>' . $addon->i18n('upkeep_type_domain') . '</option>';
$content .= '<option value="ip"' . ($filterType === 'ip' ? ' selected' : '') . '>' . $addon->i18n('upkeep_type_ip') . '</option>';
$content .= '<option value="pattern"' . ($filterType === 'pattern' ? ' selected' : '') . '>' . $addon->i18n('upkeep_type_pattern') . '</option>';
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

$content .= '<div class="col-md-4">';
$content .= '<input type="text" name="filter_search" class="form-control" placeholder="' . $addon->i18n('upkeep_search_blocklist') . '" value="' . rex_escape($filterSearch) . '" />';
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

// Blocklist-Eintrag hinzufügen Panel
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="add-blocklist" value="1" />';

$content .= '<div class="panel panel-danger">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-plus"></i> ' . $addon->i18n('upkeep_mail_security_add_to_blocklist') . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_type') . ' *</label>';
$content .= '<select class="form-control" name="blocklist_type" id="blocklist-type" onchange="toggleBlocklistFields()">';
$content .= '<option value="email">' . $addon->i18n('upkeep_type_email') . '</option>';
$content .= '<option value="domain">' . $addon->i18n('upkeep_type_domain') . '</option>';
$content .= '<option value="ip">' . $addon->i18n('upkeep_type_ip') . '</option>';
$content .= '<option value="pattern">' . $addon->i18n('upkeep_type_pattern') . '</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-3" id="email-field">';
$content .= '<label>' . $addon->i18n('upkeep_email_address') . ' *</label>';
$content .= '<input type="email" class="form-control" name="blocklist_email" placeholder="' . $addon->i18n('upkeep_email_placeholder') . '" />';
$content .= '</div>';

$content .= '<div class="col-md-3" id="domain-field" style="display:none;">';
$content .= '<label>' . $addon->i18n('upkeep_domain') . ' *</label>';
$content .= '<input type="text" class="form-control" name="blocklist_domain" placeholder="' . $addon->i18n('upkeep_domain_placeholder') . '" />';
$content .= '</div>';

$content .= '<div class="col-md-3" id="ip-field" style="display:none;">';
$content .= '<label>' . $addon->i18n('upkeep_ip_address') . ' *</label>';
$content .= '<input type="text" class="form-control" name="blocklist_ip" placeholder="' . $addon->i18n('upkeep_ip_placeholder') . '" />';
$content .= '<small class="help-block">' . $addon->i18n('upkeep_ip_help') . '</small>';
$content .= '</div>';

$content .= '<div class="col-md-3" id="pattern-field" style="display:none;">';
$content .= '<label>' . $addon->i18n('upkeep_pattern') . ' *</label>';
$content .= '<input type="text" class="form-control" name="blocklist_pattern" placeholder="' . $addon->i18n('upkeep_pattern_placeholder') . '" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_severity') . '</label>';
$content .= '<select class="form-control" name="blocklist_severity">';
$content .= '<option value="low">' . $addon->i18n('upkeep_severity_low') . '</option>';
$content .= '<option value="medium" selected>' . $addon->i18n('upkeep_severity_medium') . '</option>';
$content .= '<option value="high">' . $addon->i18n('upkeep_severity_high') . '</option>';
$content .= '<option value="critical">' . $addon->i18n('upkeep_severity_critical') . '</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>' . $addon->i18n('upkeep_valid_until') . '</label>';
$content .= '<input type="datetime-local" class="form-control" name="blocklist_expires" />';
$content .= '<small class="help-block">' . $addon->i18n('upkeep_empty_permanent') . '</small>';
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="row" style="margin-top: 15px;">';
$content .= '<div class="col-md-10">';
$content .= '<label>' . $addon->i18n('upkeep_reason') . '</label>';
$content .= '<input type="text" class="form-control" name="blocklist_reason" placeholder="' . $addon->i18n('upkeep_blocklist_reason_placeholder') . '" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<button type="submit" class="btn btn-danger">' . $addon->i18n('upkeep_add_to_blocklist') . '</button>';
$content .= '</div>';

$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

// JavaScript für Feld-Toggle
$content .= '<script>
function toggleBlocklistFields() {
    const type = document.getElementById("blocklist-type").value;
    document.getElementById("email-field").style.display = (type === "email") ? "block" : "none";
    document.getElementById("domain-field").style.display = (type === "domain") ? "block" : "none";
    document.getElementById("ip-field").style.display = (type === "ip") ? "block" : "none";
    document.getElementById("pattern-field").style.display = (type === "pattern") ? "block" : "none";
}
</script>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Blocklist-Einträge anzeigen
if (!empty($blocklistEntries)) {
    $content = '<form action="' . rex_url::currentBackendPage() . '" method="post" id="blocklist-form">';
    
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading">';
    $content .= '<h3 class="panel-title"><i class="fa fa-ban"></i> ' . $addon->i18n('upkeep_mail_security_blocklist_entries') . ' (' . count($blocklistEntries) . ' ' . $addon->i18n('upkeep_found') . ')</h3>';
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
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#blocklist-form input[type=checkbox]\').prop(\'checked\', true)">' . $addon->i18n('upkeep_select_all') . '</button> ';
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#blocklist-form input[type=checkbox]\').prop(\'checked\', false)">' . $addon->i18n('upkeep_deselect_all') . '</button>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr>';
    $content .= '<th width="30"><input type="checkbox" id="select-all" /></th>';
    $content .= '<th>' . $addon->i18n('upkeep_email_domain_pattern') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_type') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_severity') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_status') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_reason') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_valid_until') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_created') . '</th>';
    $content .= '<th>' . $addon->i18n('upkeep_actions') . '</th>';
    $content .= '</tr>';
    $content .= '</thead>';
    $content .= '<tbody>';
    
    foreach ($blocklistEntries as $entry) {
        $severityClass = match($entry['severity']) {
            'critical' => 'danger',
            'high' => 'warning',
            'medium' => 'info',
            default => 'default'
        };
        
        $statusClass = 'default';
        $statusText = $addon->i18n('upkeep_status_inactive');
        
        if ($entry['is_expired']) {
            $statusClass = 'warning';
            $statusText = $addon->i18n('upkeep_status_expired');
        } elseif ($entry['status']) {
            $statusClass = 'success';
            $statusText = $addon->i18n('upkeep_status_active');
        }
        
        $typeLabels = [
            'email' => $addon->i18n('upkeep_type_email'),
            'domain' => $addon->i18n('upkeep_type_domain'),
            'ip' => $addon->i18n('upkeep_type_ip'),
            'pattern' => $addon->i18n('upkeep_type_pattern')
        ];
        
        $rowClass = (!$entry['status'] || $entry['is_expired']) ? ' text-muted' : '';
        
        $content .= '<tr' . $rowClass . '>';
        $content .= '<td><input type="checkbox" name="selected-blocklist[]" value="' . $entry['id'] . '" /></td>';
        $content .= '<td><code>' . rex_escape($entry['identifier']) . '</code></td>';
        $content .= '<td><span class="label label-primary">' . ($typeLabels[$entry['blocklist_type']] ?? $entry['blocklist_type']) . '</span></td>';
        $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($entry['severity']) . '</span></td>';
        $content .= '<td><span class="label label-' . $statusClass . '">' . $statusText . '</span></td>';
        $content .= '<td>' . rex_escape(substr($entry['reason'] ?? '', 0, 50)) . (strlen($entry['reason'] ?? '') > 50 ? '...' : '') . '</td>';
        
        $expiresText = '-';
        if ($entry['expires_at']) {
            $expiresText = rex_formatter::strftime(strtotime($entry['expires_at']), 'datetime');
            if ($entry['is_expired']) {
                $expiresText = '<span class="text-danger">' . $expiresText . '</span>';
            }
        }
        $content .= '<td>' . $expiresText . '</td>';
        
        $content .= '<td>' . rex_formatter::strftime(strtotime($entry['created_at']), 'date') . '</td>';
        $content .= '<td>';
        
        if (!$entry['is_expired']) {
            // Status-Toggle
            $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
            $content .= '<input type="hidden" name="toggle-blocklist" value="' . $entry['id'] . '" />';
            $content .= '<input type="hidden" name="current-status" value="' . ($entry['status'] ? 1 : 0) . '" />';
            $content .= '<button type="submit" class="btn btn-xs btn-' . ($entry['status'] ? 'warning' : 'success') . '" title="' . ($entry['status'] ? $addon->i18n('upkeep_deactivate') : $addon->i18n('upkeep_activate')) . '">';
            $content .= '<i class="fa fa-' . ($entry['status'] ? 'pause' : 'play') . '"></i>';
            $content .= '</button>';
            $content .= '</form> ';
        }
        
        // Löschen
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="remove-blocklist" value="' . $entry['id'] . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-danger" onclick="return confirm(\'' . $addon->i18n('upkeep_delete_blocklist_confirm') . '\')" title="' . $addon->i18n('upkeep_delete') . '">';
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
            $("#blocklist-form input[type=checkbox]").prop("checked", this.checked);
        });
    });
    </script>';
    
} else {
    $content = '<div class="alert alert-info">';
    $content .= '<h4>' . $addon->i18n('upkeep_no_blocklist_entries_found') . '</h4>';
    $content .= '<p>' . $addon->i18n('upkeep_no_blocklist_entries_configured') . '</p>';
    $content .= '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');