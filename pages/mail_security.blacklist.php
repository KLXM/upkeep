<?php

use KLXM\Upkeep\MailSecurityFilter;

$error = '';
$success = '';
$addon = rex_addon::get('upkeep');

// Blacklist-Eintrag hinzufügen
if (rex_post('add-blacklist', 'string') === '1') {
    $email = trim(rex_post('blacklist_email', 'string', ''));
    $domain = trim(rex_post('blacklist_domain', 'string', ''));
    $ip = trim(rex_post('blacklist_ip', 'string', ''));
    $pattern = trim(rex_post('blacklist_pattern', 'string', ''));
    $type = rex_post('blacklist_type', 'string', 'email');
    $severity = rex_post('blacklist_severity', 'string', 'medium');
    $reason = trim(rex_post('blacklist_reason', 'string', ''));
    $expires = rex_post('blacklist_expires', 'string', '');
    
    // Validierung basierend auf Typ
    $isValid = false;
    $targetValue = '';
    
    switch ($type) {
        case 'email':
            if (!empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $isValid = true;
                $targetValue = $email;
            } else {
                $error = 'Ungültige E-Mail-Adresse.';
            }
            break;
        case 'domain':
            if (!empty($domain) && preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain)) {
                $isValid = true;
                $targetValue = $domain;
            } else {
                $error = 'Ungültige Domain.';
            }
            break;
        case 'ip':
            if (!empty($ip) && (filter_var($ip, FILTER_VALIDATE_IP) || preg_match('/^[\d.*]+$/', $ip))) {
                $isValid = true;
                $targetValue = $ip;
            } else {
                $error = 'Ungültige IP-Adresse. Erlaubt: 192.168.1.1 oder 192.168.*';
            }
            break;
        case 'pattern':
            if (!empty($pattern)) {
                $isValid = true;
                $targetValue = $pattern;
            } else {
                $error = 'Pattern darf nicht leer sein.';
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
            $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
            
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
            
            $sql->setValue('blacklist_type', $type);
            $sql->setValue('severity', $severity);
            $sql->setValue('reason', $reason);
            $sql->setValue('expires_at', $expiresAt);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            $success = 'Eintrag erfolgreich zur Blacklist hinzugefügt.';
        } catch (Exception $e) {
            $error = 'Fehler beim Hinzufügen: ' . $e->getMessage();
        }
    }
}

// Blacklist-Eintrag entfernen
if (rex_post('remove-blacklist', 'int') > 0) {
    $blacklistId = rex_post('remove-blacklist', 'int');
    
    try {
        $sql = rex_sql::factory();
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_blacklist') . " WHERE id = ?", [$blacklistId]);
        $success = 'Blacklist-Eintrag erfolgreich entfernt.';
    } catch (Exception $e) {
        $error = 'Fehler beim Entfernen: ' . $e->getMessage();
    }
}

// Blacklist-Status ändern
if (rex_post('toggle-blacklist', 'int') > 0) {
    $blacklistId = rex_post('toggle-blacklist', 'int');
    $currentStatus = rex_post('current-status', 'int', 1);
    $newStatus = $currentStatus ? 0 : 1;
    
    try {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
        $sql->setWhere(['id' => $blacklistId]);
        $sql->setValue('status', $newStatus);
        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
        $sql->update();
        
        $success = 'Blacklist-Status erfolgreich geändert.';
    } catch (Exception $e) {
        $error = 'Fehler beim Ändern des Status: ' . $e->getMessage();
    }
}

// Bulk-Aktionen
if (rex_post('bulk-action', 'string') && rex_post('selected-blacklist', 'array')) {
    $action = rex_post('bulk-action', 'string');
    $selectedIds = rex_post('selected-blacklist', 'array');
    $affectedCount = 0;
    
    try {
        $sql = rex_sql::factory();
        
        foreach ($selectedIds as $id) {
            $id = (int) $id;
            if ($id > 0) {
                switch ($action) {
                    case 'delete':
                        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_blacklist') . " WHERE id = ?", [$id]);
                        $affectedCount++;
                        break;
                    case 'activate':
                        $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
                        $sql->setWhere(['id' => $id]);
                        $sql->setValue('status', 1);
                        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                        $sql->update();
                        $affectedCount++;
                        break;
                    case 'deactivate':
                        $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
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
            'delete' => 'gelöscht',
            'activate' => 'aktiviert', 
            'deactivate' => 'deaktiviert'
        ];
        
        $success = $affectedCount . ' Blacklist-Einträge wurden ' . ($actionNames[$action] ?? 'bearbeitet') . '.';
        
    } catch (Exception $e) {
        $error = 'Fehler bei Bulk-Aktion: ' . $e->getMessage();
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

// Blacklist-Einträge laden mit Filter
$whereConditions = [];
$whereParams = [];

if (!empty($filterType)) {
    $whereConditions[] = "blacklist_type = ?";
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
    $query = "SELECT * FROM " . rex::getTable('upkeep_mail_blacklist') . " {$whereClause} ORDER BY severity DESC, created_at DESC";
    $sql->setQuery($query, $whereParams);
    
    $blacklistEntries = [];
    while ($sql->hasNext()) {
        $entry = [
            'id' => (int) $sql->getValue('id'),
            'email_address' => $sql->getValue('email_address'),
            'domain' => $sql->getValue('domain'),
            'ip_address' => $sql->getValue('ip_address'),
            'pattern' => $sql->getValue('pattern'),
            'blacklist_type' => $sql->getValue('blacklist_type'),
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
        
        $blacklistEntries[] = $entry;
        $sql->next();
    }
    
} catch (Exception $e) {
    $blacklistEntries = [];
    echo rex_view::error('Fehler beim Laden der Blacklist: ' . $e->getMessage());
}

// Filter-Panel
$content = '<form method="get" action="' . rex_url::currentBackendPage() . '">';
$content .= '<input type="hidden" name="page" value="upkeep" />';
$content .= '<input type="hidden" name="subpage" value="mail_security" />';
$content .= '<input type="hidden" name="subsubpage" value="blacklist" />';

$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-filter"></i> Filter & Suche</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-2">';
$content .= '<select name="filter_type" class="form-control">';
$content .= '<option value="">Alle Typen</option>';
$content .= '<option value="email"' . ($filterType === 'email' ? ' selected' : '') . '>E-Mail</option>';
$content .= '<option value="domain"' . ($filterType === 'domain' ? ' selected' : '') . '>Domain</option>';
$content .= '<option value="ip"' . ($filterType === 'ip' ? ' selected' : '') . '>IP-Adresse</option>';
$content .= '<option value="pattern"' . ($filterType === 'pattern' ? ' selected' : '') . '>Pattern</option>';
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

$content .= '<div class="col-md-4">';
$content .= '<input type="text" name="filter_search" class="form-control" placeholder="Suche in E-Mail/Domain/Pattern/Grund" value="' . rex_escape($filterSearch) . '" />';
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

// Blacklist-Eintrag hinzufügen Panel
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="add-blacklist" value="1" />';

$content .= '<div class="panel panel-danger">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-plus"></i> Zur Blacklist hinzufügen</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-2">';
$content .= '<label>Typ *</label>';
$content .= '<select class="form-control" name="blacklist_type" id="blacklist-type" onchange="toggleBlacklistFields()">';
$content .= '<option value="email">E-Mail</option>';
$content .= '<option value="domain">Domain</option>';
$content .= '<option value="ip">IP-Adresse</option>';
$content .= '<option value="pattern">Pattern</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-3" id="email-field">';
$content .= '<label>E-Mail-Adresse *</label>';
$content .= '<input type="email" class="form-control" name="blacklist_email" placeholder="spam@example.com" />';
$content .= '</div>';

$content .= '<div class="col-md-3" id="domain-field" style="display:none;">';
$content .= '<label>Domain *</label>';
$content .= '<input type="text" class="form-control" name="blacklist_domain" placeholder="spam.com" />';
$content .= '</div>';

$content .= '<div class="col-md-3" id="ip-field" style="display:none;">';
$content .= '<label>IP-Adresse *</label>';
$content .= '<input type="text" class="form-control" name="blacklist_ip" placeholder="192.168.1.100 oder 192.168.*" />';
$content .= '<small class="help-block">Wildcards möglich: 192.168.* oder 10.0.0.*</small>';
$content .= '</div>';

$content .= '<div class="col-md-3" id="pattern-field" style="display:none;">';
$content .= '<label>Pattern *</label>';
$content .= '<input type="text" class="form-control" name="blacklist_pattern" placeholder="*.spam.com" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Schweregrad</label>';
$content .= '<select class="form-control" name="blacklist_severity">';
$content .= '<option value="low">Niedrig</option>';
$content .= '<option value="medium" selected>Mittel</option>';
$content .= '<option value="high">Hoch</option>';
$content .= '<option value="critical">Kritisch</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>Gültig bis</label>';
$content .= '<input type="datetime-local" class="form-control" name="blacklist_expires" />';
$content .= '<small class="help-block">Leer = permanent</small>';
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="row" style="margin-top: 15px;">';
$content .= '<div class="col-md-10">';
$content .= '<label>Grund</label>';
$content .= '<input type="text" class="form-control" name="blacklist_reason" placeholder="Grund für Blacklisting (z.B. Spam, Phishing, etc.)" />';
$content .= '</div>';

$content .= '<div class="col-md-2">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<button type="submit" class="btn btn-danger">Zur Blacklist hinzufügen</button>';
$content .= '</div>';

$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

// JavaScript für Feld-Toggle
$content .= '<script>
function toggleBlacklistFields() {
    const type = document.getElementById("blacklist-type").value;
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

// Blacklist-Einträge anzeigen
if (!empty($blacklistEntries)) {
    $content = '<form action="' . rex_url::currentBackendPage() . '" method="post" id="blacklist-form">';
    
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading">';
    $content .= '<h3 class="panel-title"><i class="fa fa-ban"></i> Blacklist-Einträge (' . count($blacklistEntries) . ' gefunden)</h3>';
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
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#blacklist-form input[type=checkbox]\').prop(\'checked\', true)">Alle auswählen</button> ';
    $content .= '<button type="button" class="btn btn-sm btn-default" onclick="$(\'#blacklist-form input[type=checkbox]\').prop(\'checked\', false)">Alle abwählen</button>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr>';
    $content .= '<th width="30"><input type="checkbox" id="select-all" /></th>';
    $content .= '<th>E-Mail/Domain/Pattern</th>';
    $content .= '<th>Typ</th>';
    $content .= '<th>Schweregrad</th>';
    $content .= '<th>Status</th>';
    $content .= '<th>Grund</th>';
    $content .= '<th>Gültig bis</th>';
    $content .= '<th>Erstellt</th>';
    $content .= '<th>Aktionen</th>';
    $content .= '</tr>';
    $content .= '</thead>';
    $content .= '<tbody>';
    
    foreach ($blacklistEntries as $entry) {
        $severityClass = match($entry['severity']) {
            'critical' => 'danger',
            'high' => 'warning',
            'medium' => 'info',
            default => 'default'
        };
        
        $statusClass = 'default';
        $statusText = 'Inaktiv';
        
        if ($entry['is_expired']) {
            $statusClass = 'warning';
            $statusText = 'Abgelaufen';
        } elseif ($entry['status']) {
            $statusClass = 'success';
            $statusText = 'Aktiv';
        }
        
        $typeLabels = [
            'email' => 'E-Mail',
            'domain' => 'Domain',
            'ip' => 'IP-Adresse',
            'pattern' => 'Pattern'
        ];
        
        $rowClass = (!$entry['status'] || $entry['is_expired']) ? ' text-muted' : '';
        
        $content .= '<tr' . $rowClass . '>';
        $content .= '<td><input type="checkbox" name="selected-blacklist[]" value="' . $entry['id'] . '" /></td>';
        $content .= '<td><code>' . rex_escape($entry['identifier']) . '</code></td>';
        $content .= '<td><span class="label label-primary">' . ($typeLabels[$entry['blacklist_type']] ?? $entry['blacklist_type']) . '</span></td>';
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
            $content .= '<input type="hidden" name="toggle-blacklist" value="' . $entry['id'] . '" />';
            $content .= '<input type="hidden" name="current-status" value="' . ($entry['status'] ? 1 : 0) . '" />';
            $content .= '<button type="submit" class="btn btn-xs btn-' . ($entry['status'] ? 'warning' : 'success') . '" title="' . ($entry['status'] ? 'Deaktivieren' : 'Aktivieren') . '">';
            $content .= '<i class="fa fa-' . ($entry['status'] ? 'pause' : 'play') . '"></i>';
            $content .= '</button>';
            $content .= '</form> ';
        }
        
        // Löschen
        $content .= '<form action="' . rex_url::currentBackendPage() . '" method="post" style="display:inline;">';
        $content .= '<input type="hidden" name="remove-blacklist" value="' . $entry['id'] . '" />';
        $content .= '<button type="submit" class="btn btn-xs btn-danger" onclick="return confirm(\'Blacklist-Eintrag wirklich löschen?\')" title="Löschen">';
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
            $("#blacklist-form input[type=checkbox]").prop("checked", this.checked);
        });
    });
    </script>';
    
} else {
    $content = '<div class="alert alert-info">';
    $content .= '<h4>Keine Blacklist-Einträge gefunden</h4>';
    $content .= '<p>Es wurden noch keine E-Mail-Adressen oder Domains blockiert oder Ihre Filter haben keine Ergebnisse geliefert.</p>';
    $content .= '</div>';
}

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');