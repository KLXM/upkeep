<?php

use KLXM\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Prüfen ob IPS-Tabellen existieren
$sql = rex_sql::factory();
try {
    $sql->setQuery("SHOW TABLES LIKE ?", [rex::getTable('upkeep_ips_blocked_ips')]);
    $tableExists = $sql->getRows() > 0;
} catch (Exception $e) {
    $tableExists = false;
}

if (!$tableExists) {
    echo '<div class="alert alert-warning">';
    echo '<h4><i class="fa fa-exclamation-triangle"></i> IPS-Datenbanktabellen fehlen</h4>';
    echo '<p>Die Intrusion Prevention System Tabellen wurden noch nicht erstellt.</p>';
    echo '<p>Bitte installieren Sie das Upkeep AddOn erneut über das Backend.</p>';
    echo '</div>';
    return;
}

// Bulk-Import von IP-Listen
if (rex_post('bulk_import_ips', 'bool')) {
    $ipList = rex_post('ip_list', 'string', '');
    $duration = rex_post('bulk_duration', 'string', '24h');
    $reason = rex_post('bulk_reason', 'string', '');
    
    if (empty($ipList)) {
        echo rex_view::error($addon->i18n('upkeep_ips_ip_list_required'));
    } else {
        $results = IntrusionPrevention::processBulkIpImport($ipList, $duration, $reason);
        
        if ($results['success_count'] > 0) {
            echo rex_view::success($addon->i18n('upkeep_ips_bulk_success', $results['success_count']));
        }
        
        if ($results['error_count'] > 0) {
            $errorMsg = "Fehler bei {$results['error_count']} IPs:";
            foreach ($results['errors'] as $error) {
                $errorMsg .= "<br>• " . rex_escape($error);
            }
            echo rex_view::warning($errorMsg);
        }
        
        if ($results['skipped_count'] > 0) {
            echo rex_view::info("Übersprungen: {$results['skipped_count']} IPs (bereits gesperrt oder in Positivliste).");
        }
    }
}

// IP manuell sperren
if (rex_post('add_blocked_ip', 'bool')) {
    $ip = rex_post('ip_address', 'string', '');
    $duration = rex_post('block_duration', 'string', 'permanent');
    $reason = rex_post('reason', 'string', '');
    
    if (empty($ip)) {
        echo rex_view::error($addon->i18n('upkeep_ips_blocked_ip_required'));
    } else {
        $result = IntrusionPrevention::blockIpManually($ip, $duration, $reason);
        
        if ($result['success']) {
            echo rex_view::success($result['message']);
        } else {
            // Zeige spezifische Fehlermeldung
            $errorMsg = $result['message'];
            
            // Füge Hilfetext für häufige Fehler hinzu
            switch ($result['error_code']) {
                case 'INVALID_IP_FORMAT':
                    $errorMsg .= '<br><small class="text-muted">Beispiele für gültige IP-Adressen: 192.168.1.100, 2001:db8::8a2e:370:7334</small>';
                    break;
                case 'IP_ALREADY_BLOCKED':
                    $errorMsg .= '<br><small class="text-muted">Sie können die IP-Adresse erst entsperren und dann erneut sperren.</small>';
                    break;
                case 'IP_IN_POSITIVLISTE':
                    $errorMsg .= '<br><small class="text-muted">Gehen Sie zu IPS → Positivliste, um die IP-Adresse zu entfernen.</small>';
                    break;
                case 'DATABASE_ERROR':
                    $errorMsg .= '<br><small class="text-muted">Prüfen Sie die REDAXO-Logs für weitere Details oder kontaktieren Sie den Administrator.</small>';
                    break;
            }
            
            echo rex_view::error($errorMsg);
        }
    }
}

// IP entsperren
if (rex_get('action') === 'unblock' && rex_get('ip', 'string')) {
    $ip = rex_get('ip', 'string');
    if (IntrusionPrevention::unblockIp($ip)) {
        echo rex_view::success("IP {$ip} wurde entsperrt");
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_unblock_error', $ip));
    }
}

// Formular zum manuellen Hinzufügen von gesperrten IPs
$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_ips_blocked_add'), false);
$fragment->setVar('body', '
<div class="panel-body">
    <div class="alert alert-info">
        <p><i class="fa fa-info-circle"></i> ' . $addon->i18n('upkeep_ips_blocked_help') . '</p>
        <ul class="small" style="margin-bottom: 0;">
            <li><strong>IPv4:</strong> z.B. 192.168.1.100, 203.0.113.0</li>
            <li><strong>IPv6:</strong> z.B. 2001:db8::1, ::1</li>
            <li><strong>CIDR IPv4:</strong> z.B. 192.168.1.0/24, 10.0.0.0/8</li>
            <li><strong>CIDR IPv6:</strong> z.B. 2001:db8::/32</li>
            <li><strong>Hinweis:</strong> IPs aus der Positivliste können nicht gesperrt werden</li>
        </ul>
    </div>
    
    <form action="' . rex_url::currentBackendPage() . '" method="post" id="blockIpForm">
        <div class="row">
            <div class="col-md-4">
                <div class="form-group">
                    <label for="ip_address">' . $addon->i18n('upkeep_ips_ip_address') . ' <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="ip_address" name="ip_address" 
                           placeholder="192.168.1.100 oder 192.168.1.0/24" required 
                           title="Geben Sie eine gültige IPv4/IPv6 Adresse oder CIDR-Notation ein">
                    <small class="help-block">Einzelne IP oder CIDR-Bereich (z.B. 192.168.1.0/24)</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="form-group">
                    <label for="block_duration">' . $addon->i18n('upkeep_ips_block_duration') . '</label>
                    <select class="form-control selectpicker" id="block_duration" name="block_duration" data-style="btn-default">
                        <option value="permanent">' . $addon->i18n('upkeep_ips_block_duration_permanent') . '</option>
                        <option value="1h">' . $addon->i18n('upkeep_ips_block_duration_1h') . '</option>
                        <option value="6h">' . $addon->i18n('upkeep_ips_block_duration_6h') . '</option>
                        <option value="24h">' . $addon->i18n('upkeep_ips_block_duration_24h') . '</option>
                        <option value="7d">' . $addon->i18n('upkeep_ips_block_duration_7d') . '</option>
                        <option value="30d">' . $addon->i18n('upkeep_ips_block_duration_30d') . '</option>
                    </select>
                </div>
            </div>
            <div class="col-md-5">
                <div class="form-group">
                    <label for="reason">' . $addon->i18n('upkeep_ips_description') . '</label>
                    <input type="text" class="form-control" id="reason" name="reason" 
                           placeholder="' . $addon->i18n('upkeep_ips_block_reason_manual') . '"
                           maxlength="255">
                    <small class="help-block">Optional: Grund für die Sperrung (max. 255 Zeichen)</small>
                </div>
            </div>
        </div>
        <div class="form-group">
            <button type="submit" name="add_blocked_ip" value="1" class="btn btn-primary">
                <i class="fa fa-ban"></i> ' . $addon->i18n('upkeep_ips_blocked_add') . '
            </button>
            <button type="button" class="btn btn-default" onclick="document.getElementById(\'blockIpForm\').reset();">
                <i class="fa fa-refresh"></i> Zurücksetzen
            </button>
        </div>
    </form>
</div>

<script>
// Client-side IP and CIDR validation
document.getElementById("ip_address").addEventListener("input", function() {
    var input = this.value.trim();
    
    if (!input) {
        this.setCustomValidity("");
        return;
    }
    
    // Check if it\'s CIDR notation
    if (input.includes("/")) {
        if (validateCidr(input)) {
            this.setCustomValidity("");
        } else {
            this.setCustomValidity("Bitte geben Sie eine gültige CIDR-Notation ein (z.B. 192.168.1.0/24)");
        }
    } else {
        // Single IP validation
        var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        var ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        
        if (ipv4Regex.test(input) || ipv6Regex.test(input)) {
            this.setCustomValidity("");
        } else {
            this.setCustomValidity("Bitte geben Sie eine gültige IPv4 oder IPv6 Adresse ein");
        }
    }
});

function validateCidr(cidr) {
    var parts = cidr.split("/");
    if (parts.length !== 2) return false;
    
    var ip = parts[0];
    var prefix = parseInt(parts[1]);
    
    // Validate IP part
    var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    var ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    
    if (ipv4Regex.test(ip)) {
        // IPv4: prefix 0-32
        return prefix >= 0 && prefix <= 32;
    } else if (ipv6Regex.test(ip)) {
        // IPv6: prefix 0-128
        return prefix >= 0 && prefix <= 128;
    }
    
    return false;
}
</script>
', false);
echo $fragment->parse('core/page/section.php');

// Bulk-Import Formular
$bulkFragment = new rex_fragment();
$bulkFragment->setVar('class', 'edit', false);
$bulkFragment->setVar('title', 'Bulk-Import: Mehrere IPs gleichzeitig sperren', false);
$bulkFragment->setVar('body', '
<div class="panel-body">
    <div class="alert alert-info">
        <p><i class="fa fa-upload"></i> Importieren Sie mehrere IP-Adressen oder CIDR-Bereiche gleichzeitig.</p>
        <ul class="small" style="margin-bottom: 0;">
            <li>Eine IP-Adresse oder CIDR pro Zeile</li>
            <li>Kommentare mit # am Zeilenanfang werden ignoriert</li>
            <li>Beispiel: 192.168.1.100, 10.0.0.0/8, 2001:db8::/32</li>
        </ul>
    </div>
    
    <form action="' . rex_url::currentBackendPage() . '" method="post" id="bulkImportForm">
        <div class="row">
            <div class="col-md-6">
                <div class="form-group">
                    <label for="ip_list">IP-Adressen/CIDR-Bereiche <span class="text-danger">*</span></label>
                    <textarea class="form-control" id="ip_list" name="ip_list" rows="10" required
                              placeholder="192.168.1.100&#10;10.0.0.0/8&#10;203.0.113.0/24&#10;# Kommentar wird ignoriert&#10;2001:db8::/32"></textarea>
                    <small class="help-block">Eine IP/CIDR pro Zeile, Kommentare mit # möglich</small>
                </div>
            </div>
            <div class="col-md-3">
                <div class="form-group">
                    <label for="bulk_duration">Sperrdauer für alle IPs</label>
                    <select class="form-control selectpicker" id="bulk_duration" name="bulk_duration" data-style="btn-default">
                        <option value="1h">' . $addon->i18n('upkeep_ips_block_duration_1h') . '</option>
                        <option value="6h">' . $addon->i18n('upkeep_ips_block_duration_6h') . '</option>
                        <option value="24h" selected>' . $addon->i18n('upkeep_ips_block_duration_24h') . '</option>
                        <option value="7d">' . $addon->i18n('upkeep_ips_block_duration_7d') . '</option>
                        <option value="30d">' . $addon->i18n('upkeep_ips_block_duration_30d') . '</option>
                        <option value="permanent">' . $addon->i18n('upkeep_ips_block_duration_permanent') . '</option>
                    </select>
                </div>
            </div>
            <div class="col-md-3">
                <div class="form-group">
                    <label for="bulk_reason">Grund für Bulk-Import</label>
                    <input type="text" class="form-control" id="bulk_reason" name="bulk_reason" 
                           placeholder="z.B. Spam-Liste vom ' . date('Y-m-d') . '"
                           maxlength="255">
                    <small class="help-block">Optional: Grund für alle IPs</small>
                </div>
            </div>
        </div>
        <div class="form-group">
            <button type="submit" name="bulk_import_ips" value="1" class="btn btn-warning">
                <i class="fa fa-upload"></i> IPs importieren und sperren
            </button>
            <button type="button" class="btn btn-default" onclick="document.getElementById(\'bulkImportForm\').reset();">
                <i class="fa fa-refresh"></i> Formular leeren
            </button>
            <button type="button" class="btn btn-info" onclick="showBulkExamples()">
                <i class="fa fa-question-circle"></i> Beispiele
            </button>
        </div>
    </form>
    
    <div id="bulkExamples" style="display: none;">
        <hr>
        <h5>Beispiel-IP-Listen:</h5>
        <div class="row">
            <div class="col-md-4">
                <h6>Bekannte Spam-IPs:</h6>
                <pre class="small">203.0.113.100
203.0.113.101
203.0.113.102</pre>
            </div>
            <div class="col-md-4">
                <h6>IP-Bereiche:</h6>
                <pre class="small"># Verdächtiges Netzwerk
10.0.0.0/8
192.168.1.0/24
172.16.0.0/12</pre>
            </div>
            <div class="col-md-4">
                <h6>Gemischte Liste:</h6>
                <pre class="small"># Liste vom ' . date('Y-m-d') . '
203.0.113.50
# Ganzes Netzwerk sperren
198.51.100.0/24
2001:db8:bad::/48</pre>
            </div>
        </div>
    </div>
</div>

<script>
function showBulkExamples() {
    var examples = document.getElementById("bulkExamples");
    if (examples.style.display === "none") {
        examples.style.display = "block";
    } else {
        examples.style.display = "none";
    }
}
</script>
', false);
echo $bulkFragment->parse('core/page/section.php');

// Quick Actions: Bedrohliche IPs schnell sperren
$recentThreatIps = IntrusionPrevention::getRecentThreatIps(10);
if (!empty($recentThreatIps)) {
    echo '<div class="panel panel-info">';
    echo '<div class="panel-heading">';
    echo '<i class="fa fa-bolt"></i> Schnellaktionen: Bedrohliche IPs sperren';
    echo '</div>';
    echo '<div class="panel-body">';
    echo '<p class="text-muted">IPs mit den meisten Bedrohungen in den letzten 24 Stunden:</p>';
    echo '<div class="table-responsive">';
    echo '<table class="table table-condensed">';
    echo '<thead><tr>';
    echo '<th>IP-Adresse</th>';
    echo '<th><i class="fa fa-globe"></i> Land</th>';
    echo '<th>Bedrohungen</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_severity') . '</th>';
    echo '<th>Letzte Bedrohung</th>';
    echo '<th class="text-center">Aktion</th>';
    echo '</tr></thead><tbody>';
    
    foreach ($recentThreatIps as $threatIp) {
        $countryInfo = IntrusionPrevention::getCountryByIp($threatIp['ip']);
        $severityClass = match($threatIp['max_severity']) {
            'critical' => 'label-danger',
            'high' => 'label-warning',
            'medium' => 'label-info',
            default => 'label-default'
        };
        
        echo '<tr>';
        echo '<td><code>' . rex_escape($threatIp['ip']) . '</code></td>';
        echo '<td>';
        if ($countryInfo && $countryInfo['code'] !== 'UNKNOWN') {
            echo '<small class="text-muted">' . rex_escape($countryInfo['name']) . '</small>';
        } else {
            echo '<small class="text-muted">-</small>';
        }
        echo '</td>';
        echo '<td><span class="badge">' . $threatIp['threat_count'] . '</span></td>';
        echo '<td><span class="label ' . $severityClass . '">' . ucfirst($threatIp['max_severity']) . '</span></td>';
        echo '<td><small>' . date('d.m.Y H:i', strtotime($threatIp['last_threat'])) . '</small></td>';
        echo '<td class="text-center">';
        echo '<form method="post" style="display:inline;">';
        echo '<input type="hidden" name="ip_address" value="' . rex_escape($threatIp['ip']) . '">';
        echo '<input type="hidden" name="block_duration" value="24h">';
        echo '<input type="hidden" name="reason" value="Hohe Bedrohungsaktivität (' . $threatIp['threat_count'] . ' Bedrohungen)">';
        echo '<button type="submit" name="add_blocked_ip" value="1" class="btn btn-xs btn-danger" ';
        echo 'onclick="return confirm(\'IP ' . rex_escape($threatIp['ip']) . ' für 24h sperren?\')" ';
        echo 'title="IP für 24 Stunden sperren">';
        echo '<i class="fa fa-ban"></i> 24h sperren';
        echo '</button>';
        echo '</form>';
        echo '</td>';
        echo '</tr>';
    }
    
    echo '</tbody></table>';
    echo '</div>';
    echo '<p class="small text-muted"><i class="fa fa-info-circle"></i> Diese IPs haben in den letzten 24 Stunden die meisten Sicherheitsbedrohungen verursacht und werden automatisch für 24 Stunden gesperrt.</p>';
    echo '</div>';
    echo '</div>';
}

// Gesperrte IPs laden
$sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                WHERE expires_at IS NULL OR expires_at > NOW() 
                ORDER BY created_at DESC");

echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-shield"></i> ' . $addon->i18n('upkeep_ips_blocked_entries');
echo '</div>';

if ($sql->getRows() > 0) {
    echo '<div class="table-responsive">';
    echo '<table class="table table-striped table-hover">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . $addon->i18n('upkeep_ips_ip') . '</th>';
    echo '<th><i class="fa fa-globe"></i> Land</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_type') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_severity') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_reason') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_expires') . '</th>';
    echo '<th>' . $addon->i18n('upkeep_ips_created') . '</th>';
    echo '<th class="text-center">' . $addon->i18n('upkeep_actions') . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';
    
    while ($sql->hasNext()) {
        $ip = $sql->getValue('ip_address');
        $blockType = $sql->getValue('block_type');
        $expiresAt = $sql->getValue('expires_at');
        $reason = $sql->getValue('reason');
        $threatLevel = $sql->getValue('threat_level');
        $createdAt = $sql->getValue('created_at');
        
        // Länder-Information ermitteln (nur wenn GeoIP verfügbar)
        $countryInfo = null;
        if (class_exists('KLXM\Upkeep\IntrusionPrevention')) {
            try {
                $countryInfo = IntrusionPrevention::getCountryByIp($ip);
            } catch (Exception $e) {
                // Fehler ignorieren
            }
        }
        
        echo '<tr>';
        echo '<td><span class="label label-default">' . rex_escape($ip) . '</span></td>';
        
        // Land-Spalte
        echo '<td>';
        if ($countryInfo && $countryInfo['code'] !== 'UNKNOWN') {
            echo '<small class="text-muted">' . rex_escape($countryInfo['name']) . '</small>';
        } else {
            echo '<small class="text-muted">-</small>';
        }
        echo '</td>';
        echo '<td>';
        $typeClass = $blockType === 'permanent' ? 'label-danger' : 'label-warning';
        echo '<span class="label ' . $typeClass . '">' . ucfirst($blockType) . '</span>';
        echo '</td>';
        echo '<td>';
        $severityClass = match($threatLevel) {
            'critical' => 'label-danger',
            'high' => 'label-warning',
            'medium' => 'label-info',
            'low' => 'label-default',
            default => 'label-default'
        };
        echo '<span class="label ' . $severityClass . '">' . ucfirst($threatLevel) . '</span>';
        echo '</td>';
        echo '<td>' . rex_escape(substr($reason, 0, 50)) . (strlen($reason) > 50 ? '...' : '') . '</td>';
        echo '<td>' . ($expiresAt ? date('d.m.Y H:i', strtotime($expiresAt)) : 'Permanent') . '</td>';
        echo '<td>' . date('d.m.Y H:i', strtotime($createdAt)) . '</td>';
        echo '<td class="text-center">';
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'unblock', 'ip' => $ip]) . '" class="btn btn-xs btn-success" onclick="return confirm(\'' . $addon->i18n('upkeep_ips_confirm_unblock') . '\')">';
        echo '<i class="fa fa-unlock"></i> Entsperren';
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
    echo '<p class="text-muted"><i class="fa fa-check-circle text-success"></i> ' . $addon->i18n('upkeep_ips_no_blocked_entries') . '</p>';
    echo '</div>';
}

echo '</div>';
