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

// IP manuell sperren
if (rex_post('add_blocked_ip', 'bool')) {
    $ip = rex_post('ip_address', 'string', '');
    $duration = rex_post('block_duration', 'string', 'permanent');
    $reason = rex_post('reason', 'string', '');
    
    if ($ip) {
        if (IntrusionPrevention::blockIpManually($ip, $duration, $reason)) {
            echo rex_view::success($addon->i18n('upkeep_ips_blocked_added'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_ips_error_blocking'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_ips_blocked_ip_required'));
    }
}

// IP entsperren
if (rex_get('action') === 'unblock' && rex_get('ip', 'string')) {
    $ip = rex_get('ip', 'string');
    if (IntrusionPrevention::unblockIp($ip)) {
        echo rex_view::success("IP {$ip} wurde entsperrt");
    } else {
        echo rex_view::error("Fehler beim Entsperren der IP {$ip}");
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
    </div>
    
    <form action="' . rex_url::currentBackendPage() . '" method="post">
        <div class="row">
            <div class="col-md-4">
                <div class="form-group">
                    <label for="ip_address">' . $addon->i18n('upkeep_ips_ip_address') . ' <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="ip_address" name="ip_address" placeholder="192.168.1.100" required>
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
                    <input type="text" class="form-control" id="reason" name="reason" placeholder="' . $addon->i18n('upkeep_ips_block_reason_manual') . '">
                </div>
            </div>
        </div>
        <div class="form-group">
            <button type="submit" name="add_blocked_ip" value="1" class="btn btn-primary">
                <i class="fa fa-ban"></i> ' . $addon->i18n('upkeep_ips_blocked_add') . '
            </button>
        </div>
    </form>
</div>
', false);
echo $fragment->parse('core/page/section.php');

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
        
        echo '<tr>';
        echo '<td><span class="label label-default">' . rex_escape($ip) . '</span></td>';
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
