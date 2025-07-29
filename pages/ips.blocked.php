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

// IP entsperren
if (rex_get('action') === 'unblock' && rex_get('ip', 'string')) {
    $ip = rex_get('ip', 'string');
    if (IntrusionPrevention::unblockIp($ip)) {
        echo rex_view::success("IP {$ip} wurde entsperrt");
    } else {
        echo rex_view::error("Fehler beim Entsperren der IP {$ip}");
    }
}

// Gesperrte IPs laden
$sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                WHERE expires_at IS NULL OR expires_at > NOW() 
                ORDER BY created_at DESC");

echo '<div class="panel panel-default">';
echo '<div class="panel-heading">';
echo '<i class="fa fa-shield"></i> ' . $addon->i18n('upkeep_ips_blocked');
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
        echo '<a href="' . rex_url::currentBackendPage(['action' => 'unblock', 'ip' => $ip]) . '" class="btn btn-xs btn-success" onclick="return confirm(\'IP ' . rex_escape($ip) . ' entsperren?\')">';
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
    echo '<p class="text-muted"><i class="fa fa-check-circle text-success"></i> Keine gesperrten IPs vorhanden</p>';
    echo '</div>';
}

echo '</div>';
