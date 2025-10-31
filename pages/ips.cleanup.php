<?php

use FriendsOfRedaxo\Upkeep\IntrusionPrevention;

$addon = rex_addon::get('upkeep');

// Manuelle Bereinigung ausführen
if (rex_post('cleanup', 'bool')) {
    $results = IntrusionPrevention::cleanupExpiredData();
    
    $messages = [];
    if ($results['expired_ips'] > 0) {
        $messages[] = $results['expired_ips'] . ' abgelaufene IP-Sperrungen gelöscht';
    }
    if ($results['old_threats'] > 0) {
        $messages[] = $results['old_threats'] . ' alte Bedrohungs-Logs gelöscht (älter als 30 Tage)';
    }
    if ($results['old_rate_limits'] > 0) {
        $messages[] = $results['old_rate_limits'] . ' alte Rate-Limit-Daten gelöscht';
    }
    
    if (empty($messages)) {
        echo rex_view::info('Keine Bereinigung notwendig - alle Daten sind aktuell.');
    } else {
        echo rex_view::success($addon->i18n('upkeep_ips_cleanup_success_detail', implode(', ', $messages)));
    }
}

// Bereinigungsstatistiken
$sql = rex_sql::factory();

// Abgelaufene IP-Sperrungen zählen
$sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
               WHERE block_type = 'temporary' AND expires_at IS NOT NULL AND expires_at < NOW()");
$expiredIps = (int) $sql->getValue('count');

// Alte Logs zählen
$sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " 
               WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
$oldThreats = (int) $sql->getValue('count');

// Alte Rate-Limit-Daten zählen
$sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
               WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR)");
$oldRateLimits = (int) $sql->getValue('count');

// Gesamtstatistiken
$sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips'));
$totalBlockedIps = (int) $sql->getValue('count');

$sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log'));
$totalThreats = (int) $sql->getValue('count');

?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">
            <i class="fa fa-cog"></i> IPS-Datenverwaltung
        </h3>
    </div>
    <div class="panel-body">
        
        <div class="row">
            <div class="col-md-6">
                <h4>Aktuelle Datenbank-Statistiken</h4>
                <table class="table table-striped">
                    <tr>
                        <td><strong>Gesperrte IPs (gesamt):</strong></td>
                        <td><span class="label label-<?= $totalBlockedIps > 0 ? 'warning' : 'success' ?>"><?= $totalBlockedIps ?></span></td>
                    </tr>
                    <tr>
                        <td><strong>Bedrohungs-Logs (gesamt):</strong></td>
                        <td><span class="label label-info"><?= $totalThreats ?></span></td>
                    </tr>
                    <tr>
                        <td colspan="2"><hr></td>
                    </tr>
                    <tr>
                        <td><strong>Abgelaufene IP-Sperrungen:</strong></td>
                        <td><span class="label label-<?= $expiredIps > 0 ? 'danger' : 'success' ?>"><?= $expiredIps ?></span></td>
                    </tr>
                    <tr>
                        <td><strong>Alte Bedrohungs-Logs (>30 Tage):</strong></td>
                        <td><span class="label label-<?= $oldThreats > 0 ? 'warning' : 'success' ?>"><?= $oldThreats ?></span></td>
                    </tr>
                    <tr>
                        <td><strong>Alte Rate-Limit-Daten (>2h):</strong></td>
                        <td><span class="label label-<?= $oldRateLimits > 0 ? 'warning' : 'success' ?>"><?= $oldRateLimits ?></span></td>
                    </tr>
                </table>
            </div>
            
            <div class="col-md-6">
                <h4>Automatische Bereinigung</h4>
                <div class="alert alert-info">
                    <h5><i class="fa fa-info-circle"></i> Automatischer Cleanup</h5>
                    <p>Das IPS führt automatisch eine Bereinigung durch:</p>
                    <ul>
                        <li><strong>Bei jedem Request</strong>: 1% Wahrscheinlichkeit für Cleanup</li>
                        <li><strong>Abgelaufene IPs</strong>: Werden bei Prüfung ignoriert</li>
                        <li><strong>Alte Logs</strong>: Werden nach 30 Tagen gelöscht</li>
                        <li><strong>Rate-Limits</strong>: Werden nach 2 Stunden gelöscht</li>
                    </ul>
                </div>
                
                <h4>Manuelle Bereinigung</h4>
                <?php if ($expiredIps > 0 || $oldThreats > 0 || $oldRateLimits > 0): ?>
                    <div class="alert alert-warning">
                        <strong><?= $addon->i18n('upkeep_cleanup_recommended_title') ?></strong><br>
                        <?= $addon->i18n('upkeep_ips_cleanup_found', $expiredIps + $oldThreats + $oldRateLimits) ?>
                    </div>
                <?php else: ?>
                    <div class="alert alert-success">
                        <strong><?= $addon->i18n('upkeep_database_clean_title') ?></strong><br>
                        <?= $addon->i18n('upkeep_ips_cleanup_no_cleanup_needed') ?>
                    </div>
                <?php endif; ?>
                
                <form method="post">
                    <button type="submit" name="cleanup" value="1" class="btn btn-warning" 
                            <?= ($expiredIps + $oldThreats + $oldRateLimits === 0) ? 'disabled' : '' ?>>
                        <i class="fa fa-trash"></i> Jetzt bereinigen
                    </button>
                </form>
            </div>
        </div>
        
    </div>
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">
            <i class="fa fa-terminal"></i> Konsolen-Kommando
        </h3>
    </div>
    <div class="panel-body">
        <p>Sie können die Bereinigung auch per Konsolen-Kommando durchführen:</p>
        <pre><code>php redaxo/bin/console upkeep:ips:cleanup</code></pre>
        <p class="help-block">
            <strong>Tipp:</strong> Fügen Sie dieses Kommando zu einem Cronjob hinzu, um regelmäßige Bereinigungen zu automatisieren.
            <br>Empfohlen: Täglich um 2:00 Uhr nachts.
        </p>
        
        <div class="alert alert-info">
            <h5><i class="fa fa-clock-o"></i> Cron-Beispiel</h5>
            <pre><code># Täglich um 2:00 Uhr IPS-Datenbank bereinigen
0 2 * * * cd /pfad/zu/redaxo && php redaxo/bin/console upkeep:ips:cleanup</code></pre>
        </div>
    </div>
</div>
