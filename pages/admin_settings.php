<?php
/**
 * Admin Settings für Wartungsfreigaben und Modulkonfiguration
 */

use KLXM\Upkeep\SecurityAdvisor;

$addon = rex_addon::get('upkeep');
$user = rex::getUser();

// Nur Admins haben Zugriff
if (!$user->isAdmin()) {
    echo rex_view::error('Nur Administratoren haben Zugriff auf diese Einstellungen.');
    return;
}

$advisor = new SecurityAdvisor();

// Handle Form Submissions
if (rex_post('submit', 'string')) {
    $success = true;
    $message = '';
    
    // Ablaufzeit in Tagen speichern
    $releaseDays = (int) rex_post('admin_release_days', 'int', 30);
    if ($releaseDays < 1 || $releaseDays > 180) {
        $releaseDays = 30;
    }
    $addon->setConfig('admin_release_days', $releaseDays);
    
    // Modul-Aktivierung/Deaktivierung - korrekte Checkbox-Behandlung
    // Bei Checkboxen: Wenn nicht gesetzt, dann false, sonst true
    $securityAdvisorEnabled = rex_post('security_advisor_enabled', 'int', 0) === 1;
    $mailSecurityEnabled = rex_post('mail_security_enabled', 'int', 0) === 1;
    $reportingEnabled = rex_post('reporting_enabled', 'int', 0) === 1;
    $ipsEnabled = rex_post('ips_enabled', 'int', 0) === 1;
    
    // Alternative Speichermethode über rex_config
    rex_config::set('upkeep', 'security_advisor_enabled', $securityAdvisorEnabled);
    rex_config::set('upkeep', 'mail_security_enabled', $mailSecurityEnabled);
    rex_config::set('upkeep', 'reporting_enabled', $reportingEnabled);
    rex_config::set('upkeep', 'ips_enabled', $ipsEnabled);
    
    // Zusätzlich über Addon-Konfiguration
    $addon->setConfig('security_advisor_enabled', $securityAdvisorEnabled);
    $addon->setConfig('mail_security_enabled', $mailSecurityEnabled);
    $addon->setConfig('reporting_enabled', $reportingEnabled);
    $addon->setConfig('ips_enabled', $ipsEnabled);
    
    // Prüfe ob die Werte tatsächlich gespeichert wurden
    $savedSecurityAdvisor = $addon->getConfig('security_advisor_enabled', true);
    $savedMailSecurity = $addon->getConfig('mail_security_enabled', true);
    $savedReporting = $addon->getConfig('reporting_enabled', true);
    $savedIps = $addon->getConfig('ips_enabled', true);
    
    // Admin-Freigaben verwalten
    $checkTypes = ['php_config', 'database', 'server_status', 'security_settings'];
    
    foreach ($checkTypes as $checkType) {
        $isReleased = (bool) rex_post("release_{$checkType}", 'int', 0);
        
        if ($isReleased) {
            $advisor->setAdminRelease($checkType);
        } else {
            $advisor->removeAdminRelease($checkType);
        }
    }
    
    if ($success) {
        $statusText = 'Einstellungen wurden gespeichert.<br>';
        $statusText .= '<small>';
        $statusText .= 'Security Advisor: ' . ($savedSecurityAdvisor ? 'Aktiviert' : 'Deaktiviert') . '<br>';
        $statusText .= 'Mail Security: ' . ($savedMailSecurity ? 'Aktiviert' : 'Deaktiviert') . '<br>';
        $statusText .= 'Reporting: ' . ($savedReporting ? 'Aktiviert' : 'Deaktiviert') . '<br>';
        $statusText .= 'IPS: ' . ($savedIps ? 'Aktiviert' : 'Deaktiviert');
        $statusText .= '</small>';
        echo rex_view::success($statusText);
    }
}

// Aktuelle Werte laden (nach eventuellem Speichern)
$currentReleaseDays = $addon->getConfig('admin_release_days', 30);

// Versuche Werte aus beiden Speichermethoden zu laden
$securityAdvisorEnabled = rex_config::get('upkeep', 'security_advisor_enabled', $addon->getConfig('security_advisor_enabled', true));
$mailSecurityEnabled = rex_config::get('upkeep', 'mail_security_enabled', $addon->getConfig('mail_security_enabled', true));
$reportingEnabled = rex_config::get('upkeep', 'reporting_enabled', $addon->getConfig('reporting_enabled', true));
$ipsEnabled = rex_config::get('upkeep', 'ips_enabled', $addon->getConfig('ips_enabled', true));

$phpReleased = $advisor->isCheckReleased('php_config');
$dbReleased = $advisor->isCheckReleased('database');
$serverReleased = $advisor->isCheckReleased('server_status');

?>

<div class="row">
    <div class="col-lg-8">
        <!-- Modul-Konfiguration Panel -->
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="fa fa-puzzle-piece"></i> Modul-Konfiguration
                </h3>
            </div>
            <div class="panel-body">
                <p class="text-muted">
                    Deaktivieren Sie hier Module, die für Ihre Installation nicht relevant sind. 
                    Deaktivierte Module werden aus der Navigation entfernt und ihre Dashboard-Kacheln ausgeblendet.
                </p>
                
                <form method="post">
                    
                    <!-- Security Advisor -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="security_advisor_enabled" value="1" <?= $securityAdvisorEnabled ? 'checked' : '' ?>>
                                <strong>Security Advisor aktiviert</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Sicherheitsanalyse und -empfehlungen für das System.
                            <?php if (!$securityAdvisorEnabled): ?>
                                <br><span class="text-warning">
                                    <i class="fa fa-exclamation-triangle"></i> Modul ist deaktiviert - Navigation und Dashboard-Kachel sind ausgeblendet
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <!-- Mail Security -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="mail_security_enabled" value="1" <?= $mailSecurityEnabled ? 'checked' : '' ?>>
                                <strong>Mail Security aktiviert</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Schutz vor Spam und verdächtigen E-Mails.
                            <?php if (!$mailSecurityEnabled): ?>
                                <br><span class="text-warning">
                                    <i class="fa fa-exclamation-triangle"></i> Modul ist deaktiviert - Navigation und Dashboard-Kachel sind ausgeblendet
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <!-- Reporting -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="reporting_enabled" value="1" <?= $reportingEnabled ? 'checked' : '' ?>>
                                <strong>Reporting aktiviert</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            System-Health-Monitoring und E-Mail-Berichte.
                            <?php if (!$reportingEnabled): ?>
                                <br><span class="text-warning">
                                    <i class="fa fa-exclamation-triangle"></i> Modul ist deaktiviert - Navigation und Dashboard-Kachel sind ausgeblendet
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <!-- IPS (Intrusion Prevention System) -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="ips_enabled" value="1" <?= $ipsEnabled ? 'checked' : '' ?>>
                                <strong>IPS (Intrusion Prevention System) aktiviert</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Schutz vor Angriffen und verdächtigen Zugriffen.
                            <?php if (!$ipsEnabled): ?>
                                <br><span class="text-warning">
                                    <i class="fa fa-exclamation-triangle"></i> Modul ist deaktiviert - Navigation und Dashboard-Kachel sind ausgeblendet
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <hr>
                    
                    <h4>Admin-Wartungsfreigaben</h4>
                    <p class="text-muted">
                        Als Administrator können Sie Wartungshinweise für bestimmte System-Checks temporär freigeben. 
                        Diese werden dann für normale Benutzer als "geprüft" markiert und lösen keine Wartungshinweise aus.
                    </p>
                    
                    <!-- Ablaufzeit-Einstellung -->
                    <div class="form-group">
                        <label for="admin_release_days">
                            <strong>Freigabe-Dauer (in Tagen)</strong>
                        </label>
                        <select name="admin_release_days" id="admin_release_days" class="form-control" style="width: auto; display: inline-block;">
                            <?php
                            $options = [7 => '7 Tage', 14 => '14 Tage', 30 => '30 Tage', 60 => '60 Tage', 90 => '90 Tage', 120 => '120 Tage', 150 => '150 Tage', 180 => '180 Tage'];
                            foreach ($options as $days => $label):
                            ?>
                                <option value="<?= $days ?>" <?= $currentReleaseDays == $days ? 'selected' : '' ?>>
                                    <?= $label ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <small class="help-block">
                            Nach dieser Zeit werden die Freigaben automatisch zurückgesetzt und die Checks wieder aktiv.
                        </small>
                    </div>
                    
                    <hr>
                    
                    <!-- PHP-Konfiguration Freigabe -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="release_php_config" value="1" <?= $phpReleased ? 'checked' : '' ?>>
                                <strong>Server/PHP-Konfiguration als geprüft markieren</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Unterdrückt Warnungen zu PHP-Versionen und Server-Einstellungen für normale Benutzer.
                            <?php if ($phpReleased): ?>
                                <br><span class="text-success">
                                    <i class="fa fa-check"></i> Freigabe aktiv bis <?= date('d.m.Y H:i', $addon->getConfig('admin_release_php_config', 0) + ($currentReleaseDays * 24 * 60 * 60)) ?>
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <!-- Datenbank Freigabe -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="release_database" value="1" <?= $dbReleased ? 'checked' : '' ?>>
                                <strong>Datenbank-Status als geprüft markieren</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Unterdrückt Warnungen zu Datenbank-Versionen für normale Benutzer.
                            <?php if ($dbReleased): ?>
                                <br><span class="text-success">
                                    <i class="fa fa-check"></i> Freigabe aktiv bis <?= date('d.m.Y H:i', $addon->getConfig('admin_release_database', 0) + ($currentReleaseDays * 24 * 60 * 60)) ?>
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <!-- Server Status Freigabe -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="release_server_status" value="1" <?= $serverReleased ? 'checked' : '' ?>>
                                <strong>Server-Status als geprüft markieren</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Unterdrückt allgemeine Server-Status-Warnungen für normale Benutzer.
                            <?php if ($serverReleased): ?>
                                <br><span class="text-success">
                                    <i class="fa fa-check"></i> Freigabe aktiv bis <?= date('d.m.Y H:i', $addon->getConfig('admin_release_server_status', 0) + ($currentReleaseDays * 24 * 60 * 60)) ?>
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <!-- Sicherheitseinstellungen Freigabe -->
                    <div class="form-group">
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="release_security_settings" value="1" <?= $advisor->isCheckReleased('security_settings') ? 'checked' : '' ?>>
                                <strong>Sicherheitseinstellungen als geprüft markieren</strong>
                            </label>
                        </div>
                        <small class="text-muted">
                            Unterdrückt Warnungen zu fehlenden Security-Headers und anderen Sicherheitseinstellungen.
                            <?php if ($advisor->isCheckReleased('security_settings')): ?>
                                <br><span class="text-success">
                                    <i class="fa fa-check"></i> Freigabe aktiv bis <?= date('d.m.Y H:i', $addon->getConfig('admin_release_security_settings', 0) + ($currentReleaseDays * 24 * 60 * 60)) ?>
                                </span>
                            <?php endif; ?>
                        </small>
                    </div>
                    
                    <hr>
                    
                    <div class="form-group">
                        <button type="submit" name="submit" value="1" class="btn btn-primary">
                            <i class="fa fa-save"></i> Einstellungen speichern
                        </button>
                    </div>
                    
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-lg-4">
        <div class="panel panel-info">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="fa fa-info-circle"></i> Hinweise
                </h3>
            </div>
            <div class="panel-body">
                <h5>Modul-Deaktivierung</h5>
                <ul class="list-unstyled">
                    <li><i class="fa fa-check text-success"></i> Entfernt Navigation aus dem Menü</li>
                    <li><i class="fa fa-check text-success"></i> Blendet Dashboard-Kacheln aus</li>
                    <li><i class="fa fa-check text-success"></i> Funktionalität bleibt im Hintergrund aktiv</li>
                    <li><i class="fa fa-info text-info"></i> Reduziert UI-Überladung</li>
                </ul>
                
                <hr>
                
                <h5>Was passiert bei einer Freigabe?</h5>
                <ul class="list-unstyled">
                    <li><i class="fa fa-check text-success"></i> Die entsprechende Karte wird blau markiert</li>
                    <li><i class="fa fa-check text-success"></i> Status zeigt "GEPRÜFT" an</li>
                    <li><i class="fa fa-check text-success"></i> Keine Wartungshinweise für Benutzer</li>
                    <li><i class="fa fa-clock-o text-info"></i> Automatischer Ablauf nach gewählter Zeit</li>
                </ul>
                
                <hr>
                
                <h5>Sicherheitshinweis</h5>
                <p class="text-warning">
                    <i class="fa fa-exclamation-triangle"></i>
                    Freigaben sollten nur nach tatsächlicher Prüfung durch einen Techniker erfolgen.
                    Kritische Sicherheitsprobleme bleiben weiterhin sichtbar.
                </p>
            </div>
        </div>
    </div>
</div>