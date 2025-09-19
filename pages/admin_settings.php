<?php
/**
 * Admin Settings für Wartungsfreigaben
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
        echo rex_view::success('Einstellungen wurden gespeichert.');
    }
}

// Aktuelle Werte laden
$currentReleaseDays = $addon->getConfig('admin_release_days', 30);
$phpReleased = $advisor->isCheckReleased('php_config');
$dbReleased = $advisor->isCheckReleased('database');
$serverReleased = $advisor->isCheckReleased('server_status');

?>

<div class="row">
    <div class="col-lg-8">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="fa fa-cog"></i> Admin-Wartungsfreigaben
                </h3>
            </div>
            <div class="panel-body">
                <p class="text-muted">
                    Als Administrator können Sie Wartungshinweise für bestimmte System-Checks temporär freigeben. 
                    Diese werden dann für normale Benutzer als "geprüft" markiert und lösen keine Wartungshinweise aus.
                </p>
                
                <form method="post">
                    
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