<?php
/**
 * Upkeep AddOn - Wartung Hauptseite
 * 
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

$addon = rex_addon::get('upkeep');

// Korrektur für falsche Standard-Konfiguration (einmalig)
if ($addon->getConfig('all_domains_locked') === true && 
    !$addon->getConfig('frontend_active', false) && 
    !$addon->getConfig('backend_active', false)) {
    // Wenn all_domains_locked auf true steht, aber weder Frontend noch Backend aktiv sind,
    // dann war das ein Konfigurationsfehler - korrigieren
    $addon->setConfig('all_domains_locked', false);
}

// Frontend Wartungsstatus
$frontendActive = $addon->getConfig('frontend_active', false);
$backendActive = $addon->getConfig('backend_active', false);
$allDomainsLocked = $addon->getConfig('all_domains_locked', false);

// YRewrite Domain-Status (falls verfügbar)
$domainCount = 0;
$lockedDomains = [];
if (rex_addon::get('yrewrite')->isAvailable()) {
    $domains = rex_yrewrite::getDomains();
    $domainCount = count($domains);
    
    foreach ($domains as $domain) {
        $domainConfig = $addon->getConfig('domain_' . $domain->getId(), []);
        if (!empty($domainConfig['maintenance_active'])) {
            $lockedDomains[] = $domain->getName();
        }
    }
}

// Status-Klassen
$frontendStatusClass = $frontendActive ? 'text-success' : 'text-muted';
$backendStatusClass = $backendActive ? 'text-warning' : 'text-muted';
$domainStatusClass = (!empty($lockedDomains) || $allDomainsLocked) ? 'text-warning' : 'text-muted';

echo rex_view::title($addon->i18n('upkeep_maintenance_title'));

?>

<div class="row">
    <div class="col-md-4">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-globe"></i> 
                    <?= $addon->i18n('upkeep_frontend_title') ?>
                </h3>
            </div>
            <div class="panel-body">
                <div class="maintenance-status <?= $frontendStatusClass ?>">
                    <i class="rex-icon fa fa-<?= $frontendActive ? 'check-circle' : 'times-circle' ?>"></i>
                    <span class="status-text">
                        <?= $frontendActive ? $addon->i18n('upkeep_status_active') : $addon->i18n('upkeep_status_inactive') ?>
                    </span>
                </div>
                
                <div class="maintenance-info">
                    <?php if ($frontendActive): ?>
                        <p class="text-info">
                            <i class="rex-icon fa fa-info-circle"></i>
                            <?= $addon->i18n('upkeep_frontend_active_info') ?>
                        </p>
                        
                        <?php
                        $allowedIPs = explode(',', $addon->getConfig('allowed_ips', ''));
                        $allowedIPs = array_filter(array_map('trim', $allowedIPs));
                        if (!empty($allowedIPs)): ?>
                            <p class="text-muted">
                                <small>
                                    <i class="rex-icon fa fa-shield"></i>
                                    <?= count($allowedIPs) ?> <?= $addon->i18n('upkeep_allowed_ips') ?>
                                </small>
                            </p>
                        <?php endif; ?>
                    <?php else: ?>
                        <p class="text-muted">
                            <?= $addon->i18n('upkeep_frontend_inactive_info') ?>
                        </p>
                    <?php endif; ?>
                </div>
                
                <div class="maintenance-actions">
                    <a href="<?= rex_url::backendPage('upkeep/maintenance/frontend') ?>" class="btn btn-primary btn-sm">
                        <i class="rex-icon fa fa-cog"></i> <?= $addon->i18n('upkeep_configure') ?>
                    </a>
                    
                    <?php if ($frontendActive): ?>
                        <a href="<?= rex_url::backendPage('upkeep/maintenance/frontend', ['action' => 'deactivate']) ?>" 
                           class="btn btn-success btn-sm" 
                           onclick="return confirm('<?= $addon->i18n('upkeep_confirm_deactivate') ?>')">
                            <i class="rex-icon fa fa-power-off"></i> <?= $addon->i18n('upkeep_deactivate') ?>
                        </a>
                    <?php else: ?>
                        <a href="<?= rex_url::backendPage('upkeep/maintenance/frontend', ['action' => 'activate']) ?>" 
                           class="btn btn-default btn-sm"
                           onclick="return confirm('<?= $addon->i18n('upkeep_confirm_activate') ?>')">
                            <i class="rex-icon fa fa-power-off"></i> <?= $addon->i18n('upkeep_activate') ?>
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-users"></i> 
                    <?= $addon->i18n('upkeep_backend_title') ?>
                </h3>
            </div>
            <div class="panel-body">
                <div class="maintenance-status <?= $backendStatusClass ?>">
                    <i class="rex-icon fa fa-<?= $backendActive ? 'exclamation-triangle' : 'times-circle' ?>"></i>
                    <span class="status-text">
                        <?= $backendActive ? $addon->i18n('upkeep_status_active') : $addon->i18n('upkeep_status_inactive') ?>
                    </span>
                </div>
                
                <div class="maintenance-info">
                    <?php if ($backendActive): ?>
                        <p class="text-warning">
                            <i class="rex-icon fa fa-warning"></i>
                            <?= $addon->i18n('upkeep_backend_active_info') ?>
                        </p>
                    <?php else: ?>
                        <p class="text-muted">
                            <?= $addon->i18n('upkeep_backend_inactive_info') ?>
                        </p>
                    <?php endif; ?>
                </div>
                
                <div class="maintenance-actions">
                    <a href="<?= rex_url::backendPage('upkeep/maintenance/backend') ?>" class="btn btn-primary btn-sm">
                        <i class="rex-icon fa fa-cog"></i> <?= $addon->i18n('upkeep_configure') ?>
                    </a>
                    
                    <?php if ($backendActive): ?>
                        <a href="<?= rex_url::backendPage('upkeep/maintenance/backend', ['action' => 'deactivate']) ?>" 
                           class="btn btn-warning btn-sm"
                           onclick="return confirm('<?= $addon->i18n('upkeep_confirm_deactivate_backend') ?>')">
                            <i class="rex-icon fa fa-power-off"></i> <?= $addon->i18n('upkeep_deactivate') ?>
                        </a>
                    <?php else: ?>
                        <a href="<?= rex_url::backendPage('upkeep/maintenance/backend', ['action' => 'activate']) ?>" 
                           class="btn btn-default btn-sm"
                           onclick="return confirm('<?= $addon->i18n('upkeep_confirm_activate_backend') ?>')">
                            <i class="rex-icon fa fa-power-off"></i> <?= $addon->i18n('upkeep_activate') ?>
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">
                    <i class="rex-icon fa fa-sitemap"></i> 
                    <?= $addon->i18n('upkeep_domains_title') ?>
                </h3>
            </div>
            <div class="panel-body">
                <div class="maintenance-status <?= $domainStatusClass ?>">
                    <i class="rex-icon fa fa-<?= (!empty($lockedDomains) || $allDomainsLocked) ? 'exclamation-triangle' : 'times-circle' ?>"></i>
                    <span class="status-text">
                        <?php if ($allDomainsLocked): ?>
                            <?= $addon->i18n('upkeep_all_domains_locked') ?>
                        <?php elseif (!empty($lockedDomains)): ?>
                            <?= count($lockedDomains) ?> <?= $addon->i18n('upkeep_domains_locked') ?>
                        <?php else: ?>
                            <?= $addon->i18n('upkeep_no_domains_locked') ?>
                        <?php endif; ?>
                    </span>
                </div>
                
                <div class="maintenance-info">
                    <?php if (rex_addon::get('yrewrite')->isAvailable()): ?>
                        <p class="text-muted">
                            <i class="rex-icon fa fa-info-circle"></i>
                            <?= $domainCount ?> <?= $addon->i18n('upkeep_total_domains') ?>
                        </p>
                        
                        <?php if ($allDomainsLocked): ?>
                            <p class="text-warning">
                                <small>
                                    <i class="rex-icon fa fa-exclamation-triangle"></i>
                                    <?= $addon->i18n('upkeep_all_domains_forced_locked') ?>
                                </small>
                            </p>
                        <?php endif; ?>
                        
                        <?php if (!empty($lockedDomains)): ?>
                            <div class="locked-domains">
                                <small class="text-warning">
                                    <strong><?= $addon->i18n('upkeep_locked_domains') ?>:</strong><br>
                                    <?= implode('<br>', array_slice($lockedDomains, 0, 3)) ?>
                                    <?php if (count($lockedDomains) > 3): ?>
                                        <br><em>+ <?= count($lockedDomains) - 3 ?> weitere...</em>
                                    <?php endif; ?>
                                </small>
                            </div>
                        <?php endif; ?>
                    <?php else: ?>
                        <p class="text-muted">
                            <i class="rex-icon fa fa-exclamation-circle"></i>
                            <?= $addon->i18n('upkeep_yrewrite_required') ?>
                        </p>
                    <?php endif; ?>
                </div>
                
                <div class="maintenance-actions">
                    <a href="<?= rex_url::backendPage('upkeep/maintenance/domains') ?>" class="btn btn-primary btn-sm">
                        <i class="rex-icon fa fa-cog"></i> <?= $addon->i18n('upkeep_configure') ?>
                    </a>
                    
                    <?php if (rex_addon::get('yrewrite')->isAvailable()): ?>
                        <?php if ($allDomainsLocked): ?>
                            <a href="<?= rex_url::backendPage('upkeep/maintenance/domains', ['action' => 'unlock_all']) ?>" 
                               class="btn btn-warning btn-sm"
                               onclick="return confirm('<?= $addon->i18n('upkeep_confirm_unlock_all_domains') ?>')">
                                <i class="rex-icon fa fa-unlock"></i> <?= $addon->i18n('upkeep_unlock_all') ?>
                            </a>
                        <?php else: ?>
                            <a href="<?= rex_url::backendPage('upkeep/maintenance/domains', ['action' => 'lock_all']) ?>" 
                               class="btn btn-default btn-sm"
                               onclick="return confirm('<?= $addon->i18n('upkeep_confirm_lock_all_domains') ?>')">
                                <i class="rex-icon fa fa-lock"></i> <?= $addon->i18n('upkeep_lock_all') ?>
                            </a>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php if ($frontendActive || $backendActive || !empty($lockedDomains) || $allDomainsLocked): ?>
<div class="row">
    <div class="col-md-12">
        <div class="alert alert-info">
            <h4><i class="rex-icon fa fa-info-circle"></i> <?= $addon->i18n('upkeep_maintenance_active_notice') ?></h4>
            <p><?= $addon->i18n('upkeep_maintenance_active_description') ?></p>
            
            <div class="maintenance-emergency">
                <strong><?= $addon->i18n('upkeep_emergency_access') ?>:</strong><br>
                <code>touch <?= rex_path::base('.emergency') ?></code>
                <p class="help-block">
                    <?= $addon->i18n('upkeep_emergency_access_description') ?>
                </p>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<style>
.maintenance-status {
    font-size: 16px;
    font-weight: bold;
    margin-bottom: 15px;
}

.maintenance-status i {
    margin-right: 8px;
}

.maintenance-info {
    margin-bottom: 20px;
    min-height: 60px;
}

.maintenance-actions {
    text-align: center;
}

.maintenance-actions .btn {
    margin: 2px;
}

.locked-domains {
    margin-top: 10px;
    padding: 8px;
    background-color: #fcf8e3;
    border-left: 4px solid #f0ad4e;
    border-radius: 3px;
}

.maintenance-emergency {
    margin-top: 15px;
    padding: 10px;
    background-color: #f5f5f5;
    border-left: 4px solid #337ab7;
    border-radius: 3px;
}

.maintenance-emergency code {
    background-color: #333;
    color: #fff;
    padding: 4px 8px;
    border-radius: 3px;
    font-family: 'Monaco', 'Consolas', monospace;
}
</style>
