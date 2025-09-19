<?php

use KLXM\Upkeep\MailSecurityFilter;

$addon = rex_addon::get('upkeep');

// Mail Security Statistiken laden
$stats = MailSecurityFilter::getMailSecurityStats();

// Status-Panel
$content = '<div class="row">';

// Status Cards
$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . ($stats['active'] ? 'success' : 'danger') . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa fa-shield fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . ($stats['active'] ? $addon->i18n('upkeep_mail_security_active') : $addon->i18n('upkeep_mail_security_inactive')) . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_mail_security') . '</div>';
$content .= '</div></div></div>';
$content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/settings') . '">';
$content .= '<div class="panel-footer"><span class="pull-left">' . $addon->i18n('upkeep_settings') . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span><div class="clearfix"></div></div>';
$content .= '</a></div></div>';

// Rate Limiting Status
$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . ($stats['rate_limiting_enabled'] ? 'success' : 'warning') . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa fa-clock-o fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . ($stats['rate_limiting_enabled'] ? $addon->i18n('upkeep_mail_security_active') : $addon->i18n('upkeep_mail_security_inactive')) . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_mail_security_rate_limiting') . '</div>';
$content .= '</div></div></div>';
$content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/settings') . '">';
$content .= '<div class="panel-footer"><span class="pull-left">' . $addon->i18n('upkeep_configure') . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span><div class="clearfix"></div></div>';
$content .= '</a></div></div>';

// E-Mails heute
$mailsToday = isset($stats['rate_limiting']['total_mails']) ? (int) $stats['rate_limiting']['total_mails'] : 0;
$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-info">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa fa-envelope fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . $mailsToday . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_mail_security_emails_today') . '</div>';
$content .= '</div></div></div>';
$content .= '<div class="panel-footer"><span class="pull-left">Eindeutige IPs: ' . (isset($stats['rate_limiting']['unique_ips']) ? (int) $stats['rate_limiting']['unique_ips'] : 0) . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-info-circle"></i></span><div class="clearfix"></div></div>';
$content .= '</div></div>';

// Bedrohungen heute
$threatsToday = count($stats['threats_24h'] ?? []);
$content .= '<div class="col-lg-3 col-md-6">';
$content .= '<div class="panel panel-' . ($threatsToday > 0 ? 'danger' : 'success') . '">';
$content .= '<div class="panel-heading">';
$content .= '<div class="row">';
$content .= '<div class="col-xs-3"><i class="fa fa-exclamation-triangle fa-5x"></i></div>';
$content .= '<div class="col-xs-9 text-right">';
$content .= '<div class="huge">' . $threatsToday . '</div>';
$content .= '<div>' . $addon->i18n('upkeep_mail_security_threats_today') . '</div>';
$content .= '</div></div></div>';
$content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/threats') . '">';
$content .= '<div class="panel-footer"><span class="pull-left">' . $addon->i18n('upkeep_mail_security_details') . '</span>';
$content .= '<span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span><div class="clearfix"></div></div>';
$content .= '</a></div></div>';

$content .= '</div>'; // Ende row

// Bedrohungsübersicht
if (!empty($stats['threats_24h'])) {
    $content .= '<div class="row">';
    $content .= '<div class="col-lg-8">';
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_mail_security_top_threats') . '</h3></div>';
    $content .= '<div class="panel-body">';
    $content .= '<div class="table-responsive">';
    $content .= '<table class="table table-striped table-hover">';
    $content .= '<thead>';
    $content .= '<tr><th>' . $addon->i18n('upkeep_mail_security_threat_type') . '</th><th>' . $addon->i18n('upkeep_mail_security_count') . '</th><th>' . $addon->i18n('upkeep_ips_severity') . '</th><th>' . $addon->i18n('upkeep_ips_action') . '</th></tr>';
    $content .= '</thead>';
    $content .= '<tbody>';
    
    foreach (array_slice($stats['threats_24h'], 0, 10) as $threat) {
        $severityClass = match($threat['severity']) {
            'critical' => 'danger',
            'high' => 'warning',
            'medium' => 'info',
            default => 'default'
        };
        
        $threatTypeDisplay = str_replace('mail_', '', $threat['type']);
        $threatTypeDisplay = ucwords(str_replace('_', ' ', $threatTypeDisplay));
        
        $content .= '<tr>';
        $content .= '<td>' . rex_escape($threatTypeDisplay) . '</td>';
        $content .= '<td><span class="badge">' . $threat['count'] . '</span></td>';
        $content .= '<td><span class="label label-' . $severityClass . '">' . rex_escape($threat['severity']) . '</span></td>';
        $content .= '<td><a href="' . rex_url::backendPage('upkeep/mail_security/threats', ['filter' => $threat['type']]) . '" class="btn btn-xs btn-primary">' . $addon->i18n('upkeep_details') . '</a></td>';
        $content .= '</tr>';
    }
    
    $content .= '</tbody>';
    $content .= '</table>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
    
    // Quick Actions Panel
    $content .= '<div class="col-lg-4">';
    $content .= '<div class="panel panel-default">';
    $content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-cogs"></i> ' . $addon->i18n('upkeep_mail_security_quick_actions') . '</h3></div>';
    $content .= '<div class="panel-body">';
    
    // Badwords-Statistik
    $badwordCount = count(MailSecurityFilter::getBadwords());
    $content .= '<div class="alert alert-info">';
    $content .= '<strong>' . $badwordCount . '</strong> ' . $addon->i18n('upkeep_mail_security_badwords_configured') . '<br>';
    $content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/badwords') . '" class="btn btn-sm btn-info">' . $addon->i18n('upkeep_mail_security_manage') . '</a>';
    $content .= '</div>';
    
    // Blocklist-Statistik
    try {
        $sql = rex_sql::factory();
        $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_mail_blocklist') . " WHERE status = 1");
        $blocklistCount = (int) $sql->getValue('count');
        
        $content .= '<div class="alert alert-warning">';
        $content .= '<strong>' . $blocklistCount . '</strong> ' . $addon->i18n('upkeep_mail_security_blocklist_entries') . '<br>';
        $content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/blocklist') . '" class="btn btn-sm btn-warning">' . $addon->i18n('upkeep_mail_security_manage') . '</a>';
        $content .= '</div>';
    } catch (Exception $e) {
        // Tabelle existiert noch nicht
    }
    
    // Schnellaktionen
    $content .= '<hr>';
    $content .= '<div class="btn-group-vertical btn-group-sm" style="width: 100%;">';
    
    if (!$stats['active']) {
        $content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/settings') . '" class="btn btn-success">';
        $content .= '<i class="fa fa-power-off"></i> ' . $addon->i18n('upkeep_mail_security_activate') . '</a>';
    } else {
        $content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/settings') . '" class="btn btn-danger">';
        $content .= '<i class="fa fa-power-off"></i> ' . $addon->i18n('upkeep_mail_security_deactivate') . '</a>';
    }
    
    $content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/cleanup') . '" class="btn btn-default">';
    $content .= '<i class="fa fa-trash"></i> ' . $addon->i18n('upkeep_mail_security_cleanup') . '</a>';
    
    $content .= '<a href="' . rex_url::backendPage('upkeep/mail_security/threats') . '" class="btn btn-primary">';
    $content .= '<i class="fa fa-list"></i> ' . $addon->i18n('upkeep_mail_security_all_threats') . '</a>';
    
    $content .= '</div>';
    
    $content .= '</div>';
    $content .= '</div>';
    $content .= '</div>';
    
    $content .= '</div>'; // Ende row
}

// System-Info Panel
$content .= '<div class="row">';
$content .= '<div class="col-lg-12">';
$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-info-circle"></i> ' . $addon->i18n('upkeep_mail_security_system_info') . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';

// Konfiguration
$content .= '<div class="col-md-4">';
$content .= '<h4>' . $addon->i18n('upkeep_mail_security_current_config') . '</h4>';
$content .= '<dl class="dl-horizontal">';
$content .= '<dt>Mail Security:</dt><dd>' . ($stats['active'] ? '<span class="text-success">' . $addon->i18n('upkeep_active') . '</span>' : '<span class="text-danger">' . $addon->i18n('upkeep_inactive') . '</span>') . '</dd>';
$content .= '<dt>' . $addon->i18n('upkeep_mail_security_rate_limiting') . ':</dt><dd>' . ($stats['rate_limiting_enabled'] ? '<span class="text-success">' . $addon->i18n('upkeep_active') . '</span>' : '<span class="text-muted">' . $addon->i18n('upkeep_inactive') . '</span>') . '</dd>';
$content .= '<dt>' . $addon->i18n('upkeep_mail_security_debug_logging') . ':</dt><dd>' . ($addon->getConfig('mail_security_debug', false) ? '<span class="text-warning">' . $addon->i18n('upkeep_active') . '</span>' : '<span class="text-muted">' . $addon->i18n('upkeep_inactive') . '</span>') . '</dd>';
$content .= '<dt>' . $addon->i18n('upkeep_mail_security_detailed_logging') . ':</dt><dd>' . ($addon->getConfig('mail_security_detailed_logging', false) ? '<span class="text-info">' . $addon->i18n('upkeep_active') . '</span>' : '<span class="text-muted">' . $addon->i18n('upkeep_inactive') . '</span>') . '</dd>';
$content .= '</dl>';
$content .= '</div>';

// Rate Limits
$content .= '<div class="col-md-4">';
$content .= '<h4>' . $addon->i18n('upkeep_mail_security_rate_limits') . '</h4>';
$content .= '<dl class="dl-horizontal">';
$content .= '<dt>Pro Minute:</dt><dd>' . (int) $addon->getConfig('mail_rate_limit_per_minute', 10) . ' E-Mails</dd>';
$content .= '<dt>Pro Stunde:</dt><dd>' . (int) $addon->getConfig('mail_rate_limit_per_hour', 50) . ' E-Mails</dd>';
$content .= '<dt>Pro Tag:</dt><dd>' . (int) $addon->getConfig('mail_rate_limit_per_day', 200) . ' E-Mails</dd>';
$content .= '</dl>';
$content .= '</div>';

// Erlaubte Domains
$content .= '<div class="col-md-4">';
$content .= '<h4>' . $addon->i18n('upkeep_mail_security_sender_restriction') . '</h4>';
$allowedDomains = $addon->getConfig('mail_allowed_sender_domains', '');
if (empty($allowedDomains)) {
    $content .= '<p class="text-muted">' . $addon->i18n('upkeep_mail_security_all_domains_allowed') . '</p>';
} else {
    $domains = array_filter(array_map('trim', explode("\n", $allowedDomains)));
    $content .= '<p><strong>' . count($domains) . '</strong> ' . $addon->i18n('upkeep_mail_security_allowed_domains') . ':</p>';
    $content .= '<ul class="list-unstyled">';
    foreach (array_slice($domains, 0, 5) as $domain) {
        $content .= '<li><code>' . rex_escape($domain) . '</code></li>';
    }
    if (count($domains) > 5) {
        $content .= '<li class="text-muted">... und ' . (count($domains) - 5) . ' ' . $addon->i18n('upkeep_mail_security_more_domains') . '</li>';
    }
    $content .= '</ul>';
}
$content .= '</div>';

$content .= '</div>'; // Ende row
$content .= '</div>';
$content .= '</div>';
$content .= '</div>';
$content .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');