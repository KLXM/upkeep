<?php
/**
 * Upkeep AddOn - Reporting Dashboard
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

$addon = rex_addon::get('upkeep');

// Subpage check
$subpage = rex_be_controller::getCurrentPagePart(2);

// Content
$content = '';

// Header fragment
$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_reporting_title'));
$fragment->setVar('body', '<p>' . $addon->i18n('upkeep_reporting_description') . '</p>', false);
$content .= $fragment->parse('core/page/section.php');

// Reporting Overview Cards
$cards = [];

// System Health Card
$healthStatus = $addon->getConfig('system_health_enabled', false);
$healthStatusClass = $healthStatus ? 'text-success' : 'text-muted';
$healthStatusIcon = $healthStatus ? 'fa-check-circle' : 'fa-circle-o';

$cards[] = [
    'title' => $addon->i18n('upkeep_system_health_title'),
    'icon' => 'fa-heartbeat',
    'status' => $healthStatus,
    'description' => $addon->i18n('upkeep_system_health_card_description'),
    'link' => rex_url::backendPage('upkeep/reporting/system_health'),
    'stats' => [
        $addon->i18n('upkeep_system_health_api_status') => '<span class="' . $healthStatusClass . '"><i class="fa ' . $healthStatusIcon . '"></i> ' . 
            ($healthStatus ? $addon->i18n('upkeep_enabled') : $addon->i18n('upkeep_disabled')) . '</span>'
    ]
];

// Mail Reporting Card
$mailStatus = $addon->getConfig('mail_reporting_enabled', false);
$mailStatusClass = $mailStatus ? 'text-success' : 'text-muted';
$mailStatusIcon = $mailStatus ? 'fa-check-circle' : 'fa-circle-o';
$mailMode = (int) $addon->getConfig('mail_reporting_mode', 1) === 0 ? 
    $addon->i18n('upkeep_mail_reporting_mode_immediate') : 
    $addon->i18n('upkeep_mail_reporting_mode_bundle');

$cards[] = [
    'title' => $addon->i18n('upkeep_mail_reporting_title'),
    'icon' => 'fa-paper-plane',
    'status' => $mailStatus,
    'description' => $addon->i18n('upkeep_mail_reporting_card_description'),
    'link' => rex_url::backendPage('upkeep/reporting/mail_reporting'),
    'stats' => [
        $addon->i18n('upkeep_mail_reporting_status') => '<span class="' . $mailStatusClass . '"><i class="fa ' . $mailStatusIcon . '"></i> ' . 
            ($mailStatus ? $addon->i18n('upkeep_enabled') : $addon->i18n('upkeep_disabled')) . '</span>',
        $addon->i18n('upkeep_mail_reporting_mode_label') => $mailMode
    ]
];

// Render cards
$cardContent = '<div class="row">';
foreach ($cards as $card) {
    $statusClass = $card['status'] ? 'panel-success' : 'panel-default';
    
    $cardContent .= '<div class="col-md-6">';
    $cardContent .= '<div class="panel ' . $statusClass . '">';
    $cardContent .= '<div class="panel-heading">';
    $cardContent .= '<h3 class="panel-title"><i class="fa ' . $card['icon'] . '"></i> ' . $card['title'] . '</h3>';
    $cardContent .= '</div>';
    $cardContent .= '<div class="panel-body">';
    $cardContent .= '<p>' . $card['description'] . '</p>';
    
    if (!empty($card['stats'])) {
        $cardContent .= '<dl class="dl-horizontal">';
        foreach ($card['stats'] as $label => $value) {
            $cardContent .= '<dt>' . $label . ':</dt>';
            $cardContent .= '<dd>' . $value . '</dd>';
        }
        $cardContent .= '</dl>';
    }
    
    $cardContent .= '<a href="' . $card['link'] . '" class="btn btn-primary">';
    $cardContent .= '<i class="fa fa-cog"></i> ' . $addon->i18n('upkeep_configure');
    $cardContent .= '</a>';
    $cardContent .= '</div>';
    $cardContent .= '</div>';
    $cardContent .= '</div>';
}
$cardContent .= '</div>';

$fragment = new rex_fragment();
$fragment->setVar('title', $addon->i18n('upkeep_reporting_overview'));
$fragment->setVar('body', $cardContent, false);
$content .= $fragment->parse('core/page/section.php');

echo $content;