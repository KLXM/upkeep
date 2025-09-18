<?php
/**
 * Upkeep AddOn - Mail Reporting Configuration
 * 
 * Based on Security AddOn error_notification.php patterns
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

use KLXM\Upkeep\MailReporting;

$addon = rex_addon::get('upkeep');

echo rex_view::content($addon->i18n('upkeep_mail_reporting_info'));

// Handle form submission
if ('update' == rex_request('func', 'string')) {
    $addon->setConfig('mail_reporting_enabled', rex_request('mail_reporting_enabled', 'int'));
    $addon->setConfig('mail_reporting_email', rex_request('mail_reporting_email', 'string'));
    $addon->setConfig('mail_reporting_name', rex_request('mail_reporting_name', 'string'));
    $addon->setConfig('mail_reporting_key', rex_request('mail_reporting_key', 'string'));
    $addon->setConfig('mail_reporting_mode', rex_request('mail_reporting_mode', 'int'));
    
    // Report type settings
    $addon->setConfig('mail_reporting_security_advisor', rex_request('mail_reporting_security_advisor', 'int'));
    $addon->setConfig('mail_reporting_ips_threats', rex_request('mail_reporting_ips_threats', 'int'));
    $addon->setConfig('mail_reporting_maintenance', rex_request('mail_reporting_maintenance', 'int'));
    $addon->setConfig('mail_reporting_phpmailer_errors', rex_request('mail_reporting_phpmailer_errors', 'int'));
    $addon->setConfig('mail_reporting_status_reports', rex_request('mail_reporting_status_reports', 'int'));
    
    // Bundle settings
    $addon->setConfig('mail_reporting_bundle_interval', rex_request('mail_reporting_bundle_interval', 'int', 3600));
    
    echo rex_view::success($addon->i18n('upkeep_mail_reporting_settings_updated'));
}

// Handle actions
if ('send_test' == rex_request('func', 'string')) {
    if (MailReporting::isEnabled()) {
        if (MailReporting::sendTestEmail()) {
            echo rex_view::success($addon->i18n('upkeep_mail_reporting_test_sent'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_mail_reporting_test_failed'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_mail_reporting_disabled'));
    }
}

if ('send_bundle' == rex_request('func', 'string')) {
    $interval = rex_request('bundle_interval', 'int', 3600);
    if (MailReporting::sendBundleReport($interval)) {
        echo rex_view::success($addon->i18n('upkeep_mail_reporting_bundle_sent'));
    } else {
        echo rex_view::error($addon->i18n('upkeep_mail_reporting_bundle_failed'));
    }
}

if ('send_status' == rex_request('func', 'string')) {
    if (MailReporting::isEnabled()) {
        if (MailReporting::sendStatusReport()) {
            echo rex_view::success($addon->i18n('upkeep_mail_reporting_status_sent'));
        } else {
            echo rex_view::error($addon->i18n('upkeep_mail_reporting_status_failed'));
        }
    } else {
        echo rex_view::error($addon->i18n('upkeep_mail_reporting_disabled'));
    }
}

if ('delete_logs' == rex_request('func', 'string')) {
    MailReporting::deleteLogFiles();
    echo rex_view::success($addon->i18n('upkeep_mail_reporting_logs_deleted'));
}

$formElements = [];

// Enable/Disable Mail Reporting
$selEnabled = new rex_select();
$selEnabled->setId('mail_reporting_enabled');
$selEnabled->setName('mail_reporting_enabled');
$selEnabled->setSize(1);
$selEnabled->setAttribute('class', 'form-control selectpicker');
$selEnabled->setSelected($addon->getConfig('mail_reporting_enabled', 0));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selEnabled->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_enabled">' . rex_escape($addon->i18n('upkeep_mail_reporting_enabled')) . '</label>';
$n['field'] = $selEnabled->get();
$formElements[] = $n;

// Email Address
$n = [];
$n['label'] = '<label for="mail_reporting_email">' . $addon->i18n('upkeep_mail_reporting_email') . '</label>';
$n['field'] = '<input class="form-control" id="mail_reporting_email" type="email" name="mail_reporting_email" placeholder="' . rex_escape(rex::getErrorEmail()) . '" value="' . rex_escape($addon->getConfig('mail_reporting_email', '')) . '" />';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_email_note') . '</p>';
$formElements[] = $n;

// Email Name
$n = [];
$n['label'] = '<label for="mail_reporting_name">' . $addon->i18n('upkeep_mail_reporting_name') . '</label>';
$n['field'] = '<input class="form-control" id="mail_reporting_name" type="text" name="mail_reporting_name" placeholder="' . rex_escape(MailReporting::EMAIL_NAME) . '" value="' . rex_escape($addon->getConfig('mail_reporting_name', '')) . '" />';
$formElements[] = $n;

// Report Key (for identification)
$n = [];
$n['label'] = '<label for="mail_reporting_key">' . $addon->i18n('upkeep_mail_reporting_key') . '</label>';
$n['field'] = '<input class="form-control" id="mail_reporting_key" type="text" name="mail_reporting_key" value="' . rex_escape($addon->getConfig('mail_reporting_key', '')) . '" />';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_key_note') . '</p>';
$formElements[] = $n;

// Reporting Mode
$selMode = new rex_select();
$selMode->setId('mail_reporting_mode');
$selMode->setName('mail_reporting_mode');
$selMode->setSize(1);
$selMode->setAttribute('class', 'form-control selectpicker');
$selMode->setSelected($addon->getConfig('mail_reporting_mode', 1));
foreach ([
    0 => $addon->i18n('upkeep_mail_reporting_mode_immediate'),
    1 => $addon->i18n('upkeep_mail_reporting_mode_bundle'),
] as $i => $type) {
    $selMode->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_mode">' . rex_escape($addon->i18n('upkeep_mail_reporting_mode')) . '</label>';
$n['field'] = $selMode->get();
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_mode_note') . '</p>';
$formElements[] = $n;

// Divider
$n = [];
$n['label'] = '<label></label>';
$n['field'] = '<hr>';
$formElements[] = $n;

// Section Header for Report Types
$n = [];
$n['label'] = '<label></label>';
$n['field'] = '<h4>' . $addon->i18n('upkeep_mail_reporting_types') . '</h4>';
$formElements[] = $n;

// Security Advisor Reports
$selSecurityAdvisor = new rex_select();
$selSecurityAdvisor->setId('mail_reporting_security_advisor');
$selSecurityAdvisor->setName('mail_reporting_security_advisor');
$selSecurityAdvisor->setSize(1);
$selSecurityAdvisor->setAttribute('class', 'form-control selectpicker');
$selSecurityAdvisor->setSelected($addon->getConfig('mail_reporting_security_advisor', 1));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selSecurityAdvisor->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_security_advisor">🛡️ ' . rex_escape($addon->i18n('upkeep_mail_reporting_security_advisor')) . '</label>';
$n['field'] = $selSecurityAdvisor->get();
$formElements[] = $n;

// IPS Threat Reports
$selIPSThreats = new rex_select();
$selIPSThreats->setId('mail_reporting_ips_threats');
$selIPSThreats->setName('mail_reporting_ips_threats');
$selIPSThreats->setSize(1);
$selIPSThreats->setAttribute('class', 'form-control selectpicker');
$selIPSThreats->setSelected($addon->getConfig('mail_reporting_ips_threats', 1));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selIPSThreats->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_ips_threats">🚨 ' . rex_escape($addon->i18n('upkeep_mail_reporting_ips_threats')) . '</label>';
$n['field'] = $selIPSThreats->get();
$formElements[] = $n;

// Maintenance Reports
$selMaintenance = new rex_select();
$selMaintenance->setId('mail_reporting_maintenance');
$selMaintenance->setName('mail_reporting_maintenance');
$selMaintenance->setSize(1);
$selMaintenance->setAttribute('class', 'form-control selectpicker');
$selMaintenance->setSelected($addon->getConfig('mail_reporting_maintenance', 1));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selMaintenance->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_maintenance">🔧 ' . rex_escape($addon->i18n('upkeep_mail_reporting_maintenance')) . '</label>';
$n['field'] = $selMaintenance->get();
$formElements[] = $n;

// PHPMailer Error Reports
$selPHPMailerErrors = new rex_select();
$selPHPMailerErrors->setId('mail_reporting_phpmailer_errors');
$selPHPMailerErrors->setName('mail_reporting_phpmailer_errors');
$selPHPMailerErrors->setSize(1);
$selPHPMailerErrors->setAttribute('class', 'form-control selectpicker');
$selPHPMailerErrors->setSelected($addon->getConfig('mail_reporting_phpmailer_errors', 1));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selPHPMailerErrors->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_phpmailer_errors">❌ ' . rex_escape($addon->i18n('upkeep_mail_reporting_phpmailer_errors')) . '</label>';
$n['field'] = $selPHPMailerErrors->get();
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_phpmailer_errors_note') . '</p>';
$formElements[] = $n;

// Status Reports
$selStatusReports = new rex_select();
$selStatusReports->setId('mail_reporting_status_reports');
$selStatusReports->setName('mail_reporting_status_reports');
$selStatusReports->setSize(1);
$selStatusReports->setAttribute('class', 'form-control selectpicker');
$selStatusReports->setSelected($addon->getConfig('mail_reporting_status_reports', 0));
foreach ([0 => $addon->i18n('upkeep_disabled'), 1 => $addon->i18n('upkeep_enabled')] as $i => $type) {
    $selStatusReports->addOption($type, $i);
}

$n = [];
$n['label'] = '<label for="mail_reporting_status_reports">📊 ' . rex_escape($addon->i18n('upkeep_mail_reporting_status_reports')) . '</label>';
$n['field'] = $selStatusReports->get();
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_status_reports_note') . '</p>';
$formElements[] = $n;

// Bundle Interval (for bundle mode)
$n = [];
$n['label'] = '<label for="mail_reporting_bundle_interval">' . $addon->i18n('upkeep_mail_reporting_bundle_interval') . '</label>';
$n['field'] = '<input class="form-control" id="mail_reporting_bundle_interval" type="number" name="mail_reporting_bundle_interval" value="' . rex_escape($addon->getConfig('mail_reporting_bundle_interval', 3600)) . '" min="300" max="86400" />';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_bundle_interval_note') . '</p>';
$formElements[] = $n;

// Another divider
$n = [];
$n['label'] = '<label></label>';
$n['field'] = '<hr>';
$formElements[] = $n;

// Save button
$n = [];
$n['label'] = '<label></label>';
$n['field'] = '<button class="btn btn-save" type="submit" name="config-submit" value="1" title="' . $addon->i18n('upkeep_save') . '">' . $addon->i18n('upkeep_save') . '</button>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$formElementsView = $fragment->parse('core/form/form.php');

$content = '
<form action="' . rex_url::currentBackendPage() . '" method="post">
    <input type="hidden" name="func" value="update" />
    <fieldset>
        ' . $formElementsView . '
    </fieldset>
</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit');
$fragment->setVar('title', $addon->i18n('upkeep_mail_reporting_settings'));
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Actions Section
$formElements = [];

// Test Email
$n = [];
$n['label'] = '<label>' . $addon->i18n('upkeep_mail_reporting_test') . '</label>';
$n['field'] = '<div class="btn-group">';
$n['field'] .= '<button class="btn btn-primary" type="submit" name="func" value="send_test" title="' . $addon->i18n('upkeep_mail_reporting_send_test') . '">';
$n['field'] .= '<i class="rex-icon fa fa-envelope"></i> ' . $addon->i18n('upkeep_mail_reporting_send_test') . '</button>';
$n['field'] .= '</div>';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_send_test_note') . '</p>';
$formElements[] = $n;

// Bundle Report
$n = [];
$n['label'] = '<label>' . $addon->i18n('upkeep_mail_reporting_bundle') . '</label>';
$n['field'] = '<div class="input-group">';
$n['field'] .= '<input class="form-control" type="number" name="bundle_interval" value="3600" min="300" max="86400" placeholder="3600" />';
$n['field'] .= '<span class="input-group-btn">';
$n['field'] .= '<button class="btn btn-default" type="submit" name="func" value="send_bundle" title="' . $addon->i18n('upkeep_mail_reporting_send_bundle') . '">';
$n['field'] .= '<i class="rex-icon fa fa-archive"></i> ' . $addon->i18n('upkeep_mail_reporting_send_bundle') . '</button>';
$n['field'] .= '</span>';
$n['field'] .= '</div>';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_send_bundle_note') . '</p>';
$formElements[] = $n;

// Status Report
$n = [];
$n['label'] = '<label>' . $addon->i18n('upkeep_mail_reporting_status_report') . '</label>';
$n['field'] = '<div class="btn-group">';
$n['field'] .= '<button class="btn btn-info" type="submit" name="func" value="send_status" title="' . $addon->i18n('upkeep_mail_reporting_send_status') . '">';
$n['field'] .= '<i class="rex-icon fa fa-bar-chart"></i> ' . $addon->i18n('upkeep_mail_reporting_send_status') . '</button>';
$n['field'] .= '</div>';
$n['field'] .= '<p class="help-block rex-note">' . $addon->i18n('upkeep_mail_reporting_send_status_note') . '</p>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$formElementsView = $fragment->parse('core/form/form.php');

$content = '
<form action="' . rex_url::currentBackendPage() . '" method="post">
    <fieldset>
        ' . $formElementsView . '
    </fieldset>
</form>';

$fragment = new rex_fragment();
$fragment->setVar('class', 'edit');
$fragment->setVar('title', $addon->i18n('upkeep_mail_reporting_actions'));
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Log Management Section
if (!file_exists(MailReporting::getDataPath())) {
    echo rex_view::error(rex_i18n::rawMsg('upkeep_mail_reporting_path_not_exists', MailReporting::getDataPath()));
} else {
    $logFiles = MailReporting::getLogFiles();
    
    $formElements = [];
    
    // Log Information
    $n = [];
    $n['label'] = '<label>' . $addon->i18n('upkeep_mail_reporting_logs') . '</label>';
    $n['field'] = '<div>' . $addon->i18n('upkeep_mail_reporting_logs_info', count($logFiles), MailReporting::getDataPath()) . '</div>';
    $formElements[] = $n;
    
    // Log Actions
    if (!empty($logFiles)) {
        $n = [];
        $n['label'] = '<label>' . $addon->i18n('upkeep_mail_reporting_log_actions') . '</label>';
        $n['field'] = '<div class="btn-group">';
        $n['field'] .= '<button class="btn btn-danger" type="submit" name="func" value="delete_logs" onclick="return confirm(\'' . $addon->i18n('upkeep_mail_reporting_delete_logs_confirm') . '\')" title="' . $addon->i18n('upkeep_mail_reporting_delete_logs') . '">';
        $n['field'] .= '<i class="rex-icon fa fa-trash"></i> ' . $addon->i18n('upkeep_mail_reporting_delete_logs') . '</button>';
        $n['field'] .= '</div>';
        $formElements[] = $n;
    }
    
    $fragment = new rex_fragment();
    $fragment->setVar('elements', $formElements, false);
    $formElementsView = $fragment->parse('core/form/form.php');
    
    $content = '
    <form action="' . rex_url::currentBackendPage() . '" method="post">
        <fieldset>
            ' . $formElementsView . '
        </fieldset>
    </form>';
    
    $fragment = new rex_fragment();
    $fragment->setVar('class', 'edit');
    $fragment->setVar('title', $addon->i18n('upkeep_mail_reporting_log_management'));
    $fragment->setVar('body', $content, false);
    echo $fragment->parse('core/page/section.php');
}

// Information Section
$info = '<div class="alert alert-info">';
$info .= '<h4><i class="rex-icon fa fa-info-circle"></i> ' . $addon->i18n('upkeep_mail_reporting_info_title') . '</h4>';
$info .= '<ul>';
$info .= '<li><strong>' . $addon->i18n('upkeep_mail_reporting_info_immediate') . '</strong>: ' . $addon->i18n('upkeep_mail_reporting_info_immediate_desc') . '</li>';
$info .= '<li><strong>' . $addon->i18n('upkeep_mail_reporting_info_bundle') . '</strong>: ' . $addon->i18n('upkeep_mail_reporting_info_bundle_desc') . '</li>';
$info .= '<li><strong>' . $addon->i18n('upkeep_mail_reporting_info_cronjob') . '</strong>: <code>php bin/console upkeep:mail-reporting:send-bundle</code></li>';
$info .= '</ul>';
$info .= '</div>';

echo $info;