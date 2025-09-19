<?php

use KLXM\Upkeep\MailSecurityFilter;

$error = '';
$success = '';
$addon = rex_addon::get('upkeep');

// Konfiguration speichern
if (rex_post('form-submit', 'string') === '1') {
    try {
        // Mail Security Grundeinstellungen
        $addon->setConfig('mail_security_active', (bool) rex_post('mail_security_active', 'int', 0));
        $addon->setConfig('mail_rate_limiting_enabled', (bool) rex_post('mail_rate_limiting_enabled', 'int', 0));
        $addon->setConfig('mail_security_debug', (bool) rex_post('mail_security_debug', 'int', 0));
        $addon->setConfig('mail_security_detailed_logging', (bool) rex_post('mail_security_detailed_logging', 'int', 0));
        
        // Rate-Limiting Konfiguration (mindestens 1)
        $addon->setConfig('mail_rate_limit_per_minute', max(1, (int) rex_post('rate_limit_per_minute', 'int', 10)));
        $addon->setConfig('mail_rate_limit_per_hour', max(1, (int) rex_post('rate_limit_per_hour', 'int', 50)));
        $addon->setConfig('mail_rate_limit_per_day', max(1, (int) rex_post('rate_limit_per_day', 'int', 200)));
        
        // Erweiterte Einstellungen
        $addon->setConfig('mail_security_block_suspicious', (bool) rex_post('block_suspicious', 'int', 0));
        $addon->setConfig('mail_security_temp_block_duration', max(1, (int) rex_post('temp_block_duration', 'int', 60)));
        $addon->setConfig('mail_security_max_spam_attempts', max(1, (int) rex_post('max_spam_attempts', 'int', 3)));
        
        // Content-Filter-Einstellungen
        $addon->setConfig('mail_security_check_subject', (bool) rex_post('check_subject', 'int', 1));
        $addon->setConfig('mail_security_check_body', (bool) rex_post('check_body', 'int', 1));
        $addon->setConfig('mail_security_check_sender', (bool) rex_post('check_sender', 'int', 1));
        $addon->setConfig('mail_security_sanitize_content', (bool) rex_post('sanitize_content', 'int', 0));
        
        // Sender-Beschränkungen
        $allowedDomains = trim(rex_post('allowed_sender_domains', 'string', ''));
        $addon->setConfig('mail_allowed_sender_domains', $allowedDomains);
        
        $allowedIps = trim(rex_post('allowed_sender_ips', 'string', ''));
        $addon->setConfig('mail_allowed_sender_ips', $allowedIps);
        
        // Notification-Einstellungen
        $addon->setConfig('mail_security_notify_admin', (bool) rex_post('notify_admin', 'int', 0));
        $adminEmail = trim(rex_post('admin_notification_email', 'string', ''));
        if (!empty($adminEmail) && !filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
            throw new Exception($addon->i18n('upkeep_mail_security_invalid_admin_email'));
        }
        $addon->setConfig('mail_security_admin_email', $adminEmail);
        
        $notificationThreshold = rex_post('notification_threshold', 'string', 'high');
        $addon->setConfig('mail_security_notification_threshold', $notificationThreshold);
        
        $success = $addon->i18n('upkeep_config_saved');
        
    } catch (Exception $e) {
        $error = $addon->i18n('upkeep_config_error') . ' ' . rex_escape($e->getMessage());
    }
}

// Test-E-Mail versenden
if (rex_post('send-test-email', 'string') === '1') {
    $testEmailTo = trim(rex_post('test_email_to', 'string', ''));
    $testType = rex_post('test_type', 'string', 'clean');
    
    if (!empty($testEmailTo) && filter_var($testEmailTo, FILTER_VALIDATE_EMAIL)) {
        try {
            // Mock PHPMailer für Test
            $mockMailer = new stdClass();
            $mockMailer->From = 'test@' . rex_server('HTTP_HOST', 'string', 'localhost');
            $mockMailer->FromName = 'Mail Security Test';
            $mockMailer->to = [[$testEmailTo, 'Test Recipient']];
            
            switch ($testType) {
                case 'badword':
                    $mockMailer->Subject = 'Test E-Mail mit Viagra';
                    $mockMailer->Body = 'Dies ist eine Test-E-Mail mit einem Badword: viagra';
                    break;
                case 'injection':
                    $mockMailer->Subject = 'Code Injection Test';
                    $mockMailer->Body = 'Test mit Script: <script>alert("test")</script>';
                    break;
                case 'spam':
                    $mockMailer->Subject = 'Free Money - Act Now!';
                    $mockMailer->Body = 'Congratulations! You have won millions of dollars. Click here now!';
                    break;
                default:
                    $mockMailer->Subject = 'Mail Security Test - Clean';
                    $mockMailer->Body = 'Dies ist eine saubere Test-E-Mail zur Überprüfung der Mail Security.';
                    break;
            }
            
            $mockMailer->AltBody = strip_tags($mockMailer->Body);
            
            $ep = new rex_extension_point('PHPMAILER_PRE_SEND', $mockMailer);
            
            // Mail Security Filter testen
            if (MailSecurityFilter::isMailSecurityActive()) {
                MailSecurityFilter::filterMail($ep);
                $success = $addon->i18n('upkeep_mail_security_test_passed', $testType);
            } else {
                $success = $addon->i18n('upkeep_mail_security_test_skipped');
            }
            
        } catch (Exception $e) {
            $success = $addon->i18n('upkeep_mail_security_test_blocked', $testType, $e->getMessage());
        }
    } else {
        $error = $addon->i18n('upkeep_mail_security_invalid_test_email');
    }
}

// Error/Success Messages
if ($error) {
    echo rex_view::error($error);
}
if ($success) {
    echo rex_view::success($success);
}

// Aktuelle Konfiguration laden
$config = [
    'mail_security_active' => $addon->getConfig('mail_security_active', false),
    'mail_rate_limiting_enabled' => $addon->getConfig('mail_rate_limiting_enabled', false),
    'mail_security_debug' => $addon->getConfig('mail_security_debug', false),
    'mail_security_detailed_logging' => $addon->getConfig('mail_security_detailed_logging', false),
    'mail_rate_limit_per_minute' => $addon->getConfig('mail_rate_limit_per_minute', 10),
    'mail_rate_limit_per_hour' => $addon->getConfig('mail_rate_limit_per_hour', 50),
    'mail_rate_limit_per_day' => $addon->getConfig('mail_rate_limit_per_day', 200),
    'mail_security_block_suspicious' => $addon->getConfig('mail_security_block_suspicious', false),
    'mail_security_temp_block_duration' => $addon->getConfig('mail_security_temp_block_duration', 60),
    'mail_security_max_spam_attempts' => $addon->getConfig('mail_security_max_spam_attempts', 3),
    'mail_security_check_subject' => $addon->getConfig('mail_security_check_subject', true),
    'mail_security_check_body' => $addon->getConfig('mail_security_check_body', true),
    'mail_security_check_sender' => $addon->getConfig('mail_security_check_sender', true),
    'mail_security_sanitize_content' => $addon->getConfig('mail_security_sanitize_content', false),
    'mail_allowed_sender_domains' => $addon->getConfig('mail_allowed_sender_domains', ''),
    'mail_allowed_sender_ips' => $addon->getConfig('mail_allowed_sender_ips', ''),
    'mail_security_notify_admin' => $addon->getConfig('mail_security_notify_admin', false),
    'mail_security_admin_email' => $addon->getConfig('mail_security_admin_email', ''),
    'mail_security_notification_threshold' => $addon->getConfig('mail_security_notification_threshold', 'high'),
];

// Hauptkonfiguration
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="form-submit" value="1" />';

$content .= '<div class="panel panel-primary">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-cog"></i> ' . $addon->i18n('upkeep_mail_security_basic_settings') . '</h3></div>';
$content .= '<div class="panel-body">';

$formElements = [];

// Hauptschalter
$n = [];
$n['label'] = '<label for="mail-security-active"><strong>' . $addon->i18n('upkeep_mail_security_activate_system') . '</strong></label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="mail-security-active" name="mail_security_active" value="1"' . ($config['mail_security_active'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_activate_system_desc') . '</label></div>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="mail-rate-limiting"><strong>' . $addon->i18n('upkeep_mail_security_activate_rate_limiting') . '</strong></label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="mail-rate-limiting" name="mail_rate_limiting_enabled" value="1"' . ($config['mail_rate_limiting_enabled'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_rate_limiting_desc') . '</label></div>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="mail-debug"><strong>' . $addon->i18n('upkeep_mail_security_debug_logging') . '</strong></label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="mail-debug" name="mail_security_debug" value="1"' . ($config['mail_security_debug'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_debug_logging_desc') . '</label></div>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="mail-detailed-logging"><strong>' . $addon->i18n('upkeep_mail_security_detailed_logging') . '</strong></label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="mail-detailed-logging" name="mail_security_detailed_logging" value="1"' . ($config['mail_security_detailed_logging'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_detailed_logging_desc') . '</label></div>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</div>';
$content .= '</div>';

// Rate-Limiting Konfiguration
$content .= '<div class="panel panel-info">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-clock-o"></i> ' . $addon->i18n('upkeep_mail_security_rate_limiting_config') . '</h3></div>';
$content .= '<div class="panel-body">';

$formElements = [];

$n = [];
$n['label'] = '<label for="rate-limit-minute">' . $addon->i18n('upkeep_mail_security_emails_per_minute') . '</label>';
$n['field'] = '<input class="form-control" type="number" id="rate-limit-minute" name="rate_limit_per_minute" value="' . (int) $config['mail_rate_limit_per_minute'] . '" min="1" max="100" />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="rate-limit-hour">' . $addon->i18n('upkeep_mail_security_emails_per_hour') . '</label>';
$n['field'] = '<input class="form-control" type="number" id="rate-limit-hour" name="rate_limit_per_hour" value="' . (int) $config['mail_rate_limit_per_hour'] . '" min="1" max="1000" />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="rate-limit-day">' . $addon->i18n('upkeep_mail_security_emails_per_day') . '</label>';
$n['field'] = '<input class="form-control" type="number" id="rate-limit-day" name="rate_limit_per_day" value="' . (int) $config['mail_rate_limit_per_day'] . '" min="1" max="10000" />';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</div>';
$content .= '</div>';

// Erweiterte Sicherheitseinstellungen
$content .= '<div class="panel panel-warning">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-shield"></i> ' . $addon->i18n('upkeep_mail_security_advanced_settings') . '</h3></div>';
$content .= '<div class="panel-body">';

$formElements = [];

$n = [];
$n['label'] = '<label for="block-suspicious">' . $addon->i18n('upkeep_mail_security_block_suspicious') . '</label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="block-suspicious" name="block_suspicious" value="1"' . ($config['mail_security_block_suspicious'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_block_suspicious_desc') . '</label></div>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="temp-block-duration">' . $addon->i18n('upkeep_mail_security_temp_block_duration') . '</label>';
$n['field'] = '<input class="form-control" type="number" id="temp-block-duration" name="temp_block_duration" value="' . (int) $config['mail_security_temp_block_duration'] . '" min="1" max="1440" /><small class="help-block">' . $addon->i18n('upkeep_mail_security_temp_block_duration_desc') . '</small>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="max-spam-attempts">' . $addon->i18n('upkeep_mail_security_max_spam_attempts') . '</label>';
$n['field'] = '<input class="form-control" type="number" id="max-spam-attempts" name="max_spam_attempts" value="' . (int) $config['mail_security_max_spam_attempts'] . '" min="1" max="10" /><small class="help-block">' . $addon->i18n('upkeep_mail_security_max_spam_attempts_desc') . '</small>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</div>';
$content .= '</div>';

// Content-Filter-Einstellungen
$content .= '<div class="panel panel-success">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-filter"></i> ' . $addon->i18n('upkeep_mail_security_content_filter') . '</h3></div>';
$content .= '<div class="panel-body">';

$formElements = [];

$n = [];
$n['label'] = '<label>' . $addon->i18n('upkeep_mail_security_check_areas') . '</label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" name="check_subject" value="1"' . ($config['mail_security_check_subject'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_check_subject') . '</label></div>';
$n['field'] .= '<div class="checkbox"><label><input type="checkbox" name="check_body" value="1"' . ($config['mail_security_check_body'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_check_body') . '</label></div>';
$n['field'] .= '<div class="checkbox"><label><input type="checkbox" name="check_sender" value="1"' . ($config['mail_security_check_sender'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_check_sender') . '</label></div>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="sanitize-content">' . $addon->i18n('upkeep_mail_security_sanitize_content') . '</label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="sanitize-content" name="sanitize_content" value="1"' . ($config['mail_security_sanitize_content'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_sanitize_content_desc') . '</label></div>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</div>';
$content .= '</div>';

// Absender-Beschränkungen
$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-users"></i> ' . $addon->i18n('upkeep_mail_security_sender_restrictions') . '</h3></div>';
$content .= '<div class="panel-body">';

$formElements = [];

$n = [];
$n['label'] = '<label for="allowed-domains">' . $addon->i18n('upkeep_mail_security_allowed_sender_domains') . '<br><small class="text-muted">' . $addon->i18n('upkeep_mail_security_allowed_sender_domains_desc') . '</small></label>';
$n['field'] = '<textarea class="form-control" id="allowed-domains" name="allowed_sender_domains" rows="5" placeholder="example.com&#10;mycompany.de">' . rex_escape($config['mail_allowed_sender_domains']) . '</textarea>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="allowed-ips">' . $addon->i18n('upkeep_mail_security_allowed_sender_ips') . '<br><small class="text-muted">' . $addon->i18n('upkeep_mail_security_allowed_sender_ips_desc') . '</small></label>';
$n['field'] = '<textarea class="form-control" id="allowed-ips" name="allowed_sender_ips" rows="3" placeholder="192.168.1.100&#10;10.0.0.50">' . rex_escape($config['mail_allowed_sender_ips']) . '</textarea>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</div>';
$content .= '</div>';

// Admin-Benachrichtigungen
$content .= '<div class="panel panel-info">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-bell"></i> ' . $addon->i18n('upkeep_mail_security_admin_notifications') . '</h3></div>';
$content .= '<div class="panel-body">';

$formElements = [];

$n = [];
$n['label'] = '<label for="notify-admin">' . $addon->i18n('upkeep_mail_security_activate_notifications') . '</label>';
$n['field'] = '<div class="checkbox"><label><input type="checkbox" id="notify-admin" name="notify_admin" value="1"' . ($config['mail_security_notify_admin'] ? ' checked="checked"' : '') . ' /> ' . $addon->i18n('upkeep_mail_security_activate_notifications_desc') . '</label></div>';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="admin-email">' . $addon->i18n('upkeep_mail_security_admin_email') . '</label>';
$n['field'] = '<input class="form-control" type="email" id="admin-email" name="admin_notification_email" value="' . rex_escape($config['mail_security_admin_email']) . '" placeholder="admin@example.com" />';
$formElements[] = $n;

$n = [];
$n['label'] = '<label for="notification-threshold">' . $addon->i18n('upkeep_mail_security_notification_threshold') . '</label>';
$n['field'] = '<select class="form-control" id="notification-threshold" name="notification_threshold">';
$n['field'] .= '<option value="low"' . ($config['mail_security_notification_threshold'] === 'low' ? ' selected' : '') . '>' . $addon->i18n('upkeep_mail_security_threshold_low') . '</option>';
$n['field'] .= '<option value="medium"' . ($config['mail_security_notification_threshold'] === 'medium' ? ' selected' : '') . '>' . $addon->i18n('upkeep_mail_security_threshold_medium') . '</option>';
$n['field'] .= '<option value="high"' . ($config['mail_security_notification_threshold'] === 'high' ? ' selected' : '') . '>' . $addon->i18n('upkeep_mail_security_threshold_high') . '</option>';
$n['field'] .= '<option value="critical"' . ($config['mail_security_notification_threshold'] === 'critical' ? ' selected' : '') . '>' . $addon->i18n('upkeep_mail_security_threshold_critical') . '</option>';
$n['field'] .= '</select>';
$formElements[] = $n;

$fragment = new rex_fragment();
$fragment->setVar('elements', $formElements, false);
$content .= $fragment->parse('core/form/form.php');

$content .= '</div>';
$content .= '</div>';

// Save Button
$content .= '<div class="panel panel-default">';
$content .= '<div class="panel-body text-center">';
$content .= '<button class="btn btn-primary btn-lg" type="submit"><i class="fa fa-save"></i> ' . $addon->i18n('upkeep_settings_saved') . '</button>';
$content .= '</div>';
$content .= '</div>';

$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');

// Test-Panel
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<input type="hidden" name="send-test-email" value="1" />';

$content .= '<div class="panel panel-warning">';
$content .= '<div class="panel-heading"><h3 class="panel-title"><i class="fa fa-flask"></i> ' . $addon->i18n('upkeep_mail_security_test_system') . '</h3></div>';
$content .= '<div class="panel-body">';

$content .= '<div class="row">';
$content .= '<div class="col-md-4">';
$content .= '<label>' . $addon->i18n('upkeep_mail_security_test_email_address') . '</label>';
$content .= '<input type="email" class="form-control" name="test_email_to" placeholder="test@example.com" required />';
$content .= '</div>';

$content .= '<div class="col-md-4">';
$content .= '<label>' . $addon->i18n('upkeep_mail_security_test_type') . '</label>';
$content .= '<select class="form-control" name="test_type">';
$content .= '<option value="clean">' . $addon->i18n('upkeep_mail_security_test_clean') . '</option>';
$content .= '<option value="badword">' . $addon->i18n('upkeep_mail_security_test_badword') . '</option>';
$content .= '<option value="injection">' . $addon->i18n('upkeep_mail_security_test_injection') . '</option>';
$content .= '<option value="spam">' . $addon->i18n('upkeep_mail_security_test_spam') . '</option>';
$content .= '</select>';
$content .= '</div>';

$content .= '<div class="col-md-4">';
$content .= '<label>&nbsp;</label><br>';
$content .= '<button type="submit" class="btn btn-warning">' . $addon->i18n('upkeep_mail_security_run_test') . '</button>';
$content .= '</div>';

$content .= '</div>';

$content .= '<div class="alert alert-info" style="margin-top: 15px;">';
$content .= '<strong>' . $addon->i18n('upkeep_mail_security_test_hint_title') . ':</strong> ' . $addon->i18n('upkeep_mail_security_test_hint_desc');
$content .= '</div>';

$content .= '</div>';
$content .= '</div>';
$content .= '</form>';

$fragment = new rex_fragment();
$fragment->setVar('title', '', false);
$fragment->setVar('body', $content, false);
echo $fragment->parse('core/page/section.php');