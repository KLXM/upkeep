<?php

namespace KLXM\Upkeep;

use rex_addon;

/**
 * Alle Einstellungen von upkeep an einer Stelle: Bereiche, Gruppen, Felder, Standardwerte.
 * Die Seite pages/settings.php rendert und speichert ausschließlich anhand dieser Definition.
 *
 * Feldtypen: switch, text, email, number, textarea, select, password (nur setzen, wird als Hash gespeichert),
 * secret (nur anzeigen + neu erzeugen), langtexts (Texte der Wartungsseite je Sprache).
 */
final class SettingsSections
{
    /** @return array<string, array> */
    public static function all(): array
    {
        $sections = [
            'general' => [
                'icon' => 'fa-sliders', 'color' => 'gray',
                'groups' => [
                    ['title' => 'upkeep_set_group_modules', 'note' => 'upkeep_set_group_modules_note', 'fields' => [
                        ['key' => 'ips_active', 'type' => 'switch', 'default' => 0, 'icon' => ['fa-shield', 'blue'], 'link' => 'ips'],
                        ['key' => 'form_protection_active', 'type' => 'switch', 'default' => 0, 'icon' => ['fa-wpforms', 'green'], 'link' => 'forms'],
                        ['key' => 'mail_security_active', 'type' => 'switch', 'default' => 0, 'icon' => ['fa-envelope-o', 'teal'], 'link' => 'mail'],
                        ['key' => 'domain_mapping_active', 'type' => 'switch', 'default' => 0, 'icon' => ['fa-share', 'indigo'], 'link' => 'redirects'],
                        ['key' => 'advisor_active', 'type' => 'switch', 'default' => 1, 'icon' => ['fa-lightbulb-o', 'orange'], 'link' => 'advisor'],
                        ['key' => 'mail_reporting_enabled', 'type' => 'switch', 'default' => 0, 'icon' => ['fa-paper-plane', 'purple'], 'link' => 'reporting'],
                        ['key' => 'system_health_enabled', 'type' => 'switch', 'default' => 0, 'icon' => ['fa-heartbeat', 'pink'], 'link' => 'api'],
                    ]],
                    ['title' => 'upkeep_set_group_contact', 'fields' => [
                        ['key' => 'maintenance_contact', 'type' => 'textarea', 'default' => '', 'placeholder' => "Agentur Muster\nsupport@example.org · 01234 56789"],
                    ]],
                    ['title' => 'upkeep_set_group_network', 'fields' => [
                        ['key' => 'trusted_proxies', 'type' => 'textarea', 'default' => '', 'placeholder' => "10.0.0.0/8\n2001:db8::/32", 'validate' => 'iplist'],
                    ]],
                ],
            ],
            'maintenance' => [
                'icon' => 'fa-power-off', 'color' => 'red', 'state' => 'frontend_active',
                'groups' => [
                    ['title' => 'upkeep_set_group_access', 'fields' => [
                        ['key' => 'bypass_logged_in', 'type' => 'switch', 'default' => 1],
                        ['key' => 'allowed_ips', 'type' => 'textarea', 'default' => '', 'validate' => 'iplist', 'currentIp' => true],
                        ['key' => 'frontend_password', 'type' => 'password', 'hashKey' => 'frontend_password_hash'],
                    ]],
                    ['title' => 'upkeep_set_group_bypass', 'fields' => [
                        ['key' => 'allow_bypass_param', 'type' => 'switch', 'default' => 0],
                        ['key' => 'bypass_param_key', 'type' => 'text', 'default' => 'access', 'validate' => 'paramname'],
                        ['key' => 'bypass_secret', 'type' => 'secret', 'action' => 'regenerate_bypass', 'bypassLink' => true],
                    ]],
                    ['title' => 'upkeep_set_group_http', 'fields' => [
                        ['key' => 'http_status_code', 'type' => 'select', 'default' => '503', 'options' => ['503' => 'upkeep_http_503', '403' => 'upkeep_http_403']],
                        ['key' => 'retry_after', 'type' => 'number', 'default' => 3600, 'min' => 0, 'max' => 604800],
                        ['key' => 'silent_mode', 'type' => 'switch', 'default' => 0],
                    ]],
                    ['title' => 'upkeep_set_group_texts', 'fields' => [
                        ['key' => 'multilanguage_enabled', 'type' => 'switch', 'default' => 1],
                        ['key' => 'multilanguage_default', 'type' => 'text', 'default' => 'de', 'validate' => 'langcode'],
                        ['key' => 'multilanguage_texts', 'type' => 'langtexts'],
                    ]],
                ],
            ],
            'redirects' => [
                'icon' => 'fa-share', 'color' => 'indigo', 'state' => 'domain_mapping_active',
                'groups' => [
                    ['title' => '', 'fields' => [
                        ['key' => 'domain_mapping_active', 'type' => 'switch', 'default' => 0],
                    ]],
                ],
                'pageLink' => ['upkeep/maintenance/redirects', 'upkeep_set_open_redirects'],
            ],
            'ips' => [
                'icon' => 'fa-shield', 'color' => 'blue', 'state' => 'ips_active',
                'groups' => [
                    ['title' => '', 'fields' => [
                        ['key' => 'ips_active', 'type' => 'switch', 'default' => 0],
                        ['key' => 'ips_monitor_only', 'type' => 'switch', 'default' => 0],
                    ]],
                    ['title' => 'upkeep_set_group_ips_unlock', 'fields' => [
                        ['key' => 'ips_unlock_max', 'type' => 'number', 'default' => 3, 'min' => 0, 'max' => 50],
                        ['key' => 'ips_unlock_hours', 'type' => 'number', 'default' => 24, 'min' => 1, 'max' => 720],
                        ['key' => 'ips_contact_info', 'type' => 'text', 'default' => ''],
                    ]],
                    ['title' => 'upkeep_set_group_ips_rate', 'note' => 'upkeep_set_group_ips_rate_note', 'fields' => [
                        ['key' => 'ips_rate_limiting_enabled', 'type' => 'switch', 'default' => 0],
                        ['key' => 'ips_burst_limit', 'type' => 'number', 'default' => 600, 'min' => 10, 'max' => 100000],
                        ['key' => 'ips_strict_limit', 'type' => 'number', 'default' => 200, 'min' => 5, 'max' => 100000],
                        ['key' => 'ips_burst_window', 'type' => 'number', 'default' => 60, 'min' => 10, 'max' => 3600],
                    ]],
                    ['title' => 'upkeep_set_group_logging', 'fields' => [
                        ['key' => 'ips_threat_log_retention_days', 'type' => 'number', 'default' => 30, 'min' => 1, 'max' => 365],
                        ['key' => 'ips_cleanup_auto', 'type' => 'switch', 'default' => 1],
                        ['key' => 'ips_disable_system_logging', 'type' => 'switch', 'default' => 0],
                        ['key' => 'ips_fail2ban_logging', 'type' => 'switch', 'default' => 0],
                        ['key' => 'ips_debug_mode', 'type' => 'switch', 'default' => 0],
                    ]],
                ],
                'actions' => ['ips_cleanup', 'geoip_update'],
            ],
            'forms' => [
                'icon' => 'fa-wpforms', 'color' => 'green', 'state' => 'form_protection_active',
                'groups' => [
                    ['title' => '', 'fields' => [
                        ['key' => 'form_protection_active', 'type' => 'switch', 'default' => 0],
                        ['key' => 'form_protection_level', 'type' => 'select', 'default' => 'normal', 'options' => ['normal' => 'upkeep_set_form_level_normal', 'strict' => 'upkeep_set_form_level_strict']],
                    ]],
                    ['title' => 'upkeep_set_group_form_checks', 'fields' => [
                        ['key' => 'form_protection_min_time', 'type' => 'number', 'default' => 3, 'min' => 0, 'max' => 120],
                        ['key' => 'form_protection_max_links', 'type' => 'number', 'default' => 3, 'min' => 0, 'max' => 100],
                        ['key' => 'form_protection_badwords', 'type' => 'switch', 'default' => 1],
                        ['key' => 'form_protection_pow', 'type' => 'switch', 'default' => 1],
                        ['key' => 'form_protection_script_check', 'type' => 'switch', 'default' => 0],
                        ['key' => 'form_protection_rate_limit', 'type' => 'number', 'default' => 5, 'min' => 0, 'max' => 1000],
                        ['key' => 'form_protection_rate_window', 'type' => 'number', 'default' => 600, 'min' => 60, 'max' => 86400],
                    ]],
                    ['title' => 'upkeep_set_group_form_behaviour', 'fields' => [
                        ['key' => 'form_protection_message', 'type' => 'text', 'default' => ''],
                        ['key' => 'form_protection_exclude', 'type' => 'textarea', 'default' => ''],
                        ['key' => 'form_protection_report_ips', 'type' => 'switch', 'default' => 1],
                        ['key' => 'form_protection_log_days', 'type' => 'number', 'default' => 30, 'min' => 1, 'max' => 365],
                    ]],
                    ['title' => 'upkeep_set_group_form_expert', 'note' => 'upkeep_set_group_form_expert_note', 'fields' => [
                        ['key' => 'form_protection_threshold', 'type' => 'number', 'default' => 60, 'min' => 10, 'max' => 500],
                        ['key' => 'form_protection_threshold_strict', 'type' => 'number', 'default' => 40, 'min' => 10, 'max' => 500],
                    ]],
                ],
                'pageLink' => ['upkeep/protection/forms', 'upkeep_set_open_forms'],
            ],
            'mail' => [
                'icon' => 'fa-envelope-o', 'color' => 'teal', 'state' => 'mail_security_active',
                'groups' => [
                    ['title' => '', 'fields' => [
                        ['key' => 'mail_security_active', 'type' => 'switch', 'default' => 0],
                        ['key' => 'mail_security_block_suspicious', 'type' => 'switch', 'default' => 0],
                    ]],
                    ['title' => 'upkeep_set_group_mail_checks', 'fields' => [
                        ['key' => 'mail_security_check_subject', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_security_check_body', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_security_check_sender', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_security_sanitize_content', 'type' => 'switch', 'default' => 0],
                    ]],
                    ['title' => 'upkeep_set_group_mail_rate', 'fields' => [
                        ['key' => 'mail_rate_limiting_enabled', 'type' => 'switch', 'default' => 0],
                        ['key' => 'mail_rate_limit_per_minute', 'type' => 'number', 'default' => 10, 'min' => 1, 'max' => 10000],
                        ['key' => 'mail_rate_limit_per_hour', 'type' => 'number', 'default' => 50, 'min' => 1, 'max' => 100000],
                        ['key' => 'mail_rate_limit_per_day', 'type' => 'number', 'default' => 200, 'min' => 1, 'max' => 1000000],
                        ['key' => 'mail_security_temp_block_duration', 'type' => 'number', 'default' => 60, 'min' => 1, 'max' => 10080],
                        ['key' => 'mail_security_max_spam_attempts', 'type' => 'number', 'default' => 3, 'min' => 1, 'max' => 100],
                    ]],
                    ['title' => 'upkeep_set_group_mail_sender', 'fields' => [
                        ['key' => 'mail_allowed_sender_domains', 'type' => 'textarea', 'default' => '', 'validate' => 'domainlist'],
                        ['key' => 'mail_allowed_sender_ips', 'type' => 'textarea', 'default' => '', 'validate' => 'iplist'],
                    ]],
                    ['title' => 'upkeep_set_group_mail_notify', 'fields' => [
                        ['key' => 'mail_security_notify_admin', 'type' => 'switch', 'default' => 0],
                        ['key' => 'mail_security_admin_email', 'type' => 'email', 'default' => ''],
                        ['key' => 'mail_security_notification_threshold', 'type' => 'select', 'default' => 'high', 'options' => ['low' => 'upkeep_mail_security_threshold_low', 'medium' => 'upkeep_mail_security_threshold_medium', 'high' => 'upkeep_mail_security_threshold_high', 'critical' => 'upkeep_mail_security_threshold_critical']],
                    ]],
                    ['title' => 'upkeep_set_group_logging', 'fields' => [
                        ['key' => 'mail_security_detailed_logging', 'type' => 'switch', 'default' => 0],
                        ['key' => 'mail_security_debug', 'type' => 'switch', 'default' => 0],
                    ]],
                ],
                'actions' => ['mail_cleanup'],
                'pageLink' => ['upkeep/protection/mail', 'upkeep_set_open_mail'],
            ],
            'advisor' => [
                'icon' => 'fa-lightbulb-o', 'color' => 'orange', 'state' => 'advisor_active',
                'groups' => [
                    ['title' => '', 'fields' => [
                        ['key' => 'advisor_active', 'type' => 'switch', 'default' => 1],
                        ['key' => 'admin_release_days', 'type' => 'number', 'default' => 30, 'min' => 1, 'max' => 365],
                    ]],
                ],
                'pageLink' => ['upkeep/advisor', 'upkeep_set_open_advisor'],
            ],
            'reporting' => [
                'icon' => 'fa-paper-plane', 'color' => 'purple', 'state' => 'mail_reporting_enabled',
                'groups' => [
                    ['title' => '', 'fields' => [
                        ['key' => 'mail_reporting_enabled', 'type' => 'switch', 'default' => 0],
                        ['key' => 'mail_reporting_email', 'type' => 'email', 'default' => ''],
                        ['key' => 'mail_reporting_name', 'type' => 'text', 'default' => ''],
                        ['key' => 'mail_reporting_key', 'type' => 'text', 'default' => ''],
                    ]],
                    ['title' => 'upkeep_set_group_reporting_mode', 'fields' => [
                        ['key' => 'mail_reporting_mode', 'type' => 'select', 'default' => '1', 'options' => ['0' => 'upkeep_mail_reporting_mode_immediate', '1' => 'upkeep_mail_reporting_mode_bundle']],
                        ['key' => 'mail_reporting_bundle_interval', 'type' => 'number', 'default' => 3600, 'min' => 300, 'max' => 86400],
                    ]],
                    ['title' => 'upkeep_set_group_reporting_events', 'fields' => [
                        ['key' => 'mail_reporting_ips_threats', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_reporting_maintenance', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_reporting_security_advisor', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_reporting_phpmailer_errors', 'type' => 'switch', 'default' => 1],
                        ['key' => 'mail_reporting_status_reports', 'type' => 'switch', 'default' => 0],
                    ]],
                ],
                'actions' => ['report_test', 'report_status'],
            ],
            'api' => [
                'icon' => 'fa-key', 'color' => 'pink', 'state' => 'system_health_enabled',
                'groups' => [
                    ['title' => 'upkeep_set_group_api_maintenance', 'fields' => [
                        ['key' => 'api_token', 'type' => 'secret', 'action' => 'regenerate_api_token'],
                    ]],
                    ['title' => 'upkeep_set_group_api_health', 'fields' => [
                        ['key' => 'system_health_enabled', 'type' => 'switch', 'default' => 0],
                        ['key' => 'system_health_key', 'type' => 'secret', 'action' => 'regenerate_health_key'],
                    ]],
                ],
            ],
        ];

        return $sections;
    }

    /** Ein Feld je Schlüssel – für Speichern und Prüfen */
    public static function fields(string $section): array
    {
        $fields = [];
        foreach (self::all()[$section]['groups'] ?? [] as $group) {
            foreach ($group['fields'] as $field) {
                $fields[$field['key']] = $field;
            }
        }
        return $fields;
    }

    public static function isOn(string $key): bool
    {
        return (bool) rex_addon::get('upkeep')->getConfig($key, false);
    }
}
