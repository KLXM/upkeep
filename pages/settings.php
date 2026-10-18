<?php

/**
 * Einstellungen (nur Admins): alle Bereiche an einer Stelle, Aufbau wie die macOS-Systemeinstellungen.
 * Definition der Felder: lib/SettingsSections.php
 */

use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\MailReporting;
use KLXM\Upkeep\SettingsSections;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
if (!rex::requireUser()->isAdmin()) {
    echo rex_view::error(rex_escape(rex_i18n::rawMsg('upkeep_set_admin_only')));
    return;
}
$sections = SettingsSections::all();
$section = rex_request('section', 'string', 'general');
if (!isset($sections[$section])) {
    $section = 'general';
}
$def = $sections[$section];
$csrf = rex_csrf_token::factory('upkeep_settings');
$url = static fn (string $s) => rex_url::backendPage('upkeep/settings', ['section' => $s]);
$label = static fn (string $key) => rex_i18n::rawMsg('upkeep_set_' . $key);
$help = static function (string $key) use ($addon): string {
    $k = 'upkeep_set_' . $key . '_help';
    $text = rex_i18n::rawMsg($k);
    return $text === '[translate:' . $k . ']' ? '' : $text;
};

/** Prüft Listen aus IPs/Netzen, Domains usw. Gibt die bereinigte Liste oder null (ungültig) zurück. */
$validateList = static function (string $raw, string $type): ?string {
    $items = array_values(array_filter(array_map('trim', preg_split('/[\r\n,]+/', $raw) ?: [])));
    foreach ($items as $item) {
        $ok = match ($type) {
            'iplist' => (bool) filter_var($item, FILTER_VALIDATE_IP)
                || (1 === preg_match('#^([0-9a-f:.]+)/(\d{1,3})$#i', $item, $m) && filter_var($m[1], FILTER_VALIDATE_IP) && (int) $m[2] <= (str_contains($m[1], ':') ? 128 : 32)),
            'domainlist' => 1 === preg_match('/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $item),
            default => true,
        };
        if (!$ok) {
            return null;
        }
    }
    return implode("\n", $items);
};

// ---------- Speichern ----------
$messages = [];
if ('post' === rex_request_method()) {
    if (!$csrf->isValid()) {
        $messages[] = rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } elseif (rex_post('upk_save', 'bool')) {
        $errors = [];
        foreach (SettingsSections::fields($section) as $key => $field) {
            $type = $field['type'];
            if ('secret' === $type) {
                continue;
            }
            if ('switch' === $type) {
                $addon->setConfig($key, rex_post($key, 'int', 0) ? 1 : 0);
                continue;
            }
            if ('password' === $type) {
                $new = (string) rex_post($key, 'string', '');
                if ('' !== $new) {
                    if (mb_strlen($new) < 8) {
                        $errors[] = rex_i18n::rawMsg('upkeep_set_error_password_short');
                    } else {
                        // setFrontendPassword beendet zugleich bestehende Freischaltungen
                        \KLXM\Upkeep\Upkeep::setFrontendPassword($new);
                        $addon->removeConfig($key);
                    }
                }
                continue;
            }
            if ('langtexts' === $type) {
                $rows = rex_post('langtexts', 'array', []);
                $clean = [];
                foreach ($rows as $row) {
                    if (!is_array($row) || !empty($row['remove'])) {
                        continue;
                    }
                    $code = strtolower(trim((string) ($row['language_code'] ?? '')));
                    if ('' === $code) {
                        continue;
                    }
                    if (!preg_match('/^[a-z]{2}([_-][a-z]{2})?$/', $code)) {
                        $errors[] = rex_i18n::rawMsg('upkeep_set_error_langcode', $code);
                        continue;
                    }
                    $entry = ['language_code' => $code];
                    foreach (['language_name', 'title', 'message', 'password_label', 'password_button', 'language_switch'] as $f) {
                        $entry[$f] = trim((string) ($row[$f] ?? ''));
                    }
                    $clean[] = $entry;
                }
                $addon->setConfig($key, json_encode($clean, JSON_UNESCAPED_UNICODE));
                continue;
            }
            $value = (string) rex_post($key, 'string', '');
            if ('number' === $type) {
                $num = (int) $value;
                $num = max($field['min'] ?? PHP_INT_MIN, min($field['max'] ?? PHP_INT_MAX, $num));
                $addon->setConfig($key, $num);
                continue;
            }
            if ('select' === $type) {
                if (isset($field['options'][$value])) {
                    $addon->setConfig($key, ctype_digit($value) ? (int) $value : $value);
                }
                continue;
            }
            if ('email' === $type && '' !== trim($value) && !filter_var(trim($value), FILTER_VALIDATE_EMAIL)) {
                $errors[] = rex_i18n::rawMsg('upkeep_set_error_email', $label($key));
                continue;
            }
            $value = trim($value);
            switch ($field['validate'] ?? '') {
                case 'iplist':
                case 'domainlist':
                    $list = $validateList($value, $field['validate']);
                    if (null === $list) {
                        $errors[] = rex_i18n::rawMsg('upkeep_set_error_list', $label($key));
                        continue 2;
                    }
                    $value = $list;
                    break;
                case 'paramname':
                    if (!preg_match('/^[a-z0-9_-]{1,40}$/i', $value)) {
                        $errors[] = rex_i18n::rawMsg('upkeep_set_error_paramname');
                        continue 2;
                    }
                    break;
                case 'langcode':
                    if (!preg_match('/^[a-z]{2}([_-][a-z]{2})?$/i', $value)) {
                        $errors[] = rex_i18n::rawMsg('upkeep_set_error_langcode', $value);
                        continue 2;
                    }
                    break;
            }
            $addon->setConfig($key, $value);
        }
        $excluded = preg_split('/[\s,]+/', (string) $addon->getConfig('form_protection_exclude', ''), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if ('forms' === $section && in_array('formular', $excluded, true)) {
            $errors[] = rex_i18n::rawMsg('upkeep_set_exclude_warn_default');
        }
        $messages[] = $errors
            ? rex_view::warning(rex_escape(rex_i18n::rawMsg('upkeep_set_saved_with_errors')) . '<br>' . implode('<br>', array_map('rex_escape', $errors)))
            : rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_saved')));
    } else {
        // Aktionen
        $action = rex_post('upk_action', 'string', '');
        try {
            switch ($action) {
                case 'regenerate_bypass':
                    \KLXM\Upkeep\Upkeep::regenerateBypassSecret();
                    $messages[] = rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_secret_regenerated')));
                    break;
                case 'regenerate_api_token':
                    $addon->setConfig('api_token', bin2hex(random_bytes(32)));
                    $messages[] = rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_secret_regenerated')));
                    break;
                case 'regenerate_health_key':
                    $addon->setConfig('system_health_key', bin2hex(random_bytes(32)));
                    $messages[] = rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_secret_regenerated')));
                    break;
                case 'ips_cleanup':
                    $result = IntrusionPrevention::cleanupExpiredData();
                    $parts = [];
                    foreach ((array) $result as $k => $v) {
                        if (is_numeric($v)) {
                            $parts[] = rex_escape((string) $k) . ': ' . (int) $v;
                        }
                    }
                    $messages[] = rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_cleanup_done')) . ($parts ? ' (' . implode(', ', $parts) . ')' : ''));
                    break;
                case 'geoip_update':
                    @set_time_limit(120);
                    $ok = method_exists(IntrusionPrevention::class, 'updateGeoDatabase') && IntrusionPrevention::updateGeoDatabase();
                    $messages[] = $ok ? rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_ips_geo_update_success'))) : rex_view::error(rex_escape(rex_i18n::rawMsg('upkeep_ips_geo_update_error')));
                    break;
                case 'mail_cleanup':
                    $days = max(1, min(3650, rex_post('days', 'int', 30)));
                    $cutoff = date('Y-m-d H:i:s', time() - $days * 86400);
                    $deleted = 0;
                    $sql = rex_sql::factory();
                    foreach ([
                        ['upkeep_mail_rate_limit', 'created_at < ?'],
                        ['upkeep_mail_threat_log', 'created_at < ?'],
                        ['upkeep_ips_threat_log', "threat_type LIKE 'mail_%' AND created_at < ?"],
                    ] as [$table, $where]) {
                        try {
                            $sql->setQuery('DELETE FROM ' . rex::getTable($table) . ' WHERE ' . $where, [$cutoff]);
                            $deleted += $sql->getRows();
                        } catch (rex_sql_exception) {
                            // Tabelle fehlt – überspringen
                        }
                    }
                    $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_mail_blocklist') . ' WHERE expires_at IS NOT NULL AND expires_at < ?', [date('Y-m-d H:i:s')]);
                    $deleted += $sql->getRows();
                    $messages[] = rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_mail_cleanup_done', (string) $deleted)));
                    break;
                case 'report_test':
                    $messages[] = MailReporting::sendTestEmail() ? rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_mail_reporting_test_sent'))) : rex_view::error(rex_escape(rex_i18n::rawMsg('upkeep_mail_reporting_test_failed')));
                    break;
                case 'report_status':
                    $messages[] = MailReporting::sendStatusReport() ? rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_mail_reporting_status_sent'))) : rex_view::error(rex_escape(rex_i18n::rawMsg('upkeep_mail_reporting_status_failed')));
                    break;
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $messages[] = rex_view::error(rex_escape(rex_i18n::rawMsg('upkeep_set_action_failed')));
        }
    }
}

// ---------- Seitenleiste ----------
$sidebar = '<nav class="upk-sidebar" aria-label="' . rex_escape(rex_i18n::rawMsg('upkeep_nav_settings')) . '">';
$order = ['general', '-', 'maintenance', 'redirects', '-', 'ips', 'forms', 'mail', '-', 'advisor', 'reporting', 'api'];
foreach ($order as $key) {
    if ('-' === $key) {
        $sidebar .= '<div class="upk-sidebar-sep"></div>';
        continue;
    }
    $s = $sections[$key];
    $state = isset($s['state']) ? '<span class="upk-state' . (SettingsSections::isOn($s['state']) ? ' upk-state--on' : '') . '" aria-hidden="true"></span>' : '';
    $sidebar .= '<a href="' . $url($key) . '"' . ($key === $section ? ' class="active" aria-current="page"' : '') . '>'
        . Ui::icon($s['icon'], $s['color']) . '<span>' . rex_escape(rex_i18n::rawMsg('upkeep_set_section_' . $key)) . '</span>' . $state . '</a>';
}
$sidebar .= '</nav>';

// ---------- Felder rendern ----------
$renderField = static function (array $field) use ($addon, $label, $help, $section, $url): string {
    $key = $field['key'];
    $id = 'upk-f-' . $key;
    $type = $field['type'];
    $value = $addon->getConfig($key, $field['default'] ?? '');
    $iconHtml = isset($field['icon']) ? Ui::icon($field['icon'][0], $field['icon'][1]) : '';

    switch ($type) {
        case 'switch':
            $control = Ui::switch($key, (bool) $value, $id);
            if (isset($field['link'])) {
                $control = '<a class="btn btn-link btn-xs upk-link" href="' . $url($field['link']) . '">' . rex_escape(rex_i18n::rawMsg('upkeep_set_more')) . '</a>' . $control;
            }
            return Ui::row($label($key), $control, $help($key), $id, $iconHtml);
        case 'number':
            return Ui::row($label($key), '<input class="form-control" type="number" id="' . $id . '" name="' . rex_escape($key) . '" value="' . rex_escape((string) (int) $value) . '"'
                . (isset($field['min']) ? ' min="' . (int) $field['min'] . '"' : '') . (isset($field['max']) ? ' max="' . (int) $field['max'] . '"' : '') . '>', $help($key), $id);
        case 'select':
            $opts = '';
            foreach ($field['options'] as $optValue => $optLabel) {
                $opts .= '<option value="' . rex_escape((string) $optValue) . '"' . ((string) $value === (string) $optValue ? ' selected' : '') . '>' . rex_escape(rex_i18n::rawMsg($optLabel)) . '</option>';
            }
            return Ui::row($label($key), '<select class="form-control" id="' . $id . '" name="' . rex_escape($key) . '">' . $opts . '</select>', $help($key), $id);
        case 'textarea':
            $text = is_array($value) ? implode("\n", $value) : (string) $value;
            $hint = $help($key);
            if (!empty($field['currentIp'])) {
                $hint = trim($hint . ' ' . rex_i18n::rawMsg('upkeep_set_your_ip', (string) rex_server('REMOTE_ADDR', 'string', '')));
            }
            $html = Ui::row($label($key), '<textarea class="form-control upk-mono" rows="3" id="' . $id . '" name="' . rex_escape($key) . '"'
                . (isset($field['placeholder']) ? ' placeholder="' . rex_escape($field['placeholder']) . '"' : '') . '>' . rex_escape($text) . '</textarea>', $hint, $id, '', true);
            if ('formnames' === ($field['explain'] ?? '')) {
                // Erklärung: woher der Formularname kommt, wie man ihn setzt oder ein Formular direkt ausnimmt
                $code = static fn (string $c) => '<code>' . rex_escape($c) . '</code>';
                $seen = class_exists(\KLXM\Upkeep\FormProtection::class) ? array_keys((array) (\KLXM\Upkeep\FormProtection::getStats(365)['by_form'] ?? [])) : [];
                $html .= '<div class="upk-explain">'
                    . '<p>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_name')) . '</p>'
                    . '<p>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_set')) . '</p>'
                    . '<ul><li>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_pipe')) . ' ' . $code('objparams|form_name|kontakt') . '</li>'
                    . '<li>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_php')) . ' ' . $code("\$yform->setObjectparams('form_name', 'kontakt');") . '</li></ul>'
                    . '<p>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_direct')) . '</p>'
                    . '<ul><li>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_pipe')) . ' ' . $code('objparams|upkeep_spam_protection|0') . '</li>'
                    . '<li>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_php')) . ' ' . $code("\$yform->setObjectparams('upkeep_spam_protection', 0);") . '</li></ul>'
                    . ($seen ? '<p>' . rex_escape(rex_i18n::rawMsg('upkeep_set_exclude_explain_seen')) . ' ' . implode(', ', array_map($code, $seen)) . '</p>' : '')
                    . '</div>';
            }
            return $html;
        case 'password':
            $isSet = '' !== (string) $addon->getConfig($field['hashKey'], '') || '' !== (string) $addon->getConfig($key, '');
            return Ui::row($label($key), '<input class="form-control" type="password" autocomplete="new-password" minlength="8" id="' . $id . '" name="' . rex_escape($key) . '" placeholder="'
                . rex_escape(rex_i18n::rawMsg($isSet ? 'upkeep_set_password_keep' : 'upkeep_set_password_none')) . '">', $help($key), $id);
        case 'secret':
            $secret = (string) $addon->getConfig($key, '');
            $display = $secret;
            if (!empty($field['bypassLink']) && '' !== $secret) {
                $display = rtrim((string) rex::getServer(), '/') . '/?' . rawurlencode((string) $addon->getConfig('bypass_param_key', 'access')) . '=' . rawurlencode($secret);
            }
            $control = '<input class="form-control upk-mono" type="text" readonly id="' . $id . '" value="' . rex_escape($display) . '" placeholder="' . rex_escape(rex_i18n::rawMsg('upkeep_set_secret_empty')) . '">';
            return Ui::row($label($key), $control, $help($key), $id, '', true)
                . '<div class="upk-row"><div class="upk-row-label"></div><div class="upk-row-control">'
                . '<button type="submit" form="upk-action-' . rex_escape($field['action']) . '" class="btn btn-default btn-xs" data-confirm="' . rex_escape(rex_i18n::rawMsg('upkeep_set_secret_regenerate_confirm')) . '">'
                . '<i class="rex-icon fa fa-refresh" aria-hidden="true"></i> ' . rex_escape(rex_i18n::rawMsg($secret ? 'upkeep_set_secret_regenerate' : 'upkeep_set_secret_create')) . '</button></div></div>';
        case 'langtexts':
            $rows = json_decode((string) $addon->getConfig($key, '[]'), true);
            $rows = is_array($rows) ? $rows : [];
            $rows[] = ['language_code' => '', '_new' => true];
            $html = '';
            foreach ($rows as $i => $row) {
                $isNew = !empty($row['_new']);
                $f = static function (string $name, string $type = 'text') use ($row, $i, $addon) {
                    $fid = 'upk-lt-' . $i . '-' . $name;
                    $val = (string) ($row[$name] ?? '');
                    $input = 'textarea' === $type
                        ? '<textarea class="form-control" rows="3" id="' . $fid . '" name="langtexts[' . $i . '][' . $name . ']">' . rex_escape($val) . '</textarea>'
                        : '<input class="form-control" type="text" id="' . $fid . '" name="langtexts[' . $i . '][' . $name . ']" value="' . rex_escape($val) . '">';
                    return '<div class="form-group' . ('textarea' === $type ? ' upk-lang-wide' : '') . '"><label for="' . $fid . '">' . rex_escape(rex_i18n::rawMsg('upkeep_set_lt_' . $name)) . '</label>' . $input . '</div>';
                };
                $title = $isNew ? rex_i18n::rawMsg('upkeep_set_lt_add') : (($row['language_name'] ?? '') ?: $row['language_code']) . ' (' . $row['language_code'] . ')';
                $grid = '<div class="upk-lang-grid">' . $f('language_code') . $f('language_name') . $f('title') . $f('language_switch') . $f('message', 'textarea') . $f('password_label') . $f('password_button') . '</div>';
                $remove = $isNew ? '' : '<label class="checkbox-inline"><input type="checkbox" name="langtexts[' . $i . '][remove]" value="1"> ' . rex_escape(rex_i18n::rawMsg('upkeep_set_lt_remove')) . '</label>';
                $html .= '<details class="upk-lang"><summary><strong>' . rex_escape($title) . '</strong></summary>' . $grid . $remove . '</details>';
            }
            return Ui::row($label($key), '', $help($key)) . $html;
        default: // text, email
            return Ui::row($label($key), '<input class="form-control" type="' . ('email' === $type ? 'email' : 'text') . '" id="' . $id . '" name="' . rex_escape($key) . '" value="' . rex_escape((string) $value) . '">', $help($key), $id);
    }
};

// ---------- Inhalt ----------
$content = '<div class="upk-settings-head">' . Ui::icon($def['icon'], $def['color'])
    . '<div><h2>' . rex_escape(rex_i18n::rawMsg('upkeep_set_section_' . $section)) . '</h2><p>' . rex_escape(rex_i18n::rawMsg('upkeep_set_section_' . $section . '_desc')) . '</p></div></div>';
$content .= implode('', $messages);

$content .= '<form method="post" action="' . $url($section) . '">' . $csrf->getHiddenField() . '<input type="hidden" name="upk_save" value="1">';
foreach ($def['groups'] as $group) {
    $rows = array_map($renderField, $group['fields']);
    $content .= Ui::group('' !== $group['title'] ? rex_i18n::rawMsg($group['title']) : '', $rows, isset($group['note']) ? rex_i18n::rawMsg($group['note']) : '');
}
$content .= '<div class="upk-settings-actions">';
if (isset($def['pageLink'])) {
    $content .= '<a class="btn btn-default" href="' . rex_url::backendPage($def['pageLink'][0]) . '">' . rex_escape(rex_i18n::rawMsg($def['pageLink'][1])) . '</a>';
}
$content .= '<button type="submit" class="btn btn-save">' . rex_escape(rex_i18n::rawMsg('upkeep_set_save')) . '</button></div></form>';

// Separate Formulare für Aktionen (Knöpfe in Feldern verweisen per form="…" darauf)
foreach (SettingsSections::fields($section) as $field) {
    if ('secret' === $field['type']) {
        $content .= '<form id="upk-action-' . rex_escape($field['action']) . '" method="post" action="' . $url($section) . '" hidden>' . $csrf->getHiddenField()
            . '<input type="hidden" name="upk_action" value="' . rex_escape($field['action']) . '"></form>';
    }
}

// Werkzeuge des Bereichs
$tools = [];
foreach ($def['actions'] ?? [] as $action) {
    $btn = static fn (string $label, string $confirm = '', array $extra = []) => Ui::postButton($action, $label, 'upkeep_settings', $extra, 'btn-default btn-sm', $confirm, '', $url($section));
    switch ($action) {
        case 'ips_cleanup':
            $tools[] = Ui::row(rex_i18n::rawMsg('upkeep_set_tool_ips_cleanup'), $btn(rex_i18n::rawMsg('upkeep_set_tool_run'), rex_i18n::rawMsg('upkeep_set_tool_ips_cleanup_confirm')), rex_i18n::rawMsg('upkeep_set_tool_ips_cleanup_help'));
            break;
        case 'geoip_update':
            $tools[] = Ui::row(rex_i18n::rawMsg('upkeep_set_tool_geoip'), $btn(rex_i18n::rawMsg('upkeep_set_tool_run')), rex_i18n::rawMsg('upkeep_set_tool_geoip_help'));
            break;
        case 'mail_cleanup':
            $tools[] = Ui::row(rex_i18n::rawMsg('upkeep_set_tool_mail_cleanup'), $btn(rex_i18n::rawMsg('upkeep_set_tool_mail_cleanup_30'), rex_i18n::rawMsg('upkeep_set_tool_ips_cleanup_confirm'), ['days' => 30]), rex_i18n::rawMsg('upkeep_set_tool_mail_cleanup_help'));
            break;
        case 'report_test':
            $tools[] = Ui::row(rex_i18n::rawMsg('upkeep_set_tool_report_test'), $btn(rex_i18n::rawMsg('upkeep_set_tool_send')), rex_i18n::rawMsg('upkeep_set_tool_report_test_help'));
            break;
        case 'report_status':
            $tools[] = Ui::row(rex_i18n::rawMsg('upkeep_set_tool_report_status'), $btn(rex_i18n::rawMsg('upkeep_set_tool_send')));
            break;
    }
}
if ($tools) {
    $content .= Ui::group(rex_i18n::rawMsg('upkeep_set_group_tools'), $tools);
}

echo '<div class="upk-settings">' . $sidebar . '<div class="upk-settings-main">' . $content . '</div></div>';
