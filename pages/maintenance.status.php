<?php

/**
 * Wartung: Website (Frontend) und Backend sperren/freigeben, mit Überblick, wer trotzdem Zugang hat.
 */

use KLXM\Upkeep\Ui;
use KLXM\Upkeep\Upkeep;

$addon = rex_addon::get('upkeep');
$user = rex::requireUser();
$csrf = rex_csrf_token::factory('upkeep_maintenance');

if ('post' === rex_request_method() && rex_post('upk_save', 'bool')) {
    if (!$csrf->isValid()) {
        echo rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        $areas = ['frontend' => rex_post('frontend_active', 'int', 0) ? true : false];
        // Backend sperren dürfen nur Admins (sie selbst bleiben immer drin)
        if ($user->isAdmin()) {
            $areas['backend'] = rex_post('backend_active', 'int', 0) ? true : false;
        }
        foreach ($areas as $area => $on) {
            if ((bool) $addon->getConfig($area . '_active', false) === $on) {
                continue;
            }
            if (method_exists(Upkeep::class, 'setMaintenance')) {
                Upkeep::setMaintenance($area, $on, 'backend');
            } else {
                $addon->setConfig($area . '_active', $on ? 1 : 0);
            }
        }
        echo rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_saved')));
    }
}

$frontendOn = (bool) $addon->getConfig('frontend_active', false);
$backendOn = (bool) $addon->getConfig('backend_active', false);

$switches = [
    Ui::row(rex_i18n::rawMsg('upkeep_maint_frontend'), Ui::switch('frontend_active', $frontendOn, 'upk-frontend'), rex_i18n::rawMsg('upkeep_maint_frontend_help'), 'upk-frontend', Ui::icon('fa-globe', 'red')),
];
if ($user->isAdmin()) {
    $switches[] = Ui::row(rex_i18n::rawMsg('upkeep_maint_backend'), Ui::switch('backend_active', $backendOn, 'upk-backend'), rex_i18n::rawMsg('upkeep_maint_backend_help'), 'upk-backend', Ui::icon('fa-users', 'orange'));
}

// Wer kommt trotz Wartung auf die Website?
$access = [];
$yes = Ui::badge(rex_i18n::rawMsg('upkeep_dash_on'), 'ok');
$no = Ui::badge(rex_i18n::rawMsg('upkeep_dash_off'));
$access[] = Ui::row(rex_i18n::rawMsg('upkeep_set_bypass_logged_in'), $addon->getConfig('bypass_logged_in', true) ? $yes : $no);
$ips = array_filter(array_map('trim', preg_split('/[\r\n,]+/', (string) $addon->getConfig('allowed_ips', '')) ?: []));
$access[] = Ui::row(rex_i18n::rawMsg('upkeep_set_allowed_ips'), Ui::badge((string) count($ips), $ips ? 'info' : 'muted'), implode(', ', array_slice($ips, 0, 5)));
$hasPassword = '' !== (string) $addon->getConfig('frontend_password_hash', '') || '' !== (string) $addon->getConfig('frontend_password', '');
$access[] = Ui::row(rex_i18n::rawMsg('upkeep_set_frontend_password'), $hasPassword ? $yes : $no);
$access[] = Ui::row(rex_i18n::rawMsg('upkeep_set_allow_bypass_param'), $addon->getConfig('allow_bypass_param', false) ? $yes : $no);

$foot = $user->isAdmin()
    ? '<a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'maintenance']) . '">' . rex_escape(rex_i18n::rawMsg('upkeep_maint_open_settings')) . '</a>'
    : '';

echo '<form method="post" action="' . rex_url::currentBackendPage() . '">' . $csrf->getHiddenField() . '<input type="hidden" name="upk_save" value="1">'
    . Ui::group(rex_i18n::rawMsg('upkeep_maint_group_switches'), $switches, rex_i18n::rawMsg('upkeep_maint_admin_note'))
    . '<div class="upk-settings-actions"><a class="btn btn-default" href="' . rex_escape(rex_url::frontend()) . '" target="_blank" rel="noopener">' . rex_escape(rex_i18n::rawMsg('upkeep_maint_preview')) . '</a>'
    . '<button type="submit" class="btn btn-save">' . rex_escape(rex_i18n::rawMsg('upkeep_set_save')) . '</button></div></form>'
    . Ui::group(rex_i18n::rawMsg('upkeep_maint_group_access'), $access)
    . ('' !== $foot ? '<div class="upk-settings-actions">' . $foot . '</div>' : '');
