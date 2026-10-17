<?php

/**
 * Wartung je Domain (YRewrite): einzelne Domains oder alle sperren.
 */

use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');

if (!rex_addon::get('yrewrite')->isAvailable()) {
    echo rex_view::info(rex_escape(rex_i18n::rawMsg('upkeep_yrewrite_not_available')));
    return;
}

$csrf = rex_csrf_token::factory('upkeep_domains');
$domains = array_filter(rex_yrewrite::getDomains(), static fn ($d) => 'default' !== $d->getName());

if ('post' === rex_request_method() && rex_post('upk_save', 'bool')) {
    if (!$csrf->isValid()) {
        echo rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        $addon->setConfig('all_domains_locked', rex_post('all_domains_locked', 'int', 0) ? 1 : 0);
        $status = [];
        foreach ($domains as $domain) {
            $status[$domain->getName()] = (bool) rex_post('domain_' . md5($domain->getName()), 'int', 0);
        }
        $addon->setConfig('domain_status', $status);
        rex_extension::registerPoint(new rex_extension_point('UPKEEP_MAINTENANCE_CHANGED', ['area' => 'domains', 'source' => 'backend']));
        echo rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_set_saved')));
    }
}

$all = (bool) $addon->getConfig('all_domains_locked', false);
$status = (array) $addon->getConfig('domain_status', []);

$rows = [];
foreach ($domains as $domain) {
    $name = $domain->getName();
    $id = 'upk-domain-' . md5($name);
    $rows[] = Ui::row($name, Ui::switch('domain_' . md5($name), !empty($status[$name]), $id, $all), (string) $domain->getUrl(), $id, Ui::icon('fa-globe', 'blue'));
}

echo '<form method="post" action="' . rex_url::currentBackendPage() . '">' . $csrf->getHiddenField() . '<input type="hidden" name="upk_save" value="1">'
    . Ui::group('', [Ui::row(rex_i18n::rawMsg('upkeep_lock_all_domains'), Ui::switch('all_domains_locked', $all, 'upk-all-domains'), rex_i18n::rawMsg('upkeep_domains_all_help'), 'upk-all-domains', Ui::icon('fa-lock', 'red'))])
    . ($rows ? Ui::group(rex_i18n::rawMsg('upkeep_domains_single'), $rows, $all ? rex_i18n::rawMsg('upkeep_domains_all_active_note') : rex_i18n::rawMsg('upkeep_domains_notice_short'))
        : Ui::group('', ['<div class="upk-empty">' . rex_escape(rex_i18n::rawMsg('upkeep_domains_none')) . '</div>']))
    . '<div class="upk-settings-actions"><button type="submit" class="btn btn-save">' . rex_escape(rex_i18n::rawMsg('upkeep_set_save')) . '</button></div></form>';
