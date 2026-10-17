<?php

/**
 * Upkeep 3.0 – Schutz: E-Mail-Sicherheit.
 *
 * Tabs: ?tab=events|badwords|blocklist|patterns, Inhalte in pages/mail/<tab>.php.
 */

use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$pageKey = 'upkeep/protection/mail';
$mailTabs = [
    'events' => rex_i18n::rawMsg('upkeep_mail_tab_events'),
    'badwords' => rex_i18n::rawMsg('upkeep_mail_security_badwords'),
    'blocklist' => rex_i18n::rawMsg('upkeep_mail_security_blocklist'),
    'patterns' => rex_i18n::rawMsg('upkeep_mail_tab_patterns'),
];
$tab = rex_request('tab', 'string', 'events');
if (!isset($mailTabs[$tab])) {
    $tab = 'events';
}
$tabUrl = static fn (array $params = []): string => rex_url::backendPage($pageKey, ['tab' => $tab] + $params);

$active = (bool) $addon->getConfig('mail_security_active', false);
$headActions = Ui::badge(rex_i18n::rawMsg($active ? 'upkeep_mail_module_on' : 'upkeep_mail_module_off'), $active ? 'ok' : 'muted');
if (rex::requireUser()->isAdmin()) {
    $headActions .= ' <a class="btn btn-default" href="' . rex_url::backendPage('upkeep/settings', ['section' => 'mail']) . '">' . rex_escape(rex_i18n::rawMsg('upkeep_nav_settings')) . '</a>';
}
echo Ui::hero(rex_i18n::rawMsg('upkeep_set_section_mail'), rex_i18n::rawMsg('upkeep_set_section_mail_desc'), Ui::icon('fa-envelope-o', 'teal'), $headActions);

$segments = [];
foreach ($mailTabs as $key => $label) {
    $segments[$key] = [$label, rex_url::backendPage($pageKey, ['tab' => $key])];
}
echo Ui::segmented($segments, $tab, rex_i18n::rawMsg('upkeep_set_section_mail'));

include __DIR__ . '/mail/' . $tab . '.php';

// "Alle auswählen" für Sammelaktionen (Checkbox mit data-upk-check-all="<form-id>")
?>
<script nonce="<?= rex_response::getNonce() ?>">
(function () {
    if (window.upkCheckAllBound) {
        return;
    }
    window.upkCheckAllBound = true;
    document.addEventListener('change', function (event) {
        var master = event.target;
        if (!master.matches || !master.matches('[data-upk-check-all]')) {
            return;
        }
        var formId = master.getAttribute('data-upk-check-all');
        document.querySelectorAll('input[type="checkbox"][form="' + formId + '"][name$="[]"]').forEach(function (box) {
            box.checked = master.checked;
        });
    });
})();
</script>
