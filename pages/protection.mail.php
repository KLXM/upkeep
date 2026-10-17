<?php

/**
 * Upkeep 3.0 – Schutz: E-Mail-Sicherheit.
 *
 * Tabs: ?tab=events|badwords|blocklist|patterns, Inhalte in pages/mail/<tab>.php.
 */

$addon = rex_addon::get('upkeep');
$pageKey = 'upkeep/protection/mail';
$mailTabs = [
    'events' => $addon->i18n('upkeep_mail_tab_events'),
    'badwords' => $addon->i18n('upkeep_mail_security_badwords'),
    'blocklist' => $addon->i18n('upkeep_mail_security_blocklist'),
    'patterns' => $addon->i18n('upkeep_mail_tab_patterns'),
];
$tab = rex_request('tab', 'string', 'events');
if (!isset($mailTabs[$tab])) {
    $tab = 'events';
}
$tabUrl = static fn (array $params = []): string => rex_url::backendPage($pageKey, ['tab' => $tab] + $params);

$active = (bool) $addon->getConfig('mail_security_active', false);

echo '<div class="upk-toolbar">'
    . '<span class="upk-badge ' . ($active ? 'upk-badge--ok' : 'upk-badge--muted') . '">' . rex_escape($active ? $addon->i18n('upkeep_mail_module_on') : $addon->i18n('upkeep_mail_module_off')) . '</span> '
    . '<a href="' . rex_url::backendPage('upkeep/settings', ['section' => 'mail']) . '"><i class="rex-icon fa-cog"></i> ' . rex_escape($addon->i18n('upkeep_pages_settings_link')) . '</a>'
    . '</div>';

echo '<div class="upk-tabs"><ul class="nav nav-tabs">';
foreach ($mailTabs as $key => $label) {
    echo '<li' . ($key === $tab ? ' class="active"' : '') . '><a href="' . rex_url::backendPage($pageKey, ['tab' => $key]) . '">' . rex_escape($label) . '</a></li>';
}
echo '</ul></div>';

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
