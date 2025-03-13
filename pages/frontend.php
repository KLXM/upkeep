<?php
/**
 * Frontend-Einstellungen für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();
$form = rex_config_form::factory($addon->getName());

// Allgemeine Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_general_settings'));

// Frontend-Wartungsmodus aktivieren/deaktivieren
$field = $form->addSelectField('frontend_active');
$field->setLabel($addon->i18n('upkeep_frontend_active'));
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_active'), 1);
$select->addOption($addon->i18n('upkeep_inactive'), 0);

// Überschrift für die Wartungsseite
$field = $form->addTextField('maintenance_page_title');
$field->setLabel($addon->i18n('upkeep_page_title'));
$field->setAttribute('class', 'form-control');

// Nachricht für die Wartungsseite
$field = $form->addTextAreaField('maintenance_page_message');
$field->setLabel($addon->i18n('upkeep_page_message'));
$field->setAttribute('class', 'form-control');
$field->setAttribute('rows', 5);

// Einstellungen für Zugriffsberechtigung
$field = $form->addFieldset($addon->i18n('upkeep_access_settings'));

// Passwort für Frontend-Zugang
$field = $form->addTextField('frontend_password');
$field->setLabel($addon->i18n('upkeep_frontend_password'));
$field->setAttribute('class', 'form-control');
$field->setNotice($addon->i18n('upkeep_frontend_password_notice'));

// Angemeldte Benutzer vom Wartungsmodus ausnehmen
$field = $form->addSelectField('bypass_logged_in');
$field->setLabel($addon->i18n('upkeep_bypass_logged_in'));
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_yes'), 1);
$select->addOption($addon->i18n('upkeep_no'), 0);

// Liste der erlaubten IP-Adressen
$field = $form->addTextField('allowed_ips');
$field->setLabel($addon->i18n('upkeep_allowed_ips'));
$field->setAttribute('class', 'form-control');

// Aktuelle IP-Adresse anzeigen
$notice = $addon->i18n('upkeep_your_ip') . ': <code>' . rex_server('REMOTE_ADDR', 'string', '') . '</code>';
$notice .= ' <button class="btn btn-sm btn-primary" type="button" id="upkeep-add-ip">' . $addon->i18n('upkeep_add_ip') . '</button>';
$field->setNotice($notice);

// HTTP-Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_http_settings'));

// HTTP-Statuscode
$field = $form->addSelectField('http_status_code');
$field->setLabel($addon->i18n('upkeep_http_status_code'));
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_http_503'), rex_response::HTTP_SERVICE_UNAVAILABLE);
$select->addOption($addon->i18n('upkeep_http_503_no_cache'), '503');
$select->addOption($addon->i18n('upkeep_http_403'), rex_response::HTTP_FORBIDDEN);
#$select->addOption($addon->i18n('upkeep_http_307'), rex_response::HTTP_TEMPORARY_REDIRECT);

// Retry-After Header
$field = $form->addInputField('number', 'retry_after', null, ['min' => '0']);
$field->setLabel($addon->i18n('upkeep_retry_after'));
$field->setNotice($addon->i18n('upkeep_retry_after_notice'));
$field->setAttribute('class', 'form-control');

// YRewrite-Domain-Einstellungen
if (rex_addon::get('yrewrite')->isAvailable()) {
    $field = $form->addFieldset($addon->i18n('upkeep_yrewrite_settings'));
    
    $field = $form->addSelectField('allowed_domains', null, ['class' => 'form-control selectpicker', 'multiple' => 'multiple']);
    $field->setLabel($addon->i18n('upkeep_allowed_domains'));
    $select = $field->getSelect();
    
    foreach (rex_yrewrite::getDomains() as $domain) {
        if ($domain->getName() !== 'default') {
            $select->addOption($domain->getName(), $domain->getName());
        }
    }
}

// Vorschau-Bereich
$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_settings'), false);
$fragment->setVar('body', $form->get(), false);
echo $fragment->parse('core/page/section.php');

// JavaScript für IP-Adresse hinzufügen
?>
<script type="text/javascript">
document.addEventListener('DOMContentLoaded', function() {
    // IP-Adresse hinzufügen
    document.getElementById('upkeep-add-ip').addEventListener('click', function() {
        var ipField = document.querySelector('input[name="allowed_ips"]');
        var currentIp = '<?= rex_server('REMOTE_ADDR', 'string', '') ?>';
        
        if (ipField.value.trim() === '') {
            ipField.value = currentIp;
        } else {
            // Prüfen, ob IP bereits enthalten ist
            if (!ipField.value.split(',').map(ip => ip.trim()).includes(currentIp)) {
                ipField.value = ipField.value + ', ' + currentIp;
            }
        }
    });
});
</script>
