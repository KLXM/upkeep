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
$field->setAttribute('id', 'upkeep-allowed-ips');

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


// API-Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_api_settings'));

// API Token
$field = $form->addTextField('api_token');
$field->setLabel($addon->i18n('upkeep_api_token'));
$field->setAttribute('class', 'form-control');
$field->setNotice($addon->i18n('upkeep_api_token_notice'));

// Button zum Generieren eines zufälligen Tokens
$genButton = '<button class="btn btn-sm btn-primary" type="button" id="upkeep-gen-token">' . $addon->i18n('upkeep_generate_token') . '</button>';
$field->setNotice($field->getNotice() . ' ' . $genButton);

// Vorschau-Bereich
$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_settings'), false);
$fragment->setVar('body', $form->get(), false);
echo $fragment->parse('core/page/section.php');
?>
<script type="text/javascript">
$(document).on('rex:ready', function() {
    // IP-Adresse hinzufügen
    $('#upkeep-add-ip').on('click', function(e) {
        e.preventDefault();
        var ipField = $('#upkeep-allowed-ips');
        var currentIp = '<?= rex_server('REMOTE_ADDR', 'string', '') ?>';
        
        if (ipField.val().trim() === '') {
            ipField.val(currentIp);
        } else {
            // IP-Adressen als Array verarbeiten
            var ips = ipField.val().split(',').map(function(ip) {
                return ip.trim();
            });
            
            // Prüfen, ob IP bereits enthalten ist
            if (ips.indexOf(currentIp) === -1) {
                ips.push(currentIp);
                ipField.val(ips.join(', '));
            }
        }
    });

    // Token generieren - korrigierte Selektoren
    $('#upkeep-gen-token').on('click', function(e) {
        e.preventDefault();
        // Zufälligen Token generieren
        var token = '';
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (var i = 0; i < 32; i++) {
            token += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        // Korrekter Selektor basierend auf dem tatsächlichen Eingabefeld
        $('input[name="api_einstellungen[api_token]"]').val(token);
        // Alternative mit ID
        $('#api-einstellungen-api-token').val(token);
    });
});
</script>
