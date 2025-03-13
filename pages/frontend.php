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
$field = $form->addInputField('password', 'frontend_password_input', null, ['id' => 'upkeep-password']);
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

// JavaScript für IP-Adresse und Passwort-Handling
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
    
    // Passwort-Handling beim Speichern
    document.querySelector('form.rex-form').addEventListener('submit', function(e) {
        var passwordField = document.getElementById('upkeep-password');
        var hiddenField = document.createElement('input');
        
        // Nur wenn das Passwort-Feld ausgefüllt ist, ein gehashtes Passwort speichern
        if (passwordField.value.trim() !== '') {
            e.preventDefault();
            
            // AJAX-Request zum Hashen des Passworts
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '<?= rex_url::currentBackendPage(['upkeep_action' => 'hash_password']) ?>', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    var response = JSON.parse(xhr.responseText);
                    
                    // Verstecktes Feld für das gehashte Passwort erstellen
                    hiddenField.type = 'hidden';
                    hiddenField.name = 'frontend_password';
                    hiddenField.value = response.hash;
                    
                    // Zum Formular hinzufügen und abschicken
                    document.querySelector('form.rex-form').appendChild(hiddenField);
                    document.querySelector('form.rex-form').submit();
                }
            };
            xhr.send('password=' + encodeURIComponent(passwordField.value));
        }
    });
});
</script>

<?php
// AJAX-Handler für Passwort-Hashing
if (rex_request('upkeep_action', 'string') === 'hash_password') {
    $password = rex_request('password', 'string');
    $hash = password_hash($password, PASSWORD_DEFAULT);
    
    header('Content-Type: application/json');
    echo json_encode(['hash' => $hash]);
    exit;
}
