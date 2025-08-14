<?php
/**
 * Frontend-Einstellungen für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();

// Sicherstellen, dass Standard-Konfiguration vorhanden ist
if ($addon->getConfig('multilanguage_enabled') === null) {
    $addon->setConfig('multilanguage_enabled', 1);
}

if ($addon->getConfig('multilanguage_default') === null) {
    $addon->setConfig('multilanguage_default', 'de');
}

if ($addon->getConfig('multilanguage_texts', '') === '') {
    $defaultTexts = [
        [
            'language_code' => 'de',
            'language_name' => 'Deutsch',
            'title' => 'Wartungsarbeiten',
            'message' => 'Diese Website befindet sich derzeit im Wartungsmodus. Bitte versuchen Sie es später erneut.',
            'password_label' => 'Passwort eingeben',
            'password_button' => 'Anmelden',
            'language_switch' => 'Sprache wählen'
        ],
        [
            'language_code' => 'en',
            'language_name' => 'English',
            'title' => 'Maintenance Mode',
            'message' => 'This website is currently under maintenance. Please try again later.',
            'password_label' => 'Enter Password',
            'password_button' => 'Login',
            'language_switch' => 'Choose Language'
        ]
    ];
    
    $addon->setConfig('multilanguage_texts', json_encode($defaultTexts));
}

// Verarbeitung des Sprachtexte-Formulars
if (rex_post('config-submit', 'int', 0) && rex_post('config', 'array', [])) {
    $config = rex_post('config', 'array', []);
    if (isset($config['multilanguage_texts'])) {
        // JSON validieren
        $languageTexts = json_decode($config['multilanguage_texts'], true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($languageTexts)) {
            rex_config::set($addon->getName(), 'multilanguage_texts', $config['multilanguage_texts']);
            echo rex_view::success($addon->i18n('upkeep_config_saved') ?: 'Einstellungen wurden gespeichert.');
        } else {
            echo rex_view::error($addon->i18n('upkeep_config_error') ?: 'Fehler beim Speichern der Einstellungen.');
        }
    }
}

$form = rex_config_form::factory($addon->getName());

// Allgemeine Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_general_settings'));

// Frontend-Wartungsmodus aktivieren/deaktivieren
$field = $form->addSelectField('frontend_active');
$field->setLabel($addon->i18n('upkeep_frontend_active') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_frontend_active_tooltip')) . '"></i>');
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_active'), 1);
$select->addOption($addon->i18n('upkeep_inactive'), 0);

// Mehrsprachigkeit
$field = $form->addFieldset($addon->i18n('upkeep_multilanguage_settings'));

// Mehrsprachigkeit aktivieren
$field = $form->addSelectField('multilanguage_enabled');
$field->setLabel($addon->i18n('upkeep_multilanguage_enabled') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_multilanguage_enabled_tooltip')) . '"></i>');
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_yes'), 1);
$select->addOption($addon->i18n('upkeep_no'), 0);

// Sprachtexte als verstecktes Feld (wird über separates Formular verwaltet)
$field = $form->addHiddenField('multilanguage_texts');

// Einstellungen für Zugriffsberechtigung
$field = $form->addFieldset($addon->i18n('upkeep_access_settings'));

// URL-Parameter für Bypass
$field = $form->addSelectField('allow_bypass_param');
$field->setLabel($addon->i18n('upkeep_allow_bypass_param') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_allow_bypass_param_tooltip')) . '"></i>');
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_yes'), 1);
$select->addOption($addon->i18n('upkeep_no'), 0);

$field = $form->addTextField('bypass_param_key');
$field->setLabel($addon->i18n('upkeep_bypass_param_key') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_bypass_param_key_tooltip')) . '"></i>');
$field->setAttribute('class', 'form-control');
$field->setNotice($addon->i18n('upkeep_bypass_param_key_notice'));

// Passwort für Frontend-Zugang
$field = $form->addTextField('frontend_password');
$field->setLabel($addon->i18n('upkeep_frontend_password') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_frontend_password_tooltip')) . '"></i>');
$field->setAttribute('class', 'form-control');
$field->setNotice($addon->i18n('upkeep_frontend_password_notice'));

// Angemeldte Benutzer vom Wartungsmodus ausnehmen
$field = $form->addSelectField('bypass_logged_in');
$field->setLabel($addon->i18n('upkeep_bypass_logged_in') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_bypass_logged_in_tooltip')) . '"></i>');
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_yes'), 1);
$select->addOption($addon->i18n('upkeep_no'), 0);

// Liste der erlaubten IP-Adressen
$field = $form->addTextField('allowed_ips');
$field->setLabel($addon->i18n('upkeep_allowed_ips') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_allowed_ips_tooltip')) . '"></i>');
$field->setAttribute('class', 'form-control');
$field->setAttribute('id', 'upkeep-allowed-ips');

// Aktuelle IP-Adresse anzeigen
$clientIp = rex_server('REMOTE_ADDR', 'string', '');
$serverIp = $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['SERVER_NAME'] ?? 'localhost');

// IP-Adressen als formatierte Liste mit Buttons
$notice = '<div class="ip-addresses">';
$notice .= '<div class="ip-address-row"><span class="ip-label">' . $addon->i18n('upkeep_your_ip') . ':</span> <code class="ip-code">' . $clientIp . '</code>';
$notice .= ' <button class="btn btn-xs btn-primary" type="button" id="upkeep-add-ip"><i class="rex-icon fa-plus"></i> ' . $addon->i18n('upkeep_add_ip') . '</button></div>';
$notice .= '<div class="ip-address-row"><span class="ip-label">' . $addon->i18n('upkeep_server_ip') . ':</span> <code class="ip-code">' . $serverIp . '</code>';
$notice .= ' <button class="btn btn-xs btn-primary" type="button" id="upkeep-add-server-ip"><i class="rex-icon fa-plus"></i> ' . $addon->i18n('upkeep_add_server_ip') . '</button></div>';
$notice .= '</div>';
$notice .= '<style>
.ip-addresses { margin-top: 5px; }
.ip-address-row { margin-bottom: 5px; display: flex; align-items: center; }
.ip-label { min-width: 120px; }
.ip-code { margin: 0 10px; display: inline-block; min-width: 100px; }
</style>';
$field->setNotice($notice);

// HTTP-Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_http_settings'));

// HTTP-Statuscode
$field = $form->addSelectField('http_status_code');
$field->setLabel($addon->i18n('upkeep_http_status_code') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_http_status_code_tooltip')) . '"></i>');
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_http_503'), rex_response::HTTP_SERVICE_UNAVAILABLE);
$select->addOption($addon->i18n('upkeep_http_503_no_cache'), '503');
$select->addOption($addon->i18n('upkeep_http_403'), rex_response::HTTP_FORBIDDEN);
#$select->addOption($addon->i18n('upkeep_http_307'), rex_response::HTTP_TEMPORARY_REDIRECT);

// Retry-After Header
$field = $form->addInputField('number', 'retry_after', null, ['min' => '0']);
$field->setLabel($addon->i18n('upkeep_retry_after') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_retry_after_tooltip')) . '"></i>');
$field->setNotice($addon->i18n('upkeep_retry_after_notice'));
$field->setAttribute('class', 'form-control');


// API-Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_api_settings'));

// API Token
$field = $form->addTextField('api_token');
$field->setLabel($addon->i18n('upkeep_api_token') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_api_token_tooltip')) . '"></i>');
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

// Sprachtexte-Repeater am Ende hinzufügen
$languageTexts = rex_config::get($addon->getName(), 'multilanguage_texts', '[]');
$textsArray = json_decode($languageTexts, true) ?: [];

// Standard-Eintrag für Deutsch falls noch nicht vorhanden
if (empty($textsArray)) {
    $textsArray = [
        [
            'language_code' => 'de',
            'language_name' => 'Deutsch',
            'title' => 'Wartungsarbeiten',
            'message' => 'Diese Website befindet sich derzeit im Wartungsmodus. Bitte versuchen Sie es später erneut.',
            'password_label' => 'Passwort eingeben',
            'password_button' => 'Anmelden',
            'language_switch' => 'Sprache wählen'
        ]
    ];
}

// Formular für Sprachtexte als separater Bereich
$languageForm = '
<form id="language-texts-form" method="post" action="">
    <input type="hidden" name="config[multilanguage_texts]" id="multilanguage_texts_field" value="' . rex_escape(json_encode($textsArray)) . '">
    
    <div class="form-group">
        <label class="control-label">' . $addon->i18n('upkeep_multilanguage_texts') . ' <i class="rex-icon fa-question-circle" data-toggle="tooltip" data-placement="right" title="' . rex_escape($addon->i18n('upkeep_multilanguage_texts_tooltip')) . '"></i></label>
        <div id="language-repeater">
            <div class="language-entries">';

foreach ($textsArray as $index => $text) {
    $languageForm .= '
        <div class="language-entry panel panel-default" data-index="' . $index . '">
            <div class="panel-heading">
                <h4 class="panel-title">
                    <span class="language-title">' . rex_escape($text['language_name'] ?? 'Sprache') . ' (' . rex_escape($text['language_code'] ?? '') . ')</span>
                    <div class="pull-right">
                        <button type="button" class="btn btn-xs btn-danger remove-language" title="Sprache entfernen">
                            <i class="rex-icon fa-trash"></i>
                        </button>
                    </div>
                </h4>
            </div>
            <div class="panel-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Sprachcode (z.B. de, en, fr)</label>
                            <input type="text" class="form-control language-code" value="' . rex_escape($text['language_code'] ?? '') . '" placeholder="de">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Sprachname (z.B. Deutsch, English)</label>
                            <input type="text" class="form-control language-name" value="' . rex_escape($text['language_name'] ?? '') . '" placeholder="Deutsch">
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Überschrift</label>
                    <input type="text" class="form-control language-title-input" value="' . rex_escape($text['title'] ?? '') . '" placeholder="Wartungsarbeiten">
                </div>
                <div class="form-group">
                    <label>Hauptnachricht</label>
                    <textarea class="form-control language-message" rows="3" placeholder="Diese Website befindet sich derzeit im Wartungsmodus...">' . rex_escape($text['message'] ?? '') . '</textarea>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Passwort-Eingabe Bezeichnung</label>
                            <input type="text" class="form-control language-password-label" value="' . rex_escape($text['password_label'] ?? '') . '" placeholder="Passwort eingeben">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Anmelde-Button Text</label>
                            <input type="text" class="form-control language-password-button" value="' . rex_escape($text['password_button'] ?? '') . '" placeholder="Anmelden">
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Sprachwechsel Bezeichnung</label>
                    <input type="text" class="form-control language-switch" value="' . rex_escape($text['language_switch'] ?? '') . '" placeholder="Sprache wählen">
                </div>
            </div>
        </div>';
}

$languageForm .= '
            </div>
            <div class="form-group">
                <button type="button" class="btn btn-success" id="add-language">
                    <i class="rex-icon fa-plus"></i> Neue Sprache hinzufügen
                </button>
                <button type="submit" class="btn btn-save" name="config-submit" value="1">
                    <i class="rex-icon rex-icon-save"></i> Sprachtexte speichern
                </button>
            </div>
        </div>
    </div>
</form>';

// Fragment für die Sprachtexte
$languageFragment = new rex_fragment();
$languageFragment->setVar('class', 'edit', false);
$languageFragment->setVar('title', $addon->i18n('upkeep_multilanguage_texts'), false);
$languageFragment->setVar('body', $languageForm, false);
echo $languageFragment->parse('core/page/section.php');
?>
<script type="text/javascript">
$(document).on('rex:ready', function() {
    // Bootstrap-Tooltips aktivieren
    $('[data-toggle="tooltip"]').tooltip();
    
    // Funktion zum Aktualisieren des versteckten JSON-Felds
    function updateLanguageTexts() {
        var languages = [];
        $('.language-entry').each(function() {
            var entry = {
                language_code: $(this).find('.language-code').val(),
                language_name: $(this).find('.language-name').val(),
                title: $(this).find('.language-title-input').val(),
                message: $(this).find('.language-message').val(),
                password_label: $(this).find('.language-password-label').val(),
                password_button: $(this).find('.language-password-button').val(),
                language_switch: $(this).find('.language-switch').val()
            };
            languages.push(entry);
        });
        
        // Korrekte Feldname-Struktur für das separate Formular
        $('#multilanguage_texts_field').val(JSON.stringify(languages));
    }
    
    // Neue Sprache hinzufügen
    $('#add-language').on('click', function() {
        var newIndex = $('.language-entry').length;
        var newEntry = $(`
            <div class="language-entry panel panel-default" data-index="${newIndex}">
                <div class="panel-heading">
                    <h4 class="panel-title">
                        <span class="language-title">Neue Sprache</span>
                        <div class="pull-right">
                            <button type="button" class="btn btn-xs btn-danger remove-language" title="Sprache entfernen">
                                <i class="rex-icon fa-trash"></i>
                            </button>
                        </div>
                    </h4>
                </div>
                <div class="panel-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Sprachcode (z.B. de, en, fr)</label>
                                <input type="text" class="form-control language-code" placeholder="en">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Sprachname (z.B. Deutsch, English)</label>
                                <input type="text" class="form-control language-name" placeholder="English">
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Überschrift</label>
                        <input type="text" class="form-control language-title-input" placeholder="Maintenance Mode">
                    </div>
                    <div class="form-group">
                        <label>Hauptnachricht</label>
                        <textarea class="form-control language-message" rows="3" placeholder="This website is currently under maintenance..."></textarea>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Passwort-Eingabe Bezeichnung</label>
                                <input type="text" class="form-control language-password-label" placeholder="Enter Password">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Anmelde-Button Text</label>
                                <input type="text" class="form-control language-password-button" placeholder="Login">
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Sprachwechsel Bezeichnung</label>
                        <input type="text" class="form-control language-switch" placeholder="Choose Language">
                    </div>
                </div>
            </div>
        `);
        
        $('.language-entries').append(newEntry);
        updateLanguageTexts();
    });
    
    // Sprache entfernen
    $(document).on('click', '.remove-language', function() {
        if ($('.language-entry').length > 1) {
            $(this).closest('.language-entry').remove();
            updateLanguageTexts();
        } else {
            alert('Mindestens eine Sprache muss vorhanden sein.');
        }
    });
    
    // Panel-Titel beim Ändern von Code oder Name aktualisieren
    $(document).on('input', '.language-code, .language-name', function() {
        var entry = $(this).closest('.language-entry');
        var code = entry.find('.language-code').val();
        var name = entry.find('.language-name').val();
        var title = name ? name + (code ? ' (' + code + ')' : '') : (code ? code : 'Neue Sprache');
        entry.find('.language-title').text(title);
        updateLanguageTexts();
    });
    
    // Alle anderen Eingabefelder überwachen
    $(document).on('input', '.language-entry input, .language-entry textarea', function() {
        updateLanguageTexts();
    });
    
    // Initial das JSON aktualisieren
    updateLanguageTexts();
    
    // Funktion zum Hinzufügen einer IP-Adresse zum Whitelist-Feld
    function addIpToWhitelist(ip) {
        var ipField = $('#upkeep-allowed-ips');
        
        if (ipField.val().trim() === '') {
            // Wenn das Feld leer ist, einfach die IP hinzufügen
            ipField.val(ip);
        } else {
            // IP-Adressen als Array verarbeiten und alle Leerzeichen entfernen
            var ips = ipField.val().split(',').map(function(ip) {
                return ip.trim();
            }).filter(function(ip) {
                // Leere Einträge filtern
                return ip !== '';
            });
            
            // Prüfen, ob IP bereits enthalten ist
            if (ips.indexOf(ip) === -1) {
                ips.push(ip);
                // Saubere Komma-getrennte Liste ohne unnötige Leerzeichen
                ipField.val(ips.join(','));
            }
        }
    }
    
    // Client-IP-Adresse hinzufügen
    $('#upkeep-add-ip').on('click', function(e) {
        e.preventDefault();
        var currentIp = '<?= rex_server('REMOTE_ADDR', 'string', '') ?>';
        addIpToWhitelist(currentIp);
    });
    
    // Server-IP-Adresse hinzufügen
    $('#upkeep-add-server-ip').on('click', function(e) {
        e.preventDefault();
        var serverIp = '<?= $_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['SERVER_NAME'] ?? 'localhost') ?>';
        addIpToWhitelist(serverIp);
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
