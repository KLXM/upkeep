<?php
/**
 * Frontend-Einstellungen für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();

// Schnellaktionen verarbeiten
$action = rex_request::get('action', 'string', '');
$message = '';

if ($action === 'activate' && $_POST) {
    $addon->setConfig('frontend_active', true);
    $message = rex_view::success($addon->i18n('upkeep_frontend_activated'));
} elseif ($action === 'deactivate' && $_POST) {
    $addon->setConfig('frontend_active', false);
    $message = rex_view::success($addon->i18n('upkeep_frontend_deactivated'));
} elseif ($action === 'activate') {
    // GET Request - Bestätigungsformular anzeigen
    echo rex_view::title($addon->i18n('upkeep_frontend_title'));
    $content = '
    <div class="alert alert-warning">
        <h4><i class="rex-icon fa fa-exclamation-triangle"></i> ' . $addon->i18n('upkeep_confirm_activate') . '</h4>
        <p>' . $addon->i18n('upkeep_frontend_activate_warning') . '</p>
        <form method="post">
            <input type="hidden" name="action" value="activate">
            <button type="submit" class="btn btn-warning">
                <i class="rex-icon fa fa-power-off"></i> ' . $addon->i18n('upkeep_activate') . '
            </button>
            <a href="' . rex_url::backendPage('upkeep/maintenance/frontend') . '" class="btn btn-default">
                <i class="rex-icon fa fa-times"></i> ' . $addon->i18n('upkeep_cancel') . '
            </a>
        </form>
    </div>';
    echo $content;
    return;
} elseif ($action === 'deactivate') {
    // GET Request - Bestätigungsformular anzeigen
    echo rex_view::title($addon->i18n('upkeep_frontend_title'));
    $content = '
    <div class="alert alert-info">
        <h4><i class="rex-icon fa fa-info-circle"></i> ' . $addon->i18n('upkeep_confirm_deactivate') . '</h4>
        <p>' . $addon->i18n('upkeep_frontend_deactivate_info') . '</p>
        <form method="post">
            <input type="hidden" name="action" value="deactivate">
            <button type="submit" class="btn btn-success">
                <i class="rex-icon fa fa-power-off"></i> ' . $addon->i18n('upkeep_deactivate') . '
            </button>
            <a href="' . rex_url::backendPage('upkeep/maintenance/frontend') . '" class="btn btn-default">
                <i class="rex-icon fa fa-times"></i> ' . $addon->i18n('upkeep_cancel') . '
            </a>
        </form>
    </div>';
    echo $content;
    return;
}

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

// Domain-Info direkt nach dem Select-Feld einfügen (nur wenn YRewrite verfügbar)
$yrewriteAvailable = rex_addon::get('yrewrite')->isAvailable();
if ($yrewriteAvailable) {
    // Domain-Status laden für Übersicht
    $allDomainsLocked = (bool) $addon->getConfig('all_domains_locked', false);
    $domainStatus = (array) $addon->getConfig('domain_status', []);
    $domains = rex_yrewrite::getDomains();
    
    // Aktive Domains zählen (die im Wartungsmodus sind)
    $lockedDomains = [];
    $unlockedDomains = [];
    
    foreach ($domains as $domain) {
        $name = $domain->getName();
        if ($name !== 'default') {
            if ($allDomainsLocked || (!empty($domainStatus[$name]) && $domainStatus[$name])) {
                $lockedDomains[] = $name;
            } else {
                $unlockedDomains[] = $name;
            }
        }
    }
    
    $frontendActive = (bool) $addon->getConfig('frontend_active', false);
    
    // Domain-Info HTML für aktiven Wartungsmodus
    $domainInfoHtml = '<div id="upkeep-domain-info-active" class="alert alert-info" style="margin-top:15px;' . ($frontendActive ? '' : 'display:none;') . '">';
    $domainInfoHtml .= '<h4><i class="fa fa-globe"></i> ' . $addon->i18n('upkeep_domain_status_overview') . '</h4>';
    $domainInfoHtml .= '<div class="row">';
    $domainInfoHtml .= '<div class="col-md-6">';
    $domainInfoHtml .= '<p><strong><i class="fa fa-lock text-danger"></i> ' . $addon->i18n('upkeep_domains_in_maintenance') . ':</strong></p>';
    if (!empty($lockedDomains)) {
        $domainInfoHtml .= '<ul class="list-unstyled">';
        foreach ($lockedDomains as $d) {
            $domainInfoHtml .= '<li><code>' . rex_escape($d) . '</code></li>';
        }
        $domainInfoHtml .= '</ul>';
    } else {
        $domainInfoHtml .= '<p class="text-muted">' . $addon->i18n('upkeep_no_domains_locked') . '</p>';
    }
    $domainInfoHtml .= '</div>';
    $domainInfoHtml .= '<div class="col-md-6">';
    $domainInfoHtml .= '<p><strong><i class="fa fa-unlock text-success"></i> ' . $addon->i18n('upkeep_domains_accessible') . ':</strong></p>';
    if (!empty($unlockedDomains)) {
        $domainInfoHtml .= '<ul class="list-unstyled">';
        foreach ($unlockedDomains as $d) {
            $domainInfoHtml .= '<li><code>' . rex_escape($d) . '</code></li>';
        }
        $domainInfoHtml .= '</ul>';
    } else {
        $domainInfoHtml .= '<p class="text-muted">' . $addon->i18n('upkeep_all_domains_locked') . '</p>';
    }
    $domainInfoHtml .= '</div>';
    $domainInfoHtml .= '</div>';
    $domainInfoHtml .= '<p class="text-center" style="margin-top:10px;"><a href="' . rex_url::backendPage('upkeep/maintenance/domains') . '" class="btn btn-primary btn-sm"><i class="fa fa-globe"></i> ' . $addon->i18n('upkeep_configure_domains') . '</a></p>';
    $domainInfoHtml .= '</div>';
    
    // Hinweis für inaktiven Wartungsmodus
    $domainInfoHtml .= '<div id="upkeep-domain-info-inactive" class="alert alert-warning" style="margin-top:15px;' . ($frontendActive ? 'display:none;' : '') . '">';
    $domainInfoHtml .= '<i class="fa fa-info-circle"></i> ' . $addon->i18n('upkeep_domain_hint_inactive');
    $domainInfoHtml .= ' <a href="' . rex_url::backendPage('upkeep/maintenance/domains') . '">' . $addon->i18n('upkeep_configure_domains') . '</a>';
    $domainInfoHtml .= '</div>';
    
    $field = $form->addRawField($domainInfoHtml);
}

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

// Erfolgsmeldung anzeigen (von Schnellaktionen)
if (!empty($message)) {
    echo $message;
}

// Vorschau-Bereich (Einstellungen-Formular)
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
            'title' => $addon->i18n('upkeep_page_title_placeholder'),
            'message' => $addon->i18n('upkeep_page_message_placeholder'),
            'password_label' => $addon->i18n('upkeep_password_label_placeholder'),
            'password_button' => $addon->i18n('upkeep_password_button_placeholder'),
            'language_switch' => $addon->i18n('upkeep_language_switch_placeholder')
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
                    <span class="language-title">' . rex_escape($text['language_name'] ?? $addon->i18n('upkeep_language_singular')) . ' (' . rex_escape($text['language_code'] ?? '') . ')</span>
                    <div class="pull-right">
                        <button type="button" class="btn btn-xs btn-danger remove-language" title="' . rex_escape($addon->i18n('upkeep_remove_language_title')) . '">
                            <i class="rex-icon fa-trash"></i>
                        </button>
                    </div>
                </h4>
            </div>
            <div class="panel-body">
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>' . rex_escape($addon->i18n('upkeep_language_code_label')) . '</label>
                            <input type="text" class="form-control language-code" value="' . rex_escape($text['language_code'] ?? '') . '" placeholder="' . rex_escape($addon->i18n('upkeep_language_code_placeholder')) . '">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>' . rex_escape($addon->i18n('upkeep_language_name_label')) . '</label>
                            <input type="text" class="form-control language-name" value="' . rex_escape($text['language_name'] ?? '') . '" placeholder="' . rex_escape($addon->i18n('upkeep_language_name_placeholder')) . '">
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>' . rex_escape($addon->i18n('upkeep_page_title_label')) . '</label>
                    <input type="text" class="form-control language-title-input" value="' . rex_escape($text['title'] ?? '') . '" placeholder="' . rex_escape($addon->i18n('upkeep_page_title_placeholder')) . '">
                </div>
                <div class="form-group">
                    <label>' . rex_escape($addon->i18n('upkeep_page_message_label')) . '</label>
                    <textarea class="form-control language-message" rows="3" placeholder="' . rex_escape($addon->i18n('upkeep_page_message_placeholder')) . '">' . rex_escape($text['message'] ?? '') . '</textarea>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>' . rex_escape($addon->i18n('upkeep_password_label_label')) . '</label>
                            <input type="text" class="form-control language-password-label" value="' . rex_escape($text['password_label'] ?? '') . '" placeholder="' . rex_escape($addon->i18n('upkeep_password_label_placeholder')) . '">
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>' . rex_escape($addon->i18n('upkeep_password_button_label')) . '</label>
                            <input type="text" class="form-control language-password-button" value="' . rex_escape($text['password_button'] ?? '') . '" placeholder="' . rex_escape($addon->i18n('upkeep_password_button_placeholder')) . '">
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>' . rex_escape($addon->i18n('upkeep_language_switch_label')) . '</label>
                    <input type="text" class="form-control language-switch" value="' . rex_escape($text['language_switch'] ?? '') . '" placeholder="' . rex_escape($addon->i18n('upkeep_language_switch_placeholder')) . '">
                </div>
            </div>
        </div>';
}

$languageForm .= '
            </div>
            <div class="form-group">
                <button type="button" class="btn btn-success" id="add-language">
                    <i class="rex-icon fa-plus"></i> ' . $addon->i18n('upkeep_add_language') . '
                </button>
                <button type="submit" class="btn btn-save" name="config-submit" value="1">
                    <i class="rex-icon rex-icon-save"></i> ' . $addon->i18n('upkeep_save_language_texts') . '
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
<script type="text/javascript" nonce="<?= rex_response::getNonce() ?>">
$(document).on('rex:ready', function() {
    // PHP translations for JavaScript
    var i18n = {
        languageCodeLabel: <?= json_encode($addon->i18n('upkeep_language_code_label')) ?>,
        languageCodePlaceholder: <?= json_encode($addon->i18n('upkeep_language_code_placeholder')) ?>,
        languageNameLabel: <?= json_encode($addon->i18n('upkeep_language_name_label')) ?>,
        languageNamePlaceholder: <?= json_encode($addon->i18n('upkeep_language_name_placeholder')) ?>,
        pageTitleLabel: <?= json_encode($addon->i18n('upkeep_page_title_label')) ?>,
        pageTitlePlaceholder: <?= json_encode($addon->i18n('upkeep_page_title_placeholder')) ?>,
        pageMessageLabel: <?= json_encode($addon->i18n('upkeep_page_message_label')) ?>,
        pageMessagePlaceholder: <?= json_encode($addon->i18n('upkeep_page_message_placeholder')) ?>,
        passwordLabelLabel: <?= json_encode($addon->i18n('upkeep_password_label_label')) ?>,
        passwordLabelPlaceholder: <?= json_encode($addon->i18n('upkeep_password_label_placeholder')) ?>,
        passwordButtonLabel: <?= json_encode($addon->i18n('upkeep_password_button_label')) ?>,
        passwordButtonPlaceholder: <?= json_encode($addon->i18n('upkeep_password_button_placeholder')) ?>,
        languageSwitchLabel: <?= json_encode($addon->i18n('upkeep_language_switch_label')) ?>,
        languageSwitchPlaceholder: <?= json_encode($addon->i18n('upkeep_language_switch_placeholder')) ?>,
        newLanguage: <?= json_encode($addon->i18n('upkeep_new_language')) ?>,
        removeLanguageTitle: <?= json_encode($addon->i18n('upkeep_remove_language_title')) ?>,
        alertMinOneLanguage: <?= json_encode($addon->i18n('upkeep_alert_min_one_language')) ?>
    };
    
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
                        <span class="language-title">${i18n.newLanguage}</span>
                        <div class="pull-right">
                            <button type="button" class="btn btn-xs btn-danger remove-language" title="${i18n.removeLanguageTitle}">
                                <i class="rex-icon fa-trash"></i>
                            </button>
                        </div>
                    </h4>
                </div>
                <div class="panel-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>${i18n.languageCodeLabel}</label>
                                <input type="text" class="form-control language-code" placeholder="${i18n.languageCodePlaceholder}">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>${i18n.languageNameLabel}</label>
                                <input type="text" class="form-control language-name" placeholder="${i18n.languageNamePlaceholder}">
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>${i18n.pageTitleLabel}</label>
                        <input type="text" class="form-control language-title-input" placeholder="${i18n.pageTitlePlaceholder}">
                    </div>
                    <div class="form-group">
                        <label>${i18n.pageMessageLabel}</label>
                        <textarea class="form-control language-message" rows="3" placeholder="${i18n.pageMessagePlaceholder}"></textarea>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>${i18n.passwordLabelLabel}</label>
                                <input type="text" class="form-control language-password-label" placeholder="${i18n.passwordLabelPlaceholder}">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>${i18n.passwordButtonLabel}</label>
                                <input type="text" class="form-control language-password-button" placeholder="${i18n.passwordButtonPlaceholder}">
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>${i18n.languageSwitchLabel}</label>
                        <input type="text" class="form-control language-switch" placeholder="${i18n.languageSwitchPlaceholder}">
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
            alert(i18n.alertMinOneLanguage);
        }
    });
    
    // Panel-Titel beim Ändern von Code oder Name aktualisieren
    $(document).on('input', '.language-code, .language-name', function() {
        var entry = $(this).closest('.language-entry');
        var code = entry.find('.language-code').val();
        var name = entry.find('.language-name').val();
        var title = name ? name + (code ? ' (' + code + ')' : '') : (code ? code : i18n.newLanguage);
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
    
    // Domain-Info Panel basierend auf frontend_active Select ein-/ausblenden
    var $frontendActiveSelect = $('select[name="allgemeine_einstellungen[frontend_active]"]');
    
    // Funktion zum Aktualisieren der Domain-Info Anzeige
    function updateDomainInfoVisibility() {
        var isActive = $frontendActiveSelect.val() === '1';
        if (isActive) {
            $('#upkeep-domain-info-active').slideDown(300);
            $('#upkeep-domain-info-inactive').slideUp(300);
        } else {
            $('#upkeep-domain-info-active').slideUp(300);
            $('#upkeep-domain-info-inactive').slideDown(300);
        }
    }
    
    // Bei Änderung des Selects
    $frontendActiveSelect.on('change', updateDomainInfoVisibility);
    
    // Initial beim Laden die richtige Anzeige setzen
    var isActiveInitial = $frontendActiveSelect.val() === '1';
    if (isActiveInitial) {
        $('#upkeep-domain-info-active').show();
        $('#upkeep-domain-info-inactive').hide();
    } else {
        $('#upkeep-domain-info-active').hide();
        $('#upkeep-domain-info-inactive').show();
    }
});
</script>
