<?php
/**
 * Domain-Einstellungen für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();

// Wenn YRewrite nicht verfügbar ist, Hinweis anzeigen
if (!rex_addon::get('yrewrite')->isAvailable()) {
    echo rex_view::info($addon->i18n('upkeep_yrewrite_not_available'));
    return;
}

// Domains aus YRewrite holen
$domains = rex_yrewrite::getDomains();

// Aktuelle Einstellungen laden
$allowedDomains = (array) $addon->getConfig('allowed_domains', []);
$domainStatus = (array) $addon->getConfig('domain_status', []);

// Formular abgesendet?
if (rex_post('save', 'boolean')) {
    // Einstellungen speichern
    $domainStatus = [];
    foreach ($domains as $domain) {
        $name = $domain->getName();
        if ($name !== 'default') {
            $domainStatus[$name] = rex_post('domain_' . md5($name), 'boolean', false);
        }
    }
    
    // Konfiguration speichern
    $addon->setConfig('domain_status', $domainStatus);
    
    // Erfolgsmeldung
    echo rex_view::success($addon->i18n('upkeep_settings_saved'));
}

// Tabelle mit Domains erstellen
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';
$content .= '<table class="table table-striped table-hover">';
$content .= '<thead><tr>';
$content .= '<th>' . $addon->i18n('upkeep_domain') . '</th>';
$content .= '<th>' . $addon->i18n('upkeep_maintenance_active') . '</th>';
$content .= '</tr></thead>';
$content .= '<tbody>';

foreach ($domains as $domain) {
    $name = $domain->getName();
    if ($name !== 'default') {
        $content .= '<tr>';
        $content .= '<td>' . htmlspecialchars($name) . '</td>';
        $content .= '<td>';
        $content .= '<div class="rex-select-style">';
        $content .= '<select class="form-control" name="domain_' . md5($name) . '">';
        $content .= '<option value="0"' . ($domainStatus[$name] ?? false ? '' : ' selected') . '>' . $addon->i18n('upkeep_inactive') . '</option>';
        $content .= '<option value="1"' . ($domainStatus[$name] ?? false ? ' selected' : '') . '>' . $addon->i18n('upkeep_active') . '</option>';
        $content .= '</select>';
        $content .= '</div>';
        $content .= '</td>';
        $content .= '</tr>';
    }
}

$content .= '</tbody></table>';
$content .= '<div class="form-group">';
$content .= '<button class="btn btn-primary" type="submit" name="save" value="1">' . $addon->i18n('upkeep_save') . '</button>';
$content .= '</div>';
$content .= '</form>';

// Hinweis zur Domain-Konfiguration
$notice = '<div class="alert alert-info">';
$notice .= $addon->i18n('upkeep_domains_notice');
$notice .= '</div>';

// Fragment erstellen und ausgeben
$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_domains_management'), false);
$fragment->setVar('body', $notice . $content, false);
echo $fragment->parse('core/page/section.php');
