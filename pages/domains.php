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
$domainStatus = (array) $addon->getConfig('domain_status', []);
$allDomainsLocked = (bool) $addon->getConfig('all_domains_locked', false);

// Formular abgesendet?
if (rex_post('save', 'bool')) {
    // Globale Option für alle Domains speichern
    $allDomainsLocked = rex_post('all_domains_locked', 'bool', false);
    $addon->setConfig('all_domains_locked', $allDomainsLocked);
    
    // Nur wenn nicht alle Domains gesperrt sind, individuelle Einstellungen speichern
    if (!$allDomainsLocked) {
        // Einstellungen speichern
        $domainStatus = [];
        foreach ($domains as $domain) {
            $name = $domain->getName();
            if ($name !== 'default') {
                $domainStatus[$name] = rex_post('domain_' . md5($name), 'bool', false);
            }
        }
        
        // Konfiguration speichern
        $addon->setConfig('domain_status', $domainStatus);
    }
    
    // Erfolgsmeldung
    echo rex_view::success($addon->i18n('upkeep_settings_saved'));
}

// Tabelle mit Domains erstellen
$content = '<form action="' . rex_url::currentBackendPage() . '" method="post">';

// Option für alle Domains
$content .= '<div class="form-group">';
$content .= '<label class="control-label">' . $addon->i18n('upkeep_lock_all_domains') . '</label>';
$content .= '<div class="rex-select-style">';
$content .= '<select class="form-control" name="all_domains_locked" id="all-domains-locked">';
$content .= '<option value="0"' . (!$allDomainsLocked ? ' selected' : '') . '>' . $addon->i18n('upkeep_no') . '</option>';
$content .= '<option value="1"' . ($allDomainsLocked ? ' selected' : '') . '>' . $addon->i18n('upkeep_yes') . '</option>';
$content .= '</select>';
$content .= '</div>';
$content .= '</div>';

// Individuelle Domain-Einstellungen
$content .= '<div id="individual-domains" ' . ($allDomainsLocked ? 'style="display:none;"' : '') . '>';
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
$content .= '</div>';

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

// JavaScript für die Umschaltung der individuellen Domain-Einstellungen
?>
<script type="text/javascript">
$(document).on('rex:ready', function() {
    $('#all-domains-locked').on('change', function() {
        if ($(this).val() == '1') {
            $('#individual-domains').hide();
        } else {
            $('#individual-domains').show();
        }
    });
});
</script>
