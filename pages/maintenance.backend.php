<?php
/**
 * Backend-Einstellungen für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;

// Nur für Administratoren zugänglich
if (!rex::getUser()->isAdmin()) {
    echo rex_view::error($this->i18n('upkeep_no_permission'));
    return;
}

$addon = Upkeep::getAddon();
$form = rex_config_form::factory($addon->getName());

// Allgemeine Einstellungen
$field = $form->addFieldset($addon->i18n('upkeep_backend_settings'));

// Backend-Wartungsmodus aktivieren/deaktivieren
$field = $form->addSelectField('backend_active');
$field->setLabel($addon->i18n('upkeep_backend_active'));
$select = $field->getSelect();
$select->addOption($addon->i18n('upkeep_active'), 1);
$select->addOption($addon->i18n('upkeep_inactive'), 0);

// Information zur Backend-Sperrung
$notice = $form->addRawField('<div class="alert alert-info">' . $addon->i18n('upkeep_backend_notice') . '</div>');

// Sektion anzeigen
$fragment = new rex_fragment();
$fragment->setVar('class', 'edit', false);
$fragment->setVar('title', $addon->i18n('upkeep_backend_settings'), false);
$fragment->setVar('body', $form->get(), false);
echo $fragment->parse('core/page/section.php');
