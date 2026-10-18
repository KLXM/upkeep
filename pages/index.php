<?php

/**
 * Rahmen aller upkeep-Seiten: Titel, Styles, Unterseite.
 */

$addon = rex_addon::get('upkeep');
echo rex_view::title($addon->i18n('upkeep_title'));

// Ausgeschaltetes Modul: nur Hinweis, keine Bearbeitung (auch nicht per direkter Adresse)
$disabledSection = KLXM\Upkeep\ModuleGate::disabledSection((string) rex_be_controller::getCurrentPage());
if (null !== $disabledSection) {
    $link = rex::requireUser()->isAdmin()
        ? '<a class="btn btn-primary" href="' . rex_url::backendPage('upkeep/settings', ['section' => $disabledSection]) . '">' . rex_escape(rex_i18n::rawMsg('upkeep_module_off_link')) . '</a>'
        : '';
    echo KLXM\Upkeep\Ui::hero(rex_i18n::rawMsg('upkeep_module_off_title'), rex_i18n::rawMsg('upkeep_module_off_text'), KLXM\Upkeep\Ui::icon('fa-power-off', 'gray'), $link);
    return;
}

rex_be_controller::includeCurrentPageSubPath();
