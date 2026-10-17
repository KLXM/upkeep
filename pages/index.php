<?php

/**
 * Rahmen aller upkeep-Seiten: Titel, Styles, Unterseite.
 */

$addon = rex_addon::get('upkeep');
echo rex_view::title($addon->i18n('upkeep_title'));

rex_be_controller::includeCurrentPageSubPath();
