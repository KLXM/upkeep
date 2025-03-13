<?php
/**
 * Hauptseite des Upkeep AddOns
 */

use KLXM\Upkeep\Upkeep;

$addon = Upkeep::getAddon();
echo rex_view::title($addon->i18n('title'));

// Subpage einbinden
rex_be_controller::includeCurrentPageSubPath();
