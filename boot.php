<?php
/**
 * Boot-Datei für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;

// Falls Setup aktiv ist, nichts tun
if (rex::isSetup()) {
    return;
}

// Register Extension Point nach dem Laden aller Packages
rex_extension::register('PACKAGES_INCLUDED', static function () {
    // Starte Session im Frontend, falls erforderlich
    if (rex::isFrontend() && !rex_backend_login::hasSession()) {
        rex_login::startSession();
    }
    
    // Frontend-Prüfung
    if (rex::isFrontend()) {
        Upkeep::checkFrontend();
    }
    
    // Backend-Prüfung
    if (rex::isBackend()) {
        if (rex::getUser()) {
            Upkeep::checkBackend();
        }
        
        // Statusindikator im Backend-Menü setzen
        Upkeep::setStatusIndicator();
        
        // CSS für das Backend laden
        rex_view::addCssFile(rex_addon::get('upkeep')->getAssetsUrl('css/upkeep.css'));
    }
});
