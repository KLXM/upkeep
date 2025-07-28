<?php
/**
 * Boot-Datei für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;
use KLXM\Upkeep\IntrusionPrevention;

// Falls Setup aktiv ist, nichts tun
if (rex::isSetup()) {
    return;
}

// Intrusion Prevention System - ALLERERSTE Prüfung
IntrusionPrevention::checkRequest();

// Stellen Sie sicher, dass die Session immer verfügbar ist
if (!rex_backend_login::hasSession()) {
    rex_login::startSession();
}

// Register Extension Point nach dem Laden aller Packages
rex_extension::register('PACKAGES_INCLUDED', static function () {
    // Frontend-Wartungsmodus-Prüfung ZUERST
    if (rex::isFrontend()) {
        Upkeep::checkFrontend();
    }
    
    // Backend-Wartungsmodus-Prüfung
    if (rex::isBackend()) {
        if (rex::getUser()) {
            Upkeep::checkBackend();
        }
        
        // Statusindikator im Backend-Menü setzen
        Upkeep::setStatusIndicator();
        
        // CSS für das Backend laden
        rex_view::addCssFile(rex_addon::get('upkeep')->getAssetsUrl('css/upkeep.css'));
    }
    
    // URL-Redirects (nur wenn kein Wartungsmodus aktiv war)
    Upkeep::checkDomainMapping();
}, rex_extension::EARLY);
