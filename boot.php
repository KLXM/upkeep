<?php
/**
 * Boot-Datei für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;
use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\MailSecurityFilter;

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
        
        // Cronjob für IPS-Cleanup registrieren (nur wenn Cronjob-AddOn verfügbar)
        if (rex_addon::get('cronjob')->isAvailable() && !rex::isSafeMode()) {
            rex_cronjob_manager::registerType('rex_upkeep_ips_cleanup_cronjob');
        }
    }
    
    // URL-Redirects (nur wenn kein Wartungsmodus aktiv war)
    Upkeep::checkDomainMapping();
}, rex_extension::EARLY);

// Mail Security Filter für PHPMailer registrieren
// Nur registrieren wenn PHPMailer-AddOn verfügbar ist
if (rex_addon::get('phpmailer')->isAvailable()) {
    rex_extension::register('PHPMAILER_PRE_SEND', static function (rex_extension_point $ep) {
        try {
            return MailSecurityFilter::filterMail($ep);
        } catch (Exception $e) {
            // Log der Exception für Debugging
            if (rex_addon::get('upkeep')->getConfig('mail_security_debug', false)) {
                rex_logger::factory()->log('error', 'Mail Security Filter Error: ' . $e->getMessage());
            }
            
            // Exception weiterwerfen um E-Mail-Versand zu stoppen
            throw $e;
        }
    });
}
