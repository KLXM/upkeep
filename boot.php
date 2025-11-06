<?php
/**
 * Boot-Datei für das Upkeep AddOn
 */

use KLXM\Upkeep\Upkeep;
use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\MailSecurityFilter;
use KLXM\Upkeep\MailReporting;

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

// Frontend-Wartungsmodus-Prüfung DIREKT ausführen (nicht in Extension Point)
// Dies muss sofort geschehen, bevor andere Addons laden
if (rex::isFrontend()) {
    Upkeep::checkFrontend();
}

// Backend-Wartungsmodus-Prüfung DIREKT ausführen (nicht in Extension Point)
// Muss früh geschehen, aber nach Session-Initialisierung
if (rex::isBackend()) {
    // Benutzer erstellen falls noch nicht vorhanden
    rex_backend_login::createUser();
    
    // Backend-Sperre prüfen wenn Benutzer existiert
    if (rex::getUser()) {
        Upkeep::checkBackend();
    }
}

// Register Extension Point nach dem Laden aller Packages
rex_extension::register('PACKAGES_INCLUDED', static function () {
    // Mail Reporting System initialisieren
    MailReporting::init();
    
        // Backend-spezifische Initialisierungen
        if (rex::isBackend()) {
            // Statusindikator im Backend-Menü setzen
            Upkeep::setStatusIndicator();
            
            // CSS für das Backend laden
            rex_view::addCssFile(rex_addon::get('upkeep')->getAssetsUrl('css/upkeep.css'));
            
            // Cronjob für IPS-Cleanup registrieren (nur wenn Cronjob-AddOn verfügbar)
            if (rex_addon::get('cronjob')->isAvailable() && !rex::isSafeMode()) {
                rex_cronjob_manager::registerType('rex_upkeep_ips_cleanup_cronjob');
            }
        }    // URL-Redirects (nur wenn kein Wartungsmodus aktiv war)
    Upkeep::checkDomainMapping();
}, rex_extension::EARLY);

// Impersonate-Warnung über OUTPUT_FILTER - wird bei jeder Backend-Seite geprüft
if (rex::isBackend()) {
    rex_extension::register('OUTPUT_FILTER', static function (rex_extension_point $ep) {
        // Nur im Backend und nur wenn alle Bedingungen erfüllt sind
        $addon = rex_addon::get('upkeep');
        if (!rex::isBackend() || !$addon->getConfig('backend_active', false)) {
            return $ep->getSubject();
        }

        // Prüfen ob wir im Impersonate-Modus sind
        $impersonator = rex::getImpersonator();
        if (!$impersonator instanceof rex_user) {
            return $ep->getSubject();
        }

        // Warnung nur anzeigen wenn der aktuelle Benutzer kein Admin ist
        $currentUser = rex::getUser();
        if ($currentUser instanceof rex_user && $currentUser->isAdmin()) {
            return $ep->getSubject();
        }

        // Warnung anzeigen
        $userName = $currentUser instanceof rex_user ? 
            ($currentUser->getName() ?: $currentUser->getLogin()) : 
            'Unknown User';
        
        // $addon ist bereits oben definiert
        $message = $addon->i18n('upkeep_impersonate_warning_message', $userName);
        $content = $ep->getSubject();
        
        $warningHtml = '
        <div class="alert alert-warning" style="margin: 15px;">
            <h4><i class="rex-icon rex-icon-warning"></i> ' . rex_escape($addon->i18n('upkeep_impersonate_warning_title')) . '</h4>
            <p>' . rex_escape($message) . '</p>
        </div>';
        
        // Warnung nach dem Hauptmenü einfügen
        if (strpos($content, '<div id="rex-page-main">') !== false) {
            $content = str_replace(
                '<div id="rex-page-main">',
                '<div id="rex-page-main">' . $warningHtml,
                $content
            );
        }
        
        return $content;
    }, rex_extension::LATE);
}

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



// Security Advisor API Route registrieren (deprecated)
if (rex::isBackend() && rex_request::get('api') === 'security_advisor') {
    include rex_addon::get('upkeep')->getPath('api/security_advisor.php');
    exit;
}

// Content Security Policy für Backend - nach Security AddOn Vorbild
if (rex::isBackend() && rex_addon::get('upkeep')->getConfig('csp_enabled', false)) {
    // CSP Header direkt in boot.php setzen wie das Security AddOn
    $cspRules = [
        'script-src' => ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'style-src' => ["'self'", "'unsafe-inline'"],
        'base-uri' => ["'self'"],
        'object-src' => ["'none'"],
        'frame-ancestors' => ["'self'"],
        'form-action' => ["'self'"],
        'img-src' => ["'self'", 'data:', 'https:'],
        'connect-src' => ["'self'"]
    ];
    
    // CSP-String bauen
    $cspValues = [];
    foreach ($cspRules as $directive => $sources) {
        $cspValues[] = $directive . ' ' . implode(' ', $sources);
    }
    $cspHeader = implode('; ', $cspValues);
    
    rex_response::setHeader('Content-Security-Policy', $cspHeader);
    rex_response::sendCacheControl('no-store');
    rex_response::setHeader('Pragma', 'no-cache');
}
