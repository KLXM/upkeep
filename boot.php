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

// Impersonate-Warnung über OUTPUT_FILTER als JavaScript-Modal
if (rex::isBackend()) {
    rex_extension::register('OUTPUT_FILTER', static function (rex_extension_point $ep) {
        // Debug-Informationen sammeln
        $addon = rex_addon::get('upkeep');
        $debugInfo = [
            'isBackend' => rex::isBackend(),
            'backendActive' => $addon->getConfig('backend_active', false),
            'hasImpersonator' => rex::getImpersonator() instanceof rex_user,
            'currentUserIsAdmin' => rex::getUser() instanceof rex_user && rex::getUser()->isAdmin(),
            'impersonatorName' => rex::getImpersonator() ? rex::getImpersonator()->getLogin() : 'none',
            'currentUserName' => rex::getUser() ? rex::getUser()->getLogin() : 'none'
        ];
        
        // Debug-Script immer einfügen wenn im Backend
        if (rex::isBackend()) {
            $content = $ep->getSubject();
            $debugScript = '
            <script type="text/javascript" nonce="' . rex_response::getNonce() . '">
            console.log("Upkeep Debug Info:", ' . json_encode($debugInfo) . ');
            </script>';
            
            if (strpos($content, '</body>') !== false) {
                $content = str_replace('</body>', $debugScript . '</body>', $content);
            }
        }
        
        // Nur im Backend und nur wenn alle Bedingungen erfüllt sind
        if (!rex::isBackend() || !$addon->getConfig('backend_active', false)) {
            return isset($content) ? $content : $ep->getSubject();
        }

        // Prüfen ob wir im Impersonate-Modus sind
        $impersonator = rex::getImpersonator();
        if (!$impersonator instanceof rex_user) {
            return isset($content) ? $content : $ep->getSubject();
        }

        // Warnung nur anzeigen wenn der aktuelle Benutzer kein Admin ist
        $currentUser = rex::getUser();
        if ($currentUser instanceof rex_user && $currentUser->isAdmin()) {
            return isset($content) ? $content : $ep->getSubject();
        }

        // Warnung anzeigen
        $userName = $currentUser instanceof rex_user ? 
            ($currentUser->getName() ?: $currentUser->getLogin()) : 
            'Unknown User';
        
        $title = $addon->i18n('upkeep_impersonate_warning_title');
        $message = $addon->i18n('upkeep_impersonate_warning_message', $userName);
        if (!isset($content)) {
            $content = $ep->getSubject();
        }
        
        // JavaScript für Modal und permanente Warnung hinzufügen
        $warningScript = '
        <script type="text/javascript" nonce="' . rex_response::getNonce() . '">
        jQuery(document).ready(function($) {
            // Modal beim ersten Laden anzeigen
            if (!sessionStorage.getItem("upkeep_impersonate_warning_shown")) {
                alert("⚠️ ' . rex_escape($title, 'js') . '\\n\\n' . rex_escape($message, 'js') . '");
                sessionStorage.setItem("upkeep_impersonate_warning_shown", "1");
            }
            
            // Permanente Warnung am Seitenanfang hinzufügen
            var warningHtml = \'<div id="upkeep-impersonate-warning" style="background-color: #fcf8e3; border: 1px solid #faebcc; color: #8a6d3b; padding: 15px; margin: 15px; border-radius: 4px; position: relative; z-index: 1050;">\' +
                \'<h4 style="margin-top: 0;"><i class="rex-icon rex-icon-warning"></i> ' . rex_escape($title) . '</h4>\' +
                \'<p style="margin-bottom: 0;">' . rex_escape($message) . '</p>\' +
                \'</div>\';
            
            // Warnung nach dem Header einfügen
            if ($("#rex-page-main").length) {
                $("#rex-page-main").prepend(warningHtml);
            } else if ($("body").length) {
                $("body").prepend(warningHtml);
            }
        });
        </script>';
        
        // Script vor dem schließenden body-Tag einfügen
        if (strpos($content, '</body>') !== false) {
            $content = str_replace('</body>', $warningScript . '</body>', $content);
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
