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
    $addon = rex_addon::get('upkeep');
    
    // Backend-spezifische Initialisierungen
    if (rex::isBackend()) {
        // Hide menu items based on module settings
        if (!$addon->getConfig('module_security_advisor_enabled', true)) {
            $addon->setProperty('page', array_filter($addon->getProperty('page'), function($key) {
                return $key !== 'security_advisor';
            }, ARRAY_FILTER_USE_KEY));
        }
        
        if (!$addon->getConfig('module_mail_security_enabled', true)) {
            $addon->setProperty('page', array_filter($addon->getProperty('page'), function($key) {
                return $key !== 'mail_security';
            }, ARRAY_FILTER_USE_KEY));
        }
        
        if (!$addon->getConfig('module_reporting_enabled', true)) {
            $addon->setProperty('page', array_filter($addon->getProperty('page'), function($key) {
                return $key !== 'reporting';
            }, ARRAY_FILTER_USE_KEY));
        }
        
        // Statusindikator im Backend-Menü setzen
        Upkeep::setStatusIndicator();
        
        // CSS für das Backend laden
        rex_view::addCssFile($addon->getAssetsUrl('css/upkeep.css'));
        
        // Cronjob für IPS-Cleanup registrieren (nur wenn Cronjob-AddOn verfügbar)
        if (rex_addon::get('cronjob')->isAvailable() && !rex::isSafeMode()) {
            rex_cronjob_manager::registerType('rex_upkeep_ips_cleanup_cronjob');
        }
    }
    
    // Mail Reporting System initialisieren (nur wenn Reporting-Modul aktiviert)
    if ($addon->getConfig('module_reporting_enabled', true)) {
        MailReporting::init();
    }
    
    // URL-Redirects (nur wenn kein Wartungsmodus aktiv war)
    Upkeep::checkDomainMapping();
}, rex_extension::EARLY);

// Impersonate-Warnung über OUTPUT_FILTER: Inline-Info im Backend (einmal pro Session)
if (rex::isBackend()) {
    rex_extension::register('OUTPUT_FILTER', static function (rex_extension_point $ep) {
        $addon = rex_addon::get('upkeep');

        // Nur wenn Backend-Wartungsmodus aktiv ist
        if (!$addon->getConfig('backend_active', false)) {
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

        // Anzeige vorbereiten (sichere Übergabe der Texte an JS mittels json_encode)
        $title = $addon->i18n('upkeep_impersonate_warning_title');
        $userName = $currentUser instanceof rex_user ? ($currentUser->getName() ?: $currentUser->getLogin()) : 'Unknown User';
        $message = $addon->i18n('upkeep_impersonate_warning_message', $userName);

        // JSON-sichere Strings für JS (vermeidet manuelles Escaping)
        $titleJson = json_encode($title, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT);
        $messageJson = json_encode($message, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT);

        $content = $ep->getSubject();

        // Bootstrap 3 Modal für elegante Anzeige der Warnung
        // Anzeige erfolgt nur einmal pro Browser-Session (sessionStorage).
        $modalId = 'upkeep-impersonate-modal-' . uniqid();
        
        $modalHtml = '
        <!-- Upkeep Impersonate Warning Modal -->
        <div class="modal fade" id="' . $modalId . '" tabindex="-1" role="dialog" aria-labelledby="' . $modalId . '-label">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                    <div class="modal-header" style="background-color: #f0ad4e; color: white;">
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                            <span aria-hidden="true">&times;</span>
                        </button>
                        <h4 class="modal-title" id="' . $modalId . '-label">
                            <i class="rex-icon rex-icon-warning"></i> ' . rex_escape($title) . '
                        </h4>
                    </div>
                    <div class="modal-body">
                        <p>' . rex_escape($message) . '</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-primary" data-dismiss="modal">' . $addon->i18n('upkeep_impersonate_ok') . '</button>
                    </div>
                </div>
            </div>
        </div>';
        
        $warningScript = '
        <script type="text/javascript" nonce="' . rex_response::getNonce() . '">
        (function(){
            try {
                if (!sessionStorage.getItem("upkeep_impersonate_warning_shown")) {
                    jQuery(function($){
                        // Modal beim Laden der Seite anzeigen
                        $("#' . $modalId . '").modal({
                            backdrop: "static",
                            keyboard: false
                        });
                        
                        // Session-Flag setzen wenn Modal geschlossen wird
                        $("#' . $modalId . '").on("hidden.bs.modal", function() {
                            sessionStorage.setItem("upkeep_impersonate_warning_shown", "1");
                        });
                    });
                }
            } catch(e) {
                // Fallback: nichts tun
            }
        })();
        </script>';

        // Modal HTML und Script vor dem schließenden body-Tag einfügen
        if (strpos($content, '</body>') !== false) {
            $content = str_replace('</body>', $modalHtml . $warningScript . '</body>', $content);
        }

        return $content;
    }, rex_extension::LATE);
}

// Mail Security Filter für PHPMailer registrieren
// Nur registrieren wenn PHPMailer-AddOn verfügbar ist und das Modul aktiviert ist
$upkeepAddon = rex_addon::get('upkeep');
if (rex_addon::get('phpmailer')->isAvailable() && $upkeepAddon->getConfig('module_mail_security_enabled', true)) {
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



// Security Advisor API Route registrieren (deprecated) - nur wenn Modul aktiviert
if (rex::isBackend() && rex_request::get('api') === 'security_advisor' && $upkeepAddon->getConfig('module_security_advisor_enabled', true)) {
    include $upkeepAddon->getPath('api/security_advisor.php');
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
