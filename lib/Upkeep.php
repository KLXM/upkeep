<?php

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_backend_login;
use rex_config;
use rex_extension;
use rex_extension_point;
use rex_fragment;
use rex_request;
use rex_response;
use rex_server;
use rex_session;
use rex_user;
use rex_yrewrite;

/**
 * Hauptklasse für das Upkeep-AddOn
 * Verwaltet den Wartungsmodus für Frontend und Backend
 */
class Upkeep
{
    private static ?rex_addon $addon = null;

    /**
     * Liefert die Addon-Instanz
     */
    public static function getAddon(): rex_addon
    {
        if (self::$addon === null) {
            self::$addon = rex_addon::get('upkeep');
        }
        return self::$addon;
    }

    /**
     * Prüft, ob die aktuelle IP-Adresse in der Whitelist steht
     */
    public static function isIpAllowed(): bool
    {
        $ip = rex_server('REMOTE_ADDR', 'string', '');
        $allowedIps = (string) self::getConfig('allowed_ips', '');

        if ($allowedIps !== '') {
            $allowedIpsArray = array_filter(explode(',', $allowedIps));
            return in_array($ip, $allowedIpsArray, true);
        }

        return false;
    }

  /**
 * Prüft, ob die aktuelle Domäne im Wartungsmodus sein soll
 */
public static function isDomainAllowed(): bool
{
    if (!rex_addon::get('yrewrite')->isAvailable()) {
        return false;
    }

    $currentDomain = rex_yrewrite::getCurrentDomain()?->getName();
    if (!$currentDomain) {
        return false;
    }

    // Prüfen, ob alle Domains gesperrt sind
    $allDomainsLocked = (bool) self::getConfig('all_domains_locked', false);
    if ($allDomainsLocked) {
        return false; // Keine Domain ist erlaubt
    }

    // Holen der Domain-Statuseinstellungen aus der Konfiguration
    $domainStatus = (array) self::getConfig('domain_status', []);
    
    // Wenn die aktuelle Domain einen Eintrag hat und dieser auf 1/true gesetzt ist,
    // dann ist der Wartungsmodus für diese Domain aktiv und wir geben false zurück
    if (isset($domainStatus[$currentDomain]) && $domainStatus[$currentDomain]) {
        return false;
    }
    
    // Wenn es keinen Eintrag gibt oder der Wert 0/false ist,
    // dann ist der Wartungsmodus für diese Domain inaktiv und wir geben true zurück
    return true;
}

    /**
     * Prüft, ob das eingegebene Passwort korrekt ist
     */
    public static function isPasswordValid(): bool
    {
        $configPassword = (string) self::getConfig('frontend_password', '');
        
        // Passwort darf nicht leer sein
        if ($configPassword === '') {
            return false;
        }

        // Prüfen, ob bereits in der Session gespeichert
        if (rex_session('upkeep_authorized', 'bool', false)) {
            return true;
        }

        // Passwort aus Anfrage überprüfen - jetzt direkter Vergleich
        $inputPassword = rex_request('upkeep_password', 'string', '');
        if ($inputPassword !== '' && $inputPassword === $configPassword) {
            // Bei korrektem Passwort in Session speichern
            rex_set_session('upkeep_authorized', true);
            return true;
        }

        return false;
    }

    /**
     * Prüft, ob der aktuelle Benutzer angemeldet ist und Zugriff haben soll
     */
    public static function isUserAllowed(): bool
    {
        // Prüfen, ob angemeldete Benutzer Zugriff haben sollen
        if (!self::getConfig('bypass_logged_in', true)) {
            return false;
        }

        rex_backend_login::createUser();
        $user = rex::getUser();

        // Admins haben immer Zugriff
        if ($user instanceof rex_user && $user->isAdmin()) {
            return true;
        }

        // Andere angemeldete Benutzer haben Zugriff, wenn aktiviert
        if ($user instanceof rex_user) {
            return true;
        }

        return false;
    }

/**
 * Prüft, ob Frontend-Zugriff erlaubt ist oder gesperrt werden soll
 */
public static function checkFrontend(): void
{
    // Wenn der Wartungsmodus deaktiviert ist, nichts tun
    if (!self::getConfig('frontend_active', false)) {
        return;
    }
    
    // Prüfen, ob es sich um einen API-Aufruf handelt
    if (rex_request('rex-api-call', 'string', '') === 'upkeep') {
        return; // API-Aufrufe immer erlauben
    }

    // Prüfen, ob der Zugriff über eine Ausnahme erlaubt ist
    if (self::isIpAllowed() || self::isDomainAllowed() || self::isPasswordValid() || self::isUserAllowed()) {
        return;
    }

    // Extension Point, um bestimmte Medien oder Pfade freizuschalten
    $requestUri = rex_server('REQUEST_URI', 'string', '');
    $allowedPaths = [];
    $allowedPathsList = rex_extension::registerPoint(
        new rex_extension_point('UPKEEP_ALLOWED_PATHS', $allowedPaths)
    );
    
    foreach ($allowedPathsList as $path) {
        if (str_contains($requestUri, $path)) {
            return;
        }
    }

    // Wartungsseite anzeigen
    $fragment = new rex_fragment();
    
    // HTTP Response Code setzen (aus Konfiguration)
    $httpStatusCode = self::getConfig('http_status_code', rex_response::HTTP_SERVICE_UNAVAILABLE);
    rex_response::setStatus($httpStatusCode);
    
    // Retry-After Header setzen, wenn konfiguriert
    $retryAfter = self::getConfig('retry_after', 0);
    if ($retryAfter > 0) {
        header('Retry-After: ' . $retryAfter);
    }
    
    // Cache-Header setzen, damit die Seite nicht gecacht wird
    rex_response::sendCacheControl();
    
    // Wartungsseite ausgeben und Script beenden
    exit($fragment->parse('upkeep/frontend.php'));
}

    /**
     * Prüft, ob Backend-Zugriff erlaubt ist oder gesperrt werden soll
     */
    public static function checkBackend(): void
    {
        // Wenn der Wartungsmodus deaktiviert ist, nichts tun
        if (!self::getConfig('backend_active', false)) {
            return;
        }

        // Admins haben immer Zugriff
        if (rex::getUser() instanceof rex_user && rex::getUser()->isAdmin()) {
            return;
        }

        // Backend-Benutzer sperren
        $fragment = new rex_fragment();
        
        // HTTP Response Code setzen (aus Konfiguration)
        $httpStatusCode = self::getConfig('http_status_code', rex_response::HTTP_SERVICE_UNAVAILABLE);
        rex_response::setStatus($httpStatusCode);
        
        // Cache-Header setzen, damit die Seite nicht gecacht wird
        rex_response::sendCacheControl();
        
        // Wartungsseite ausgeben und Script beenden
        exit($fragment->parse('upkeep/backend.php'));
    }

    /**
     * Setzt Statusindikator im Backend-Menü
     */
    public static function setStatusIndicator(): void
    {
        $addon = self::getAddon();
        $page = $addon->getProperty('page');

        if (self::getConfig('backend_active', false)) {
            $page['title'] .= ' <span class="label label-danger">B</span>';
        }

        if (self::getConfig('frontend_active', false)) {
            $page['title'] .= ' <span class="label label-warning">F</span>';
        }

        $addon->setProperty('page', $page);
    }

    /**
     * Helper-Methode für Konfigurationsabruf
     */
    private static function getConfig(string $key, mixed $default = null): mixed
    {
        return self::getAddon()->getConfig($key, $default);
    }
}
