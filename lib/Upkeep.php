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
use rex_sql;
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
            // IP-Adressen trennen und trimmen
            $allowedIpsArray = array_filter(array_map('trim', explode(',', $allowedIps)));
            return in_array($ip, $allowedIpsArray, true);
        }

        return false;
    }

  /**
 * Prüft, ob die aktuelle Domain im Wartungsmodus ist
 * Gibt TRUE zurück wenn die Domain gesperrt werden soll
 */
public static function isDomainInMaintenance(): bool
{
    // Wenn YRewrite nicht verfügbar, keine Domain-basierte Logik
    if (!rex_addon::get('yrewrite')->isAvailable()) {
        return true; // Fallback: Wartungsmodus gilt für alle
    }

    $currentDomain = rex_yrewrite::getCurrentDomain()?->getName();
    if (!$currentDomain) {
        return true; // Keine Domain erkannt, Wartungsmodus aktiv
    }

    // Prüfen, ob alle Domains gesperrt sind
    $allDomainsLocked = (bool) self::getConfig('all_domains_locked', false);
    if ($allDomainsLocked) {
        return true; // Alle Domains sind im Wartungsmodus
    }

    // Holen der Domain-Statuseinstellungen aus der Konfiguration
    $domainStatus = (array) self::getConfig('domain_status', []);
    
    // Wenn die aktuelle Domain einen Eintrag hat und dieser auf 1/true gesetzt ist,
    // dann ist der Wartungsmodus für diese Domain aktiv
    if (isset($domainStatus[$currentDomain]) && $domainStatus[$currentDomain]) {
        return true; // Diese Domain ist im Wartungsmodus
    }
    
    // Wenn es keinen Eintrag gibt oder der Wert 0/false ist,
    // dann ist der Wartungsmodus für diese Domain NICHT aktiv
    return false;
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
    
    // WICHTIG: Erst prüfen ob diese Domain überhaupt im Wartungsmodus ist
    // Wenn nicht, sofort erlauben - egal was andere Einstellungen sagen
    if (!self::isDomainInMaintenance()) {
        return; // Diese Domain ist nicht im Wartungsmodus
    }
    
    // Ab hier wissen wir: Diese Domain SOLL gesperrt werden
    // Jetzt prüfen wir die Bypass-Möglichkeiten
    
    // Prüfen, ob bereits eine Session existiert (von Passwort oder vorherigem Bypass)
    if (rex_session('upkeep_authorized', 'bool', false)) {
        return;
    }
    
    // URL-Parameter für Bypass prüfen (ZUERST!)
    $allowBypassParam = self::getConfig('allow_bypass_param', 0);
    $bypassParamKey = self::getConfig('bypass_param_key', 'access');
    
    if ($allowBypassParam && $bypassParamKey && rex_request($bypassParamKey, 'string', '') !== '') {
        // Bypass-Parameter gefunden - Session setzen wie bei Passwort-Eingabe
        rex_set_session('upkeep_authorized', true);
        // Wartungsseite umgehen
        return;
    }
    
    // Prüfen, ob es sich um einen API-Aufruf handelt
    if (rex_request('rex-api-call', 'string', '') === 'upkeep') {
        return; // API-Aufrufe immer erlauben
    }

    // Prüfen, ob der Zugriff über eine Ausnahme erlaubt ist (IP, Passwort, User)
    if (self::isIpAllowed() || self::isPasswordValid() || self::isUserAllowed()) {
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
    
    // Silent mode check: Only send HTTP status, no further processing
    $silentMode = (bool) self::getConfig('silent_mode', false);
    if ($silentMode) {
        exit;
    }

    // Wartungsseite anzeigen
    $fragment = new rex_fragment();
    
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

        // Im Impersonate-Modus: Prüfen, ob der ursprüngliche Benutzer (Impersonator) ein Admin ist
        $impersonator = rex::getImpersonator();
        if ($impersonator instanceof rex_user && $impersonator->isAdmin()) {
            return;
        }

        // Backend-Benutzer sperren
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
        exit($fragment->parse('upkeep/backend.php'));
    }



    /**
     * Konfiguriert die Module-Seiten basierend auf den Admin-Einstellungen
     * Blendet deaktivierte Module aus der Navigation aus
     */
    public static function configureModulePages(): void
    {
        $addon = self::getAddon();
        $page = $addon->getProperty('page');
        
        if (!$page || !isset($page['subpages'])) {
            return;
        }
        
        // Prüfen, ob Module deaktiviert sind und entsprechende Seiten ausblenden
        $securityAdvisorEnabled = $addon->getConfig('security_advisor_enabled', true);
        $mailSecurityEnabled = $addon->getConfig('mail_security_enabled', true);
        $reportingEnabled = $addon->getConfig('reporting_enabled', true);
        $ipsEnabled = $addon->getConfig('ips_enabled', true);
        
        // Security Advisor ausblenden wenn deaktiviert
        if (!$securityAdvisorEnabled && isset($page['subpages']['security_advisor'])) {
            unset($page['subpages']['security_advisor']);
        }
        
        // Mail Security ausblenden wenn deaktiviert
        if (!$mailSecurityEnabled && isset($page['subpages']['mail_security'])) {
            unset($page['subpages']['mail_security']);
        }
        
        // Reporting ausblenden wenn deaktiviert
        if (!$reportingEnabled && isset($page['subpages']['reporting'])) {
            unset($page['subpages']['reporting']);
        }
        
        // IPS ausblenden wenn deaktiviert
        if (!$ipsEnabled && isset($page['subpages']['ips'])) {
            unset($page['subpages']['ips']);
        }
        
        $addon->setProperty('page', $page);
    }

    /**
     * Setzt Statusindikator im Backend-Menü
     */
    public static function setStatusIndicator(): void
    {
        $addon = self::getAddon();
        $page = $addon->getProperty('page');

        if (self::getConfig('backend_active', false)) {
            $page['title'] .= ' <span class="label label-danger" title="' . $addon->i18n('upkeep_indicator_backend') . '">B</span>';
        }

        if (self::getConfig('frontend_active', false)) {
            $page['title'] .= ' <span class="label label-warning" title="' . $addon->i18n('upkeep_indicator_frontend') . '">F</span>';
        }

        if (self::getConfig('domain_mapping_active', false)) {
            $page['title'] .= ' <span class="label label-default" title="' . $addon->i18n('upkeep_indicator_domains') . '">R</span>';
        }

        // IPS-Indikator hinzufügen
        if (self::getConfig('ips_active', false)) {
            // Prüfe Bedrohungslevel für Farbe
            try {
                $stats = IntrusionPrevention::getStatistics();
                $threatsToday = $stats['threats_today'] ?? 0;
                $blockedIps = $stats['blocked_ips'] ?? 0;
                
                if ($threatsToday > 10) {
                    $labelClass = 'label-danger';  // Rot bei vielen Bedrohungen
                    $tooltip = $addon->i18n('upkeep_indicator_security') . ' - ' . $threatsToday . ' Bedrohungen heute';
                } elseif ($threatsToday > 0) {
                    $labelClass = 'label-warning'; // Gelb bei wenigen Bedrohungen
                    $tooltip = $addon->i18n('upkeep_indicator_security') . ' - ' . $threatsToday . ' Bedrohungen heute';
                } else {
                    $labelClass = 'label-success'; // Grün wenn alles ruhig
                    $tooltip = $addon->i18n('upkeep_indicator_security');
                }
                
                if ($blockedIps > 0) {
                    $tooltip .= ' - ' . $blockedIps . ' IPs gesperrt';
                }
            } catch (\Exception $e) {
                $labelClass = 'label-success'; // Fallback
                $tooltip = $addon->i18n('upkeep_indicator_security');
            }
            
            $page['title'] .= ' <span class="label ' . $labelClass . '" title="' . htmlspecialchars($tooltip) . '">S</span>';
        }

        $addon->setProperty('page', $page);
    }

    /**
     * Prüft Domain-Mapping und führt Redirects durch
     */
    public static function checkDomainMapping(): void
    {
        // Nur im Frontend prüfen
        if (!rex::isFrontend()) {
            return;
        }

        // Prüfen, ob Domain-Mapping global aktiviert ist
        if (!self::getConfig('domain_mapping_active', false)) {
            return;
        }

        $currentDomain = rex_server('HTTP_HOST', 'string', '');
        $currentPath = rex_server('REQUEST_URI', 'string', '');
        
        if ($currentDomain === '') {
            return;
        }

        // Domains für das Matching vorbereiten (mit und ohne www + IDN-Varianten)
        $domainsToCheck = [$currentDomain];
        
        // Wenn Domain mit www. beginnt, füge auch Variante ohne www hinzu
        if (str_starts_with($currentDomain, 'www.')) {
            $domainsToCheck[] = substr($currentDomain, 4);
        } else {
            // Wenn Domain ohne www, füge auch Variante mit www hinzu
            $domainsToCheck[] = 'www.' . $currentDomain;
        }
        
        // IDN-Varianten hinzufügen (sowohl Unicode als auch Punycode)
        $additionalDomains = [];
        foreach ($domainsToCheck as $domain) {
            // Punycode zu Unicode konvertieren (falls aktuell Punycode)
            if (function_exists('idn_to_utf8') && str_contains($domain, 'xn--')) {
                $unicodeDomain = idn_to_utf8($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
                if ($unicodeDomain !== false && $unicodeDomain !== $domain) {
                    $additionalDomains[] = $unicodeDomain;
                }
            }
            
            // Unicode zu Punycode konvertieren (falls aktuell Unicode)
            if (function_exists('idn_to_ascii') && !str_contains($domain, 'xn--')) {
                $punycodeDomain = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
                if ($punycodeDomain !== false && $punycodeDomain !== $domain) {
                    $additionalDomains[] = $punycodeDomain;
                }
            }
        }
        
        // Alle Varianten zusammenführen und doppelte entfernen
        $domainsToCheck = array_unique(array_merge($domainsToCheck, $additionalDomains));

        // Erst exakte Domain-Mappings prüfen (ohne Wildcard)
        foreach ($domainsToCheck as $domainToCheck) {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT target_url, redirect_code FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE source_domain = ? AND (source_path = "" OR source_path IS NULL) AND status = 1 ORDER BY id', [$domainToCheck]);

            if ($sql->getRows() > 0) {
                $targetUrl = $sql->getValue('target_url');
                $httpCode = (int) $sql->getValue('redirect_code');
                
                self::performRedirect($targetUrl, $httpCode);
            }
        }

        // Dann Wildcard-Mappings prüfen
        foreach ($domainsToCheck as $domainToCheck) {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT target_url, redirect_code, source_path, is_wildcard FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE source_domain = ? AND source_path != "" AND source_path IS NOT NULL AND status = 1 ORDER BY LENGTH(source_path) DESC', [$domainToCheck]);

            while ($sql->hasNext()) {
                $sourcePath = $sql->getValue('source_path');
                $isWildcard = (bool) $sql->getValue('is_wildcard');
                
                if (self::matchesPath($currentPath, $sourcePath, $isWildcard)) {
                    $targetUrl = $sql->getValue('target_url');
                    $httpCode = (int) $sql->getValue('redirect_code');
                    
                    // Wildcard-Ersetzung durchführen
                    if ($isWildcard && str_contains($targetUrl, '*')) {
                        $targetUrl = self::replaceWildcard($currentPath, $sourcePath, $targetUrl);
                    }
                    
                    self::performRedirect($targetUrl, $httpCode);
                }
                
                $sql->next();
            }
        }
    }

    /**
     * Prüft, ob der aktuelle Pfad mit dem Quell-Pfad übereinstimmt
     */
    private static function matchesPath(string $currentPath, string $sourcePath, bool $isWildcard): bool
    {
        if (!$isWildcard) {
            return $currentPath === $sourcePath;
        }

        // Wildcard-Matching
        if (str_ends_with($sourcePath, '/*')) {
            $basePattern = rtrim($sourcePath, '/*');
            return str_starts_with($currentPath, $basePattern);
        }

        return false;
    }

    /**
     * Ersetzt Wildcards in der Ziel-URL
     */
    private static function replaceWildcard(string $currentPath, string $sourcePath, string $targetUrl): string
    {
        if (str_ends_with($sourcePath, '/*') && str_contains($targetUrl, '*')) {
            $basePattern = rtrim($sourcePath, '/*');
            
            // Sicherheitscheck: Pfad muss mit basePattern beginnen
            if (!str_starts_with($currentPath, $basePattern)) {
                return $targetUrl; // Kein Replacement, wenn Pattern nicht passt
            }
            
            $remainingPathStartIndex = strlen($basePattern);
            
            // Bounds-Check für substr
            if ($remainingPathStartIndex >= strlen($currentPath)) {
                $remainingPath = '';
            } else {
                $remainingPath = substr($currentPath, $remainingPathStartIndex);
                $remainingPath = ltrim($remainingPath, '/');
            }
            
            return str_replace('*', $remainingPath, $targetUrl);
        }

        return $targetUrl;
    }

    /**
     * Führt die tatsächliche Umleitung durch
     */
    private static function performRedirect(string $targetUrl, int $httpCode): void
    {
        // URL validieren und bei Bedarf Protocol hinzufügen
        if (!str_starts_with($targetUrl, 'http://') && !str_starts_with($targetUrl, 'https://')) {
            $targetUrl = 'https://' . $targetUrl;
        }
        
        // Redirect durchführen
        rex_response::setStatus($httpCode);
        rex_response::sendRedirect($targetUrl);
        exit;
    }

    /**
     * Helper-Methode für Konfigurationsabruf
     */
    private static function getConfig(string $key, mixed $default = null): mixed
    {
        return self::getAddon()->getConfig($key, $default);
    }
}
