<?php

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_backend_login;
use rex_extension;
use rex_extension_point;
use rex_fragment;
use rex_login;
use rex_logger;
use rex_response;
use rex_sql;
use rex_url;
use rex_user;
use rex_yrewrite;
use Throwable;

/**
 * Hauptklasse für das Upkeep-AddOn
 * Verwaltet den Wartungsmodus für Frontend und Backend
 */
class Upkeep
{
    /** Fehlversuche für das Wartungspasswort pro IP im Zeitfenster */
    public const PASSWORD_MAX_ATTEMPTS = 5;

    /** Zeitfenster für Fehlversuche (Sekunden) */
    public const PASSWORD_LOCK_SECONDS = 900;

    /** Fehlversuche für das Wartungspasswort über alle Adressen im Zeitfenster */
    public const PASSWORD_GLOBAL_MAX = 50;

    /** Zeitfenster für die globale Obergrenze (Sekunden) */
    public const PASSWORD_GLOBAL_WINDOW = 900;

    private static ?rex_addon $addon = null;

    /** Fehlerzustand des Passwortformulars: null | 'invalid' | 'locked' */
    private static ?string $passwordError = null;

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

    // ------------------------------------------------------------------
    // Zugriffsprüfungen
    // ------------------------------------------------------------------

    /**
     * Prüft, ob die aktuelle Client-IP in der Liste erlaubter IPs steht
     * (Komma, Zeilenumbruch oder Leerzeichen getrennt, CIDR erlaubt).
     */
    public static function isIpAllowed(): bool
    {
        $allowedIps = (string) self::getConfig('allowed_ips', '');
        if ($allowedIps === '') {
            return false;
        }
        return ClientIp::inList(ClientIp::get(), $allowedIps);
    }

    /**
     * Prüft, ob die aktuelle Domain im Wartungsmodus ist
     * Gibt TRUE zurück wenn die Domain gesperrt werden soll
     */
    public static function isDomainInMaintenance(): bool
    {
        if (!rex_addon::get('yrewrite')->isAvailable()) {
            return true;
        }

        $currentDomain = rex_yrewrite::getCurrentDomain()?->getName();
        if (!$currentDomain) {
            return true;
        }

        if ((bool) self::getConfig('all_domains_locked', false)) {
            return true;
        }

        $domainStatus = (array) self::getConfig('domain_status', []);
        return !empty($domainStatus[$currentDomain]);
    }

    /**
     * Gibt es ein Passwort für die Wartungsseite (Hash oder 2.x-Klartext)?
     */
    public static function hasFrontendPassword(): bool
    {
        return (string) self::getConfig('frontend_password_hash', '') !== ''
            || (string) self::getConfig('frontend_password', '') !== '';
    }

    /**
     * Setzt das Passwort der Wartungsseite (speichert nur den Hash). Leer = kein Passwort.
     */
    public static function setFrontendPassword(string $plain): void
    {
        $addon = self::getAddon();
        if ($plain === '') {
            $addon->setConfig('frontend_password_hash', '');
        } else {
            $addon->setConfig('frontend_password_hash', password_hash($plain, PASSWORD_DEFAULT));
        }
        $addon->removeConfig('frontend_password');
    }

    /**
     * Prüft, ob der Besucher per Passwort freigeschaltet ist bzw. verarbeitet einen Passwort-POST.
     * Nur POST-Feld "upkeep_password". Fehlversuche sind pro IP begrenzt.
     */
    public static function isPasswordValid(): bool
    {
        if (!self::hasFrontendPassword()) {
            return false;
        }

        if (self::hasValidSessionFlag()) {
            return true;
        }

        if (strtoupper(rex_server('REQUEST_METHOD', 'string', 'GET')) !== 'POST') {
            return false;
        }
        $input = $_POST['upkeep_password'] ?? null;
        if (!is_string($input) || $input === '') {
            return false;
        }
        $input = substr($input, 0, 512);

        $store = new JsonStore('maintenance_attempts', 2000);
        $ipKey = 'pw:' . ClientIp::bucket(ClientIp::get());
        if ((int) $store->get($ipKey, 0) >= self::PASSWORD_MAX_ATTEMPTS) {
            self::$passwordError = 'locked';
            return false;
        }

        // Obergrenze über alle Adressen (verteilte Versuche): Anmeldung vorübergehend aus, normale Fehlermeldung
        $globalKey = 'pw:global:' . intdiv(time(), self::PASSWORD_GLOBAL_WINDOW);
        if ((int) $store->get($globalKey, 0) >= self::PASSWORD_GLOBAL_MAX) {
            self::$passwordError = 'invalid';
            return false;
        }

        if (!self::verifyFrontendPassword($input)) {
            $store->increment($ipKey, self::PASSWORD_LOCK_SECONDS);
            $store->increment($globalKey, self::PASSWORD_GLOBAL_WINDOW);
            self::$passwordError = 'invalid';
            return false;
        }

        $store->delete($ipKey);
        self::authorizeSession(self::passwordSessionToken());
        self::redirectToSelf();
        return true;
    }

    /**
     * Fehlerzustand des Passwortformulars für die Wartungsseite.
     *
     * @return string|null null, 'invalid' oder 'locked'
     */
    public static function getPasswordError(): ?string
    {
        return self::$passwordError;
    }

    /**
     * Prüft das Passwort gegen den Hash; Fallback 2.x-Klartext (wird dann gehasht).
     */
    private static function verifyFrontendPassword(string $input): bool
    {
        $hash = (string) self::getConfig('frontend_password_hash', '');
        if ($hash !== '') {
            if (!password_verify($input, $hash)) {
                return false;
            }
            if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
                self::getAddon()->setConfig('frontend_password_hash', password_hash($input, PASSWORD_DEFAULT));
            }
            return true;
        }

        $legacy = (string) self::getConfig('frontend_password', '');
        if ($legacy !== '' && hash_equals($legacy, $input)) {
            self::setFrontendPassword($input);
            return true;
        }
        return false;
    }

    /**
     * Sitzungsmerkmal, das an den aktuellen Passwort-Hash gebunden ist
     * (Passwortwechsel beendet bestehende Freischaltungen).
     */
    private static function passwordSessionToken(): string
    {
        $hash = (string) self::getConfig('frontend_password_hash', '');
        if ($hash === '') {
            $hash = 'legacy:' . (string) self::getConfig('frontend_password', '');
        }
        return 'pw:' . substr(hash('sha256', 'upkeep-pw|' . $hash), 0, 32);
    }

    private static function bypassSessionToken(): string
    {
        return 'bp:' . substr(hash('sha256', 'upkeep-bp|' . (string) self::getConfig('bypass_secret', '')), 0, 32);
    }

    /**
     * Prüft die Sitzung, ohne eine neue Sitzung für anonyme Besucher zu starten.
     */
    private static function hasValidSessionFlag(): bool
    {
        if (!self::hasSessionCookie()) {
            return false;
        }
        try {
            rex_login::startSession();
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return false;
        }
        $value = rex_session('upkeep_authorized', 'string', '');
        if (!is_string($value) || $value === '') {
            return false;
        }
        if (self::hasFrontendPassword() && hash_equals(self::passwordSessionToken(), $value)) {
            return true;
        }
        if ((string) self::getConfig('bypass_secret', '') !== '' && hash_equals(self::bypassSessionToken(), $value)) {
            return true;
        }
        return false;
    }

    private static function hasSessionCookie(): bool
    {
        if (PHP_SESSION_ACTIVE === session_status()) {
            return true;
        }
        $name = session_name();
        return $name !== false && isset($_COOKIE[$name]);
    }

    private static function authorizeSession(string $token): void
    {
        try {
            rex_login::startSession();
            if (PHP_SESSION_ACTIVE === session_status()) {
                @session_regenerate_id(true);
            }
            rex_set_session('upkeep_authorized', $token);
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * Braucht der aktuelle Request eine Session für den Wartungsmodus?
     * Upkeep startet die Session bei Bedarf selbst; die Methode ist nur informativ.
     */
    public static function needsSession(): bool
    {
        if (!rex::isFrontend() || !self::getConfig('frontend_active', false)) {
            return false;
        }
        if (self::hasSessionCookie()) {
            return true;
        }
        if (strtoupper(rex_server('REQUEST_METHOD', 'string', 'GET')) === 'POST' && isset($_POST['upkeep_password'])) {
            return true;
        }
        $key = (string) self::getConfig('bypass_param_key', 'access');
        return $key !== '' && isset($_GET[$key]);
    }

    /**
     * Gültiger Umgehungs-Parameter? ?<bypass_param_key>=<bypass_secret>
     */
    private static function isBypassParamValid(): bool
    {
        if (!self::getConfig('allow_bypass_param', 0)) {
            return false;
        }
        $key = (string) self::getConfig('bypass_param_key', 'access');
        $secret = (string) self::getConfig('bypass_secret', '');
        if ($key === '' || $secret === '' || strlen($secret) < 16) {
            return false;
        }
        $value = $_GET[$key] ?? $_POST[$key] ?? null;
        return is_string($value) && $value !== '' && hash_equals($secret, $value);
    }

    /**
     * Geheimer Wert für den Umgehungs-Link (wird bei Bedarf erzeugt).
     */
    public static function getBypassSecret(bool $generate = true): string
    {
        $secret = (string) self::getConfig('bypass_secret', '');
        if ($secret === '' && $generate) {
            $secret = self::regenerateBypassSecret();
        }
        return $secret;
    }

    /**
     * Erzeugt einen neuen geheimen Wert (alte Links und Freischaltungen werden ungültig).
     */
    public static function regenerateBypassSecret(): string
    {
        $secret = bin2hex(random_bytes(16));
        self::getAddon()->setConfig('bypass_secret', $secret);
        return $secret;
    }

    /**
     * Fertiger Umgehungs-Link für die Startseite (oder null, wenn deaktiviert).
     */
    public static function getBypassUrl(): ?string
    {
        if (!self::getConfig('allow_bypass_param', 0)) {
            return null;
        }
        $key = (string) self::getConfig('bypass_param_key', 'access');
        $secret = self::getBypassSecret(false);
        if ($key === '' || $secret === '') {
            return null;
        }
        return rex::getServer() . '?' . rawurlencode($key) . '=' . rawurlencode($secret);
    }

    /**
     * Prüft, ob der aktuelle Benutzer angemeldet ist und Zugriff haben soll
     */
    public static function isUserAllowed(): bool
    {
        if (!self::getConfig('bypass_logged_in', true)) {
            return false;
        }
        // Ohne Session-Cookie kann es keinen Backend-Login geben (keine neue Session starten)
        if (!self::hasSessionCookie()) {
            return false;
        }
        rex_backend_login::createUser();
        return rex::getUser() instanceof rex_user;
    }

    /**
     * Prüft, ob Frontend-Zugriff erlaubt ist oder gesperrt werden soll
     */
    public static function checkFrontend(): void
    {
        try {
            if (!self::getConfig('frontend_active', false)) {
                return;
            }
            if (!self::isDomainInMaintenance()) {
                return;
            }

            if (self::hasValidSessionFlag()) {
                return;
            }

            if (self::isBypassParamValid()) {
                self::authorizeSession(self::bypassSessionToken());
                return;
            }

            // API-Aufrufe mit eigener Token-/Schlüsselprüfung erlauben
            $apiCall = rex_request('rex-api-call', 'string', '');
            if (in_array($apiCall, ['upkeep', 'upkeep_system_health', 'upkeep_mail_security'], true)) {
                return;
            }

            if (self::isIpAllowed() || self::isPasswordValid() || self::isUserAllowed()) {
                return;
            }

            if (self::isAllowedPath()) {
                return;
            }
        } catch (Throwable $e) {
            // Fehler in der Prüfung: Seite bleibt erreichbar, Fehler wird geloggt (fail open)
            rex_logger::logException($e);
            return;
        }

        self::sendMaintenancePage();
    }

    /**
     * Pfade, die per Extension Point UPKEEP_ALLOWED_PATHS freigegeben sind.
     * Vergleich nur mit dem Pfad (ohne Query), Präfix-Vergleich, relativ zur Installation.
     */
    private static function isAllowedPath(): bool
    {
        $allowedPathsList = rex_extension::registerPoint(new rex_extension_point('UPKEEP_ALLOWED_PATHS', []));
        if (!is_array($allowedPathsList) || $allowedPathsList === []) {
            return false;
        }

        $path = rawurldecode((string) (parse_url(rex_server('REQUEST_URI', 'string', '/'), PHP_URL_PATH) ?? '/'));
        if (str_contains($path, '..')) {
            return false;
        }
        $base = rtrim((string) (parse_url(rex_url::frontend(), PHP_URL_PATH) ?? '/'), '/');
        $relative = ($base !== '' && str_starts_with($path, $base . '/')) ? substr($path, strlen($base)) : $path;

        foreach ($allowedPathsList as $allowed) {
            if (!is_string($allowed) || trim($allowed) === '') {
                continue;
            }
            $allowed = '/' . ltrim(trim($allowed), '/');
            if (self::pathHasPrefix($relative, $allowed) || self::pathHasPrefix($path, $allowed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Präfix-Vergleich nur an Pfadgrenzen: /media erlaubt /media und /media/…, aber nicht /media-x.
     */
    private static function pathHasPrefix(string $path, string $prefix): bool
    {
        if ($prefix === '/' || str_ends_with($prefix, '/')) {
            return str_starts_with($path, $prefix);
        }
        return $path === $prefix || str_starts_with($path, $prefix . '/');
    }

    private static function sendMaintenancePage(): never
    {
        $httpStatusCode = (int) self::getConfig('http_status_code', rex_response::HTTP_SERVICE_UNAVAILABLE);
        if ($httpStatusCode < 200 || $httpStatusCode > 599) {
            $httpStatusCode = 503;
        }

        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code($httpStatusCode);
            $retryAfter = (int) self::getConfig('retry_after', 0);
            if ($retryAfter > 0) {
                header('Retry-After: ' . $retryAfter);
            }
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('X-Robots-Tag: noindex, nofollow');
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: SAMEORIGIN');
            header('Content-Type: text/html; charset=utf-8');
        }

        if ((bool) self::getConfig('silent_mode', false)) {
            exit;
        }

        $fragment = new rex_fragment();
        echo $fragment->parse('upkeep/frontend.php');
        exit;
    }

    /**
     * Nach erfolgreichem Passwort-POST auf dieselbe URL per GET weiterleiten (PRG).
     */
    private static function redirectToSelf(): void
    {
        if (headers_sent()) {
            return;
        }
        $uri = rex_server('REQUEST_URI', 'string', '/');
        if ($uri === '' || $uri[0] !== '/' || str_starts_with($uri, '//')) {
            $uri = '/';
        }
        rex_response::cleanOutputBuffers();
        header('Cache-Control: no-store');
        header('Location: ' . str_replace(["\r", "\n"], '', $uri), true, 303);
        exit;
    }

    /**
     * Prüft, ob Backend-Zugriff erlaubt ist oder gesperrt werden soll
     */
    public static function checkBackend(): void
    {
        if (!self::getConfig('backend_active', false)) {
            return;
        }

        $user = rex::getUser();
        if ($user instanceof rex_user && $user->isAdmin()) {
            return;
        }

        $impersonator = rex::getImpersonator();
        if ($impersonator instanceof rex_user && $impersonator->isAdmin()) {
            return;
        }

        $httpStatusCode = (int) self::getConfig('http_status_code', rex_response::HTTP_SERVICE_UNAVAILABLE);
        if ($httpStatusCode < 200 || $httpStatusCode > 599) {
            $httpStatusCode = 503;
        }
        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code($httpStatusCode);
            $retryAfter = (int) self::getConfig('retry_after', 0);
            if ($retryAfter > 0) {
                header('Retry-After: ' . $retryAfter);
            }
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Content-Type: text/html; charset=utf-8');
        }

        $fragment = new rex_fragment();
        echo $fragment->parse('upkeep/backend.php');
        exit;
    }

    // ------------------------------------------------------------------
    // Wartungsstatus setzen
    // ------------------------------------------------------------------

    /**
     * Setzt einen Wartungsstatus und löst bei Änderung UPKEEP_MAINTENANCE_CHANGED aus.
     *
     * @param string $area 'frontend', 'backend', 'all_domains' oder 'domain:<name>'
     * @param string $source z. B. 'backend', 'api', 'console', 'cronjob'
     * @return bool true, wenn sich der Status geändert hat
     */
    public static function setMaintenance(string $area, bool $active, string $source = 'backend'): bool
    {
        $addon = self::getAddon();

        if (str_starts_with($area, 'domain:')) {
            $domain = substr($area, 7);
            if ($domain === '') {
                return false;
            }
            $status = (array) $addon->getConfig('domain_status', []);
            $previous = !empty($status[$domain]);
            if ($previous === $active) {
                return false;
            }
            $status[$domain] = $active ? 1 : 0;
            $addon->setConfig('domain_status', $status);
        } else {
            $key = match ($area) {
                'frontend' => 'frontend_active',
                'backend' => 'backend_active',
                'all_domains' => 'all_domains_locked',
                default => null,
            };
            if ($key === null) {
                return false;
            }
            $previous = (bool) $addon->getConfig($key, false);
            if ($previous === $active) {
                return false;
            }
            $addon->setConfig($key, $active ? 1 : 0);
        }

        self::fireMaintenanceChanged($area, $active, $source);
        return true;
    }

    /**
     * Löst den Extension Point UPKEEP_MAINTENANCE_CHANGED aus (auch für Seiten, die Formulare
     * über rex_config_form speichern und den Wechsel selbst erkennen).
     */
    public static function fireMaintenanceChanged(string $area, bool $active, string $source = 'backend'): void
    {
        $user = rex::getUser();
        $data = [
            'type' => $area,
            'status' => $active,
            'source' => $source,
            'timestamp' => time(),
            'user' => $user instanceof rex_user ? $user->getLogin() : ($source === 'console' ? 'console' : 'System'),
            'ip' => PHP_SAPI === 'cli' ? '' : ClientIp::get(),
            'config' => [
                'allowed_ips' => (string) self::getConfig('allowed_ips', ''),
                'bypass_key' => (bool) self::getConfig('allow_bypass_param', 0),
                'multilang' => (bool) self::getConfig('multilanguage_enabled', 0),
            ],
        ];
        try {
            rex_extension::registerPoint(new rex_extension_point('UPKEEP_MAINTENANCE_CHANGED', $data));
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    // ------------------------------------------------------------------
    // Backend-Navigation
    // ------------------------------------------------------------------

    /**
     * Konfiguriert die Module-Seiten (3.0: Seiten bleiben sichtbar; 2.x-Menüschalter
     * werden nur berücksichtigt, solange sie noch existieren)
     */
    public static function configureModulePages(): void
    {
        $addon = self::getAddon();
        $page = $addon->getProperty('page');

        if (!$page || !isset($page['subpages'])) {
            return;
        }

        $map = [
            'security_advisor_enabled' => 'security_advisor',
            'mail_security_enabled' => 'mail_security',
            'reporting_enabled' => 'reporting',
            'ips_enabled' => 'ips',
        ];
        foreach ($map as $key => $subpage) {
            if ($addon->hasConfig($key) && !$addon->getConfig($key) && isset($page['subpages'][$subpage])) {
                unset($page['subpages'][$subpage]);
            }
        }

        $addon->setProperty('page', $page);
    }

    /**
     * Setzt Statusindikator im Backend-Menü (Texte escaped, Zahlen gecacht)
     */
    public static function setStatusIndicator(): void
    {
        $addon = self::getAddon();
        $page = $addon->getProperty('page');
        if (!is_array($page) || !isset($page['title'])) {
            return;
        }

        $badge = static fn (string $letter, string $title, string $modifier = ''): string => ' <span class="upkeep-nav-indicator' . ($modifier !== '' ? ' upkeep-nav-indicator--' . $modifier : '') . '" title="' . rex_escape($title) . '">' . rex_escape($letter) . '</span>';

        if (self::getConfig('backend_active', false)) {
            $page['title'] .= $badge('B', $addon->i18n('upkeep_indicator_backend'), 'danger');
        }
        if (self::getConfig('frontend_active', false)) {
            $page['title'] .= $badge('F', $addon->i18n('upkeep_indicator_frontend'), 'warning');
        }
        if (self::getConfig('domain_mapping_active', false)) {
            $page['title'] .= $badge('R', $addon->i18n('upkeep_indicator_domains'));
        }
        if (self::getConfig('mail_security_active', false)) {
            $page['title'] .= $badge('E', $addon->i18n('upkeep_indicator_mail_security'));
        }

        if (self::getConfig('ips_active', false)) {
            $tooltip = $addon->i18n('upkeep_indicator_security');
            $stats = IntrusionPrevention::getIndicatorStats();
            if ($stats['threats_today'] > 0) {
                $tooltip .= ' - ' . $addon->i18n('upkeep_indicator_threats_today', (string) $stats['threats_today']);
            }
            if ($stats['blocked_ips'] > 0) {
                $tooltip .= ' - ' . $addon->i18n('upkeep_indicator_blocked_ips', (string) $stats['blocked_ips']);
            }
            $page['title'] .= $badge('I', $tooltip);
        }

        $addon->setProperty('page', $page);
    }

    // ------------------------------------------------------------------
    // Domain-Mapping (Weiterleitungen)
    // ------------------------------------------------------------------

    /**
     * Prüft Domain-Mapping und führt Redirects durch (eine Abfrage pro Request)
     */
    public static function checkDomainMapping(): void
    {
        try {
            if (!rex::isFrontend() || !self::getConfig('domain_mapping_active', false)) {
                return;
            }

            $currentDomain = strtolower(rex_server('HTTP_HOST', 'string', ''));
            $currentDomain = preg_replace('/:\d+$/', '', $currentDomain) ?? '';
            $currentUri = rex_server('REQUEST_URI', 'string', '');
            $currentPath = (string) (parse_url($currentUri, PHP_URL_PATH) ?? '');

            if ($currentDomain === '' || !preg_match('/^[a-z0-9.\-]+$/', $currentDomain)) {
                return;
            }

            $domainsToCheck = [$currentDomain];
            $domainsToCheck[] = str_starts_with($currentDomain, 'www.') ? substr($currentDomain, 4) : 'www.' . $currentDomain;

            $additional = [];
            foreach ($domainsToCheck as $domain) {
                if (function_exists('idn_to_utf8') && str_contains($domain, 'xn--')) {
                    $unicode = idn_to_utf8($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
                    if ($unicode !== false && $unicode !== $domain) {
                        $additional[] = $unicode;
                    }
                }
            }
            $domainsToCheck = array_values(array_unique(array_merge($domainsToCheck, $additional)));

            $placeholders = implode(',', array_fill(0, count($domainsToCheck), '?'));
            $sql = rex_sql::factory();
            $rows = $sql->getArray(
                'SELECT source_domain, source_path, target_url, redirect_code, is_wildcard FROM ' . rex::getTable('upkeep_domain_mapping')
                . ' WHERE source_domain IN (' . $placeholders . ') AND status = 1 ORDER BY id',
                $domainsToCheck,
            );
            if ($rows === []) {
                return;
            }

            // 1. Exakte Domain-Mappings (ohne Pfad) in Reihenfolge der Domain-Varianten
            foreach ($domainsToCheck as $domain) {
                foreach ($rows as $row) {
                    if ($row['source_domain'] === $domain && ((string) $row['source_path']) === '') {
                        self::performRedirect((string) $row['target_url'], (int) $row['redirect_code']);
                    }
                }
            }

            // 2. Pfad-Mappings, längster Pfad zuerst
            $pathRows = array_values(array_filter($rows, static fn ($r) => ((string) $r['source_path']) !== ''));
            usort($pathRows, static fn ($a, $b) => strlen((string) $b['source_path']) <=> strlen((string) $a['source_path']));

            foreach ($pathRows as $row) {
                $sourcePath = (string) $row['source_path'];
                $isWildcard = (bool) $row['is_wildcard'];
                if (!self::matchesPath($currentUri, $currentPath, $sourcePath, $isWildcard)) {
                    continue;
                }
                $targetUrl = (string) $row['target_url'];
                if ($isWildcard && str_contains($targetUrl, '*')) {
                    $targetUrl = self::replaceWildcard($currentPath, $sourcePath, $targetUrl);
                }
                self::performRedirect($targetUrl, (int) $row['redirect_code']);
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * Prüft, ob der aktuelle Pfad mit dem Quell-Pfad übereinstimmt
     */
    private static function matchesPath(string $currentUri, string $currentPath, string $sourcePath, bool $isWildcard): bool
    {
        if (!$isWildcard) {
            return $currentUri === $sourcePath || $currentPath === $sourcePath;
        }

        if (str_ends_with($sourcePath, '/*')) {
            $base = substr($sourcePath, 0, -2);
            return $currentPath === $base || str_starts_with($currentPath, $base . '/');
        }
        if (str_ends_with($sourcePath, '*')) {
            return str_starts_with($currentPath, substr($sourcePath, 0, -1));
        }

        return $currentPath === $sourcePath;
    }

    /**
     * Ersetzt Wildcards in der Ziel-URL
     */
    private static function replaceWildcard(string $currentPath, string $sourcePath, string $targetUrl): string
    {
        if (str_ends_with($sourcePath, '/*')) {
            $base = substr($sourcePath, 0, -2);
        } elseif (str_ends_with($sourcePath, '*')) {
            $base = substr($sourcePath, 0, -1);
        } else {
            return $targetUrl;
        }

        if (!str_starts_with($currentPath, $base)) {
            return $targetUrl;
        }

        $remainingPath = ltrim(substr($currentPath, strlen($base)), '/');
        // Pfadsegmente sauber kodieren
        $remainingPath = implode('/', array_map('rawurlencode', array_map('rawurldecode', explode('/', $remainingPath))));

        return str_replace('*', $remainingPath, $targetUrl);
    }

    /**
     * Führt die tatsächliche Umleitung durch (Ziel wird validiert)
     */
    private static function performRedirect(string $targetUrl, int $httpCode): void
    {
        $targetUrl = trim($targetUrl);
        if ($targetUrl === '' || preg_match('/[\r\n\x00]/', $targetUrl)) {
            return;
        }
        if (!preg_match('~^https?://~i', $targetUrl)) {
            $targetUrl = 'https://' . ltrim($targetUrl, '/');
        }
        if (filter_var($targetUrl, FILTER_VALIDATE_URL) === false) {
            return;
        }
        $host = parse_url($targetUrl, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return;
        }
        if (!in_array($httpCode, [301, 302, 303, 307, 308], true)) {
            $httpCode = 301;
        }

        // Keine Schleife auf dieselbe URL
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $current = $scheme . '://' . rex_server('HTTP_HOST', 'string', '') . rex_server('REQUEST_URI', 'string', '');
        if (rtrim($current, '/') === rtrim($targetUrl, '/')) {
            return;
        }

        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            header('Location: ' . $targetUrl, true, $httpCode);
        }
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
