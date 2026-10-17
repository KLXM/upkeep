<?php

namespace KLXM\Upkeep;

use DateTime;
use Exception;
use rex;
use rex_addon;
use rex_config;
use rex_dir;
use rex_extension;
use rex_extension_point;
use rex_file;
use rex_logger;
use rex_path;
use rex_response;
use rex_sql;
use rex_sql_table;
use Throwable;

/**
 * Intrusion Prevention System für Upkeep AddOn
 *
 * Erkennt und blockiert verdächtige Requests basierend auf:
 * - CMS-spezifische Exploit-Versuche (WordPress, TYPO3, Drupal, Joomla)
 * - Pentest-Tools und Scanner-Signaturen
 * - SQL-Injection und Path-Traversal-Versuche
 * - Benutzerdefinierte Patterns
 *
 * 3.0: echte Client-IP über ClientIp, Sperrseite über BlockPage (ALTCHA),
 * Fail-open bei Fehlern, zusammengefasste Logs, Caches pro Request.
 */
class IntrusionPrevention
{
    /** Zeitfenster für das Zusammenfassen gleichartiger Ereignisse (Sekunden) */
    private const AGGREGATE_WINDOW = 600;

    /** Maximale Anzahl neuer Log-Zeilen pro IP und Stunde */
    private const LOG_ROWS_PER_IP_HOUR = 200;

    /** Lebensdauer des Listen-Caches (Positivliste, CIDR-Sperren) */
    private const LIST_CACHE_TTL = 300;

    /** Mindestabstand zwischen automatischen Bereinigungen (Sekunden) */
    private const CLEANUP_INTERVAL = 3600;

    private static ?rex_addon $addon = null;

    /** @var array<string, bool> */
    private static array $blockedCache = [];

    /** @var array<string, bool> */
    private static array $allowCache = [];

    /** @var array<string, mixed>|null */
    private static ?array $listCache = null;

    private static ?bool $aggregation = null;

    private static int $dnsLookups = 0;

    /**
     * Bekannte Scanner und Pentest-Tools (User-Agent)
     *
     * @var list<string>
     */
    private static array $suspiciousUserAgents = [
        'nmap',
        'nikto',
        'sqlmap',
        'burpsuite',
        'owasp zap',
        'acunetix',
        'nessus',
        'openvas',
        'masscan',
        'dirb',
        'dirbuster',
        'gobuster',
        'wfuzz',
        'hydra',
        'metasploit',
        'w3af',
    ];

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
     * Debug-Logging nur wenn Debug-Modus aktiviert ist
     */
    private static function debugLog(string $message): void
    {
        if (self::getAddon()->getConfig('ips_debug_mode', false)) {
            rex_logger::factory()->log('debug', $message);
        }
    }

    /**
     * System-Logging nur wenn nicht deaktiviert
     *
     * @param array<string, mixed> $context
     */
    private static function systemLog(string $level, string $message, array $context = []): void
    {
        if (self::getAddon()->getConfig('ips_disable_system_logging', false)) {
            return;
        }
        rex_logger::factory()->log($level, $message, $context);
    }

    /**
     * Exception-Logging - immer aktiv für kritische Fehler
     */
    private static function exceptionLog(Throwable $exception): void
    {
        try {
            rex_logger::logException($exception);
        } catch (Throwable) {
            // Logging darf niemals selbst Fehler verursachen
        }
    }

    // ------------------------------------------------------------------
    // Request-Prüfung
    // ------------------------------------------------------------------

    /**
     * Hauptfunktion: Prüft eingehende Requests auf verdächtige Patterns.
     * Fehler führen nie zum Abbruch der Seite (fail open).
     */
    public static function checkRequest(): void
    {
        try {
            if (!rex::isFrontend() || !self::isActive()) {
                return;
            }
            self::runCheck();
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }
    }

    private static function runCheck(): void
    {
        self::maybeCleanup();

        $clientIp = ClientIp::get();
        $requestUri = rex_server('REQUEST_URI', 'string', '');
        $userAgent = rex_server('HTTP_USER_AGENT', 'string', '');
        $referer = rex_server('HTTP_REFERER', 'string', '');

        // Selbst-Entsperrung über die Sperrseite (ALTCHA) vor allen Sperrentscheidungen
        if (class_exists(BlockPage::class) && method_exists(BlockPage::class, 'handleUnlock')) {
            try {
                if (BlockPage::handleUnlock()) {
                    self::$blockedCache = [];
                    self::$allowCache = [];
                    return;
                }
            } catch (Throwable $e) {
                self::exceptionLog($e);
            }
        }

        if (self::isOnPositivliste($clientIp)) {
            return;
        }

        if (self::isBlocked($clientIp)) {
            self::blockRequest('IP bereits gesperrt', $clientIp, $requestUri);
        }

        $threat = self::analyzeRequest($requestUri, $userAgent, $referer);
        if ($threat !== null) {
            self::handleThreat($threat, $clientIp, $requestUri, $userAgent);
        }

        if (self::isRateLimitingEnabled() && self::isRateLimitExceeded($clientIp)) {
            self::handleThreat([
                'type' => 'rate_limit',
                'severity' => 'medium',
                'pattern' => 'Too many requests',
            ], $clientIp, $requestUri, $userAgent);
        }
    }

    /**
     * Analysiert Request auf verdächtige Patterns.
     *
     * Reihenfolge 3.0: Patterns zuerst. Eine als legitim erkannte CMS-URL
     * senkt höchstens den Schweregrad (nie unter "low"), überspringt aber keine Prüfung.
     *
     * @return array<string, mixed>|null
     */
    private static function analyzeRequest(string $uri, string $userAgent, string $referer): ?array
    {
        $decodedUri = rawurldecode($uri);
        $path = (string) (parse_url($uri, PHP_URL_PATH) ?? '');

        $threat = null;

        // WordPress XML-RPC: immer permanente Sperre
        if (preg_match('~/xmlrpc\.php$~i', rawurldecode($path))) {
            $threat = [
                'type' => 'default_pattern',
                'category' => 'immediate_block',
                'pattern' => 'xmlrpc.php',
                'severity' => 'critical',
            ];
        }

        // 1. Standard-Patterns
        if ($threat === null) {
            foreach (self::getDefaultPatterns() as $pattern) {
                if (self::patternMatches($pattern['pattern'], (bool) $pattern['is_regex'], $decodedUri)) {
                    $threat = [
                        'type' => $pattern['is_regex'] ? 'default_pattern_regex' : 'default_pattern',
                        'category' => $pattern['category'],
                        'pattern' => $pattern['pattern'],
                        'severity' => $pattern['severity'],
                    ];
                    break;
                }
            }
        }

        // 2. User-Agent
        if ($threat === null && $userAgent !== '') {
            $userAgentLower = strtolower($userAgent);
            foreach (self::$suspiciousUserAgents as $suspiciousAgent) {
                if (str_contains($userAgentLower, $suspiciousAgent)) {
                    $threat = [
                        'type' => 'suspicious_user_agent',
                        'pattern' => $suspiciousAgent,
                        'severity' => 'high',
                    ];
                    break;
                }
            }
        }

        // 3. Custom Patterns
        if ($threat === null) {
            foreach (self::getCustomPatterns() as $pattern) {
                if (self::patternMatches($pattern['pattern'], (bool) $pattern['is_regex'], $decodedUri)) {
                    $threat = [
                        'type' => $pattern['is_regex'] ? 'custom_pattern_regex' : 'custom_pattern',
                        'pattern' => $pattern['pattern'],
                        'severity' => $pattern['severity'] ?? 'medium',
                    ];
                    break;
                }
            }
        }

        if ($threat === null) {
            return null;
        }

        // Legitime CMS-URL: Schweregrad höchstens "medium" (keine Sofortsperre)
        if (($threat['category'] ?? '') !== 'immediate_block' && self::isLegitimateUrl($uri)) {
            if (in_array($threat['severity'], ['critical', 'high'], true)) {
                $threat['severity'] = 'medium';
                $threat['downgraded'] = true;
            }
        }

        return $threat;
    }

    /**
     * Prüft ein einzelnes Pattern (RegEx-Fehler werden geloggt, gelten als kein Treffer).
     */
    private static function patternMatches(string $pattern, bool $isRegex, string $subject): bool
    {
        if ($pattern === '') {
            return false;
        }
        if (!$isRegex) {
            return stripos($subject, $pattern) !== false;
        }
        $result = PatternValidator::match($pattern, $subject);
        if ($result === null) {
            static $reported = [];
            if (!isset($reported[$pattern])) {
                $reported[$pattern] = true;
                self::systemLog('warning', 'Upkeep IPS: invalid or too complex pattern skipped: ' . substr($pattern, 0, 200));
            }
            return false;
        }
        return $result;
    }

    /**
     * Legitime CMS-URLs (streng verankert auf den Pfad, Query nur aus harmlosen Zeichen).
     */
    private static function isLegitimateUrl(string $uri): bool
    {
        $parts = parse_url($uri);
        if ($parts === false) {
            return false;
        }
        $path = rawurldecode((string) ($parts['path'] ?? ''));
        $query = (string) ($parts['query'] ?? '');

        if ($query !== '' && !preg_match('/^[a-zA-Z0-9_=&\-.%]{0,200}$/', $query)) {
            return false;
        }

        $legitimatePaths = [
            '~^/[0-9]+-[0-9]+-[\p{L}\p{N}_\-.]*\.html$~u',   // /3938-0-Regionalkonferenz.html
            '~^/[0-9]+-[a-zA-Z0-9_\-]+\.html$~',              // /12-artikel.html
        ];
        foreach ($legitimatePaths as $pattern) {
            if (preg_match($pattern, $path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Behandelt erkannte Bedrohungen
     *
     * @param array<string, mixed> $threat
     */
    private static function handleThreat(array $threat, string $ip, string $uri, string $userAgent): void
    {
        $isNew = self::logThreat($threat, $ip, $uri, $userAgent);

        self::callExternalLogging($threat, $ip, $uri, $userAgent, $isNew);

        if (self::isMonitorOnlyMode()) {
            self::debugLog("IPS: Monitor-Only mode - threat logged but not blocked: {$threat['type']} from {$ip}");
            return;
        }

        if (($threat['category'] ?? '') === 'immediate_block') {
            self::blockIpPermanently($ip, 'Malicious activity detected - permanent block');
            self::blockRequest('Malicious activity detected', $ip, $uri);
        }

        switch ($threat['severity']) {
            case 'critical':
                self::blockIpPermanently($ip, 'Critical threat detected - permanent block');
                self::blockRequest('Critical threat detected', $ip, $uri);
                // no break (blockRequest beendet den Request)
            case 'high':
                self::blockIpTemporarily($ip, 3600);
                self::blockRequest('High threat detected', $ip, $uri);
                // no break
            case 'medium':
                if (self::getViolationCount($ip) >= 3) {
                    self::blockIpTemporarily($ip, 1800);
                    self::blockRequest('Repeated violations', $ip, $uri);
                }
                break;
            default:
                break;
        }
    }

    /**
     * Meldet eine Bedrohung aus einem anderen Modul (Formularschutz, Mail-Filter).
     * Loggt immer; eskaliert nur bei aktivem IPS ohne Monitor-Only-Modus.
     * Beendet den Request nicht – die Sperre greift ab dem nächsten Request.
     *
     * critical: 24 h Sperre, high: 1 h Sperre, medium: ab 3 Verstößen in 24 h 30 min Sperre, low: nur Log.
     */
    public static function reportExternalThreat(string $type, string $severity, string $details, ?string $ip = null): void
    {
        try {
            $ip ??= ClientIp::get();
            if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
                return;
            }
            $severity = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $severity : 'medium';
            $type = substr(preg_replace('/[^a-z0-9_\-]/i', '_', $type) ?? 'external', 0, 100);

            $threat = [
                'type' => $type,
                'category' => 'external',
                'pattern' => substr($details, 0, 500),
                'severity' => $severity,
            ];
            $uri = rex_server('REQUEST_URI', 'string', '');
            $userAgent = rex_server('HTTP_USER_AGENT', 'string', '');

            $isNew = self::logThreat($threat, $ip, $uri, $userAgent);
            self::callExternalLogging($threat, $ip, $uri, $userAgent, $isNew);

            if (!self::isActive() || self::isMonitorOnlyMode() || self::isOnPositivliste($ip) || self::isBlocked($ip)) {
                return;
            }

            switch ($severity) {
                case 'critical':
                    self::blockIpTemporarily($ip, 86400, 'External report: ' . $type, 'external');
                    break;
                case 'high':
                    self::blockIpTemporarily($ip, 3600, 'External report: ' . $type, 'external');
                    break;
                case 'medium':
                    if (self::getViolationCount($ip) >= 3) {
                        self::blockIpTemporarily($ip, 1800, 'Repeated violations: ' . $type, 'external');
                    }
                    break;
            }
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }
    }

    /**
     * Extension Point für externes Logging (fail2ban, Grafana, Mail-Reporting, etc.)
     *
     * @param array<string, mixed> $threat
     */
    private static function callExternalLogging(array $threat, string $ip, string $uri, string $userAgent, bool $isNew = true): void
    {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'uri' => substr($uri, 0, 2000),
            'user_agent' => substr($userAgent, 0, 500),
            'method' => rex_server('REQUEST_METHOD', 'string', 'GET'),
            'threat_type' => $threat['type'],
            'threat_category' => $threat['category'] ?? $threat['type'],
            'pattern' => $threat['pattern'],
            'severity' => $threat['severity'],
            'action' => self::getActionForSeverity($threat['severity']),
            'monitor_only' => self::isMonitorOnlyMode(),
            'first_in_window' => $isNew,
        ];

        try {
            rex_extension::registerPoint(new rex_extension_point('UPKEEP_IPS_THREAT_DETECTED', $logData));
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }

        if (self::getAddon()->getConfig('ips_fail2ban_logging', false)) {
            self::logForFail2ban($logData);
        }
    }

    /**
     * Fail2ban-kompatibles Logging. Die Logdatei liegt immer in rex_path::log().
     *
     * @param array<string, mixed> $logData
     */
    private static function logForFail2ban(array $logData): void
    {
        $logFile = self::getFail2banLogFile();

        $clean = static fn ($v): string => str_replace(["\r", "\n"], ' ', (string) $v);
        $message = sprintf(
            '%s [REDAXO-IPS] %s threat from %s: %s (URI: %s, Pattern: %s, Action: %s)',
            $logData['timestamp'],
            strtoupper((string) $logData['severity']),
            $logData['ip'],
            $clean($logData['threat_type']),
            $clean($logData['uri']),
            $clean($logData['pattern']),
            $logData['action'],
        );

        try {
            rex_extension::registerPoint(new rex_extension_point('UPKEEP_IPS_FAIL2BAN_LOG', [
                'message' => $message,
                'logFile' => $logFile,
                'logData' => $logData,
            ]));

            // Größe begrenzen (10 MB), dann rotieren
            if (is_file($logFile) && filesize($logFile) > 10 * 1024 * 1024) {
                @rename($logFile, $logFile . '.1');
            }
            if (is_dir(dirname($logFile)) && is_writable(dirname($logFile))) {
                @file_put_contents($logFile, $message . "\n", FILE_APPEND | LOCK_EX);
            }
        } catch (Throwable $e) {
            self::debugLog('IPS: Failed to write fail2ban log: ' . $e->getMessage());
        }
    }

    /**
     * Pfad der fail2ban-Logdatei (nur innerhalb von rex_path::log()).
     */
    public static function getFail2banLogFile(): string
    {
        $configured = (string) self::getAddon()->getConfig('ips_fail2ban_logfile', '');
        $name = basename($configured);
        if ($name === '' || !preg_match('/^[a-zA-Z0-9_\-.]+\.log$/', $name)) {
            $name = 'upkeep_ips.log';
        }
        return rex_path::log($name);
    }

    /**
     * Holt die letzten IPs aus Threat-Logs für schnelle manuelle Blockierung
     *
     * @return list<array<string, mixed>>
     */
    public static function getRecentThreatIps(int $limit = 10): array
    {
        try {
            $hits = self::hitExpression();
            $sql = rex_sql::factory();
            $sql->setQuery('
                SELECT
                    t.ip_address,
                    SUM(' . $hits . ') as threat_count,
                    MAX(t.created_at) as last_threat,
                    MAX(t.severity) as max_severity,
                    SUBSTRING_INDEX(GROUP_CONCAT(DISTINCT t.threat_type ORDER BY t.created_at DESC), ",", 3) as recent_threats
                FROM ' . rex::getTable('upkeep_ips_threat_log') . ' t
                LEFT JOIN ' . rex::getTable('upkeep_ips_blocked_ips') . ' b
                    ON b.ip_address = t.ip_address AND (b.expires_at IS NULL OR b.expires_at > NOW())
                WHERE t.created_at >= ? AND b.id IS NULL
                GROUP BY t.ip_address
                ORDER BY threat_count DESC, last_threat DESC
                LIMIT ' . max(1, min(100, $limit)), [date('Y-m-d H:i:s', time() - 86400)]);

            $threatIps = [];
            foreach ($sql as $row) {
                $threatIps[] = [
                    'ip' => (string) $row->getValue('ip_address'),
                    'threat_count' => (int) $row->getValue('threat_count'),
                    'last_threat' => $row->getValue('last_threat'),
                    'max_severity' => $row->getValue('max_severity'),
                    'recent_threats' => array_filter(explode(',', (string) $row->getValue('recent_threats'))),
                ];
            }
            return $threatIps;
        } catch (Throwable $e) {
            self::debugLog('Failed to get recent threat IPs: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Prüft ob Monitor-Only Modus aktiv ist
     */
    public static function isMonitorOnlyMode(): bool
    {
        return (bool) self::getAddon()->getConfig('ips_monitor_only', false);
    }

    /**
     * Öffentliche Methode zum Anzeigen der Sperrseite (für externe Aufrufe)
     */
    public static function showBlockedPage(string $reason, string $ip = ''): void
    {
        self::blockRequest($reason, $ip !== '' ? $ip : ClientIp::get(), rex_server('REQUEST_URI', 'string', ''));
    }

    /**
     * Blockiert den Request und zeigt die Sperrseite (BlockPage mit ALTCHA-Selbstentsperrung).
     */
    private static function blockRequest(string $reason, string $ip, string $uri): never
    {
        if (class_exists(BlockPage::class) && method_exists(BlockPage::class, 'send')) {
            try {
                BlockPage::send($reason);
            } catch (Throwable $e) {
                self::exceptionLog($e);
            }
        }

        // Fallback: schlichte 403-Seite
        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate');
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');
            header('X-Robots-Tag: noindex, nofollow');
        }
        echo "403 Forbidden\n\nYour request has been blocked by the security system.\nIhre Anfrage wurde vom Sicherheitssystem blockiert.\n";
        exit;
    }

    /**
     * Prüft ob IPS aktiviert ist
     */
    public static function isActive(): bool
    {
        return (bool) self::getAddon()->getConfig('ips_active', false);
    }

    /**
     * Prüft ob Rate-Limiting aktiviert ist
     */
    public static function isRateLimitingEnabled(): bool
    {
        return (bool) self::getAddon()->getConfig('ips_rate_limiting_enabled', false);
    }

    // ------------------------------------------------------------------
    // Positivliste / Sperrliste
    // ------------------------------------------------------------------

    /**
     * Öffentliche Prüfung: steht die IP auf der Positivliste (inkl. Wartungs-IPs)?
     */
    public static function isIpAllowlisted(string $ip): bool
    {
        try {
            return self::isOnPositivliste($ip);
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Öffentliche Prüfung: ist die IP gesperrt?
     */
    public static function isIpBlocked(string $ip): bool
    {
        try {
            return self::isBlocked($ip);
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Prüft ob IP in der Positivliste steht (gecacht)
     */
    private static function isOnPositivliste(string $ip): bool
    {
        if (isset(self::$allowCache[$ip])) {
            return self::$allowCache[$ip];
        }

        // Erlaubte IPs des Wartungsmodus (Komma oder Zeilenumbruch getrennt)
        $allowedIps = (string) self::getAddon()->getConfig('allowed_ips', '');
        if ($allowedIps !== '' && ClientIp::inList($ip, $allowedIps)) {
            return self::$allowCache[$ip] = true;
        }

        $now = time();
        $lists = self::getListCache();
        foreach ($lists['positive'] as $entry) {
            if ($entry['exp'] !== 0 && $entry['exp'] < $now) {
                continue;
            }
            if (($entry['ip'] !== '' && ClientIp::inList($ip, [$entry['ip']]))
                || ($entry['range'] !== '' && ClientIp::inList($ip, [$entry['range']]))) {
                return self::$allowCache[$ip] = true;
            }
        }

        return self::$allowCache[$ip] = false;
    }

    /**
     * Prüft ob IP gesperrt ist (exakt per Index, CIDR-Bereiche aus dem Cache)
     */
    private static function isBlocked(string $ip): bool
    {
        if (isset(self::$blockedCache[$ip])) {
            return self::$blockedCache[$ip];
        }

        $sql = rex_sql::factory();
        $sql->setQuery(
            'SELECT 1 FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1',
            [$ip],
        );
        if ($sql->getRows() > 0) {
            return self::$blockedCache[$ip] = true;
        }

        $now = time();
        foreach (self::getListCache()['blocked_cidr'] as $entry) {
            if ($entry['exp'] !== 0 && $entry['exp'] < $now) {
                continue;
            }
            if (ClientIp::inCidr($ip, $entry['cidr'])) {
                return self::$blockedCache[$ip] = true;
            }
        }

        return self::$blockedCache[$ip] = false;
    }

    /**
     * Cache für Positivliste und CIDR-Sperren (Datei, 5 Minuten, bei Änderungen invalidiert).
     *
     * @return array{positive: list<array{ip: string, range: string, exp: int}>, blocked_cidr: list<array{cidr: string, exp: int}>}
     */
    private static function getListCache(): array
    {
        if (self::$listCache !== null) {
            return self::$listCache;
        }

        $file = self::listCacheFile();
        if (is_file($file) && (time() - (int) @filemtime($file)) < self::LIST_CACHE_TTL) {
            $data = json_decode((string) @file_get_contents($file), true);
            if (is_array($data) && isset($data['positive'], $data['blocked_cidr'])) {
                return self::$listCache = $data;
            }
        }

        $data = ['positive' => [], 'blocked_cidr' => []];
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT ip_address, ip_range, expires_at FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE status = 1 AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 5000');
            foreach ($sql as $row) {
                $data['positive'][] = [
                    'ip' => trim((string) $row->getValue('ip_address')),
                    'range' => trim((string) $row->getValue('ip_range')),
                    'exp' => $row->getValue('expires_at') ? (int) strtotime((string) $row->getValue('expires_at')) : 0,
                ];
            }
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT ip_address, expires_at FROM ' . rex::getTable('upkeep_ips_blocked_ips') . " WHERE ip_address LIKE '%/%' AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 5000");
            foreach ($sql as $row) {
                $data['blocked_cidr'][] = [
                    'cidr' => trim((string) $row->getValue('ip_address')),
                    'exp' => $row->getValue('expires_at') ? (int) strtotime((string) $row->getValue('expires_at')) : 0,
                ];
            }
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }

        try {
            rex_file::put($file, (string) json_encode($data));
        } catch (Throwable) {
            // Cache optional
        }

        return self::$listCache = $data;
    }

    private static function listCacheFile(): string
    {
        return rex_path::addonCache('upkeep', 'ips_lists.json');
    }

    /**
     * Verwirft alle Caches (nach Änderungen an Positiv- oder Sperrliste).
     */
    public static function invalidateCache(): void
    {
        self::$listCache = null;
        self::$blockedCache = [];
        self::$allowCache = [];
        try {
            $file = self::listCacheFile();
            if (is_file($file)) {
                @unlink($file);
            }
        } catch (Throwable) {
        }
    }

    // ------------------------------------------------------------------
    // Patterns
    // ------------------------------------------------------------------

    /**
     * Bestimmt Schweregrad basierend auf Kategorie
     */
    private static function getSeverityForCategory(string $category): string
    {
        if ($category === '') {
            return 'medium';
        }

        return match ($category) {
            'immediate_block' => 'critical',
            'shells', 'sql_injection' => 'critical',
            'path_traversal', 'config_files' => 'high',
            'wordpress', 'typo3', 'drupal', 'joomla', 'admin_panels' => 'medium',
            'info_disclosure' => 'low',
            default => 'medium',
        };
    }

    /**
     * Holt benutzerdefinierte Patterns (pro Request gecacht, fail open)
     *
     * @return list<array<string, mixed>>
     */
    public static function getCustomPatterns(): array
    {
        static $patterns = null;

        if ($patterns === null) {
            $patterns = [];
            try {
                $sql = rex_sql::factory();
                $sql->setQuery('SELECT pattern, description, severity, is_regex FROM ' . rex::getTable('upkeep_ips_custom_patterns') . ' WHERE status = 1');
                foreach ($sql as $row) {
                    $patterns[] = [
                        'pattern' => (string) $row->getValue('pattern'),
                        'description' => $row->getValue('description'),
                        'severity' => $row->getValue('severity'),
                        'is_regex' => (bool) $row->getValue('is_regex'),
                    ];
                }
            } catch (Throwable $e) {
                self::exceptionLog($e);
                $patterns = [];
            }
        }

        return $patterns;
    }

    /**
     * Holt Standard-Patterns aus der Datenbank (pro Request gecacht, fail open)
     *
     * @return list<array<string, mixed>>
     */
    public static function getDefaultPatterns(): array
    {
        static $patterns = null;

        if ($patterns === null) {
            $patterns = [];
            try {
                $sql = rex_sql::factory();
                $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_default_patterns') . ' WHERE status = 1 ORDER BY category, pattern');
                foreach ($sql as $row) {
                    $patterns[] = [
                        'id' => (int) $row->getValue('id'),
                        'category' => (string) $row->getValue('category'),
                        'pattern' => (string) $row->getValue('pattern'),
                        'description' => $row->getValue('description'),
                        'severity' => (string) $row->getValue('severity'),
                        'is_regex' => (bool) $row->getValue('is_regex'),
                        'is_default' => (bool) $row->getValue('is_default'),
                    ];
                }
            } catch (Throwable $e) {
                self::exceptionLog($e);
                $patterns = [];
            }
        }

        return $patterns;
    }

    // ------------------------------------------------------------------
    // Rate Limiting und Bot-Erkennung
    // ------------------------------------------------------------------

    /**
     * Prüft Rate Limiting
     */
    private static function isRateLimitExceeded(string $ip): bool
    {
        if (!self::isRateLimitingEnabled()) {
            return false;
        }

        try {
            self::updateRateLimit($ip);

            $sql = rex_sql::factory();
            $sql->setQuery(
                'SELECT SUM(request_count) as total FROM ' . rex::getTable('upkeep_ips_rate_limit') . ' WHERE ip_address = ? AND window_start >= ?',
                [$ip, date('Y-m-d H:i:s', time() - 60)],
            );
            $requestCount = (int) $sql->getValue('total');
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }

        $burstLimit = max(10, (int) self::getAddon()->getConfig('ips_burst_limit', 600));
        $strictLimit = max(10, (int) self::getAddon()->getConfig('ips_strict_limit', 200));
        $effectiveLimit = self::getEffectiveLimitForUri(rex_server('REQUEST_URI', 'string', ''), $burstLimit, $strictLimit);

        if ($requestCount < $effectiveLimit) {
            return false;
        }

        // Erst bei Erreichen des Limits prüfen, ob es ein verifizierter guter Bot ist (teure DNS-Prüfung)
        if (self::isGoodBot() && $requestCount < $effectiveLimit * 2) {
            return false;
        }

        return true;
    }

    /**
     * Bestimmt effektive Rate-Limits basierend auf URI
     */
    private static function getEffectiveLimitForUri(string $uri, int $defaultLimit, int $strictLimit): int
    {
        $strictPaths = ['/wp-admin/', '/wp-login.php', '/admin/', '/login', '/phpmyadmin/', '/pma/', '/xmlrpc.php'];
        $apiPaths = ['/api/', '/wp-json/', '/jsonapi/', '/graphql'];
        $staticPaths = [
            '/assets/', '/media/', '/css/', '/js/', '/images/', '/img/',
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.pdf',
        ];

        foreach ($strictPaths as $path) {
            if (stripos($uri, $path) !== false) {
                return $strictLimit;
            }
        }
        foreach ($staticPaths as $path) {
            if (stripos($uri, $path) !== false) {
                return (int) ($defaultLimit * 1.5);
            }
        }
        foreach ($apiPaths as $path) {
            if (stripos($uri, $path) !== false) {
                return (int) ($defaultLimit * 0.8);
            }
        }
        return $defaultLimit;
    }

    /**
     * Erkennt gute/legitime Bots (Google, Bing, etc.)
     */
    private static function isGoodBot(): bool
    {
        $userAgent = rex_server('HTTP_USER_AGENT', 'string', '');
        if ($userAgent === '') {
            return false;
        }

        $goodBots = [
            'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider', 'YandexBot',
            'facebookexternalhit', 'Twitterbot', 'LinkedInBot', 'WhatsApp', 'Applebot',
            'SemrushBot', 'AhrefsBot', 'MJ12bot', 'DotBot',
        ];

        foreach ($goodBots as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                if (in_array($bot, ['Googlebot', 'Bingbot'], true)) {
                    return self::verifyGoogleBot();
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Verifiziert Google/Bing Bot per Reverse- und Forward-DNS.
     * Ergebnis im Datei-Cache (max. 1000 Einträge), höchstens ein Lookup pro Request.
     */
    private static function verifyGoogleBot(): bool
    {
        $ip = ClientIp::get();
        $store = new JsonStore('dns_verify', 1000);

        $cached = $store->get($ip);
        if (is_bool($cached)) {
            return $cached;
        }

        if (self::$dnsLookups >= 1) {
            return false;
        }
        ++self::$dnsLookups;

        $verified = false;
        $hostname = self::reverseDnsLookup($ip);
        if ($hostname !== null && preg_match('/\.(googlebot\.com|google\.com|search\.msn\.com)$/i', $hostname)) {
            $verified = self::forwardDnsLookup($hostname) === $ip;
        }

        $store->set($ip, $verified, $verified ? 86400 : 3600);
        return $verified;
    }

    /**
     * Reverse DNS Lookup
     */
    private static function reverseDnsLookup(string $ip): ?string
    {
        try {
            if (function_exists('dns_get_record')) {
                $ptr = self::reversePtrName($ip);
                if ($ptr !== null) {
                    set_error_handler(static fn (): bool => true);
                    try {
                        $records = dns_get_record($ptr, DNS_PTR);
                    } finally {
                        restore_error_handler();
                    }
                    if (!empty($records[0]['target'])) {
                        $hostname = rtrim((string) $records[0]['target'], '.');
                        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                            return $hostname;
                        }
                    }
                    return null;
                }
            }

            set_error_handler(static fn (): bool => true);
            try {
                $hostname = gethostbyaddr($ip);
            } finally {
                restore_error_handler();
            }
            if ($hostname && $hostname !== $ip && filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                return $hostname;
            }
        } catch (Throwable $e) {
            self::debugLog("DNS Lookup Error für IP $ip: " . $e->getMessage());
        }

        return null;
    }

    private static function reversePtrName(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        }
        $bin = @inet_pton($ip);
        if ($bin !== false && strlen($bin) === 16) {
            $hex = bin2hex($bin);
            return implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
        }
        return null;
    }

    /**
     * Forward DNS Lookup
     */
    private static function forwardDnsLookup(string $hostname): ?string
    {
        try {
            if (function_exists('dns_get_record')) {
                set_error_handler(static fn (): bool => true);
                try {
                    $records = dns_get_record($hostname, DNS_A | DNS_AAAA);
                } finally {
                    restore_error_handler();
                }
                $ip = ClientIp::get();
                foreach ((array) $records as $record) {
                    $candidate = $record['ip'] ?? $record['ipv6'] ?? null;
                    if ($candidate !== null && @inet_pton($candidate) === @inet_pton($ip)) {
                        return $ip;
                    }
                }
                return null;
            }

            set_error_handler(static fn (): bool => true);
            try {
                $ip = gethostbyname($hostname);
            } finally {
                restore_error_handler();
            }
            if ($ip !== $hostname && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        } catch (Throwable $e) {
            self::debugLog("Forward DNS Lookup Error für Hostname $hostname: " . $e->getMessage());
        }

        return null;
    }

    /**
     * Aktualisiert Rate Limiting Counter (ohne Bereinigung – die läuft über cleanupExpiredData)
     */
    private static function updateRateLimit(string $ip): void
    {
        $windowStart = date('Y-m-d H:i:00');
        $sql = rex_sql::factory();
        $sql->setQuery(
            'UPDATE ' . rex::getTable('upkeep_ips_rate_limit') . ' SET request_count = request_count + 1, last_request = NOW() WHERE ip_address = ? AND window_start = ?',
            [$ip, $windowStart],
        );

        if ($sql->getRows() === 0) {
            $sql->setTable(rex::getTable('upkeep_ips_rate_limit'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('request_count', 1);
            $sql->setValue('window_start', $windowStart);
            $sql->setValue('last_request', date('Y-m-d H:i:s'));
            $sql->insert();
        }
    }

    // ------------------------------------------------------------------
    // Sperren und Protokoll
    // ------------------------------------------------------------------

    /**
     * Sperrt IP permanent
     */
    private static function blockIpPermanently(string $ip, string $reason = 'Critical threat detected - permanent block'): void
    {
        self::insertBlock($ip, 'permanent', null, $reason, 'critical');
    }

    /**
     * Sperrt IP temporär
     */
    private static function blockIpTemporarily(string $ip, int $seconds, string $reason = '', string $source = 'auto'): void
    {
        $expiresAt = date('Y-m-d H:i:s', time() + $seconds);
        self::insertBlock($ip, 'temporary', $expiresAt, $reason !== '' ? $reason : "Temporary block for {$seconds} seconds", 'high', $source);
    }

    private static function hasBlockSourceColumn(): bool
    {
        static $has = null;
        if ($has === null) {
            try {
                $has = rex_sql_table::get(rex::getTable('upkeep_ips_blocked_ips'))->hasColumn('source');
            } catch (Throwable) {
                $has = false;
            }
        }
        return $has;
    }

    private static function insertBlock(string $ip, string $type, ?string $expiresAt, string $reason, string $level, string $source = 'auto'): void
    {
        try {
            if (self::isBlocked($ip)) {
                return;
            }
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_blocked_ips'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('block_type', $type);
            $sql->setValue('expires_at', $expiresAt);
            $sql->setValue('reason', substr($reason, 0, 1000));
            $sql->setValue('threat_level', $level);
            if (self::hasBlockSourceColumn()) {
                $sql->setValue('source', $source);
            }
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();
            self::$blockedCache[$ip] = true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }
    }

    /**
     * Holt Anzahl der Verstöße für IP (24 h, inkl. zusammengefasster Treffer)
     */
    private static function getViolationCount(string $ip): int
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery(
                'SELECT SUM(' . self::hitExpression() . ') as count FROM ' . rex::getTable('upkeep_ips_threat_log') . ' WHERE ip_address = ? AND created_at >= ?',
                [$ip, date('Y-m-d H:i:s', time() - 86400)],
            );
            return (int) $sql->getValue('count');
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return 0;
        }
    }

    /**
     * Loggt Bedrohung. Gleichartige Ereignisse (IP + Typ + Pattern) innerhalb von
     * 10 Minuten werden zusammengefasst (hit_count). Pro IP höchstens 200 neue Zeilen pro Stunde.
     *
     * @param array<string, mixed> $threat
     * @return bool true wenn eine neue Zeile angelegt wurde
     */
    private static function logThreat(array $threat, string $ip, string $uri, string $userAgent): bool
    {
        $table = rex::getTable('upkeep_ips_threat_log');
        $pattern = substr((string) ($threat['pattern'] ?? ''), 0, 500);
        $type = substr((string) $threat['type'], 0, 100);

        try {
            if (self::$aggregation !== false) {
                try {
                    $sql = rex_sql::factory();
                    $sql->setQuery(
                        'UPDATE ' . $table . ' SET hit_count = hit_count + 1, last_seen = NOW() WHERE ip_address = ? AND threat_type = ? AND pattern_matched = ? AND created_at >= ? ORDER BY id DESC LIMIT 1',
                        [$ip, $type, $pattern, date('Y-m-d H:i:s', time() - self::AGGREGATE_WINDOW)],
                    );
                    self::$aggregation = true;
                    if ($sql->getRows() > 0) {
                        return false;
                    }
                } catch (Throwable) {
                    // Spalte hit_count fehlt noch (Update nicht gelaufen) – ohne Zusammenfassung weiter
                    self::$aggregation = false;
                }
            }

            // Obergrenze neuer Zeilen pro IP und Stunde
            $rows = (new JsonStore('threat_log_cap', 5000))->increment('ip:' . $ip . ':' . date('YmdH'), 3600);
            if ($rows > self::LOG_ROWS_PER_IP_HOUR) {
                return false;
            }

            $sql = rex_sql::factory();
            $sql->setTable($table);
            $sql->setValue('ip_address', $ip);
            $sql->setValue('request_uri', substr($uri, 0, 2000));
            $sql->setValue('user_agent', substr($userAgent, 0, 500));
            $sql->setValue('threat_type', $type);
            $sql->setValue('threat_category', substr((string) ($threat['category'] ?? $threat['type']), 0, 100));
            $sql->setValue('pattern_matched', $pattern);
            $sql->setValue('severity', $threat['severity']);
            $sql->setValue('action_taken', self::getActionForSeverity((string) $threat['severity']));
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            if (self::$aggregation === true) {
                $sql->setValue('last_seen', date('Y-m-d H:i:s'));
            }
            $sql->insert();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * SQL-Ausdruck für die Trefferzahl einer Log-Zeile (mit/ohne hit_count-Spalte)
     */
    private static function hitExpression(): string
    {
        static $expr = null;
        if ($expr === null) {
            $expr = '1';
            try {
                if (rex_sql_table::get(rex::getTable('upkeep_ips_threat_log'))->hasColumn('hit_count')) {
                    $expr = 'COALESCE(hit_count, 1)';
                }
            } catch (Throwable) {
            }
        }
        return $expr;
    }

    /**
     * Bestimmt Aktion basierend auf Schweregrad
     */
    private static function getActionForSeverity(string $severity): string
    {
        if (self::isMonitorOnlyMode()) {
            return 'logged';
        }
        return match ($severity) {
            'critical' => 'permanent_block',
            'high' => 'temporary_block',
            default => 'logged',
        };
    }


    // ------------------------------------------------------------------
    // Verwaltung (Backend)
    // ------------------------------------------------------------------

    /**
     * Fügt Custom Pattern hinzu (RegEx wird validiert)
     */
    public static function addCustomPattern(string $pattern, string $description = '', string $severity = 'medium', bool $isRegex = false): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '' || ($isRegex && !PatternValidator::isValid($pattern))) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('severity', self::normalizeSeverity($severity));
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Aktualisiert ein Custom Pattern (RegEx wird validiert)
     */
    public static function updateCustomPattern(int $id, string $pattern, string $description, string $severity, bool $isRegex, bool $status): bool
    {
        $pattern = trim($pattern);
        if ($id <= 0 || $pattern === '' || ($isRegex && !PatternValidator::isValid($pattern))) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('severity', self::normalizeSeverity($severity));
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', $status ? 1 : 0);
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->setWhere(['id' => $id]);
            $sql->update();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Entfernt Custom Pattern
     */
    public static function removeCustomPattern(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
            $sql->setWhere(['id' => $id]);
            $sql->delete();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Aktualisiert ein Default-Pattern (RegEx wird validiert)
     */
    public static function updateDefaultPattern(int $id, string $pattern, string $description, string $severity, bool $isRegex, bool $status): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '' || ($isRegex && !PatternValidator::isValid($pattern))) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_default_patterns'));
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('severity', self::normalizeSeverity($severity));
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', $status ? 1 : 0);
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->setWhere(['id' => $id]);
            $sql->update();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Schaltet den Status eines Default-Patterns um
     */
    public static function toggleDefaultPatternStatus(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('UPDATE ' . rex::getTable('upkeep_ips_default_patterns') . ' SET status = 1 - status, updated_at = NOW() WHERE id = ?', [$id]);
            return $sql->getRows() > 0;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Lädt ein Default-Pattern für die Bearbeitung
     *
     * @return array<string, mixed>|null
     */
    public static function getDefaultPattern(int $id): ?array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_default_patterns') . ' WHERE id = ?', [$id]);
            if ($sql->getRows() > 0) {
                return [
                    'id' => (int) $sql->getValue('id'),
                    'category' => $sql->getValue('category'),
                    'pattern' => $sql->getValue('pattern'),
                    'description' => $sql->getValue('description'),
                    'severity' => $sql->getValue('severity'),
                    'is_regex' => (bool) $sql->getValue('is_regex'),
                    'status' => (bool) $sql->getValue('status'),
                    'is_default' => (bool) $sql->getValue('is_default'),
                    'created_at' => $sql->getValue('created_at'),
                    'updated_at' => $sql->getValue('updated_at'),
                ];
            }
            return null;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return null;
        }
    }

    /**
     * Fügt IP zur Positivliste hinzu
     */
    public static function addToPositivliste(string $ip, string $description = '', string $category = 'trusted', ?string $ipRange = null): bool
    {
        $ip = trim($ip);
        $ipRange = $ipRange !== null ? trim($ipRange) : null;
        if (($ip === '' || !ClientIp::isValidEntry($ip)) && ($ipRange === null || $ipRange === '' || !ClientIp::isValidEntry($ipRange))) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('ip_range', $ipRange ?: null);
            $sql->setValue('description', substr($description, 0, 255));
            $sql->setValue('category', substr($category, 0, 50));
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            self::invalidateCache();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Fügt IP temporär zur Positivliste hinzu (mit Ablaufzeit)
     */
    public static function addToTemporaryPositivliste(string $ip, int $durationHours = 24, string $description = '', string $category = 'captcha_verified_temp'): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $durationHours = max(1, min(24 * 30, $durationHours));
        try {
            $expiresAt = (new DateTime())->modify("+{$durationHours} hours")->format('Y-m-d H:i:s');
            $fullDescription = substr(trim($description . " (Temporär bis {$expiresAt})"), 0, 255);

            $sql = rex_sql::factory();
            $sql->setQuery('SELECT id, expires_at FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE ip_address = ?', [$ip]);

            if ($sql->getRows() > 0) {
                // Permanente Einträge nicht in temporäre umwandeln
                if ($sql->getValue('expires_at') === null) {
                    self::invalidateCache();
                    return true;
                }
                $id = (int) $sql->getValue('id');
                $update = rex_sql::factory();
                $update->setTable(rex::getTable('upkeep_ips_positivliste'));
                $update->setValue('description', $fullDescription);
                $update->setValue('category', substr($category, 0, 50));
                $update->setValue('expires_at', $expiresAt);
                $update->setValue('status', 1);
                $update->setValue('updated_at', date('Y-m-d H:i:s'));
                $update->setWhere(['id' => $id]);
                $update->update();
            } else {
                $insert = rex_sql::factory();
                $insert->setTable(rex::getTable('upkeep_ips_positivliste'));
                $insert->setValue('ip_address', $ip);
                $insert->setValue('description', $fullDescription);
                $insert->setValue('category', substr($category, 0, 50));
                $insert->setValue('expires_at', $expiresAt);
                $insert->setValue('status', 1);
                $insert->setValue('created_at', date('Y-m-d H:i:s'));
                $insert->setValue('updated_at', date('Y-m-d H:i:s'));
                $insert->insert();
            }

            self::invalidateCache();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Entfernt IP aus Positivliste
     */
    public static function removeFromPositivliste(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE id = ?', [$id]);
            self::invalidateCache();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Holt alle Positivliste-Einträge
     *
     * @return list<array<string, mixed>>
     */
    public static function getPositivlisteEntries(): array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_positivliste') . ' ORDER BY created_at DESC');
            return $sql->getArray();
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return [];
        }
    }

    /**
     * Aktualisiert Positivliste-Eintrag (nur erlaubte Spalten)
     *
     * @param array<string, mixed> $data
     */
    public static function updatePositivlisteEntry(int $id, array $data): bool
    {
        $allowed = ['ip_address', 'ip_range', 'description', 'category', 'expires_at', 'status'];
        $data = array_intersect_key($data, array_flip($allowed));
        if ($id <= 0 || $data === []) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
            foreach ($data as $key => $value) {
                $sql->setValue($key, $value);
            }
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->setWhere(['id' => $id]);
            $sql->update();
            self::invalidateCache();
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Entsperrt IP-Adresse (bzw. CIDR-Eintrag)
     */
    public static function unblockIp(string $ip): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE ip_address = ?', [$ip]);
            $deletedRows = $sql->getRows();
            self::invalidateCache();

            if ($deletedRows > 0 && self::getAddon()->getConfig('ips_debug_mode', false)) {
                self::systemLog('info', "IPS: IP {$ip} unblocked - removed {$deletedRows} entries");
            }
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Sperrt IP-Adresse oder IP-Bereich manuell
     *
     * @param string $ip IP-Adresse oder CIDR-Notation (z.B. 192.168.1.0/24)
     * @param string $duration Sperrdauer ('permanent', '1h', '6h', '24h', '7d', '30d')
     * @param string $reason Grund für die Sperrung
     * @param string $source Herkunft (manual = nicht per Selbst-Entsperrung aufhebbar)
     * @return array{success: bool, message: string, error_code: string|null}
     */
    public static function blockIpManually(string $ip, string $duration = 'permanent', string $reason = '', string $source = 'manual'): array
    {
        $ip = trim($ip);
        if ($ip === '') {
            return ['success' => false, 'message' => 'IP-Adresse ist erforderlich', 'error_code' => 'IP_REQUIRED'];
        }

        $isCidr = str_contains($ip, '/');
        if ($isCidr) {
            $validation = self::validateCidrRange($ip);
            if (!$validation['valid']) {
                return ['success' => false, 'message' => $validation['message'], 'error_code' => 'INVALID_CIDR_FORMAT'];
            }
        } elseif (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [
                'success' => false,
                'message' => 'Ungültiges IP-Adressformat. Bitte geben Sie eine gültige IPv4- oder IPv6-Adresse oder CIDR-Notation (z. B. 192.168.1.0/24) ein.',
                'error_code' => 'INVALID_IP_FORMAT',
            ];
        }

        $validDurations = ['permanent' => null, '1h' => 3600, '6h' => 21600, '24h' => 86400, '7d' => 604800, '30d' => 2592000];
        if (!array_key_exists($duration, $validDurations)) {
            return [
                'success' => false,
                'message' => 'Ungültige Sperrdauer. Erlaubte Werte: ' . implode(', ', array_keys($validDurations)),
                'error_code' => 'INVALID_DURATION',
            ];
        }

        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT block_type, expires_at FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1', [$ip]);
            if ($sql->getRows() > 0) {
                $existingExpiresAt = $sql->getValue('expires_at');
                $expiryInfo = $existingExpiresAt ? ' bis ' . date('d.m.Y H:i', (int) strtotime((string) $existingExpiresAt)) : ' permanent';
                return [
                    'success' => false,
                    'message' => "IP/Bereich {$ip} ist bereits gesperrt (" . $sql->getValue('block_type') . $expiryInfo . ').',
                    'error_code' => 'IP_ALREADY_BLOCKED',
                ];
            }

            if (!$isCidr && self::isOnPositivliste($ip)) {
                return [
                    'success' => false,
                    'message' => "IP {$ip} steht in der Positivliste und kann nicht gesperrt werden. Entfernen Sie sie zuerst aus der Positivliste.",
                    'error_code' => 'IP_IN_POSITIVLISTE',
                ];
            }

            $seconds = $validDurations[$duration];
            $expiresAt = $seconds === null ? null : date('Y-m-d H:i:s', time() + $seconds);
            $blockType = $seconds === null ? 'permanent' : 'temporary';

            if ($reason === '') {
                $reason = $isCidr ? 'Manuell gesperrter IP-Bereich durch Administrator' : 'Manuell gesperrt durch Administrator';
            }

            $insert = rex_sql::factory();
            $insert->setTable(rex::getTable('upkeep_ips_blocked_ips'));
            $insert->setValue('ip_address', $ip);
            $insert->setValue('block_type', $blockType);
            $insert->setValue('expires_at', $expiresAt);
            $insert->setValue('reason', substr($reason, 0, 1000));
            $insert->setValue('threat_level', 'high');
            if (self::hasBlockSourceColumn()) {
                $insert->setValue('source', in_array($source, ['auto', 'manual', 'external'], true) ? $source : 'manual');
            }
            $insert->setValue('created_at', date('Y-m-d H:i:s'));
            $insert->insert();
            self::invalidateCache();

            $typeDesc = $isCidr ? 'IP-Bereich' : 'IP';
            self::systemLog('info', "IPS: {$typeDesc} {$ip} manuell gesperrt" . ($expiresAt ? " bis {$expiresAt}" : ' permanent'));

            $successMessage = "{$typeDesc} {$ip} wurde erfolgreich gesperrt ({$blockType}";
            if ($expiresAt) {
                $successMessage .= ' bis ' . date('d.m.Y H:i', (int) strtotime($expiresAt));
            }
            $successMessage .= ').';

            return ['success' => true, 'message' => $successMessage, 'error_code' => null];
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return [
                'success' => false,
                'message' => 'Datenbankfehler beim Sperren der IP-Adresse/des IP-Bereichs. Details wurden geloggt.',
                'error_code' => 'DATABASE_ERROR',
            ];
        }
    }

    /**
     * Sperrt eine einzelne IP für eine frei wählbare Dauer in Sekunden (z. B. Mail-Filter).
     * Im Gegensatz zu blockIpManually() (feste Stufen 1h/6h/24h/…) ohne Rückmeldungstexte.
     * Positivliste und Monitor-Only-Modus werden respektiert; bestehende Sperren bleiben unverändert.
     * Quelle 'auto'/'external' erlaubt die Selbstentsperrung per ALTCHA, 'manual' nicht.
     */
    public static function blockIpForSeconds(string $ip, int $seconds, string $reason = '', string $source = 'auto'): bool
    {
        try {
            $ip = trim($ip);
            if (filter_var($ip, FILTER_VALIDATE_IP) === false || $seconds < 60) {
                return false;
            }
            if (self::isMonitorOnlyMode() || self::isOnPositivliste($ip) || self::isBlocked($ip)) {
                return false;
            }
            $source = in_array($source, ['auto', 'manual', 'external'], true) ? $source : 'auto';
            self::blockIpTemporarily($ip, min($seconds, 30 * 86400), $reason, $source);
            self::invalidateCache();
            return self::isBlocked($ip);
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Validiert CIDR-Notation
     *
     * @return array{valid: bool, message: string}
     */
    private static function validateCidrRange(string $cidr): array
    {
        $parts = explode('/', $cidr);
        if (count($parts) !== 2) {
            return ['valid' => false, 'message' => 'Ungültiges CIDR-Format. Erwartetes Format: IP/Prefix (z. B. 192.168.1.0/24)'];
        }
        [$ip, $prefix] = $parts;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return ['valid' => false, 'message' => 'Ungültige IP-Adresse in CIDR-Notation'];
        }
        if (!ctype_digit($prefix)) {
            return ['valid' => false, 'message' => 'CIDR-Prefix muss eine Zahl sein'];
        }
        $max = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 32 : 128;
        if ((int) $prefix > $max) {
            return ['valid' => false, 'message' => "CIDR-Prefix muss zwischen 0 und {$max} liegen"];
        }
        return ['valid' => true, 'message' => 'Gültige CIDR-Notation'];
    }

    /**
     * Verarbeitet Bulk-Import von IP-Listen
     *
     * @return array{success_count: int, error_count: int, skipped_count: int, errors: list<string>}
     */
    public static function processBulkIpImport(string $ipList, string $duration = '24h', string $reason = ''): array
    {
        $lines = preg_split('/\R/', trim($ipList)) ?: [];
        $results = ['success_count' => 0, 'error_count' => 0, 'skipped_count' => 0, 'errors' => []];

        if ($reason === '') {
            $reason = 'Bulk-Import (' . date('Y-m-d H:i') . ')';
        }

        foreach (array_slice($lines, 0, 5000) as $line) {
            $ip = trim($line);
            if ($ip === '' || $ip[0] === '#') {
                continue;
            }
            $result = self::blockIpManually($ip, $duration, $reason);
            if ($result['success']) {
                ++$results['success_count'];
            } elseif ($result['error_code'] === 'IP_ALREADY_BLOCKED' || $result['error_code'] === 'IP_IN_POSITIVLISTE') {
                ++$results['skipped_count'];
            } else {
                ++$results['error_count'];
                $results['errors'][] = "{$ip}: " . $result['message'];
            }
        }

        self::systemLog('info', "IPS Bulk Import: {$results['success_count']} erfolgreiche, {$results['error_count']} fehlerhafte, {$results['skipped_count']} übersprungene IPs");

        return $results;
    }

    /**
     * Backward compatibility wrapper for blockIpManually
     * @deprecated Use blockIpManually() which returns detailed result array
     */
    public static function blockIpManuallyLegacy(string $ip, string $duration = 'permanent', string $reason = ''): bool
    {
        return self::blockIpManually($ip, $duration, $reason)['success'];
    }

    /**
     * Löscht Bedrohungshistorie und Rate-Limit-Daten für eine IP (Rehabilitation)
     */
    public static function clearThreatHistory(string $ip): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_threat_log') . ' WHERE ip_address = ?', [$ip]);
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_rate_limit') . ' WHERE ip_address = ?', [$ip]);
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Debug-Methode: Zeigt alle Einträge für eine IP in allen IPS-Tabellen
     *
     * @return array<string, mixed>
     */
    public static function debugIpStatus(string $ip): array
    {
        $sql = rex_sql::factory();
        $debug = [];

        try {
            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE ip_address = ?', [$ip]);
            $debug['blocked_ips'] = $sql->getArray();

            $sql->setQuery("SELECT *, CASE WHEN expires_at IS NULL THEN 'permanent' WHEN expires_at > NOW() THEN 'active' ELSE 'expired' END as status_type FROM " . rex::getTable('upkeep_ips_positivliste') . ' WHERE ip_address = ?', [$ip]);
            $debug['positivliste'] = $sql->getArray();

            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_threat_log') . ' WHERE ip_address = ? ORDER BY created_at DESC LIMIT 10', [$ip]);
            $debug['threat_history'] = $sql->getArray();

            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_rate_limit') . ' WHERE ip_address = ?', [$ip]);
            $debug['rate_limits'] = $sql->getArray();

            $debug['maintenance_allowed'] = ClientIp::inList($ip, (string) self::getAddon()->getConfig('allowed_ips', ''));
            $debug['is_blocked'] = self::isBlocked($ip);
            $debug['is_allowlisted'] = self::isOnPositivliste($ip);
            $debug['rate_limit_config'] = [
                'enabled' => self::isRateLimitingEnabled(),
                'burst_limit' => self::getAddon()->getConfig('ips_burst_limit', 600),
                'strict_limit' => self::getAddon()->getConfig('ips_strict_limit', 200),
                'burst_window' => self::getAddon()->getConfig('ips_burst_window', 60),
            ];
        } catch (Throwable $e) {
            $debug['error'] = $e->getMessage();
        }

        return $debug;
    }

    /**
     * Setzt Rate-Limit-Konfiguration
     *
     * @param array<string, mixed> $config
     */
    public static function setRateLimitConfig(array $config): bool
    {
        try {
            $addon = self::getAddon();
            if (isset($config['burst_limit'])) {
                $addon->setConfig('ips_burst_limit', max(10, (int) $config['burst_limit']));
            }
            if (isset($config['strict_limit'])) {
                $addon->setConfig('ips_strict_limit', max(10, (int) $config['strict_limit']));
            }
            if (isset($config['burst_window'])) {
                $addon->setConfig('ips_burst_window', max(10, (int) $config['burst_window']));
            }
            return true;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Statistik
    // ------------------------------------------------------------------

    /**
     * Holt Statistiken für Backend (Datumsbereiche indexfreundlich)
     *
     * @return array{blocked_ips: int, threats_today: int, threats_week: int, top_threats: list<array{type: string, count: int}>}
     */
    public static function getStatistics(): array
    {
        static $stats = null;
        if ($stats !== null) {
            return $stats;
        }

        $stats = ['blocked_ips' => 0, 'threats_today' => 0, 'threats_week' => 0, 'top_threats' => []];
        $sql = rex_sql::factory();

        try {
            $sql->setQuery('SELECT COUNT(*) as count FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE expires_at IS NULL OR expires_at > NOW()');
            $stats['blocked_ips'] = (int) $sql->getValue('count');
        } catch (Throwable $e) {
            self::debugLog('Statistics: upkeep_ips_blocked_ips table not available: ' . $e->getMessage());
        }

        try {
            $hits = self::hitExpression();
            $table = rex::getTable('upkeep_ips_threat_log');
            $today = date('Y-m-d 00:00:00');
            $weekStart = date('Y-m-d 00:00:00', (int) strtotime('monday this week'));

            $sql->setQuery('SELECT SUM(' . $hits . ') as count FROM ' . $table . ' WHERE created_at >= ?', [$today]);
            $stats['threats_today'] = (int) $sql->getValue('count');

            $sql->setQuery('SELECT SUM(' . $hits . ') as count FROM ' . $table . ' WHERE created_at >= ?', [$weekStart]);
            $stats['threats_week'] = (int) $sql->getValue('count');

            $sql->setQuery('SELECT threat_type, SUM(' . $hits . ') as count FROM ' . $table . ' WHERE created_at >= ? GROUP BY threat_type ORDER BY count DESC LIMIT 5', [$weekStart]);
            foreach ($sql as $row) {
                $stats['top_threats'][] = [
                    'type' => (string) $row->getValue('threat_type'),
                    'count' => (int) $row->getValue('count'),
                ];
            }
        } catch (Throwable $e) {
            self::debugLog('Statistics: upkeep_ips_threat_log table not available: ' . $e->getMessage());
        }

        return $stats;
    }

    /**
     * Kurze Kennzahlen für den Statusindikator im Menü (5 Minuten gecacht).
     *
     * @return array{blocked_ips: int, threats_today: int}
     */
    public static function getIndicatorStats(): array
    {
        try {
            $store = new JsonStore('stats_cache', 10);
            $cached = $store->get('indicator');
            if (is_array($cached)) {
                return $cached;
            }
            $stats = self::getStatistics();
            $result = ['blocked_ips' => $stats['blocked_ips'], 'threats_today' => $stats['threats_today']];
            $store->set('indicator', $result, 300);
            return $result;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return ['blocked_ips' => 0, 'threats_today' => 0];
        }
    }

    // ------------------------------------------------------------------
    // Bereinigung
    // ------------------------------------------------------------------

    /**
     * Bereinigt abgelaufene IP-Sperrungen und alte Logs.
     * Läuft per Cronjob/Konsole und höchstens einmal pro Stunde automatisch.
     *
     * @return array<string, int>
     */
    public static function cleanupExpiredData(?int $retentionDays = null): array
    {
        $sql = rex_sql::factory();
        $cleanup = [
            'expired_ips' => 0,
            'old_threats' => 0,
            'old_rate_limits' => 0,
            'expired_positivliste' => 0,
            'dns_cache_entries' => 0,
            'old_mail_rate_limits' => 0,
        ];
        $retentionDays ??= (int) self::getAddon()->getConfig('ips_threat_log_retention_days', 30);
        $retentionDays = max(1, min(365, $retentionDays));

        try {
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_blocked_ips') . " WHERE block_type = 'temporary' AND expires_at IS NOT NULL AND expires_at < NOW()");
            $cleanup['expired_ips'] = $sql->getRows();

            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE expires_at IS NOT NULL AND expires_at < NOW()');
            $cleanup['expired_positivliste'] = $sql->getRows();

            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_threat_log') . ' WHERE created_at < ?', [date('Y-m-d H:i:s', time() - $retentionDays * 86400)]);
            $cleanup['old_threats'] = $sql->getRows();

            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_ips_rate_limit') . ' WHERE window_start < ?', [date('Y-m-d H:i:s', time() - 7200)]);
            $cleanup['old_rate_limits'] = $sql->getRows();
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }

        try {
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_mail_rate_limit') . ' WHERE created_at < ?', [date('Y-m-d H:i:s', time() - 86400)]);
            $cleanup['old_mail_rate_limits'] = $sql->getRows();
        } catch (Throwable) {
            // Mail-Tabellen optional
        }

        $cleanup['dns_cache_entries'] = self::purgeLegacyDnsConfig();
        self::invalidateCache();

        if (array_sum($cleanup) > 0 && self::getAddon()->getConfig('ips_debug_mode', false)) {
            self::systemLog('info', 'IPS Cleanup: ' . json_encode($cleanup));
        }

        return $cleanup;
    }

    /**
     * Entfernt die DNS-Cache-Schlüssel "upkeep_dns_verify_*" aus rex_config (2.x).
     * Für update.php; liefert die Anzahl entfernter Schlüssel.
     */
    public static function purgeLegacyDnsConfig(): int
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery(
                'DELETE FROM ' . rex::getTable('config') . " WHERE namespace = 'upkeep' AND `key` LIKE ?",
                ['upkeep\_dns\_verify\_%'],
            );
            $removed = $sql->getRows();
            if ($removed > 0) {
                rex_config::refresh();
            }
            return $removed;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return 0;
        }
    }

    /**
     * Automatische Bereinigung höchstens einmal pro Stunde (Zeitstempel-Datei).
     * Abschaltbar über ips_cleanup_auto (dann nur Cronjob/Konsole/Button).
     */
    private static function maybeCleanup(): void
    {
        if (!(bool) self::getAddon()->getConfig('ips_cleanup_auto', 1)) {
            return;
        }
        $marker = rex_path::addonData('upkeep', 'store/ips_last_cleanup');
        $last = is_file($marker) ? (int) @filemtime($marker) : 0;
        if (time() - $last < self::CLEANUP_INTERVAL) {
            return;
        }
        try {
            if (!is_dir(dirname($marker))) {
                rex_dir::create(dirname($marker));
            }
            @touch($marker);
            self::cleanupExpiredData();
        } catch (Throwable $e) {
            self::exceptionLog($e);
        }
    }

    /**
     * Schaltet den Status eines Custom Patterns um
     */
    public static function toggleCustomPatternStatus(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('UPDATE ' . rex::getTable('upkeep_ips_custom_patterns') . ' SET status = 1 - status, updated_at = NOW() WHERE id = ?', [$id]);
            return $sql->getRows() > 0;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return false;
        }
    }

    /**
     * Lädt ein Custom Pattern für die Bearbeitung
     *
     * @return array<string, mixed>|null
     */
    public static function getCustomPattern(int $id): ?array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_custom_patterns') . ' WHERE id = ?', [$id]);
            if ($sql->getRows() > 0) {
                return [
                    'id' => $sql->getValue('id'),
                    'pattern' => $sql->getValue('pattern'),
                    'description' => $sql->getValue('description'),
                    'severity' => $sql->getValue('severity'),
                    'is_regex' => (bool) $sql->getValue('is_regex'),
                    'status' => (bool) $sql->getValue('status'),
                    'created_at' => $sql->getValue('created_at'),
                    'updated_at' => $sql->getValue('updated_at'),
                ];
            }
            return null;
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return null;
        }
    }

    private static function normalizeSeverity(string $severity): string
    {
        return in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $severity : 'medium';
    }

    // ------------------------------------------------------------------
    // GeoIP
    // ------------------------------------------------------------------

    /**
     * Ermittelt das Land einer IP-Adresse (nur lokale Datenbank, kein Download)
     *
     * @return array{code: string, name: string}
     */
    public static function getCountryByIp(string $ip): array
    {
        return GeoIP::getCountry($ip);
    }

    /**
     * Aktualisiert die GeoIP-Datenbank (Button/Cronjob)
     */
    public static function updateGeoDatabase(): bool
    {
        return GeoIP::updateDatabase();
    }

    /**
     * Status der GeoIP-Datenbank
     *
     * @return array<string, mixed>
     */
    public static function getGeoDatabaseStatus(): array
    {
        return GeoIP::getDatabaseStatus();
    }

    /**
     * Erweitert Threat-Logs um Länderinformationen
     *
     * @param list<array<string, mixed>> $threats
     * @return list<array<string, mixed>>
     */
    public static function enrichThreatsWithCountry(array $threats): array
    {
        foreach ($threats as &$threat) {
            $ip = $threat['ip_address'] ?? $threat['ip'] ?? null;
            if (is_string($ip) && $ip !== '') {
                $country = self::getCountryByIp($ip);
                $threat['country_code'] = $country['code'];
                $threat['country_name'] = $country['name'];
            }
        }
        unset($threat);

        return $threats;
    }

    /**
     * Gruppiert Bedrohungen nach Ländern
     *
     * @return list<array<string, mixed>>
     */
    public static function getThreatsByCountry(int $days = 7): array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('
                SELECT ip_address, SUM(' . self::hitExpression() . ') as threat_count, MAX(created_at) as last_threat
                FROM ' . rex::getTable('upkeep_ips_threat_log') . '
                WHERE created_at >= ?
                GROUP BY ip_address
                ORDER BY threat_count DESC
                LIMIT 1000
            ', [date('Y-m-d H:i:s', time() - max(1, $days) * 86400)]);
            $results = $sql->getArray();
        } catch (Throwable $e) {
            self::exceptionLog($e);
            return [];
        }

        $countries = [];
        foreach ($results as $result) {
            $ip = (string) $result['ip_address'];
            $country = self::getCountryByIp($ip);
            $code = $country['code'];

            if (!isset($countries[$code])) {
                $countries[$code] = [
                    'code' => $code,
                    'name' => $country['name'],
                    'threat_count' => 0,
                    'unique_ips' => 0,
                    'last_threat' => null,
                    'ips' => [],
                ];
            }

            $countries[$code]['threat_count'] += (int) $result['threat_count'];
            ++$countries[$code]['unique_ips'];
            $countries[$code]['ips'][] = $ip;

            if (!$countries[$code]['last_threat'] || $result['last_threat'] > $countries[$code]['last_threat']) {
                $countries[$code]['last_threat'] = $result['last_threat'];
            }
        }

        uasort($countries, static fn ($a, $b) => $b['threat_count'] <=> $a['threat_count']);

        return array_values($countries);
    }
}
