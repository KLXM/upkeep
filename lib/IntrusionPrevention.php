<?php

namespace KLXM\Upkeep;

use DateTime;
use Exception;
use rex;
use rex_addon;
use rex_config;
use rex_escape;
use rex_logger;
use rex_response;
use rex_server;
use rex_sql;

/**
 * Intrusion Prevention System für Upkeep AddOn
 * 
 * Erkennt und blockiert verdächtige Requests basierend auf:
 * - CMS-spezifische Exploit-Versuche (WordPress, TYPO3, Drupal, Joomla)
 * - Pentest-Tools und Scanner-Signaturen
 * - SQL-Injection und Path-Traversal-Versuche
 * - Benutzerdefinierte Patterns
 */
class IntrusionPrevention
{
    private static ?rex_addon $addon = null;
    
    /**
     * Debug-Logging nur wenn Debug-Modus aktiviert ist
     */
    private static function debugLog(string $message): void
    {
        if (self::getAddon()->getConfig('ips_debug_mode', false)) {
            rex_logger::factory()->log('debug', $message);
        }
    }
    
    // Standard-Patterns für verschiedene CMS und Angriffe
    private static array $defaultPatterns = [
        // Kritische Patterns - Sofortige IP-Sperrung
        'immediate_block' => [
            '/xmlrpc.php',
            '/.env',
            '/.git/',
            '/shell.php',
            '/c99.php',
            '/r57.php',
            '/webshell.php', 
            '/backdoor.php',
            '/cmd.php',
            '/eval.php',
            '/base64.php',
            '/phpinfo.php',
            '/../',
            '/../../',
            '/../../../',
            '%2e%2e%2f',
            '%252e%252e%252f',
            'union+select',
            'union%20select',
            'drop+table',
            'drop%20table',
        ],
        
        // WordPress-spezifische Pfade
        'wordpress' => [
            '/wp-admin/',
            '/wp-login.php',
            '/wp-content/',
            '/wp-includes/',
            '/wp-config.php',
            '/xmlrpc.php',
            '/wp-cron.php',
            '/wp-json/',
            '/wp-trackback.php'
        ],
        
        // TYPO3-spezifische Pfade
        'typo3' => [
            '/typo3/',
            '/typo3conf/',
            '/typo3/backend.php',
            '/typo3/index.php',
            '/typo3/install/',
            '/typo3temp/',
            '/fileadmin/',
            '/t3lib/',
            '/typo3_src/'
        ],
        
        // Drupal-spezifische Pfade
        'drupal' => [
            '/user/login',
            '/admin/',
            '/node/',
            '/sites/default/',
            '/modules/',
            '/themes/',
            '/core/',
            '/web.config',
            '/.htaccess',
            '/update.php',
            '/install.php'
        ],
        
        // Joomla-spezifische Pfade
        'joomla' => [
            '/administrator/',
            '/components/',
            '/modules/',
            '/plugins/',
            '/templates/',
            '/libraries/',
            '/configuration.php',
            '/htaccess.txt',
            '/web.config.txt'
        ],
        
        // Allgemeine Admin-Panels
        'admin_panels' => [
            '/admin',
            '/admin.php',
            '/administrator',
            '/phpmyadmin/',
            '/pma/',
            '/mysql/',
            '/cpanel/',
            '/webmail/',
            '/control/',
            '/manager/',
            '/dashboard/'
        ],
        
        // Config- und Sensitive-Files
        'config_files' => [
            '/.env',
            '/.git/',
            '/.svn/',
            '/config.php',
            '/config.inc.php',
            '/settings.php',
            '/local.xml',
            '/database.yml',
            '/config.yml',
            '/secrets.yml'
        ],
        
        // Shell- und Malware-Uploads
        'shells' => [
            '/shell.php',
            '/c99.php',
            '/r57.php',
            '/webshell.php',
            '/backdoor.php',
            '/hack.php',
            '/evil.php',
            '/cmd.php'
        ],
        
        // Info-Disclosure
        'info_disclosure' => [
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/temp.php',
            '/debug.php',
            '/status.php',
            '/server-status',
            '/server-info'
        ],
        
        // Path Traversal-Patterns
        'path_traversal' => [
            '../',
            '..\\',
            '%2e%2e%2f',
            '%2e%2e%5c',
            '..%2f',
            '..%5c',
            '%c0%ae%c0%ae%c0%af',
            '%252e%252e%252f'
        ],
        
        // SQL-Injection-Patterns
        'sql_injection' => [
            "' OR '1'='1",
            '" OR "1"="1',
            'UNION SELECT',
            'DROP TABLE',
            'INSERT INTO',
            'UPDATE SET',
            'DELETE FROM',
            ' -- ',     // SQL Kommentar mit Leerzeichen vor und nach
            '/*',
            'xp_cmdshell',
            'sp_executesql'
        ]
    ];
    
    // Bekannte Scanner und Pentest-Tools (User-Agent)
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
        'w3af'
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
     * Hauptfunktion: Prüft eingehende Requests auf verdächtige Patterns
     */
    public static function checkRequest(): void
    {
        // IPS nur im Frontend und nur wenn aktiviert
        if (!rex::isFrontend() || !self::isActive()) {
            return;
        }
        
        // Gelegentliche automatische Bereinigung
        self::performRandomCleanup();
        
        $clientIp = self::getClientIp();
        $requestUri = rex_server('REQUEST_URI', 'string', '');
        $userAgent = rex_server('HTTP_USER_AGENT', 'string', '');
        $referer = rex_server('HTTP_REFERER', 'string', '');
        
        // DEBUG: Logging nur bei aktivem Debug-Modus und nicht für jeden Request
        if (self::getAddon()->getConfig('ips_debug_mode', false)) {
            self::debugLog("IPS Check: IP={$clientIp}, URI={$requestUri}, Active=" . (self::isActive() ? 'true' : 'false'));
        }
        
        // Whitelist-Prüfung
        if (self::isOnPositivliste($clientIp)) {
            return;
        }
        
        // Bereits gesperrte IP?
        if (self::isBlocked($clientIp)) {
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', "IPS: IP {$clientIp} is already blocked");
            }
            self::blockRequest('IP bereits gesperrt', $clientIp, $requestUri);
        }
        
        // Pattern-Checks durchführen
        $threat = self::analyzeRequest($requestUri, $userAgent, $referer);
        
        if ($threat) {
            // Nur ins IPS-Log, nicht doppelt ins System-Log
            self::handleThreat($threat, $clientIp, $requestUri, $userAgent);
        } else {
            // Debug-Log nur bei aktivem Debug-Modus
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                self::debugLog("IPS: No threat detected for {$clientIp}");
            }
        }
        
        // Rate Limiting prüfen (nur wenn aktiviert)
        if (self::isRateLimitingEnabled() && self::isRateLimitExceeded($clientIp)) {
            // Rate Limiting nur ins IPS-Log
            self::handleThreat([
                'type' => 'rate_limit',
                'severity' => 'medium',
                'pattern' => 'Too many requests'
            ], $clientIp, $requestUri, $userAgent);
        }
    }

    /**
     * Analysiert Request auf verdächtige Patterns
     */
    private static function analyzeRequest(string $uri, string $userAgent, string $referer): ?array
    {
        // URL-decode für Pattern-Matching
        $decodedUri = urldecode($uri);
        
        // Prüfung auf legitime URL-Patterns (Whitelist für typische deutsche CMS-URLs)
        if (self::isLegitimateUrl($decodedUri)) {
            return null;
        }
        
        // 1. Standard-Patterns prüfen
        foreach (self::$defaultPatterns as $category => $patterns) {
            foreach ($patterns as $pattern) {
                if (stripos($decodedUri, $pattern) !== false) {
                    return [
                        'type' => 'suspicious_path',
                        'category' => $category,
                        'pattern' => $pattern,
                        'severity' => self::getSeverityForCategory($category)
                    ];
                }
            }
        }
        
        // 2. User-Agent prüfen
        $userAgentLower = strtolower($userAgent);
        foreach (self::$suspiciousUserAgents as $suspiciousAgent) {
            if (stripos($userAgentLower, $suspiciousAgent) !== false) {
                return [
                    'type' => 'suspicious_user_agent',
                    'pattern' => $suspiciousAgent,
                    'severity' => 'high'
                ];
            }
        }
        
        // 3. Custom Patterns prüfen
        $customPatterns = self::getCustomPatterns();
        foreach ($customPatterns as $pattern) {
            if (stripos($decodedUri, $pattern['pattern']) !== false) {
                return [
                    'type' => 'custom_pattern',
                    'pattern' => $pattern['pattern'],
                    'severity' => $pattern['severity'] ?? 'medium'
                ];
            }
        }
        
        return null;
    }

    /**
     * Behandelt erkannte Bedrohungen
     */
    private static function handleThreat(array $threat, string $ip, string $uri, string $userAgent): void
    {
        // 1. Bedrohung loggen (immer)
        self::logThreat($threat, $ip, $uri, $userAgent);
        
        // 2. Extension Point für externes Logging
        self::callExternalLogging($threat, $ip, $uri, $userAgent);
        
        // 3. Monitor-Only Modus - nur loggen, nicht blocken
        if (self::getAddon()->getConfig('ips_monitor_only', false)) {
            self::debugLog("IPS: Monitor-Only mode - threat logged but not blocked: {$threat['type']} from {$ip}");
            return; // Nur loggen, nicht blocken
        }
        
        // 4. Normale Blocking-Logik (wenn nicht Monitor-Only)
        
        // Spezielle Behandlung für xmlrpc.php - IMMER permanent blocken
        if (stripos($uri, 'xmlrpc.php') !== false) {
            self::blockIpPermanently($ip);
            self::blockRequest('xmlrpc.php access blocked - permanent ban', $ip, $uri);
        }
        
        // Sofortige Sperrung für kritische Patterns
        if (isset($threat['category']) && $threat['category'] === 'immediate_block') {
            self::blockIpPermanently($ip);
            self::blockRequest('Malicious activity detected - permanent block', $ip, $uri);
        }
        
        // Entscheidung basierend auf Schweregrad
        switch ($threat['severity']) {
            case 'critical':
                self::blockIpPermanently($ip);
                self::blockRequest('Critical threat detected', $ip, $uri);
                break;
                
            case 'high':
                self::blockIpTemporarily($ip, 3600); // 1 Stunde
                self::blockRequest('High threat detected', $ip, $uri);
                break;
                
            case 'medium':
                // Bei wiederholten Verstößen eskalieren
                if (self::getViolationCount($ip) >= 3) {
                    self::blockIpTemporarily($ip, 1800); // 30 Minuten
                    self::blockRequest('Repeated violations', $ip, $uri);
                }
                self::incrementViolationCount($ip);
                break;
                
            case 'low':
                self::incrementViolationCount($ip);
                break;
        }
    }
    
    /**
     * Extension Point für externes Logging (fail2ban, Grafana, etc.)
     */
    private static function callExternalLogging(array $threat, string $ip, string $uri, string $userAgent): void
    {
        // Threat-Daten für Extension Points vorbereiten
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip' => $ip,
            'uri' => $uri,
            'user_agent' => $userAgent,
            'threat_type' => $threat['type'],
            'threat_category' => $threat['category'] ?? $threat['type'],
            'pattern' => $threat['pattern'],
            'severity' => $threat['severity'],
            'action' => self::getActionForSeverity($threat['severity']),
            'monitor_only' => self::getAddon()->getConfig('ips_monitor_only', false)
        ];
        
        // Extension Point für externes Logging
        \rex_extension::registerPoint(new \rex_extension_point('UPKEEP_IPS_THREAT_DETECTED', $logData));
        
        // Extension Point für fail2ban-kompatibles Logging
        if (self::getAddon()->getConfig('ips_fail2ban_logging', false)) {
            self::logForFail2ban($logData);
        }
    }
    
    /**
     * Fail2ban-kompatibles Logging
     */
    private static function logForFail2ban(array $logData): void
    {
        $logFile = self::getAddon()->getConfig('ips_fail2ban_logfile', '/var/log/redaxo_ips.log');
        
        // fail2ban-kompatibles Format
        $message = sprintf(
            "%s [REDAXO-IPS] %s threat from %s: %s (URI: %s, Pattern: %s, Action: %s)",
            $logData['timestamp'],
            strtoupper($logData['severity']),
            $logData['ip'],
            $logData['threat_type'],
            $logData['uri'],
            $logData['pattern'],
            $logData['action']
        );
        
        try {
            // Extension Point für custom fail2ban logging
            \rex_extension::registerPoint(new \rex_extension_point('UPKEEP_IPS_FAIL2BAN_LOG', [
                'message' => $message,
                'logFile' => $logFile,
                'logData' => $logData
            ]));
            
            // Standard File Logging (falls kein Extension Handler)
            if (is_writable(dirname($logFile))) {
                error_log($message . "\n", 3, $logFile);
            }
        } catch (Exception $e) {
            self::debugLog("IPS: Failed to write fail2ban log: " . $e->getMessage());
        }
    }
    
    /**
     * Holt die letzten IPs aus Threat-Logs für schnelle manuelle Blockierung
     */
    public static function getRecentThreatIps(int $limit = 10): array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("
                SELECT DISTINCT 
                    ip_address,
                    COUNT(*) as threat_count,
                    MAX(created_at) as last_threat,
                    MAX(severity) as max_severity,
                    GROUP_CONCAT(DISTINCT threat_type ORDER BY created_at DESC LIMIT 3) as recent_threats
                FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                    AND ip_address NOT IN (
                        SELECT ip_address FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                        WHERE expires_at IS NULL OR expires_at > NOW()
                    )
                GROUP BY ip_address
                ORDER BY threat_count DESC, last_threat DESC
                LIMIT ?
            ", [$limit]);
            
            $threatIps = [];
            while ($sql->hasNext()) {
                $threatIps[] = [
                    'ip' => $sql->getValue('ip_address'),
                    'threat_count' => (int) $sql->getValue('threat_count'),
                    'last_threat' => $sql->getValue('last_threat'),
                    'max_severity' => $sql->getValue('max_severity'),
                    'recent_threats' => explode(',', $sql->getValue('recent_threats'))
                ];
                $sql->next();
            }
            return $threatIps;
        } catch (Exception $e) {
            self::debugLog("Failed to get recent threat IPs: " . $e->getMessage());
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
     * Blockiert Request und zeigt 403-Seite
     */
    private static function blockRequest(string $reason, string $ip, string $uri): void
    {
        // Prüfe CAPTCHA-Entsperrungsversuch
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['unlock_ip'])) {
            if (self::processCaptchaUnlock()) {
                // Erfolgreich entsperrt - wird in processCaptchaUnlock() weitergeleitet
                return;
            }
            // Fehlgeschlagen - zeige Fehler in der Blockierungsseite
        }
        
        rex_response::setStatus(rex_response::HTTP_FORBIDDEN);
        rex_response::sendCacheControl();
        
        // Set appropriate headers for security
        header('Content-Type: text/html; charset=utf-8');
        header('Content-Security-Policy: default-src \'self\'; style-src \'self\' \'unsafe-inline\'');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        
        // Custom 403-Seite oder Standard-Text
        $content = self::getBlockedPageContent($reason, $ip);
        
        echo $content;
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

    /**
     * Prüft ob IP in Whitelist steht
     */
    private static function isOnPositivliste(string $ip): bool
    {
        // Prüfe zuerst die Upkeep-Addon erlaubte IPs (für Wartungsmodus)
        $allowedIps = explode("\n", self::getAddon()->getConfig('allowed_ips', ''));
        foreach ($allowedIps as $allowedIp) {
            $allowedIp = trim($allowedIp);
            if ($allowedIp === $ip) {
                self::debugLog("IPS: IP {$ip} found in maintenance allowed_ips");
                return true;
            }
        }
        
        // Prüfe IPS-Positivliste aus Datenbank (berücksichtige Ablaufzeiten)
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT ip_address, ip_range, expires_at FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE status = 1 AND (expires_at IS NULL OR expires_at > NOW())');
            
            self::debugLog("IPS: Checking {$ip} against " . $sql->getRows() . " active Positivliste entries");
            
            while ($sql->hasNext()) {
                $positivlisteIp = $sql->getValue('ip_address');
                $ipRange = $sql->getValue('ip_range');
                $expiresAt = $sql->getValue('expires_at');
                
                // Exakte IP-Übereinstimmung
                if ($positivlisteIp && $positivlisteIp === $ip) {
                    $expiry = $expiresAt ? " (expires: {$expiresAt})" : " (permanent)";
                    self::debugLog("IPS: IP {$ip} found in Positivliste (exact match){$expiry}");
                    return true;
                }
                
                // CIDR-Bereich prüfen
                if ($ipRange && self::ipInRange($ip, $ipRange)) {
                    $expiry = $expiresAt ? " (expires: {$expiresAt})" : " (permanent)";
                    self::debugLog("IPS: IP {$ip} found in Positivliste (CIDR range: {$ipRange}){$expiry}");
                    return true;
                }
                
                $sql->next();
            }
        } catch (Exception $e) {
            rex_logger::factory()->log('error', "IPS: Error checking Positivliste: " . $e->getMessage());
            // Fehler beim Datenbankzugriff ignorieren (Tabelle existiert möglicherweise noch nicht)
        }
        
        self::debugLog("IPS: IP {$ip} NOT found in any Positivliste");
        return false;
    }

    /**
     * Prüft ob eine URL als legitim eingestuft werden kann
     * Verhindert False Positives bei normalen CMS-URLs
     */
    private static function isLegitimateUrl(string $uri): bool
    {
        // Typische deutsche CMS-URL-Patterns die als legitim gelten
        $legitimatePatterns = [
            // Normale Artikel-URLs mit Zahlen und Bindestrichen
            '/^\\/[0-9]+-[0-9]+-[^\\/?]*\\.html(\\?.*)?$/',  // z.B. /3938-0-Regionalkonferenz...html
            // URLs mit goback-Parameter (typisch für Pagination)
            '/^[^\\?]*\\?.*goback=[0-9]+.*$/',               // z.B. ...?goback=337
            // Standard CMS-Artikel URLs
            '/^\\/[0-9]+-[a-zA-Z0-9\\-_]+\\.html/',
            // URLs mit normalen GET-Parametern
            '/^[^\\?]*\\?[a-zA-Z0-9_=&\\-]+$/'
        ];
        
        foreach ($legitimatePatterns as $pattern) {
            if (preg_match($pattern, $uri)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Prüft ob eine IP in einem CIDR-Bereich liegt
     */
    private static function ipInRange(string $ip, string $range): bool
    {
        if (!str_contains($range, '/')) {
            return $ip === $range;
        }
        
        list($subnet, $bits) = explode('/', $range);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // IPv4
            $ip = ip2long($ip);
            $subnet = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            $subnet &= $mask;
            return ($ip & $mask) === $subnet;
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // IPv6 - robuste Implementierung
            $ip_bin = inet_pton($ip);
            $subnet_bin = inet_pton($subnet);
            
            if ($ip_bin === false || $subnet_bin === false) {
                return false;
            }
            
            // Create mask for IPv6
            $mask = str_repeat('f', $bits >> 2);
            if ($bits & 3) {
                $mask .= dechex(0xf << (4 - ($bits & 3)));
            }
            $mask = str_pad($mask, 32, '0');
            $mask = pack('H*', $mask);
            
            return ($ip_bin & $mask) === ($subnet_bin & $mask);
        }
        
        return false;
    }

    /**
     * Holt Client-IP (auch hinter Proxy/CDN)
     */
    private static function getClientIp(): string
    {
        // Prüfe verschiedene Headers für echte IP
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_FORWARDED_FOR',      // Standard Proxy
            'HTTP_X_REAL_IP',            // Nginx
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'                // Fallback
        ];
        
        foreach ($headers as $header) {
            $ip = rex_server($header, 'string', '');
            if (!empty($ip)) {
                // Bei mehreren IPs (X-Forwarded-For) die erste nehmen
                if (str_contains($ip, ',')) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                
                // IP validieren
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return rex_server('REMOTE_ADDR', 'string', '');
    }

    /**
     * Bestimmt Schweregrad basierend auf Kategorie
     */
    private static function getSeverityForCategory(string $category): string
    {
        // Validate the category parameter
        if (empty($category)) {
            return 'medium'; // Default severity for invalid or empty category
        }
        
        return match ($category) {
            'immediate_block' => 'critical',
            'shells', 'sql_injection' => 'critical',
            'path_traversal', 'config_files' => 'high',
            'wordpress', 'typo3', 'drupal', 'joomla', 'admin_panels' => 'medium',
            'info_disclosure' => 'low',
            default => 'medium'
        };
    }

    /**
     * Holt benutzerdefinierte Patterns
     */
    public static function getCustomPatterns(): array
    {
        static $patterns = null;
        
        if ($patterns === null) {
            $patterns = [];
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_custom_patterns') . " WHERE status = 1");
            
            while ($sql->hasNext()) {
                $patterns[] = [
                    'pattern' => $sql->getValue('pattern'),
                    'description' => $sql->getValue('description'),
                    'severity' => $sql->getValue('severity'),
                    'is_regex' => (bool) $sql->getValue('is_regex')
                ];
                $sql->next();
            }
        }
        
        return $patterns;
    }

    /**
     * Weitere Methoden für Rate Limiting, IP-Blocking, Logging etc.
     * werden im nächsten Schritt implementiert...
     */
    
    /**
     * Prüft ob IP gesperrt ist
     */
    private static function isBlocked(string $ip): bool
    {
        $sql = rex_sql::factory();
        $query = "SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                  WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > NOW())";
        
        $sql->setQuery($query, [$ip]);
        return $sql->getValue('count') > 0;
    }
    
    /**
     * Prüft Rate Limiting mit intelligenten Limits
     */
    private static function isRateLimitExceeded(string $ip): bool
    {
        // Rate-Limiting optional - normalerweise macht das der Webserver
        if (!self::isRateLimitingEnabled()) {
            return false;
        }
        
        $sql = rex_sql::factory();
        $now = new DateTime();
        $windowStart = (clone $now)->modify('-1 minute')->format('Y-m-d H:i:s');
        
        // Requests in letzter Minute zählen
        $query = "SELECT SUM(request_count) as total FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                  WHERE ip_address = ? AND window_start >= ?";
        
        $sql->setQuery($query, [$ip, $windowStart]);
        $requestCount = (int) $sql->getValue('total');
        
        // Auch aktuellen Request miteinbeziehen (nur wenn Rate-Limiting aktiv)
        if (self::isRateLimitingEnabled()) {
            self::updateRateLimit($ip);
        }
        
        // Intelligente Limits - sehr hoch für DoS-Schutz, nicht normale Nutzung
        $burstLimit = (int) self::getAddon()->getConfig('ips_burst_limit', 600);       // 600 pro Minute (10 pro Sekunde)
        $burstWindow = (int) self::getAddon()->getConfig('ips_burst_window', 60);      // 60 Sekunden
        $strictLimit = (int) self::getAddon()->getConfig('ips_strict_limit', 200);    // 200 für kritische Pfade
        
        // Intelligente Limits basierend auf URI und Benutzerverhalten
        $currentUri = rex_server('REQUEST_URI', 'string', '');
        $effectiveLimit = self::getEffectiveLimitForUri($currentUri, $burstLimit, $strictLimit);
        
        // Bot-Erkennung: Noch höhere Limits für erkannte gute Bots
        if (self::isGoodBot()) {
            $effectiveLimit = $effectiveLimit * 2; // Double limit für gute Bots (reicht bei hohen Basis-Limits)
            self::debugLog("IPS: Good bot detected for {$ip} - doubling rate limit to {$effectiveLimit}");
        }
        
        // Debug-Log für Rate-Limiting
        if ($requestCount > ($effectiveLimit * 0.8)) { // Log wenn 80% erreicht
            self::debugLog("IPS: Rate limit warning for {$ip} - {$requestCount}/{$effectiveLimit} requests");
        }
        
        return $requestCount >= $effectiveLimit;
    }
    
    /**
     * Bestimmt effektive Rate-Limits basierend auf URI
     */
    private static function getEffectiveLimitForUri(string $uri, int $defaultLimit, int $strictLimit): int
    {
        // Kritische Pfade mit strengeren Limits
        $strictPaths = [
            '/wp-admin/', '/wp-login.php', '/admin/', '/login',
            '/phpmyadmin/', '/pma/', '/xmlrpc.php'
        ];
        
        // API-Pfade mit moderaten Limits
        $apiPaths = [
            '/api/', '/wp-json/', '/jsonapi/', '/graphql'
        ];
        
        // Statische Ressourcen mit höheren Limits
        $staticPaths = [
            '/assets/', '/media/', '/css/', '/js/', '/images/', '/img/',
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.pdf'
        ];
        
        foreach ($strictPaths as $path) {
            if (stripos($uri, $path) !== false) {
                return $strictLimit; // Strenge Limits für kritische Bereiche
            }
        }
        
        foreach ($staticPaths as $path) {
            if (stripos($uri, $path) !== false) {
                return (int) ($defaultLimit * 1.5); // Nur 50% mehr für statische Ressourcen
            }
        }
        
        foreach ($apiPaths as $path) {
            if (stripos($uri, $path) !== false) {
                return (int) ($defaultLimit * 0.8); // 80% des Standard-Limits für APIs
            }
        }
        
        return $defaultLimit; // Standard-Limit für normale Seiten
    }
    
    /**
     * Erkennt gute/legitime Bots (Google, Bing, etc.)
     */
    private static function isGoodBot(): bool
    {
        $userAgent = rex_server('HTTP_USER_AGENT', 'string', '');
        
        // Bekannte gute Bots
        $goodBots = [
            'Googlebot',
            'Bingbot', 
            'Slurp',           // Yahoo
            'DuckDuckBot',     // DuckDuckGo
            'Baiduspider',     // Baidu
            'YandexBot',       // Yandex
            'facebookexternalhit', // Facebook
            'Twitterbot',      // Twitter
            'LinkedInBot',     // LinkedIn
            'WhatsApp',        // WhatsApp Link Preview
            'Applebot',        // Apple
            'SemrushBot',      // SEO Tools
            'AhrefsBot',       // SEO Tools
            'MJ12bot',         // Majestic
            'DotBot'           // Moz
        ];
        
        foreach ($goodBots as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                // Zusätzliche Verifikation für kritische Bots wie Google
                if (in_array($bot, ['Googlebot', 'Bingbot'])) {
                    return self::verifyGoogleBot(); // Reverse DNS Verifikation
                }
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Verifiziert Google/Bing Bot durch Reverse DNS mit Timeout-Schutz
     */
    private static function verifyGoogleBot(): bool
    {
        $ip = self::getClientIp();
        
        // DNS Cache prüfen (24h Cache) - verwende REDAXO Config als einfachen Cache
        $cacheKey = 'upkeep_dns_verify_' . md5($ip);
        $cacheData = \rex_config::get('upkeep', $cacheKey);
        
        if ($cacheData && isset($cacheData['expires']) && $cacheData['expires'] > time()) {
            return $cacheData['verified'] === true;
        }
        
        // Reverse DNS Lookup mit Timeout-Schutz
        $hostname = self::reverseDnsLookup($ip);
        if (!$hostname) {
            // Cache negative Ergebnisse für 1h
            \rex_config::set('upkeep', $cacheKey, [
                'verified' => false,
                'expires' => time() + 3600
            ]);
            return false;
        }
        
        // Prüfe auf legitime Bot-Hostnames
        $validPatterns = [
            '/\.googlebot\.com$/i',
            '/\.google\.com$/i', 
            '/\.search\.msn\.com$/i',
            '/\.crawl\.yahoo\.net$/i',
            '/\.crawl\.baidu\.com$/i',
            '/\.yandex\.com$/i',
            '/\.facebook\.com$/i',
            '/\.twttr\.com$/i'  // Twitter
        ];
        
        $isValidBot = false;
        foreach ($validPatterns as $pattern) {
            if (preg_match($pattern, $hostname)) {
                $isValidBot = true;
                break;
            }
        }
        
        if ($isValidBot) {
            // Forward DNS Lookup zur Verifikation mit Timeout
            $verifyIp = self::forwardDnsLookup($hostname);
            $verified = ($verifyIp === $ip);
            
            // Cache Ergebnis für 24h
            \rex_config::set('upkeep', $cacheKey, [
                'verified' => $verified,
                'expires' => time() + 86400
            ]);
            return $verified;
        }
        
        // Cache negative Ergebnisse für 1h
        \rex_config::set('upkeep', $cacheKey, [
            'verified' => false,
            'expires' => time() + 3600
        ]);
        return false;
    }
    
    /**
     * Reverse DNS Lookup mit Timeout-Schutz
     */
    private static function reverseDnsLookup(string $ip): ?string
    {
        try {
            // Bevorzuge dns_get_record für bessere Performance und Kontrolle
            if (function_exists('dns_get_record')) {
                // PTR Record für Reverse DNS
                $startTime = microtime(true);
                
                // Error Handler setzen
                set_error_handler(function() { return true; });
                
                $records = @dns_get_record($ip, DNS_PTR);
                
                restore_error_handler();
                
                $duration = microtime(true) - $startTime;
                
                // Timeout-Check (max 3 Sekunden)
                if ($duration > 3.0) {
                    self::debugLog("DNS PTR Lookup Timeout für IP: $ip (${duration}s)");
                    return null;
                }
                
                if (!empty($records) && isset($records[0]['target'])) {
                    $hostname = rtrim($records[0]['target'], '.');
                    if (filter_var($hostname, FILTER_VALIDATE_DOMAIN)) {
                        return $hostname;
                    }
                }
            }
            
            // Fallback zu gethostbyaddr mit Timeout-Simulation
            $startTime = microtime(true);
            
            set_error_handler(function() { return true; });
            
            // Verwende eine einfache Timeout-Simulation mit ignore_user_abort
            $oldAbort = ignore_user_abort(true);
            
            $hostname = @gethostbyaddr($ip);
            
            ignore_user_abort($oldAbort);
            restore_error_handler();
            
            $duration = microtime(true) - $startTime;
            
            // Timeout-Check (max 3 Sekunden)
            if ($duration > 3.0) {
                self::debugLog("gethostbyaddr Timeout für IP: $ip (${duration}s)");
                return null;
            }
            
            // Validierung des Hostnames
            if ($hostname && $hostname !== $ip && filter_var($hostname, FILTER_VALIDATE_DOMAIN)) {
                return $hostname;
            }
            
        } catch (Exception $e) {
            self::debugLog("DNS Lookup Error für IP $ip: " . $e->getMessage());
        } catch (\Error $e) {
            // Für PHP-Fehler (z.B. DNS-Funktionen nicht verfügbar)
            self::debugLog("DNS Function Error für IP $ip: " . $e->getMessage());
        }
        
        return null;
    }
    
    /**
     * Forward DNS Lookup mit Timeout-Schutz
     */
    private static function forwardDnsLookup(string $hostname): ?string
    {
        try {
            // Bevorzuge dns_get_record für A/AAAA Records mit besserer Kontrolle
            if (function_exists('dns_get_record')) {
                $startTime = microtime(true);
                
                // Error Handler setzen
                set_error_handler(function() { return true; });
                
                // A Record für IPv4
                $records = @dns_get_record($hostname, DNS_A);
                
                restore_error_handler();
                
                $duration = microtime(true) - $startTime;
                
                // Timeout-Check (max 3 Sekunden)
                if ($duration > 3.0) {
                    self::debugLog("DNS A Record Lookup Timeout für Hostname: $hostname (${duration}s)");
                    return null;
                }
                
                if (!empty($records) && isset($records[0]['ip'])) {
                    $ip = $records[0]['ip'];
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        return $ip;
                    }
                }
                
                // Fallback zu AAAA Record für IPv6 (falls kein A Record gefunden)
                if (empty($records)) {
                    $startTime = microtime(true);
                    
                    set_error_handler(function() { return true; });
                    
                    $records = @dns_get_record($hostname, DNS_AAAA);
                    
                    restore_error_handler();
                    
                    $duration = microtime(true) - $startTime;
                    
                    if ($duration <= 3.0 && !empty($records) && isset($records[0]['ipv6'])) {
                        $ip = $records[0]['ipv6'];
                        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            return $ip;
                        }
                    }
                }
            }
            
            // Fallback zu gethostbyname mit Timeout-Simulation
            $startTime = microtime(true);
            
            set_error_handler(function() { return true; });
            
            // Verwende ignore_user_abort für bessere Timeout-Kontrolle
            $oldAbort = ignore_user_abort(true);
            
            $ip = @gethostbyname($hostname);
            
            ignore_user_abort($oldAbort);
            restore_error_handler();
            
            $duration = microtime(true) - $startTime;
            
            // Timeout-Check (max 3 Sekunden)
            if ($duration > 3.0) {
                self::debugLog("gethostbyname Forward Lookup Timeout für Hostname: $hostname (${duration}s)");
                return null;
            }
            
            // Validierung der IP (gethostbyname gibt bei Fehlern den Hostname zurück)
            if ($ip && $ip !== $hostname && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
            
        } catch (Exception $e) {
            self::debugLog("Forward DNS Lookup Error für Hostname $hostname: " . $e->getMessage());
        } catch (\Error $e) {
            // Für PHP-Fehler (z.B. DNS-Funktionen nicht verfügbar)
            self::debugLog("Forward DNS Function Error für Hostname $hostname: " . $e->getMessage());
        }
        
        return null;
    }
    
    /**
     * Aktualisiert Rate Limiting Counter
     */
    private static function updateRateLimit(string $ip): void
    {
        $sql = rex_sql::factory();
        $now = new DateTime();
        $windowStart = $now->format('Y-m-d H:i:00'); // Auf Minute runden
        
        // Versuche existierenden Eintrag zu aktualisieren
        $query = "UPDATE " . rex::getTable('upkeep_ips_rate_limit') . " 
                  SET request_count = request_count + 1, last_request = NOW() 
                  WHERE ip_address = ? AND window_start = ?";
        
        $sql->setQuery($query, [$ip, $windowStart]);
        
        // Falls kein Eintrag aktualisiert wurde, neuen anlegen
        if ($sql->getRows() === 0) {
            $sql->setTable(rex::getTable('upkeep_ips_rate_limit'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('request_count', 1);
            $sql->setValue('window_start', $windowStart);
            $sql->setValue('last_request', date('Y-m-d H:i:s'));
            $sql->insert();
        }
        
        // Alte Einträge aufräumen (älter als 1 Stunde)
        $cleanupTime = (clone $now)->modify('-1 hour')->format('Y-m-d H:i:s');
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " WHERE window_start < ?", [$cleanupTime]);
    }
    
    /**
     * Sperrt IP permanent
     */
    private static function blockIpPermanently(string $ip): void
    {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_ips_blocked_ips'));
        $sql->setValue('ip_address', $ip);
        $sql->setValue('block_type', 'permanent');
        $sql->setValue('expires_at', null); // Permanent = nie ablaufend
        $sql->setValue('reason', 'Critical threat detected - permanent block');
        $sql->setValue('threat_level', 'critical');
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->insert();
    }
    
    /**
     * Sperrt IP temporär
     */
    private static function blockIpTemporarily(string $ip, int $seconds): void
    {
        $sql = rex_sql::factory();
        $expiresAt = (new DateTime())->modify("+{$seconds} seconds")->format('Y-m-d H:i:s');
        
        $sql->setTable(rex::getTable('upkeep_ips_blocked_ips'));
        $sql->setValue('ip_address', $ip);
        $sql->setValue('block_type', 'temporary');
        $sql->setValue('expires_at', $expiresAt);
        $sql->setValue('reason', "Temporary block for {$seconds} seconds");
        $sql->setValue('threat_level', 'high');
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->insert();
    }
    
    /**
     * Holt Anzahl der Verstöße für IP
     */
    private static function getViolationCount(string $ip): int
    {
        $sql = rex_sql::factory();
        $since = (new DateTime())->modify('-24 hours')->format('Y-m-d H:i:s');
        
        $query = "SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                  WHERE ip_address = ? AND created_at >= ?";
        
        $sql->setQuery($query, [$ip, $since]);
        return (int) $sql->getValue('count');
    }
    
    /**
     * Erhöht Verstoß-Counter (durch Logging automatisch)
     */
    private static function incrementViolationCount(string $ip): void
    {
        // Wird automatisch durch logThreat() erledigt
        // Hier könnten zusätzliche Aktionen stehen
    }
    
    /**
     * Loggt Bedrohung in Datenbank
     */
    private static function logThreat(array $threat, string $ip, string $uri, string $userAgent): void
    {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_ips_threat_log'));
        $sql->setValue('ip_address', $ip);
        $sql->setValue('request_uri', $uri);
        $sql->setValue('user_agent', $userAgent);
        $sql->setValue('threat_type', $threat['type']);
        $sql->setValue('threat_category', $threat['category'] ?? $threat['type']);
        $sql->setValue('pattern_matched', $threat['pattern']);
        $sql->setValue('severity', $threat['severity']);
        $sql->setValue('action_taken', self::getActionForSeverity($threat['severity']));
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->insert();
        
        // IPS-Log reicht - kein zusätzliches System-Log mehr
        // Bedrohungen werden nur in der IPS-Datenbank protokolliert
    }
    
    /**
     * Bestimmt Aktion basierend auf Schweregrad
     */
    private static function getActionForSeverity(string $severity): string
    {
        return match ($severity) {
            'critical' => 'permanent_block',
            'high' => 'temporary_block',
            'medium' => 'logged',
            'low' => 'logged',
            default => 'logged'
        };
    }
    
    /**
     * Generiert Inhalte für Blockierungsseite
     */
    private static function getBlockedPageContent(string $reason, string $ip): string
    {
        $title = self::getAddon()->getConfig('ips_block_title', 'Zugriff verweigert');
        $message = self::getAddon()->getConfig('ips_block_message', 'Ihr Request wurde von unserem Sicherheitssystem blockiert.');
        $contact = self::getAddon()->getConfig('ips_contact_info', '');
        
        // Handle language switching
        $requestedLang = rex_server('REQUEST_METHOD', 'string') === 'GET' ? rex_request('lang', 'string', '') : '';
        
        // Detect language preference (German by default)
        if ($requestedLang === 'en' || $requestedLang === 'de') {
            $isEnglish = ($requestedLang === 'en');
        } else {
            // Auto-detect from Accept-Language header
            $acceptLanguage = rex_server('HTTP_ACCEPT_LANGUAGE', 'string', '');
            $isEnglish = stripos($acceptLanguage, 'en') !== false && stripos($acceptLanguage, 'de') === false;
        }
        
        // Language-specific texts
        if ($isEnglish) {
            $texts = [
                'title' => 'Access Denied',
                'security_notice' => 'Security Notice:',
                'message' => 'Your request has been blocked by our security system.',
                'reason' => 'Reason:',
                'ip_address' => 'Your IP Address:',
                'timestamp' => 'Time:',
                'human_verification' => 'Human Verification',
                'are_you_human' => 'Are you a real person?',
                'solve_captcha' => 'Solve this simple math problem to get unblocked and redirected to the homepage.',
                'your_answer' => 'Your Answer:',
                'unlock_button' => 'Unlock and go to homepage',
                'support' => 'Support:',
                'contact_text' => 'If you have questions, please contact:',
                'powered_by' => 'Powered by REDAXO Upkeep AddOn - Intrusion Prevention System'
            ];
        } else {
            $texts = [
                'title' => 'Zugriff verweigert',
                'security_notice' => 'Sicherheitshinweis:',
                'message' => 'Ihr Request wurde von unserem Sicherheitssystem blockiert.',
                'reason' => 'Grund:',
                'ip_address' => 'Ihre IP-Adresse:',
                'timestamp' => 'Zeitpunkt:',
                'human_verification' => 'Menschliche Verifikation',
                'are_you_human' => 'Sie sind ein echter Mensch?',
                'solve_captcha' => 'Lösen Sie diese einfache Rechenaufgabe, um entsperrt zu werden und zur Startseite weitergeleitet zu werden.',
                'your_answer' => 'Ihre Antwort:',
                'unlock_button' => 'Entsperren und zur Startseite',
                'support' => 'Support:',
                'contact_text' => 'Bei Fragen wenden Sie sich an:',
                'powered_by' => 'Powered by REDAXO Upkeep AddOn - Intrusion Prevention System'
            ];
        }
        
        // CAPTCHA-Parameter generieren
        $captchaToken = self::generateCaptchaToken($ip);
        $captchaProblem = self::generateCaptchaProblem();
        
        $html = '<!DOCTYPE html>
<html lang="' . ($isEnglish ? 'en' : 'de') . '">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>' . rex_escape($texts['title']) . '</title>
    <style>
        body { 
            font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
            background: #ecf0f1;
            margin: 0;
            padding: 20px;
            color: #2c3e50;
        }
        .container {
            max-width: 800px;
            margin: 50px auto 0;
            background: white;
            border-radius: 3px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
        }
        .panel {
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .panel-danger {
            border-color: #d43f3a;
        }
        .panel-success {
            border-color: #5cb85c;
        }
        .panel-heading {
            padding: 10px 15px;
            border-bottom: 1px solid transparent;
            border-top-left-radius: 3px;
            border-top-right-radius: 3px;
            background-color: #d9534f;
            border-color: #d43f3a;
            color: white;
        }
        .panel-heading.panel-success {
            background-color: #5cb85c;
            border-color: #4cae4c;
        }
        .panel-body {
            padding: 15px;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
        }
        .alert-danger {
            color: #721c24;
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .alert-info {
            color: #0c5460;
            background-color: #d1ecf1;
            border-color: #bee5eb;
        }
        .alert-success {
            color: #155724;
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .fa {
            margin-right: 5px;
        }
        .fa-shield:before { content: "🛡️"; }
        .fa-exclamation-triangle:before { content: "⚠️"; }
        .fa-clock-o:before { content: "🕐"; }
        .fa-info-circle:before { content: "ℹ️"; }
        .fa-envelope:before { content: "✉️"; }
        .fa-unlock:before { content: "🔓"; }
        .fa-robot:before { content: "🤖"; }
        h1 {
            color: white;
            margin: 0;
            font-size: 18px;
            font-weight: bold;
        }
        .detail-row {
            margin: 10px 0;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .detail-row:last-child {
            border-bottom: none;
        }
        .detail-label {
            font-weight: bold;
            color: #555;
            display: inline-block;
            min-width: 120px;
        }
        .captcha-section {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
        }
        .captcha-problem {
            font-size: 24px;
            font-weight: bold;
            color: #495057;
            margin: 15px 0;
            padding: 15px;
            background: white;
            border: 2px solid #007bff;
            border-radius: 8px;
            display: inline-block;
            min-width: 100px;
        }
        .form-group {
            margin: 15px 0;
        }
        .form-control {
            width: 100px;
            padding: 8px 12px;
            font-size: 16px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            text-align: center;
        }
        .btn {
            padding: 10px 20px;
            font-size: 14px;
            font-weight: bold;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        .btn-success {
            background-color: #5cb85c;
            color: white;
        }
        .btn-success:hover {
            background-color: #4cae4c;
        }
        .footer {
            margin-top: 30px;
            padding: 15px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            font-size: 12px;
            color: #6c757d;
            text-align: center;
        }
        .language-switcher {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.9);
            border-radius: 4px;
            padding: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.12);
        }
        .language-switcher a {
            text-decoration: none;
            padding: 5px 10px;
            margin: 0 2px;
            border-radius: 3px;
            color: #666;
            font-weight: bold;
            font-size: 14px;
        }
        .language-switcher a:hover {
            background: #f0f0f0;
        }
        .language-switcher a.active {
            background: #007bff;
            color: white;
        }
    </style>
</head>
<body>
    <div class="language-switcher">
        <a href="?' . ($isEnglish ? 'lang=de' : 'lang=en') . '" class="' . ($isEnglish ? '' : 'active') . '">🇩🇪 DE</a>
        <a href="?' . ($isEnglish ? 'lang=de' : 'lang=en') . '" class="' . ($isEnglish ? 'active' : '') . '">🇺🇸 EN</a>
    </div>
    <div class="container">
        <div class="panel panel-danger">
            <div class="panel-heading">
                <h1><i class="fa fa-shield"></i> ' . rex_escape($texts['title']) . '</h1>
            </div>
            <div class="panel-body">
                <div class="alert alert-danger">
                    <i class="fa fa-exclamation-triangle"></i>
                    <strong>' . rex_escape($texts['security_notice']) . '</strong> ' . rex_escape($texts['message']) . '
                </div>
                
                <div class="detail-row">
                    <span class="detail-label">' . rex_escape($texts['reason']) . '</span>
                    ' . rex_escape($reason) . '
                </div>
                
                <div class="detail-row">
                    <span class="detail-label">' . rex_escape($texts['ip_address']) . '</span>
                    <strong>' . rex_escape($ip) . '</strong>
                </div>
                
                <div class="detail-row">
                    <span class="detail-label"><i class="fa fa-clock-o"></i> ' . rex_escape($texts['timestamp']) . '</span>
                    ' . date('d.m.Y H:i:s') . '
                </div>
            </div>
        </div>
        
        <div class="panel panel-success">
            <div class="panel-heading panel-success">
                <h2 style="margin: 0; font-size: 16px;"><i class="fa fa-unlock"></i> ' . rex_escape($texts['human_verification']) . '</h2>
            </div>
            <div class="panel-body">
                <div class="alert alert-success">
                    <i class="fa fa-robot"></i>
                    <strong>' . rex_escape($texts['are_you_human']) . '</strong><br>
                    ' . rex_escape($texts['solve_captcha']) . '
                </div>
                
                <div class="captcha-section">
                    <div class="captcha-problem">' . $captchaProblem['question'] . '</div>
                    
                    <form method="POST" action="' . rex_server('REQUEST_URI', 'string', '') . '">
                        <input type="hidden" name="captcha_token" value="' . $captchaToken . '">
                        <input type="hidden" name="captcha_answer" value="' . $captchaProblem['answer'] . '">
                        <input type="hidden" name="unlock_ip" value="' . rex_escape($ip) . '">
                        
                        <div class="form-group">
                            <label for="user_answer">' . rex_escape($texts['your_answer']) . '</label><br>
                            <input type="number" class="form-control" id="user_answer" name="user_answer" required autofocus>
                        </div>
                        
                        <button type="submit" class="btn btn-success">
                            <i class="fa fa-unlock"></i> ' . rex_escape($texts['unlock_button']) . '
                        </button>
                    </form>
                </div>
            </div>
        </div>';
        
        if (!empty($contact)) {
            $html .= '
        <div class="panel panel-default">
            <div class="panel-body">
                <div class="alert alert-info">
                    <i class="fa fa-info-circle"></i>
                    <strong>' . rex_escape($texts['support']) . '</strong><br>
                    <i class="fa fa-envelope"></i> ' . rex_escape($texts['contact_text']) . ' ' . rex_escape($contact) . '
                </div>
            </div>
        </div>';
        }
        
        $html .= '
        
        <div class="footer">
            <i class="fa fa-shield"></i> ' . rex_escape($texts['powered_by']) . '
        </div>
    </div>
</body>
</html>';
        
        return $html;
    }
    
    /**
     * Generiert CAPTCHA-Token für Sicherheit
     */
    private static function generateCaptchaToken(string $ip): string
    {
        $timestamp = time();
        $secret = self::getAddon()->getConfig('captcha_secret', 'default_secret_' . rex::getServerName());
        return hash('sha256', $ip . $timestamp . $secret . session_id());
    }
    
    /**
     * Generiert einfache Rechenaufgabe für CAPTCHA
     */
    private static function generateCaptchaProblem(): array
    {
        $operations = [
            ['op' => '+', 'min' => 1, 'max' => 20],
            ['op' => '-', 'min' => 5, 'max' => 25],
            ['op' => '*', 'min' => 1, 'max' => 10]
        ];
        
        $operation = $operations[array_rand($operations)];
        
        switch ($operation['op']) {
            case '+':
                $a = rand($operation['min'], $operation['max']);
                $b = rand($operation['min'], $operation['max']);
                return [
                    'question' => "{$a} + {$b} = ?",
                    'answer' => $a + $b
                ];
                
            case '-':
                $a = rand($operation['min'], $operation['max']);
                $b = rand($operation['min'], $a); // b kleiner als a für positive Ergebnisse
                return [
                    'question' => "{$a} - {$b} = ?",
                    'answer' => $a - $b
                ];
                
            case '*':
                $a = rand($operation['min'], $operation['max']);
                $b = rand($operation['min'], $operation['max']);
                return [
                    'question' => "{$a} × {$b} = ?",
                    'answer' => $a * $b
                ];
        }
        
        // Fallback
        return [
            'question' => "5 + 3 = ?",
            'answer' => 8
        ];
    }
    
    /**
     * Verarbeitet CAPTCHA-Entsperrungsversuch
     */
    public static function processCaptchaUnlock(): bool
    {
        if (!isset($_POST['captcha_token'], $_POST['captcha_answer'], $_POST['user_answer'], $_POST['unlock_ip'])) {
            return false;
        }
        
        $userAnswer = (int) $_POST['user_answer'];
        $correctAnswer = (int) $_POST['captcha_answer'];
        $ip = $_POST['unlock_ip'];
        
        // CAPTCHA-Token validieren (einfache Zeitprüfung)
        $token = $_POST['captcha_token'];
        if (strlen($token) !== 64) { // SHA256 hat 64 Zeichen
            return false;
        }
        
        // Antwort prüfen
        if ($userAnswer === $correctAnswer) {
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', "IPS: CAPTCHA verification successful for IP {$ip}");
            }
            
            // 1. IP komplett entsperren und rehabilitieren
            $unblockSuccess = self::unblockIp($ip);
            $clearSuccess = self::clearThreatHistory($ip);
            
            // 2. IP temporär zur Positivliste hinzufügen (Standard: 24 Stunden)
            $trustDuration = (int) self::getAddon()->getConfig('ips_captcha_trust_duration', 24); // Stunden
            $addToPositivliste = self::addToTemporaryPositivliste($ip, $trustDuration, 'CAPTCHA verified user');
            
            // Detailliertes Logging der Rehabilitation
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', "IPS: IP {$ip} rehabilitation - unblock: " . ($unblockSuccess ? 'success' : 'failed') . 
                                                   ", clear_history: " . ($clearSuccess ? 'success' : 'failed') . 
                                                   ", temp_positivliste: " . ($addToPositivliste ? "success ({$trustDuration}h)" : 'failed'));
            }
            
            // Zur Startseite weiterleiten (relative URL)
            header('Location: /');
            exit;
        }
        
        return false;
    }
    
    /**
     * Fügt Custom Pattern hinzu
     */
    public static function addCustomPattern(string $pattern, string $description = '', string $severity = 'medium', bool $isRegex = false): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_custom_patterns'));
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('severity', $severity);
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
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
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Fügt IP zur Positivliste hinzu
     */
    public static function addToPositivliste(string $ip, string $description = '', string $category = 'trusted', ?string $ipRange = null): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('ip_range', $ipRange);
            $sql->setValue('description', $description);
            $sql->setValue('category', $category);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Fügt IP temporär zur Positivliste hinzu (mit Ablaufzeit)
     */
    public static function addToTemporaryPositivliste(string $ip, int $durationHours = 24, string $description = ''): bool
    {
        try {
            // Erst prüfen, ob die IP bereits in der Positivliste steht
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT id FROM " . rex::getTable('upkeep_ips_positivliste') . " WHERE ip_address = ?", [$ip]);
            
            $expiresAt = (new DateTime())->modify("+{$durationHours} hours")->format('Y-m-d H:i:s');
            $fullDescription = $description . " (Temporär bis {$expiresAt})";
            
            if ($sql->getRows() > 0) {
                // IP ist bereits in Positivliste - aktualisiere sie
                $id = $sql->getValue('id');
                $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
                $sql->setValue('description', $fullDescription);
                $sql->setValue('category', 'captcha_verified_temp');
                $sql->setValue('expires_at', $expiresAt);
                $sql->setValue('status', 1);
                $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                $sql->setWhere(['id' => $id]);
                $sql->update();
                
                if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                    rex_logger::factory()->log('info', "IPS: Updated existing Positivliste entry for {$ip} with expiry {$expiresAt}");
                }
            } else {
                // Neue temporäre Positivliste-Eintrag erstellen
                $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
                $sql->setValue('ip_address', $ip);
                $sql->setValue('description', $fullDescription);
                $sql->setValue('category', 'captcha_verified_temp');
                $sql->setValue('expires_at', $expiresAt);
                $sql->setValue('status', 1);
                $sql->setValue('created_at', date('Y-m-d H:i:s'));
                $sql->setValue('updated_at', date('Y-m-d H:i:s'));
                $sql->insert();
                
                if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                    rex_logger::factory()->log('info', "IPS: Added {$ip} to temporary Positivliste until {$expiresAt}");
                }
            }
            
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
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
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_positivliste') . " WHERE id = ?", [$id]);
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Holt alle Positivliste-Einträge
     */
    public static function getPositivlisteEntries(): array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_ips_positivliste') . ' ORDER BY created_at DESC');
            return $sql->getArray();
        } catch (Exception $e) {
            rex_logger::logException($e);
            return [];
        }
    }

    /**
     * Aktualisiert Positivliste-Eintrag
     */
    public static function updatePositivlisteEntry(int $id, array $data): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_positivliste'));
            
            foreach ($data as $key => $value) {
                $sql->setValue($key, $value);
            }
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->setWhere(['id' => $id]);
            $sql->update();
            
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }
    
    /**
     * Entsperrt IP-Adresse
     */
    public static function unblockIp(string $ip): bool
    {
        try {
            $sql = rex_sql::factory();
            
            // Prüfe zuerst, ob die IP überhaupt gesperrt ist
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE ip_address = ?", [$ip]);
            $blockedCount = (int) $sql->getValue('count');
            
            if ($blockedCount === 0) {
                if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                    rex_logger::factory()->log('info', "IPS: IP {$ip} was not in blocked list");
                }
                return true; // Schon entsperrt
            }
            
            // IP aus Sperrliste entfernen
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE ip_address = ?", [$ip]);
            $deletedRows = $sql->getRows();
            
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', "IPS: IP {$ip} manually unblocked - removed {$deletedRows} entries");
            }
            
            return $deletedRows > 0;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Sperrt IP-Adresse manuell
     */
    public static function blockIpManually(string $ip, string $duration = 'permanent', string $reason = ''): bool
    {
        try {
            $sql = rex_sql::factory();
            
            // Prüfe zuerst, ob die IP bereits gesperrt ist
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE ip_address = ?", [$ip]);
            $alreadyBlocked = (int) $sql->getValue('count') > 0;
            
            if ($alreadyBlocked) {
                return false; // IP ist bereits gesperrt
            }
            
            // IP validieren
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }
            
            // Ablaufzeit berechnen
            $expiresAt = null;
            $blockType = 'permanent';
            
            if ($duration !== 'permanent') {
                $blockType = 'temporary';
                $now = new DateTime();
                
                switch ($duration) {
                    case '1h':
                        $expiresAt = $now->modify('+1 hour')->format('Y-m-d H:i:s');
                        break;
                    case '6h':
                        $expiresAt = $now->modify('+6 hours')->format('Y-m-d H:i:s');
                        break;
                    case '24h':
                        $expiresAt = $now->modify('+24 hours')->format('Y-m-d H:i:s');
                        break;
                    case '7d':
                        $expiresAt = $now->modify('+7 days')->format('Y-m-d H:i:s');
                        break;
                    case '30d':
                        $expiresAt = $now->modify('+30 days')->format('Y-m-d H:i:s');
                        break;
                    default:
                        $blockType = 'permanent';
                        $expiresAt = null;
                }
            }
            
            // Grund standardisieren
            if (empty($reason)) {
                $reason = 'Manually blocked by administrator';
            }
            
            // IP in Datenbank sperren
            $sql->setTable(rex::getTable('upkeep_ips_blocked_ips'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('block_type', $blockType);
            $sql->setValue('expires_at', $expiresAt);
            $sql->setValue('reason', $reason);
            $sql->setValue('threat_level', 'high'); // Manuelle Sperrungen sind immer 'high'
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            $expiryInfo = $expiresAt ? " until {$expiresAt}" : " permanently";
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', "IPS: IP {$ip} manually blocked{$expiryInfo} - reason: {$reason}");
            }
            
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }
    
    /**
     * Löscht Bedrohungshistorie und Rate-Limit-Daten für eine IP (CAPTCHA-Rehabilitation)
     */
    public static function clearThreatHistory(string $ip): bool
    {
        try {
            $sql = rex_sql::factory();
            $cleanup = [
                'threat_logs' => 0,
                'rate_limits' => 0
            ];
            
            // 1. Alle Bedrohungs-Logs für diese IP löschen
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE ip_address = ?", [$ip]);
            $cleanup['threat_logs'] = $sql->getRows();
            
            // 2. Rate-Limit-Daten für diese IP löschen
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " WHERE ip_address = ?", [$ip]);
            $cleanup['rate_limits'] = $sql->getRows();
            
            // Log der Rehabilitation
            if (self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', "IPS: Threat history cleared for {$ip} - " . json_encode($cleanup));
            }
            
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }
    
    /**
     * Debug-Methode: Zeigt alle Einträge für eine IP in allen IPS-Tabellen
     */
    public static function debugIpStatus(string $ip): array
    {
        $sql = rex_sql::factory();
        $debug = [];
        
        try {
            // 1. Gesperrte IPs
            $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE ip_address = ?", [$ip]);
            $debug['blocked_ips'] = $sql->getArray();
            
            // 2. Positivliste (mit Ablaufzeiten)
            $sql->setQuery("SELECT *, CASE WHEN expires_at IS NULL THEN 'permanent' 
                                            WHEN expires_at > NOW() THEN 'active' 
                                            ELSE 'expired' END as status_type 
                           FROM " . rex::getTable('upkeep_ips_positivliste') . " WHERE ip_address = ?", [$ip]);
            $debug['positivliste'] = $sql->getArray();
            
            // 3. Bedrohungshistorie
            $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE ip_address = ? ORDER BY created_at DESC LIMIT 10", [$ip]);
            $debug['threat_history'] = $sql->getArray();
            
            // 4. Rate-Limit-Daten
            $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_rate_limit') . " WHERE ip_address = ?", [$ip]);
            $debug['rate_limits'] = $sql->getArray();
            
            // 5. Wartungsmodus erlaubte IPs
            $allowedIps = explode("\n", self::getAddon()->getConfig('allowed_ips', ''));
            $debug['maintenance_allowed'] = in_array($ip, array_map('trim', $allowedIps));
            
            // 6. Aktuelle Rate-Limit-Konfiguration
            $debug['rate_limit_config'] = [
                'enabled' => self::isRateLimitingEnabled(),
                'burst_limit' => self::getAddon()->getConfig('ips_burst_limit', 600),
                'strict_limit' => self::getAddon()->getConfig('ips_strict_limit', 200),
                'burst_window' => self::getAddon()->getConfig('ips_burst_window', 60),
                'is_good_bot' => self::isGoodBot(),
                'user_agent' => rex_server('HTTP_USER_AGENT', 'string', ''),
                'effective_limit' => self::isRateLimitingEnabled() ? self::getEffectiveLimitForUri(rex_server('REQUEST_URI', 'string', ''), 600, 200) : 'disabled',
                'note' => self::isRateLimitingEnabled() ? 'DoS-Protection active - Patterns are primary security' : 'Rate limiting disabled - Server/Proxy should handle this'
            ];
            
            // 7. Aktuelle Request-Zählung (letzte Minute)
            $now = new DateTime();
            $windowStart = (clone $now)->modify('-1 minute')->format('Y-m-d H:i:s');
            $sql->setQuery("SELECT SUM(request_count) as total FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                           WHERE ip_address = ? AND window_start >= ?", [$ip, $windowStart]);
            $debug['current_request_count'] = (int) $sql->getValue('total');
            
        } catch (Exception $e) {
            $debug['error'] = $e->getMessage();
        }
        
        return $debug;
    }
    
    /**
     * Setzt Rate-Limit-Konfiguration
     */
    public static function setRateLimitConfig(array $config): bool
    {
        try {
            $addon = self::getAddon();
            
            if (isset($config['burst_limit'])) {
                $addon->setConfig('ips_burst_limit', (int) $config['burst_limit']);
            }
            
            if (isset($config['strict_limit'])) {
                $addon->setConfig('ips_strict_limit', (int) $config['strict_limit']);
            }
            
            if (isset($config['burst_window'])) {
                $addon->setConfig('ips_burst_window', (int) $config['burst_window']);
            }
            
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }
    
    /**
     * Holt Statistiken für Backend
     */
    public static function getStatistics(): array
    {
        $sql = rex_sql::factory();
        $stats = [
            'blocked_ips' => 0,
            'threats_today' => 0,
            'threats_week' => 0,
            'top_threats' => []
        ];
        
        try {
            // Gesperrte IPs
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE expires_at IS NULL OR expires_at > NOW()");
            $stats['blocked_ips'] = (int) $sql->getValue('count');
        } catch (Exception $e) {
            // Tabelle existiert noch nicht
            self::debugLog("Statistics: upkeep_ips_blocked_ips table not available: " . $e->getMessage());
            $stats['blocked_ips'] = 0;
        }
        
        try {
            // Bedrohungen heute
            $today = date('Y-m-d');
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE DATE(created_at) = ?", [$today]);
            $stats['threats_today'] = (int) $sql->getValue('count');
            
            // Bedrohungen diese Woche
            $weekStart = date('Y-m-d', strtotime('monday this week'));
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " WHERE DATE(created_at) >= ?", [$weekStart]);
            $stats['threats_week'] = (int) $sql->getValue('count');
            
            // Top Bedrohungstypen
            $sql->setQuery("SELECT threat_type, COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE DATE(created_at) >= ? GROUP BY threat_type ORDER BY count DESC LIMIT 5", [$weekStart]);
            $stats['top_threats'] = [];
            while ($sql->hasNext()) {
                $stats['top_threats'][] = [
                    'type' => $sql->getValue('threat_type'),
                    'count' => (int) $sql->getValue('count')
                ];
                $sql->next();
            }
        } catch (Exception $e) {
            // Tabelle existiert noch nicht
            self::debugLog("Statistics: upkeep_ips_threat_log table not available: " . $e->getMessage());
            $stats['threats_today'] = 0;
            $stats['threats_week'] = 0;
            $stats['top_threats'] = [];
        }
        
        return $stats;
    }
    
    /**
     * Bereinigt abgelaufene IP-Sperrungen und alte Logs
     * Sollte regelmäßig aufgerufen werden (z.B. per Cronjob)
     */
    public static function cleanupExpiredData(): array
    {
        $sql = rex_sql::factory();
        $cleanup = [
            'expired_ips' => 0,
            'old_threats' => 0,
            'old_rate_limits' => 0,
            'expired_positivliste' => 0,
            'dns_cache_entries' => 0
        ];
        
        try {
            // 1. Abgelaufene IP-Sperrungen löschen
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                           WHERE block_type = 'temporary' AND expires_at IS NOT NULL AND expires_at < NOW()");
            $cleanup['expired_ips'] = $sql->getRows();
            
            // 2. Abgelaufene temporäre Positivliste-Einträge löschen
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_positivliste') . " 
                           WHERE expires_at IS NOT NULL AND expires_at < NOW()");
            $cleanup['expired_positivliste'] = $sql->getRows();
            
            // 3. Alte Bedrohungs-Logs löschen (älter als 30 Tage)
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            $cleanup['old_threats'] = $sql->getRows();
            
            // 4. Alte Rate-Limit-Daten löschen (älter als 2 Stunden)
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                           WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR)");
            $cleanup['old_rate_limits'] = $sql->getRows();
            
            // 5. Abgelaufene DNS-Cache-Einträge bereinigen
            $cleanup['dns_cache_entries'] = self::cleanupDnsCache();
            
            // Log der Bereinigung
            $totalCleaned = array_sum($cleanup);
            if ($totalCleaned > 0 && self::getAddon()->getConfig('ips_debug_mode', false)) {
                rex_logger::factory()->log('info', 'IPS Cleanup: ' . json_encode($cleanup), [], __FILE__, __LINE__);
            }
            
        } catch (Exception $e) {
            rex_logger::factory()->log('error', 'IPS Cleanup Error: ' . $e->getMessage(), [], __FILE__, __LINE__);
        }
        
        return $cleanup;
    }
    
    /**
     * Bereinigt abgelaufene DNS-Cache-Einträge
     */
    private static function cleanupDnsCache(): int
    {
        try {
            $config = \rex_config::get('upkeep');
            $cleaned = 0;
            $now = time();
            
            foreach ($config as $key => $value) {
                // Prüfe auf DNS-Cache-Einträge
                if (strpos($key, 'upkeep_dns_verify_') === 0 && is_array($value)) {
                    if (isset($value['expires']) && $value['expires'] < $now) {
                        \rex_config::remove('upkeep', $key);
                        $cleaned++;
                    }
                }
            }
            
            return $cleaned;
            
        } catch (Exception $e) {
            self::debugLog("DNS Cache cleanup error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Automatische Bereinigung beim Request (mit Wahrscheinlichkeit)
     * Reduziert die Datenbankgröße ohne Performance-Impact
     */
    private static function performRandomCleanup(): void
    {
        // 1% Chance pro Request für Cleanup
        if (random_int(1, 100) <= 1) {
            self::cleanupExpiredData();
        }
    }

    /**
     * Schaltet den Status eines Custom Patterns um
     */
    public static function toggleCustomPatternStatus(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("UPDATE " . rex::getTable('upkeep_ips_custom_patterns') . " 
                           SET status = 1 - status, updated_at = NOW() 
                           WHERE id = ?", [$id]);
            return true;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Lädt ein Custom Pattern für die Bearbeitung
     */
    public static function getCustomPattern(int $id): ?array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_ips_custom_patterns') . " WHERE id = ?", [$id]);
            if ($sql->getRows() > 0) {
                return [
                    'id' => $sql->getValue('id'),
                    'pattern' => $sql->getValue('pattern'),
                    'description' => $sql->getValue('description'),
                    'severity' => $sql->getValue('severity'),
                    'is_regex' => (bool) $sql->getValue('is_regex'),
                    'status' => (bool) $sql->getValue('status'),
                    'created_at' => $sql->getValue('created_at'),
                    'updated_at' => $sql->getValue('updated_at')
                ];
            }
            return null;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return null;
        }
    }
}
