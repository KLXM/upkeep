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
    
    // Standard-Patterns für verschiedene CMS und Angriffe
    private static array $defaultPatterns = [
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
            '--',
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
        
        // DEBUG: Logging für Troubleshooting
        rex_logger::factory()->log('debug', "IPS Check: IP={$clientIp}, URI={$requestUri}, Active=" . (self::isActive() ? 'true' : 'false'));
        
        // Whitelist-Prüfung
        if (self::isOnPositivliste($clientIp)) {
            rex_logger::factory()->log('debug', "IPS: IP {$clientIp} is on Positivliste - allowing");
            return;
        }
        
        // Bereits gesperrte IP?
        if (self::isBlocked($clientIp)) {
            rex_logger::factory()->log('info', "IPS: IP {$clientIp} is already blocked");
            self::blockRequest('IP bereits gesperrt', $clientIp, $requestUri);
        }
        
        // Pattern-Checks durchführen
        $threat = self::analyzeRequest($requestUri, $userAgent, $referer);
        
        if ($threat) {
            rex_logger::factory()->log('warning', "IPS: Threat detected from {$clientIp} - " . json_encode($threat));
            self::handleThreat($threat, $clientIp, $requestUri, $userAgent);
        } else {
            rex_logger::factory()->log('debug', "IPS: No threat detected for {$clientIp}");
        }
        
        // Rate Limiting prüfen
        if (self::isRateLimitExceeded($clientIp)) {
            rex_logger::factory()->log('warning', "IPS: Rate limit exceeded for {$clientIp}");
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
        // Logging
        self::logThreat($threat, $ip, $uri, $userAgent);
        
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
     * Blockiert Request und zeigt 403-Seite
     */
    private static function blockRequest(string $reason, string $ip, string $uri): void
    {
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
    private static function isActive(): bool
    {
        return (bool) self::getAddon()->getConfig('ips_active', false);
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
                rex_logger::factory()->log('debug', "IPS: IP {$ip} found in maintenance allowed_ips");
                return true;
            }
        }
        
        // Prüfe IPS-Positivliste aus Datenbank
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT ip_address, ip_range FROM ' . rex::getTable('upkeep_ips_positivliste') . ' WHERE status = 1');
            
            rex_logger::factory()->log('debug', "IPS: Checking {$ip} against " . $sql->getRows() . " Positivliste entries");
            
            while ($sql->hasNext()) {
                $positivlisteIp = $sql->getValue('ip_address');
                $ipRange = $sql->getValue('ip_range');
                
                // Exakte IP-Übereinstimmung
                if ($positivlisteIp && $positivlisteIp === $ip) {
                    rex_logger::factory()->log('debug', "IPS: IP {$ip} found in Positivliste (exact match)");
                    return true;
                }
                
                // CIDR-Bereich prüfen
                if ($ipRange && self::ipInRange($ip, $ipRange)) {
                    rex_logger::factory()->log('debug', "IPS: IP {$ip} found in Positivliste (CIDR range: {$ipRange})");
                    return true;
                }
                
                $sql->next();
            }
        } catch (Exception $e) {
            rex_logger::factory()->log('error', "IPS: Error checking Positivliste: " . $e->getMessage());
            // Fehler beim Datenbankzugriff ignorieren (Tabelle existiert möglicherweise noch nicht)
        }
        
        rex_logger::factory()->log('debug', "IPS: IP {$ip} NOT found in any Positivliste");
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
     * Prüft Rate Limiting
     */
    private static function isRateLimitExceeded(string $ip): bool
    {
        $sql = rex_sql::factory();
        $now = new DateTime();
        $windowStart = $now->modify('-1 minute')->format('Y-m-d H:i:s');
        
        // Requests in letzter Minute zählen
        $query = "SELECT SUM(request_count) as total FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                  WHERE ip_address = ? AND window_start >= ?";
        
        $sql->setQuery($query, [$ip, $windowStart]);
        $requestCount = (int) $sql->getValue('total');
        
        // Auch aktuellen Request miteinbeziehen
        self::updateRateLimit($ip);
        
        // Limits aus Config holen
        $burstLimit = (int) self::getAddon()->getConfig('ips_burst_limit', 10);
        
        return $requestCount >= $burstLimit;
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
        $cleanupTime = $now->modify('-1 hour')->format('Y-m-d H:i:s');
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
        
        // Auch ins REDAXO-Log schreiben
        rex_logger::factory()->log('error', "IPS: Threat detected from {$ip}: {$threat['type']} - {$threat['pattern']}");
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
        
        $html = '<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>' . rex_escape($title) . '</title>
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
        .panel-heading {
            padding: 10px 15px;
            border-bottom: 1px solid transparent;
            border-top-left-radius: 3px;
            border-top-right-radius: 3px;
            background-color: #d9534f;
            border-color: #d43f3a;
            color: white;
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
        .fa {
            margin-right: 5px;
        }
        .fa-shield:before { content: "🛡️"; }
        .fa-exclamation-triangle:before { content: "⚠️"; }
        .fa-clock-o:before { content: "🕐"; }
        .fa-info-circle:before { content: "ℹ️"; }
        .fa-envelope:before { content: "✉️"; }
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
        .footer {
            margin-top: 30px;
            padding: 15px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            font-size: 12px;
            color: #6c757d;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel panel-danger">
            <div class="panel-heading">
                <h1><i class="fa fa-shield"></i> ' . rex_escape($title) . '</h1>
            </div>
            <div class="panel-body">
                <div class="alert alert-danger">
                    <i class="fa fa-exclamation-triangle"></i>
                    <strong>Sicherheitshinweis:</strong> ' . rex_escape($message) . '
                </div>
                
                <div class="detail-row">
                    <span class="detail-label">Grund:</span>
                    ' . rex_escape($reason) . '
                </div>
                
                <div class="detail-row">
                    <span class="detail-label">Ihre IP-Adresse:</span>
                    <strong>' . rex_escape($ip) . '</strong>
                </div>
                
                <div class="detail-row">
                    <span class="detail-label"><i class="fa fa-clock-o"></i> Zeitpunkt:</span>
                    ' . date('d.m.Y H:i:s') . '
                </div>';
        
        if (!empty($contact)) {
            $html .= '
                <div class="alert alert-info" style="margin-top: 20px;">
                    <i class="fa fa-info-circle"></i>
                    <strong>Support:</strong><br>
                    <i class="fa fa-envelope"></i> Bei Fragen wenden Sie sich an: ' . rex_escape($contact) . '
                </div>';
        }
        
        $html .= '
            </div>
        </div>
        
        <div class="footer">
            <i class="fa fa-shield"></i> Powered by REDAXO Upkeep AddOn - Intrusion Prevention System
        </div>
    </div>
</body>
</html>';
        
        return $html;
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
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_custom_patterns') . " WHERE id = ?", [$id]);
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
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE ip_address = ?", [$ip]);
            rex_logger::factory()->log('info', "IPS: IP {$ip} manually unblocked");
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
        $stats = [];
        
        // Gesperrte IPs
        $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_blocked_ips') . " WHERE expires_at IS NULL OR expires_at > NOW()");
        $stats['blocked_ips'] = (int) $sql->getValue('count');
        
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
            'old_rate_limits' => 0
        ];
        
        try {
            // 1. Abgelaufene IP-Sperrungen löschen
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                           WHERE block_type = 'temporary' AND expires_at IS NOT NULL AND expires_at < NOW()");
            $cleanup['expired_ips'] = $sql->getRows();
            
            // 2. Alte Bedrohungs-Logs löschen (älter als 30 Tage)
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            $cleanup['old_threats'] = $sql->getRows();
            
            // 3. Alte Rate-Limit-Daten löschen (älter als 2 Stunden)
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                           WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR)");
            $cleanup['old_rate_limits'] = $sql->getRows();
            
            // Log der Bereinigung
            if ($cleanup['expired_ips'] > 0 || $cleanup['old_threats'] > 0 || $cleanup['old_rate_limits'] > 0) {
                rex_logger::factory()->log('info', 'IPS Cleanup: ' . json_encode($cleanup), [], __FILE__, __LINE__);
            }
            
        } catch (Exception $e) {
            rex_logger::factory()->log('error', 'IPS Cleanup Error: ' . $e->getMessage(), [], __FILE__, __LINE__);
        }
        
        return $cleanup;
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
}
