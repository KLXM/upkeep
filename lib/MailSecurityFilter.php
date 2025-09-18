<?php

namespace KLXM\Upkeep;

use DateTime;
use Exception;
use rex;
use rex_addon;
use rex_config;
use rex_escape;
use rex_logger;
use rex_sql;
use rex_extension_point;

/**
 * Mail Security Filter für PHPMailer Integration
 * 
 * Erweitert das Upkeep IPS-System um E-Mail-spezifische Sicherheitsfilter:
 * - Badword-Filter für E-Mail-Inhalte
 * - Spam-Erkennung und Rate-Limiting für E-Mail-Versand
 * - Integration in das bestehende Threat-Logging System
 * - Blacklist-Management für E-Mail-Adressen und Domains
 */
class MailSecurityFilter
{
    private static ?rex_addon $addon = null;
    
    // Rate-Limiting für E-Mail-Versand (pro IP/Session)
    private static array $mailRateLimits = [
        'per_minute' => 10,  // Max 10 E-Mails pro Minute
        'per_hour' => 50,    // Max 50 E-Mails pro Stunde  
        'per_day' => 200     // Max 200 E-Mails pro Tag
    ];
    
    // Verdächtige Patterns in E-Mail-Inhalten
    private static array $spamPatterns = [
        // Typische Spam-Indikatoren
        'high_risk' => [
            '/click here now/i',
            '/urgent.{0,20}action.{0,20}required/i',
            '/congratulations.{0,30}winner/i',
            '/claim.{0,20}prize/i',
            '/limited.{0,20}time.{0,20}offer/i',
            '/act.{0,20}now/i',
            '/millions?.{0,20}dollars?/i',
            '/nigerian.{0,20}prince/i',
            '/inheritance.{0,30}fund/i',
            '/covid.{0,20}vaccine.{0,20}scam/i',
        ],
        'medium_risk' => [
            '/free.{0,20}money/i',
            '/work.{0,20}from.{0,20}home/i',
            '/make.{0,20}money.{0,20}fast/i',
            '/guaranteed.{0,20}income/i',
            '/no.{0,20}investment/i',
            '/100%.{0,20}free/i',
            '/risk.{0,20}free/i',
            '/satisfaction.{0,20}guaranteed/i',
        ],
        'low_risk' => [
            '/unsubscribe/i',
            '/special.{0,20}offer/i',
            '/discount/i',
            '/sale/i',
        ]
    ];
    
    // Code-Injection Patterns (kritische Sicherheitsbedrohungen)
    private static array $codeInjectionPatterns = [
        'critical' => [
            // JavaScript Injection
            '/<script[^>]*>/i',
            '/<\/script>/i',
            '/javascript:/i',
            '/on(load|click|error|focus|blur|change|submit|mouseover)\s*=/i',
            '/eval\s*\(/i',
            '/alert\s*\(/i',
            '/document\.(write|cookie|location)/i',
            '/window\.(open|location)/i',
            
            // PHP Code Injection
            '/<\?php/i',
            '/<\?=/i',
            '/<\?\s/i',
            '/\?>/i',
            '/exec\s*\(/i',
            '/system\s*\(/i',
            '/shell_exec\s*\(/i',
            '/passthru\s*\(/i',
            '/file_get_contents\s*\(/i',
            '/file_put_contents\s*\(/i',
            '/fopen\s*\(/i',
            '/include\s+/i',
            '/require\s+/i',
            
            // SQL Injection Patterns
            '/union\s+select/i',
            '/drop\s+table/i',
            '/truncate\s+table/i',
            '/delete\s+from/i',
            '/insert\s+into/i',
            '/update\s+.*set/i',
            '/alter\s+table/i',
            '/create\s+table/i',
            
            // Server-Side Includes
            '/<!--\s*#(exec|include|echo|config)/i',
            
            // Command Injection
            '/\|\s*(ls|cat|grep|find|wget|curl)/i',
            '/&&\s*(rm|mv|cp|chmod)/i',
            '/;\s*(whoami|id|uname)/i',
        ],
        'high' => [
            // Potential XSS
            '/<iframe[^>]*>/i',
            '/<object[^>]*>/i',
            '/<embed[^>]*>/i',
            '/<link[^>]*>/i',
            '/<meta[^>]*>/i',
            '/<base[^>]*>/i',
            '/<form[^>]*>/i',
            
            // Data URIs (can contain code)
            '/data:\s*[^,]*,/i',
            
            // Suspicious functions
            '/setTimeout\s*\(/i',
            '/setInterval\s*\(/i',
            '/Function\s*\(/i',
        ],
        'medium' => [
            // Suspicious HTML tags
            '/<style[^>]*>/i',
            '/<\/style>/i',
            '/expression\s*\(/i',
            '/behavior\s*:/i',
            
            // Suspicious attributes
            '/style\s*=.*expression/i',
            '/style\s*=.*javascript/i',
        ]
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
     * Liefert Mail-Security-Statistiken für das Dashboard
     */
    public static function getDashboardStats(): array
    {
        $addon = self::getAddon();
        $sql = rex_sql::factory();
        $stats = [
            'active' => self::isMailSecurityActive(),
            'threats_24h' => 0,
            'blocked_emails_24h' => 0,
            'badwords_count' => 0,
            'blacklist_count' => 0,
            'rate_limit_blocks_24h' => 0,
            'top_threats' => []
        ];

        try {
            // Mail-Bedrohungen der letzten 24h
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE threat_type LIKE 'mail_%' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            if ($sql->getRows() > 0) {
                $stats['threats_24h'] = (int) $sql->getValue('count');
            }

            // Blockierte E-Mails durch Rate-Limiting (24h)
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_mail_rate_limit') . " 
                           WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            if ($sql->getRows() > 0) {
                $stats['rate_limit_blocks_24h'] = (int) $sql->getValue('count');
            }

            // Aktive Badwords
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE status = 1");
            if ($sql->getRows() > 0) {
                $stats['badwords_count'] = (int) $sql->getValue('count');
            }

            // Aktive Blacklist-Einträge
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_mail_blacklist') . " 
                           WHERE status = 1 AND (expires_at IS NULL OR expires_at > NOW())");
            if ($sql->getRows() > 0) {
                $stats['blacklist_count'] = (int) $sql->getValue('count');
            }

            // Top Mail-Bedrohungen der letzten 7 Tage
            $sql->setQuery("SELECT 
                               threat_type, 
                               COUNT(*) as count, 
                               severity,
                               MAX(created_at) as last_occurrence
                           FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE threat_type LIKE 'mail_%' AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                           GROUP BY threat_type, severity
                           ORDER BY count DESC, severity DESC 
                           LIMIT 5");
            
            while ($sql->hasNext()) {
                $threatType = str_replace('mail_', '', $sql->getValue('threat_type'));
                $stats['top_threats'][] = [
                    'type' => ucwords(str_replace('_', ' ', $threatType)),
                    'count' => (int) $sql->getValue('count'),
                    'severity' => $sql->getValue('severity'),
                    'last_occurrence' => $sql->getValue('last_occurrence')
                ];
                $sql->next();
            }

            // Gesamt blockierte E-Mails (Schätzung)
            $stats['blocked_emails_24h'] = $stats['threats_24h'] + $stats['rate_limit_blocks_24h'];

        } catch (Exception $e) {
            // Tabellen existieren möglicherweise noch nicht - Standardwerte verwenden
        }

        return $stats;
    }

    /**
     * Hauptfilter-Funktion für PHPMailer PHPMAILER_PRE_SEND Extension Point
     * 
     * @param rex_extension_point $ep Extension Point mit PHPMailer-Instanz
     * @return mixed Kann den Versand durch Werfen einer Exception stoppen
     */
    public static function filterMail(rex_extension_point $ep): mixed
    {
        if (!self::isMailSecurityActive()) {
            return $ep->getSubject();
        }

        $mailer = $ep->getSubject();
        $clientIp = self::getClientIp();
        
        try {
            // 1. Rate-Limiting prüfen
            if (self::isMailRateLimitExceeded($clientIp)) {
                self::logMailThreat('rate_limit_exceeded', $clientIp, [
                    'severity' => 'high',
                    'pattern' => 'Email rate limit exceeded',
                    'action' => 'blocked'
                ]);
                
                throw new \Exception('E-Mail-Rate-Limit überschritten. Versuchen Sie es später erneut.');
            }

                        // 2. IP-Blacklist prüfen
            $ipThreat = self::checkIpBlacklist($clientIp);
            if ($ipThreat) {
                self::logMailThreat('blacklisted_ip', $clientIp, $ipThreat);
                
                if ($ipThreat['severity'] === 'critical' || $ipThreat['severity'] === 'high') {
                    throw new \Exception('Ihre IP-Adresse ist gesperrt: ' . $ipThreat['reason']);
                }
            }

            // 3. Empfänger-Blacklist prüfen
            $recipientThreat = self::checkRecipientBlacklist($mailer);
            if ($recipientThreat) {
                self::logMailThreat('blacklisted_recipient', $clientIp, $recipientThreat);
                
                if ($recipientThreat['severity'] === 'critical') {
                    throw new \Exception('E-Mail-Adresse oder Domain ist gesperrt.');
                }
            }

            // 3. Absender-Domain validieren
            $senderThreat = self::validateSenderDomain($mailer);
            if ($senderThreat) {
                self::logMailThreat('invalid_sender_domain', $clientIp, $senderThreat);
                
                if ($senderThreat['severity'] === 'high') {
                    throw new \Exception('Absender-Domain ist nicht autorisiert.');
                }
            }

            // 4. Code-Injection-Schutz (JavaScript, PHP, SQL, etc.)
            $injectionThreat = self::scanForCodeInjection($mailer);
            if ($injectionThreat) {
                self::logMailThreat('code_injection_detected', $clientIp, $injectionThreat);
                
                // Bei Code-Injection sofort blockieren und IP zur IPS-Bedrohung hinzufügen
                self::escalateToIPS($clientIp, $injectionThreat);
                
                throw new \Exception('E-Mail-Inhalt enthält potenziell schädlichen Code.');
            }

            // 5. Badword-Filter auf E-Mail-Inhalt anwenden
            $contentThreat = self::scanMailContent($mailer);
            if ($contentThreat) {
                self::logMailThreat('badword_detected', $clientIp, $contentThreat);
                
                if ($contentThreat['severity'] === 'critical') {
                    // Kritische Badwords auch an IPS eskalieren
                    self::escalateToIPS($clientIp, $contentThreat);
                    throw new \Exception('E-Mail-Inhalt enthält unzulässige Begriffe.');
                } elseif ($contentThreat['severity'] === 'high') {
                    throw new \Exception('E-Mail-Inhalt wurde als verdächtig eingestuft.');
                } else {
                    // Medium/Low: Nur loggen, weiterleiten
                    self::debugLog("Mail content flagged but allowed: " . $contentThreat['pattern']);
                }
            }

            // 6. Spam-Patterns prüfen
            $spamThreat = self::checkSpamPatterns($mailer);
            if ($spamThreat) {
                self::logMailThreat('spam_pattern_detected', $clientIp, $spamThreat);
                
                if ($spamThreat['severity'] === 'high') {
                    // Wiederholte Spam-Versuche an IPS eskalieren
                    if (self::getSpamAttemptCount($clientIp) >= 3) {
                        self::escalateToIPS($clientIp, $spamThreat);
                    }
                    throw new \Exception('E-Mail wurde als Spam klassifiziert.');
                }
            }

            // 7. Rate-Limiting Counter aktualisieren (nur bei erfolgreichen Prüfungen)
            if (self::isMailRateLimitingEnabled()) {
                self::updateMailRateLimit($clientIp);
            }

            // 8. Erfolgreiche Filterung loggen (nur bei Debug-Modus)
            if (self::getAddon()->getConfig('mail_security_debug', false)) {
                self::debugLog("Mail security check passed for IP: {$clientIp}");
            }

        } catch (Exception $e) {
            // Exception weiterwerfen - stoppt den E-Mail-Versand
            throw $e;
        }

        return $mailer;
    }

    /**
     * Prüft ob Mail-Security aktiviert ist
     */
    public static function isMailSecurityActive(): bool
    {
        return (bool) self::getAddon()->getConfig('mail_security_active', false);
    }

    /**
     * Prüft ob Mail-Rate-Limiting aktiviert ist
     */
    public static function isMailRateLimitingEnabled(): bool
    {
        return (bool) self::getAddon()->getConfig('mail_rate_limiting_enabled', false);
    }

    /**
     * Prüft Rate-Limit für E-Mail-Versand
     */
    private static function isMailRateLimitExceeded(string $ip): bool
    {
        if (!self::isMailRateLimitingEnabled()) {
            return false;
        }

        $sql = rex_sql::factory();
        $now = new DateTime();
        
        // Limits aus Config laden
        $perMinute = (int) self::getAddon()->getConfig('mail_rate_limit_per_minute', self::$mailRateLimits['per_minute']);
        $perHour = (int) self::getAddon()->getConfig('mail_rate_limit_per_hour', self::$mailRateLimits['per_hour']);
        $perDay = (int) self::getAddon()->getConfig('mail_rate_limit_per_day', self::$mailRateLimits['per_day']);

        // Prüfe verschiedene Zeitfenster
        $timeWindows = [
            'minute' => [$perMinute, '-1 minute'],
            'hour' => [$perHour, '-1 hour'],
            'day' => [$perDay, '-1 day']
        ];

        foreach ($timeWindows as $window => [$limit, $timeModifier]) {
            $windowStart = (clone $now)->modify($timeModifier)->format('Y-m-d H:i:s');
            
            $query = "SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_mail_rate_limit') . " 
                      WHERE ip_address = ? AND created_at >= ?";
            
            $sql->setQuery($query, [$ip, $windowStart]);
            $count = (int) $sql->getValue('count');
            
            if ($count >= $limit) {
                self::debugLog("Mail rate limit exceeded for {$ip}: {$count}/{$limit} in {$window}");
                return true;
            }
        }

        return false;
    }

    /**
     * Aktualisiert Mail-Rate-Limit Counter
     */
    private static function updateMailRateLimit(string $ip): void
    {
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_mail_rate_limit'));
        $sql->setValue('ip_address', $ip);
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->insert();

        // Alte Einträge aufräumen (älter als 24 Stunden)
        $cleanupTime = (new DateTime())->modify('-24 hours')->format('Y-m-d H:i:s');
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_rate_limit') . " WHERE created_at < ?", [$cleanupTime]);
    }

    /**
     * Prüft Empfänger gegen Blacklist
     */
    private static function checkRecipientBlacklist($mailer): ?array
    {
        $recipients = [];
        
        // Alle Empfänger-Typen sammeln
        foreach (['getAllRecipientAddresses'] as $method) {
            if (method_exists($mailer, $method)) {
                $recipients = array_merge($recipients, $mailer->$method());
            }
        }
        
        // Alternativ: Direkt auf Properties zugreifen falls Methoden nicht verfügbar
        if (empty($recipients)) {
            if (isset($mailer->to) && is_array($mailer->to)) {
                foreach ($mailer->to as $recipient) {
                    $recipients[] = isset($recipient[0]) ? $recipient[0] : $recipient;
                }
            }
            if (isset($mailer->cc) && is_array($mailer->cc)) {
                foreach ($mailer->cc as $recipient) {
                    $recipients[] = isset($recipient[0]) ? $recipient[0] : $recipient;
                }
            }
            if (isset($mailer->bcc) && is_array($mailer->bcc)) {
                foreach ($mailer->bcc as $recipient) {
                    $recipients[] = isset($recipient[0]) ? $recipient[0] : $recipient;
                }
            }
        }

        // Prüfe jeden Empfänger gegen Blacklist
        foreach ($recipients as $email) {
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                continue;
            }

            $threat = self::checkEmailBlacklist($email);
            if ($threat) {
                $threat['email'] = $email;
                return $threat;
            }
        }

        return null;
    }

    /**
     * Prüft einzelne E-Mail-Adresse gegen Blacklist
     */
    private static function checkEmailBlacklist(string $email): ?array
    {
        $sql = rex_sql::factory();
        
        // Domain extrahieren
        $domain = substr(strrchr($email, "@"), 1);
        
        // Prüfe gegen E-Mail-Blacklist
        $query = "SELECT * FROM " . rex::getTable('upkeep_mail_blacklist') . " 
                  WHERE (email_address = ? OR domain = ? OR pattern = ?) 
                  AND status = 1 
                  AND (expires_at IS NULL OR expires_at > NOW())
                  ORDER BY severity DESC LIMIT 1";
        
        $sql->setQuery($query, [$email, $domain, $domain]);
        
        if ($sql->getRows() > 0) {
            return [
                'type' => 'blacklisted_' . $sql->getValue('blacklist_type'),
                'severity' => $sql->getValue('severity'),
                'pattern' => $sql->getValue('email_address') ?: $sql->getValue('domain'),
                'reason' => $sql->getValue('reason')
            ];
        }

        return null;
    }

    /**
     * Prüft IP-Adresse gegen Blacklist
     */
    private static function checkIpBlacklist(string $clientIp): ?array
    {
        $sql = rex_sql::factory();
        
        // Direkte IP-Prüfung und Pattern-Matching
        $query = "SELECT * FROM " . rex::getTable('upkeep_mail_blacklist') . " 
                  WHERE blacklist_type = 'ip' 
                  AND (ip_address = ? OR ? LIKE REPLACE(pattern, '*', '%'))
                  AND status = 1 
                  AND (expires_at IS NULL OR expires_at > NOW())
                  ORDER BY severity DESC LIMIT 1";
        
        $sql->setQuery($query, [$clientIp, $clientIp]);
        
        if ($sql->getRows() > 0) {
            return [
                'type' => 'blacklisted_ip',
                'severity' => $sql->getValue('severity'),
                'pattern' => $sql->getValue('ip_address') ?: $sql->getValue('pattern'),
                'reason' => $sql->getValue('reason') ?: 'IP-Adresse ist gesperrt',
                'ip' => $clientIp
            ];
        }

        // Zusätzlich prüfen ob IP bereits im IPS-System gesperrt ist
        $ipsBlockedQuery = "SELECT severity, reason FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                            WHERE ip_address = ? AND status = 1";
        
        try {
            $sql->setQuery($ipsBlockedQuery, [$clientIp]);
            if ($sql->getRows() > 0) {
                return [
                    'type' => 'ips_blocked_ip',
                    'severity' => $sql->getValue('severity') ?: 'high',
                    'pattern' => $clientIp,
                    'reason' => $sql->getValue('reason') ?: 'IP durch IPS-System gesperrt',
                    'ip' => $clientIp
                ];
            }
        } catch (Exception $e) {
            // IPS-Tabelle existiert möglicherweise nicht - ignorieren
        }

        return null;
    }

    /**
     * Validiert Absender-Domain
     */
    private static function validateSenderDomain($mailer): ?array
    {
        $fromEmail = $mailer->From;
        
        if (empty($fromEmail) || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
            return [
                'type' => 'invalid_sender_format',
                'severity' => 'medium',
                'pattern' => $fromEmail
            ];
        }

        $domain = substr(strrchr($fromEmail, "@"), 1);
        
        // Prüfe gegen erlaubte Domains (Whitelist-Modus)
        $allowedDomains = self::getAllowedSenderDomains();
        if (!empty($allowedDomains) && !in_array($domain, $allowedDomains)) {
            return [
                'type' => 'unauthorized_sender_domain',  
                'severity' => 'high',
                'pattern' => $domain
            ];
        }

        // Prüfe gegen Domain-Blacklist
        $threat = self::checkEmailBlacklist($fromEmail);
        if ($threat) {
            $threat['type'] = 'blacklisted_sender_domain';
            return $threat;
        }

        return null;
    }

    /**
     * Holt erlaubte Absender-Domains aus Config
     */
    private static function getAllowedSenderDomains(): array
    {
        $domains = self::getAddon()->getConfig('mail_allowed_sender_domains', '');
        if (empty($domains)) {
            return []; // Leere Liste = alle Domains erlaubt
        }
        
        return array_filter(array_map('trim', explode("\n", $domains)));
    }

    /**
     * Scannt E-Mail-Inhalt auf Badwords
     */
    private static function scanMailContent($mailer): ?array
    {
        $content = '';
        
        // Alle Inhalte sammeln
        $content .= $mailer->Subject . ' ';
        $content .= $mailer->Body . ' ';
        $content .= $mailer->AltBody . ' ';
        
        // HTML-Tags entfernen für bessere Analyse
        $cleanContent = strip_tags(html_entity_decode($content));
        
        // Badwords aus Datenbank laden und prüfen
        $badwords = self::getBadwords();
        
        foreach ($badwords as $badword) {
            $pattern = $badword['pattern'];
            $isMatch = false;
            
            if ($badword['is_regex']) {
                // RegEx-Pattern
                if (@preg_match($pattern, $cleanContent)) {
                    $isMatch = true;
                }
            } else {
                // Einfacher String-Match (case-insensitive)
                if (stripos($cleanContent, $pattern) !== false) {
                    $isMatch = true;
                }
            }
            
            if ($isMatch) {
                return [
                    'type' => 'badword_match',
                    'severity' => $badword['severity'],
                    'pattern' => $pattern,
                    'category' => $badword['category'] ?? 'content'
                ];
            }
        }
        
        return null;
    }

    /**
     * Prüft E-Mail auf Spam-Patterns
     */
    private static function checkSpamPatterns($mailer): ?array
    {
        $content = $mailer->Subject . ' ' . $mailer->Body . ' ' . $mailer->AltBody;
        $cleanContent = strip_tags(html_entity_decode($content));
        
        // Prüfe nach Risikolevel
        foreach (self::$spamPatterns as $riskLevel => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $cleanContent)) {
                    $severity = match($riskLevel) {
                        'high_risk' => 'high',
                        'medium_risk' => 'medium', 
                        'low_risk' => 'low',
                        default => 'medium'
                    };
                    
                    return [
                        'type' => 'spam_pattern',
                        'severity' => $severity,
                        'pattern' => $pattern,
                        'risk_level' => $riskLevel
                    ];
                }
            }
        }
        
        return null;
    }

    /**
     * Holt Badwords aus Datenbank
     */
    public static function getBadwords(): array
    {
        static $badwords = null;
        
        if ($badwords === null) {
            $badwords = [];
            
            try {
                $sql = rex_sql::factory();
                $sql->setQuery("SELECT * FROM " . rex::getTable('upkeep_mail_badwords') . " 
                               WHERE status = 1 ORDER BY severity DESC, category");
                
                while ($sql->hasNext()) {
                    $badwords[] = [
                        'id' => (int) $sql->getValue('id'),
                        'pattern' => $sql->getValue('pattern'),
                        'severity' => $sql->getValue('severity'),
                        'category' => $sql->getValue('category'),
                        'is_regex' => (bool) $sql->getValue('is_regex'),
                        'description' => $sql->getValue('description')
                    ];
                    $sql->next();
                }
            } catch (Exception $e) {
                // Fallback - Tabelle existiert möglicherweise noch nicht
                self::debugLog("Mail badwords table not accessible: " . $e->getMessage());
                $badwords = self::getDefaultBadwords();
            }
        }
        
        return $badwords;
    }

    /**
     * Standard-Badwords wenn Datenbank nicht verfügbar
     */
    private static function getDefaultBadwords(): array
    {
        return [
            ['pattern' => 'viagra', 'severity' => 'high', 'category' => 'pharmaceutical', 'is_regex' => false],
            ['pattern' => 'cialis', 'severity' => 'high', 'category' => 'pharmaceutical', 'is_regex' => false],
            ['pattern' => 'bitcoin scam', 'severity' => 'critical', 'category' => 'financial_fraud', 'is_regex' => false],
            ['pattern' => 'nigerian prince', 'severity' => 'critical', 'category' => 'financial_fraud', 'is_regex' => false],
            ['pattern' => '/\b(fuck|shit|damn)\b/i', 'severity' => 'medium', 'category' => 'profanity', 'is_regex' => true],
        ];
    }

    /**
     * Loggt Mail-Bedrohung in Threat-System
     */
    private static function logMailThreat(string $threatType, string $ip, array $threatData): void
    {
        // In bestehende Threat-Log-Tabelle eintragen
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_ips_threat_log'));
        $sql->setValue('ip_address', $ip);
        $sql->setValue('request_uri', rex_server('REQUEST_URI', 'string', '/mail-security'));
        $sql->setValue('user_agent', rex_server('HTTP_USER_AGENT', 'string', 'Mail Security Filter'));
        $sql->setValue('threat_type', 'mail_' . $threatType);
        $sql->setValue('threat_category', $threatData['category'] ?? 'mail_security');
        $sql->setValue('pattern_matched', $threatData['pattern'] ?? '');
        $sql->setValue('severity', $threatData['severity'] ?? 'medium');
        $sql->setValue('action_taken', $threatData['action'] ?? 'blocked');
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->insert();

        // Zusätzlich in Mail-spezifisches Log (optional)
        if (self::getAddon()->getConfig('mail_security_detailed_logging', false)) {
            self::logDetailedMailThreat($threatType, $ip, $threatData);
        }
    }

    /**
     * Detailliertes Logging für Mail-Threats
     */
    private static function logDetailedMailThreat(string $threatType, string $ip, array $threatData): void
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_threat_log'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('threat_type', $threatType);
            $sql->setValue('severity', $threatData['severity'] ?? 'medium');
            $sql->setValue('pattern_matched', $threatData['pattern'] ?? '');
            $sql->setValue('email_subject', $threatData['subject'] ?? '');
            $sql->setValue('recipient_email', $threatData['email'] ?? '');
            $sql->setValue('sender_email', $threatData['sender'] ?? '');
            $sql->setValue('action_taken', $threatData['action'] ?? 'blocked');
            $sql->setValue('details', json_encode($threatData));
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();
        } catch (Exception $e) {
            // Fallback wenn Tabelle nicht existiert
            self::debugLog("Detailed mail threat logging failed: " . $e->getMessage());
        }
    }

    /**
     * Holt Anzahl der Spam-Versuche für IP in den letzten 24h
     */
    private static function getSpamAttemptCount(string $ip): int
    {
        try {
            $sql = rex_sql::factory();
            $since = (new DateTime())->modify('-24 hours')->format('Y-m-d H:i:s');
            
            $query = "SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                      WHERE ip_address = ? AND threat_type LIKE 'mail_spam%' AND created_at >= ?";
            
            $sql->setQuery($query, [$ip, $since]);
            return (int) $sql->getValue('count');
        } catch (Exception $e) {
            self::debugLog("Failed to get spam attempt count: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Holt Client-IP (auch hinter Proxy/CDN) - kopiert von IntrusionPrevention
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
     * Debug-Logging
     */
    private static function debugLog(string $message): void
    {
        if (self::getAddon()->getConfig('mail_security_debug', false)) {
            rex_logger::factory()->log('debug', "Mail Security: " . $message);
        }
    }

    /**
     * Scannt E-Mail-Inhalt auf Code-Injection (JavaScript, PHP, SQL, etc.)
     */
    private static function scanForCodeInjection($mailer): ?array
    {
        $content = '';
        
        // Alle Inhalte sammeln (auch Anhang-Namen falls verfügbar)
        $content .= $mailer->Subject . ' ';
        $content .= $mailer->Body . ' ';
        $content .= $mailer->AltBody . ' ';
        
        // Auch Absender und Empfänger prüfen
        $content .= $mailer->From . ' ';
        $content .= $mailer->FromName . ' ';
        
        // Prüfe nach Risikolevel (kritisch zuerst)
        foreach (self::$codeInjectionPatterns as $riskLevel => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $content, $matches)) {
                    return [
                        'type' => 'code_injection',
                        'severity' => $riskLevel,  // critical, high, medium
                        'pattern' => $pattern,
                        'matched_content' => substr($matches[0], 0, 100), // Erste 100 Zeichen des Matches
                        'injection_type' => self::getInjectionType($pattern)
                    ];
                }
            }
        }
        
        return null;
    }

    /**
     * Bestimmt Injection-Typ basierend auf Pattern
     */
    private static function getInjectionType(string $pattern): string
    {
        if (strpos($pattern, 'script') !== false || strpos($pattern, 'javascript') !== false) {
            return 'javascript';
        } elseif (strpos($pattern, 'php') !== false || strpos($pattern, 'exec') !== false) {
            return 'php';
        } elseif (strpos($pattern, 'select') !== false || strpos($pattern, 'union') !== false) {
            return 'sql';
        } elseif (strpos($pattern, 'include') !== false || strpos($pattern, '#exec') !== false) {
            return 'ssi';
        } else {
            return 'unknown';
        }
    }

    /**
     * Eskaliert Bedrohung an das IPS-System
     */
    private static function escalateToIPS(string $ip, array $threatData): void
    {
        try {
            // Füge zur IPS-Threat-Log-Tabelle hinzu
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_threat_log'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('request_uri', '/mail-security-escalation');
            $sql->setValue('user_agent', 'Mail Security Filter - Escalated Threat');
            $sql->setValue('threat_type', 'mail_escalated_' . $threatData['type']);
            $sql->setValue('threat_category', 'mail_security_critical');
            $sql->setValue('pattern_matched', $threatData['pattern'] ?? '');
            $sql->setValue('severity', 'critical'); // Eskalierte Bedrohungen sind immer kritisch
            $sql->setValue('action_taken', 'escalated_to_ips');
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();

            // Bei kritischen Code-Injections: IP sofort temporär blockieren
            if ($threatData['severity'] === 'critical') {
                self::temporaryBlockIp($ip, 'Mail Security: Critical code injection detected');
            }

            self::debugLog("Threat escalated to IPS for IP {$ip}: {$threatData['type']}");
            
        } catch (Exception $e) {
            self::debugLog("Failed to escalate threat to IPS: " . $e->getMessage());
        }
    }

    /**
     * Blockiert IP temporär (1 Stunde) bei kritischen Mail-Bedrohungen
     */
    private static function temporaryBlockIp(string $ip, string $reason): void
    {
        try {
            $sql = rex_sql::factory();
            $expiresAt = (new DateTime())->modify('+1 hour')->format('Y-m-d H:i:s');
            
            $sql->setTable(rex::getTable('upkeep_ips_blocked_ips'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('block_type', 'temporary');
            $sql->setValue('expires_at', $expiresAt);
            $sql->setValue('reason', $reason);
            $sql->setValue('threat_level', 'critical');
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            self::debugLog("IP {$ip} temporarily blocked for 1 hour: {$reason}");
            
        } catch (Exception $e) {
            self::debugLog("Failed to block IP {$ip}: " . $e->getMessage());
        }
    }

    /**
     * Bereinigt/Sanitized E-Mail-Inhalt von potentiell schädlichem Code
     */
    public static function sanitizeMailContent(string $content): string
    {
        // 1. HTML-Tags entfernen, aber erlaubte behalten
        $allowedTags = '<p><br><strong><b><em><i><u><a><ul><ol><li><h1><h2><h3><h4><h5><h6><blockquote><hr><div><span>';
        $content = strip_tags($content, $allowedTags);
        
        // 2. Gefährliche Attribute entfernen
        $dangerousAttributes = [
            '/\s*on\w+\s*=/i',  // onclick, onload, etc.
            '/\s*href\s*=\s*["\']javascript:/i',
            '/\s*style\s*=\s*["\'][^"\'\']*expression\s*\(/i',
            '/\s*style\s*=\s*["\'][^"\'\']*javascript:/i'
        ];
        
        foreach ($dangerousAttributes as $pattern) {
            $content = preg_replace($pattern, '', $content);
        }
        
        // 3. Script-Tags komplett entfernen
        $content = preg_replace('/<script[^>]*>.*?<\/script>/is', '', $content);
        
        // 4. PHP-Code entfernen
        $content = preg_replace('/<\?php.*?\?>/is', '', $content);
        $content = preg_replace('/<\?.*?\?>/is', '', $content);
        
        // 5. HTML-Entities für verdächtige Zeichen
        $content = str_replace(['<script', '</script', '<?php', '<?='], 
                              ['&lt;script', '&lt;/script', '&lt;?php', '&lt;?='], $content);
        
        return $content;
    }

    /**
     * Fügt Badword hinzu
     */
    public static function addBadword(string $pattern, string $severity = 'medium', string $category = 'general', bool $isRegex = false, string $description = ''): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_badwords'));
            $sql->setValue('pattern', $pattern);
            $sql->setValue('severity', $severity);
            $sql->setValue('category', $category);
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('description', $description);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            // Cache leeren
            self::clearBadwordsCache();
            
            return true;
        } catch (Exception $e) {
            self::debugLog("Failed to add badword: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Entfernt Badword
     */
    public static function removeBadword(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [$id]);
            
            // Cache leeren
            self::clearBadwordsCache();
            
            return true;
        } catch (Exception $e) {
            self::debugLog("Failed to remove badword: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Fügt E-Mail zur Blacklist hinzu
     */
    public static function addEmailBlacklist(string $email, string $domain = '', string $reason = '', string $severity = 'medium', string $type = 'email'): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
            $sql->setValue('email_address', $email);
            $sql->setValue('domain', $domain);
            $sql->setValue('blacklist_type', $type);
            $sql->setValue('severity', $severity);
            $sql->setValue('reason', $reason);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            return true;
        } catch (Exception $e) {
            self::debugLog("Failed to add email blacklist: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Leert Badwords-Cache
     */
    private static function clearBadwordsCache(): void
    {
        // Static Cache leeren
        $reflection = new \ReflectionClass(__CLASS__);
        $badwordsProperty = $reflection->getProperty('badwords');
        $badwordsProperty->setAccessible(true);
        $badwordsProperty->setValue(null, null);
    }

    /**
     * Holt Mail-Security Statistiken
     */
    public static function getMailSecurityStats(): array
    {
        try {
            $sql = rex_sql::factory();
            
            // Bedrohungen der letzten 24h
            $sql->setQuery("
                SELECT 
                    threat_type,
                    COUNT(*) as count,
                    severity
                FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                WHERE threat_type LIKE 'mail_%' 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY threat_type, severity
                ORDER BY count DESC
            ");
            
            $threats = [];
            while ($sql->hasNext()) {
                $threats[] = [
                    'type' => $sql->getValue('threat_type'),
                    'count' => (int) $sql->getValue('count'),
                    'severity' => $sql->getValue('severity')
                ];
                $sql->next();
            }
            
            // Rate-Limiting Stats
            $sql->setQuery("
                SELECT 
                    COUNT(DISTINCT ip_address) as unique_ips,
                    COUNT(*) as total_mails
                FROM " . rex::getTable('upkeep_mail_rate_limit') . "
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            ");
            
            $rateStats = [
                'unique_ips' => 0,
                'total_mails' => 0
            ];
            
            if ($sql->getRows() > 0) {
                $rateStats = [
                    'unique_ips' => (int) $sql->getValue('unique_ips'),
                    'total_mails' => (int) $sql->getValue('total_mails')
                ];
            }
            
            return [
                'threats_24h' => $threats,
                'rate_limiting' => $rateStats,
                'active' => self::isMailSecurityActive(),
                'rate_limiting_enabled' => self::isMailRateLimitingEnabled()
            ];
            
        } catch (Exception $e) {
            self::debugLog("Failed to get mail security stats: " . $e->getMessage());
            return [];
        }
    }
}