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
 * - Blocklist-Management für E-Mail-Adressen und Domains
 */
class MailSecurityFilter
{
    private static ?rex_addon $addon = null;

    /** Kopfzeile der eigenen Admin-Benachrichtigung (wird nie gefiltert) */
    public const NOTIFICATION_HEADER = 'X-Upkeep-Notification';

    private const MAX_NOTIFICATIONS_PER_HOUR = 10;

    private static bool $sendingNotification = false;
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
     * Holt Standard-Mail-Patterns aus der Datenbank (pro Request gecacht, fail open)
     */
    public static function getDefaultMailPatterns(): array
    {
        static $patterns = null;

        if ($patterns === null) {
            $patterns = [];
            try {
                $sql = rex_sql::factory();
                $sql->setQuery('SELECT category, pattern FROM ' . rex::getTable('upkeep_mail_default_patterns') . ' WHERE status = 1 ORDER BY category, severity DESC');
                foreach ($sql as $row) {
                    $patterns[(string) $row->getValue('category')][] = (string) $row->getValue('pattern');
                }
            } catch (\Throwable $e) {
                rex_logger::logException($e);
            }
        }

        return $patterns;
    }

    /**
     * Holt benutzerdefinierte Mail-Patterns aus der Datenbank (fail open)
     */
    public static function getCustomMailPatterns(): array
    {
        static $patterns = null;

        if ($patterns === null) {
            $patterns = [];
            try {
                $sql = rex_sql::factory();
                $sql->setQuery('SELECT * FROM ' . rex::getTable('upkeep_mail_custom_patterns') . ' WHERE status = 1 ORDER BY severity DESC');
                foreach ($sql as $row) {
                    $patterns[] = [
                        'pattern' => $row->getValue('pattern'),
                        'description' => $row->getValue('description'),
                        'severity' => $row->getValue('severity'),
                        'is_regex' => (bool) $row->getValue('is_regex'),
                    ];
                }
            } catch (\Throwable) {
                $patterns = [];
            }
        }

        return $patterns;
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
            'blocklist_count' => 0,
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

            // Aktive Blocklist-Einträge
            $sql->setQuery("SELECT COUNT(*) as count FROM " . rex::getTable('upkeep_mail_blocklist') . " 
                           WHERE status = 1 AND (expires_at IS NULL OR expires_at > NOW())");
            if ($sql->getRows() > 0) {
                $stats['blocklist_count'] = (int) $sql->getValue('count');
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
     * Hauptfilter-Funktion für den Extension Point PHPMAILER_PRE_SEND.
     *
     * 3.0:
     * - nur im Web-Frontend (nicht CLI/Cronjob), echte Client-IP über ClientIp
     * - Inhaltsprüfungen nur auf Benutzereingaben (POST/GET-Werte, die in der Mail vorkommen),
     *   nicht auf die Vorlagen der Website
     * - reine Inhaltstreffer werden nie an das IPS eskaliert
     * - blockierte Mails werden abgebrochen (Empfänger entfernt, send() liefert false),
     *   der Request läuft weiter (kein exit mitten in einer YForm-Aktion)
     * - Fehler im Filter: Mail wird normal versendet (fail open), Fehler wird geloggt
     *
     * @param rex_extension_point<mixed> $ep
     */
    public static function filterMail(rex_extension_point $ep): mixed
    {
        $mailer = $ep->getSubject();

        try {
            // Eigene Benachrichtigungen an den Admin nie filtern (keine Rekursion)
            if (self::$sendingNotification || !self::isMailSecurityActive() || PHP_SAPI === 'cli' || !is_object($mailer)) {
                return $mailer;
            }
            if (method_exists($mailer, 'getCustomHeaders')) {
                foreach ((array) $mailer->getCustomHeaders() as $header) {
                    if (is_array($header) && strcasecmp((string) ($header[0] ?? ''), self::NOTIFICATION_HEADER) === 0) {
                        return $mailer;
                    }
                }
            }

            $clientIp = ClientIp::get();
            if ($clientIp === '0.0.0.0') {
                return $mailer;
            }

            // Vertrauenswürdige Absender-IPs (z. B. eigener Server, Monitoring)
            $trusted = (string) self::getAddon()->getConfig('mail_allowed_sender_ips', '');
            if ($trusted !== '' && ClientIp::inList($clientIp, $trusted)) {
                return $mailer;
            }

            $findings = [];
            $block = self::evaluate($mailer, $clientIp, $findings);
            if ($block !== null) {
                self::cancelMail($mailer, $block['reason']);
                $ep->setSubject($mailer);
                self::afterBlock($clientIp, $block);
                return $mailer;
            }

            // mail_security_sanitize_content: Mail mit nicht blockierenden Inhaltstreffern
            // wird entschärft statt nur protokolliert
            if ($findings !== [] && (bool) self::getAddon()->getConfig('mail_security_sanitize_content', 0)) {
                self::sanitizeMailer($mailer);
                $ep->setSubject($mailer);
            }

            if (self::isMailRateLimitingEnabled()) {
                self::updateMailRateLimit($clientIp);
            }
            self::debugLog("Mail security check passed for IP: {$clientIp}");
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }

        return $mailer;
    }

    /**
     * Ab welcher Schwere ein Treffer die Mail blockiert (mail_security_block_suspicious):
     * - aus (Standard): nur "critical" blockiert; "high"/"medium"/"low" werden nur protokolliert
     * - an: "high" und "critical" blockieren (Verhalten bis 2.x); "high"-Spam erst ab dem dritten Versuch in 24 h
     * Immer blockiert (unabhängig vom Schalter, gelten als "critical"): überschrittenes Rate-Limit
     * (eigener Schalter), CR/LF im Betreff/Absendernamen (Header-Injection), vom IPS gesperrte IP.
     */
    private static function blocksAt(string $severity): bool
    {
        if ($severity === 'critical') {
            return true;
        }
        return $severity === 'high' && (bool) self::getAddon()->getConfig('mail_security_block_suspicious', 0);
    }

    /**
     * Führt alle Prüfungen aus. Liefert Grund und Schwere, wenn die Mail blockiert werden soll.
     * $findings sammelt nicht blockierende Inhaltstreffer (für mail_security_sanitize_content).
     *
     * Prüfgruppen: mail_security_check_subject (Betreff), mail_security_check_body (Text/HTML),
     * mail_security_check_sender (Absenderdomain, Absendername, Antwortadressen).
     * Rate-Limit, IP- und Empfänger-Blocklist laufen immer.
     *
     * @param list<array<string, mixed>> $findings
     * @return array{reason: string, severity: string}|null
     */
    private static function evaluate(object $mailer, string $clientIp, array &$findings = []): ?array
    {
        $addon = self::getAddon();
        $checkSubject = (bool) $addon->getConfig('mail_security_check_subject', 1);
        $checkBody = (bool) $addon->getConfig('mail_security_check_body', 1);
        $checkSender = (bool) $addon->getConfig('mail_security_check_sender', 1);

        // 1. Rate-Limiting (wiederholtes Überschreiten wird als "medium" ans IPS gemeldet)
        if (self::isMailRateLimitExceeded($clientIp)) {
            self::logMailThreat('rate_limit_exceeded', $clientIp, [
                'severity' => 'high',
                'pattern' => 'Email rate limit exceeded',
                'action' => 'blocked',
            ]);
            IntrusionPrevention::reportExternalThreat('mail_rate_limit', 'medium', 'Email rate limit exceeded', $clientIp);
            return ['reason' => 'rate_limit', 'severity' => 'high'];
        }

        // 2. IP-Blocklist (Mail-Blocklist oder IPS-Sperre)
        $ipThreat = self::checkIpBlocklist($clientIp);
        if ($ipThreat !== null) {
            $ipsBlocked = ($ipThreat['type'] ?? '') === 'ips_blocked_ip';
            $blocks = $ipsBlocked || self::blocksAt((string) $ipThreat['severity']);
            self::logMailThreat('blocklisted_ip', $clientIp, $ipThreat + ['action' => $blocks ? 'blocked' : 'logged']);
            if ($blocks) {
                return ['reason' => 'blocklisted_ip', 'severity' => $ipsBlocked ? 'critical' : (string) $ipThreat['severity']];
            }
        }

        // 3. Empfänger und Antwortadressen gegen Blocklist
        $recipientThreat = self::checkRecipientBlocklist($mailer);
        if ($recipientThreat !== null) {
            $blocks = self::blocksAt((string) $recipientThreat['severity']);
            self::logMailThreat('blocklisted_recipient', $clientIp, $recipientThreat + ['action' => $blocks ? 'blocked' : 'logged']);
            if ($blocks) {
                return ['reason' => 'blocklisted_recipient', 'severity' => (string) $recipientThreat['severity']];
            }
        }

        // 4. Absender-Domain (Konfigurationsfrage der Website – nie eskalieren)
        if ($checkSender) {
            $senderThreat = self::validateSenderDomain($mailer);
            if ($senderThreat !== null) {
                $blocks = self::blocksAt((string) $senderThreat['severity']);
                self::logMailThreat('invalid_sender_domain', $clientIp, $senderThreat + ['action' => $blocks ? 'blocked' : 'logged']);
                if ($blocks) {
                    return ['reason' => 'invalid_sender_domain', 'severity' => (string) $senderThreat['severity']];
                }
            }
        }

        // 5. Header-Injection in Betreff / Absendername (immer blockieren)
        $headerProps = array_merge($checkSubject ? ['Subject'] : [], $checkSender ? ['FromName'] : []);
        foreach ($headerProps as $prop) {
            $value = isset($mailer->$prop) && is_string($mailer->$prop) ? $mailer->$prop : '';
            if ($value !== '' && preg_match('/[\r\n]/', $value)) {
                self::logMailThreat('header_injection', $clientIp, ['severity' => 'critical', 'pattern' => 'CR/LF in ' . $prop, 'action' => 'blocked']);
                return ['reason' => 'header_injection', 'severity' => 'critical'];
            }
        }

        // Inhaltsprüfungen nur auf Benutzereingaben in den aktivierten Teilen der Mail
        $parts = array_merge(
            $checkSubject ? ['Subject'] : [],
            $checkBody ? ['Body', 'AltBody'] : [],
            $checkSender ? ['FromName'] : [],
        );
        if ($parts === []) {
            return null;
        }
        $userContent = self::collectUserContent($mailer, $parts, $checkSender);
        if ($userContent === '') {
            return null;
        }

        // 6. Code-Injection
        $injectionThreat = self::scanForCodeInjection($userContent);
        if ($injectionThreat !== null) {
            $blocks = self::blocksAt((string) $injectionThreat['severity']);
            self::logMailThreat('code_injection_detected', $clientIp, $injectionThreat + ['action' => $blocks ? 'blocked' : 'logged']);
            if ($blocks) {
                return ['reason' => 'code_injection', 'severity' => (string) $injectionThreat['severity']];
            }
            $findings[] = $injectionThreat;
        }

        // 7. Badwords
        $contentThreat = self::scanMailContent($userContent);
        if ($contentThreat !== null) {
            $blocks = self::blocksAt((string) $contentThreat['severity']);
            self::logMailThreat('badword_detected', $clientIp, $contentThreat + ['action' => $blocks ? 'blocked' : 'logged']);
            if ($blocks) {
                return ['reason' => 'badword', 'severity' => (string) $contentThreat['severity']];
            }
            $findings[] = $contentThreat;
        }

        // 8. Spam-Patterns ("high" nur mit block_suspicious und erst ab dem dritten Versuch in 24 h)
        $spamThreat = self::checkSpamPatterns($userContent);
        if ($spamThreat !== null) {
            $blocks = self::blocksAt((string) $spamThreat['severity']) && self::getSpamAttemptCount($clientIp) >= 2;
            self::logMailThreat('spam_pattern_detected', $clientIp, $spamThreat + ['action' => $blocks ? 'blocked' : 'logged']);
            if ($blocks) {
                return ['reason' => 'spam', 'severity' => (string) $spamThreat['severity']];
            }
            $findings[] = $spamThreat;
        }

        return null;
    }

    /**
     * Sammelt Benutzereingaben (POST/GET-Werte), die tatsächlich in den gewählten Teilen der Mail vorkommen.
     * So werden die eigenen Vorlagen der Website nicht geprüft.
     *
     * @param list<string> $parts Eigenschaften des Mailers (Subject, Body, AltBody, FromName)
     */
    private static function collectUserContent(object $mailer, array $parts = ['Subject', 'Body', 'AltBody', 'FromName'], bool $withReplyTo = true): string
    {
        $mailText = '';
        foreach ($parts as $prop) {
            if (isset($mailer->$prop) && is_string($mailer->$prop)) {
                $mailText .= ' ' . $mailer->$prop;
            }
        }
        if ($withReplyTo && method_exists($mailer, 'getReplyToAddresses')) {
            foreach ((array) $mailer->getReplyToAddresses() as $entry) {
                $mailText .= ' ' . implode(' ', array_map('strval', (array) $entry));
            }
        }
        if (trim($mailText) === '') {
            return '';
        }
        $decodedMail = html_entity_decode(strip_tags($mailText), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $rawMail = $mailText;

        $values = [];
        $collect = static function ($data, int $depth = 0) use (&$collect, &$values): void {
            if ($depth > 5 || count($values) > 200) {
                return;
            }
            foreach ((array) $data as $key => $value) {
                if (is_array($value)) {
                    $collect($value, $depth + 1);
                } elseif (is_string($value)) {
                    $key = (string) $key;
                    // Technische Felder auslassen
                    if (preg_match('/(csrf|token|captcha|altcha|^_|password)/i', $key)) {
                        continue;
                    }
                    $value = trim($value);
                    if (strlen($value) >= 3) {
                        $values[] = substr($value, 0, 20000);
                    }
                }
            }
        };
        $collect($_POST);
        $collect($_GET);

        $content = '';
        foreach ($values as $value) {
            $plain = html_entity_decode(strip_tags($value), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if (str_contains($rawMail, $value) || ($plain !== '' && str_contains($decodedMail, $plain))
                || str_contains($rawMail, htmlspecialchars($value, ENT_QUOTES))) {
                $content .= "\n" . $value;
            }
            if (strlen($content) > 65536) {
                break;
            }
        }

        return $content;
    }

    /**
     * Bricht den Versand ab, ohne den Request zu beenden: alle Empfänger werden entfernt,
     * rex_mailer::send() liefert dadurch false.
     */
    private static function cancelMail(object $mailer, string $reason): void
    {
        foreach (['clearAllRecipients', 'clearReplyTos', 'clearAttachments'] as $method) {
            if (method_exists($mailer, $method)) {
                $mailer->$method();
            }
        }
        if (property_exists($mailer, 'ErrorInfo')) {
            $mailer->ErrorInfo = 'Blocked by upkeep mail security (' . $reason . ')';
        }
        // Optional für Formulare: Grund im Request merken
        rex::setProperty('upkeep_mail_blocked', $reason);
        self::debugLog('Mail blocked: ' . $reason);
    }

    /**
     * Nach einer Blockierung: Admin benachrichtigen und wiederholte Versuche derselben IP sperren.
     *
     * @param array{reason: string, severity: string} $block
     */
    private static function afterBlock(string $clientIp, array $block): void
    {
        try {
            self::notifyAdmin($clientIp, $block);
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }
        try {
            self::trackBlockedAttempt($clientIp, $block['reason']);
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * mail_security_max_spam_attempts (3) / mail_security_temp_block_duration (60 Minuten):
     * Nach N blockierten Mails derselben Client-IP innerhalb von 24 h wird die IP über das IPS
     * temporär gesperrt (Quelle 'auto', Selbstentsperrung per ALTCHA möglich).
     * Zähler im JsonStore (nicht in rex_config).
     */
    private static function trackBlockedAttempt(string $clientIp, string $reason): void
    {
        $addon = self::getAddon();
        $max = max(1, (int) $addon->getConfig('mail_security_max_spam_attempts', 3));
        $minutes = max(1, min(10080, (int) $addon->getConfig('mail_security_temp_block_duration', 60)));

        $now = time();
        $store = new JsonStore('mail_security_attempts', 2000);
        $attempts = $store->update('ip:' . $clientIp, static function ($list) use ($now): array {
            $list = array_values(array_filter((array) $list, static fn ($t) => is_int($t) && $t > $now - 86400));
            $list[] = $now;
            return array_slice($list, -100);
        }, 86400);

        if (count((array) $attempts) < $max) {
            return;
        }
        if (IntrusionPrevention::isIpBlocked($clientIp)) {
            return;
        }
        $blocked = IntrusionPrevention::blockIpForSeconds(
            $clientIp,
            $minutes * 60,
            sprintf('Mail security: %d blocked mails in 24 h (last: %s)', count((array) $attempts), $reason),
            'auto',
        );
        if ($blocked) {
            $store->delete('ip:' . $clientIp);
            self::logMailThreat('ip_temp_blocked', $clientIp, [
                'severity' => 'high',
                'pattern' => $minutes . ' min',
                'action' => 'ip_blocked',
            ]);
        }
    }

    /**
     * mail_security_notify_admin (0) + mail_security_admin_email ('' = Fehler-E-Mail von REDAXO)
     * + mail_security_notification_threshold ('high'): kurze Klartext-Mail bei blockierten Mails
     * ab der Schwelle, höchstens 10 pro Stunde. Die Benachrichtigung selbst wird nicht gefiltert.
     *
     * @param array{reason: string, severity: string} $block
     */
    private static function notifyAdmin(string $clientIp, array $block): bool
    {
        $addon = self::getAddon();
        if (!(bool) $addon->getConfig('mail_security_notify_admin', 0)) {
            return false;
        }
        $order = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];
        $threshold = (string) $addon->getConfig('mail_security_notification_threshold', 'high');
        if (($order[$block['severity']] ?? 2) < ($order[$threshold] ?? 3)) {
            return false;
        }
        $email = trim((string) $addon->getConfig('mail_security_admin_email', ''));
        if ($email === '') {
            $email = (string) rex::getErrorEmail();
        }
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || !class_exists(\rex_mailer::class)) {
            return false;
        }

        $store = new JsonStore('mail_security_notify', 100);
        $hourKey = 'notify:' . date('YmdH');
        if ((int) $store->get($hourKey, 0) >= self::MAX_NOTIFICATIONS_PER_HOUR) {
            return false;
        }
        $store->increment($hourKey, 3600);

        $server = preg_replace('/[\r\n]+/', ' ', (string) rex::getServerName());
        $lines = [
            'Upkeep mail security blocked an email.',
            '',
            'Time: ' . date('Y-m-d H:i:s'),
            'Website: ' . $server . ' (' . rex::getServer() . ')',
            'Client IP: ' . $clientIp,
            'Reason: ' . $block['reason'],
            'Severity: ' . $block['severity'],
            'Request: ' . substr(preg_replace('/[\r\n]+/', ' ', rex_server('REQUEST_URI', 'string', '')) ?? '', 0, 300),
            '',
            'Details: REDAXO backend > Upkeep > Protection > Mail.',
            'At most ' . self::MAX_NOTIFICATIONS_PER_HOUR . ' notifications per hour are sent.',
        ];

        self::$sendingNotification = true;
        try {
            $mail = new \rex_mailer();
            $mail->isHTML(false);
            $mail->addAddress($email);
            $mail->Subject = 'Upkeep: email blocked (' . $block['severity'] . ', ' . $block['reason'] . ') - ' . mb_substr($server, 0, 60);
            $mail->Body = implode("\n", $lines);
            $mail->addCustomHeader(self::NOTIFICATION_HEADER, '1');
            return $mail->send();
        } finally {
            self::$sendingNotification = false;
        }
    }

    /**
     * Entschärft Body (HTML) und AltBody des Mailers, siehe sanitizeHtml().
     */
    private static function sanitizeMailer(object $mailer): void
    {
        if (isset($mailer->Body) && is_string($mailer->Body) && $mailer->Body !== '') {
            $mailer->Body = self::sanitizeHtml($mailer->Body);
        }
        if (isset($mailer->AltBody) && is_string($mailer->AltBody) && $mailer->AltBody !== '') {
            $mailer->AltBody = self::sanitizeHtml($mailer->AltBody);
        }
        self::debugLog('Mail content sanitized');
    }

    /**
     * Entfernt gefährliches HTML, lässt das übrige Layout (Tabellen, Bilder, Styles) unverändert:
     * script/iframe/object/embed/applet/frame/frameset/base-Elemente, on*-Attribute,
     * javascript:/vbscript:/data:text/html-URLs in href/src/action/... Wird wiederholt, bis sich nichts mehr ändert
     * (verschachtelte Tricks wie <scr<script>ipt>).
     */
    public static function sanitizeHtml(string $html): string
    {
        $elements = 'script|iframe|object|embed|applet|frameset|frame|base';
        for ($i = 0; $i < 5; ++$i) {
            $before = $html;
            // Elemente samt Inhalt, dann einzelne/öffnende/schließende Tags
            $html = (string) preg_replace('#<(' . $elements . ')\b[^>]*>.*?</\1\s*>#is', '', $html);
            $html = (string) preg_replace('#</?(' . $elements . ')\b[^>]*>?#is', '', $html);
            // Event-Handler-Attribute (onclick=, onerror= …) in Tags
            $html = (string) preg_replace('#(<[^>]*?[\s/"\'])on[a-z]+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]*)#is', '$1', $html);
            // Gefährliche URL-Schemata in Attributen
            $html = (string) preg_replace(
                '#(<[^>]*?\s(?:href|src|action|formaction|xlink:href|background|poster|data)\s*=\s*)(["\']?)\s*(?:(?:javascript|vbscript|livescript)\s*:|data\s*:\s*text/html)[^"\'\s>]*#is',
                '$1$2#',
                $html,
            );
            if ($html === $before) {
                break;
            }
        }
        return $html;
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
     * Prüft Rate-Limit für E-Mail-Versand (eine Abfrage für alle Zeitfenster)
     */
    private static function isMailRateLimitExceeded(string $ip): bool
    {
        if (!self::isMailRateLimitingEnabled()) {
            return false;
        }

        $perMinute = max(1, (int) self::getAddon()->getConfig('mail_rate_limit_per_minute', 10));
        $perHour = max(1, (int) self::getAddon()->getConfig('mail_rate_limit_per_hour', 50));
        $perDay = max(1, (int) self::getAddon()->getConfig('mail_rate_limit_per_day', 200));
        $now = time();

        try {
            $sql = rex_sql::factory();
            $sql->setQuery(
                'SELECT
                    SUM(created_at >= ?) AS m,
                    SUM(created_at >= ?) AS h,
                    COUNT(*) AS d
                 FROM ' . rex::getTable('upkeep_mail_rate_limit') . '
                 WHERE ip_address = ? AND created_at >= ?',
                [date('Y-m-d H:i:s', $now - 60), date('Y-m-d H:i:s', $now - 3600), $ip, date('Y-m-d H:i:s', $now - 86400)],
            );
            return (int) $sql->getValue('m') >= $perMinute
                || (int) $sql->getValue('h') >= $perHour
                || (int) $sql->getValue('d') >= $perDay;
        } catch (\Throwable $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Aktualisiert Mail-Rate-Limit Counter (Bereinigung über IntrusionPrevention::cleanupExpiredData)
     */
    private static function updateMailRateLimit(string $ip): void
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_rate_limit'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * Prüft Empfänger (To/Cc/Bcc) und Antwortadressen gegen die Blocklist
     */
    private static function checkRecipientBlocklist(object $mailer): ?array
    {
        $addresses = [];
        if (method_exists($mailer, 'getAllRecipientAddresses')) {
            $addresses = array_keys((array) $mailer->getAllRecipientAddresses());
        }
        foreach (['getToAddresses', 'getCcAddresses', 'getBccAddresses', 'getReplyToAddresses'] as $method) {
            if (method_exists($mailer, $method)) {
                foreach ((array) $mailer->$method() as $key => $entry) {
                    $addresses[] = is_array($entry) ? (string) ($entry[0] ?? '') : (string) $key;
                }
            }
        }

        foreach (array_unique(array_map('strtolower', $addresses)) as $email) {
            if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                continue;
            }
            $threat = self::checkEmailBlocklist($email);
            if ($threat !== null) {
                $threat['email'] = $email;
                return $threat;
            }
        }

        return null;
    }

    /**
     * Prüft einzelne E-Mail-Adresse gegen Blocklist
     */
    private static function checkEmailBlocklist(string $email): ?array
    {
        try {
            $domain = strtolower((string) substr((string) strrchr($email, '@'), 1));
            $sql = rex_sql::factory();
            $sql->setQuery(
                'SELECT * FROM ' . rex::getTable('upkeep_mail_blocklist') . "
                 WHERE (email_address = ? OR domain = ? OR pattern = ?)
                   AND status = 1 AND (expires_at IS NULL OR expires_at > NOW())
                 ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low') LIMIT 1",
                [$email, $domain, $domain],
            );
            if ($sql->getRows() > 0) {
                return [
                    'type' => 'blocklisted_' . $sql->getValue('blocklist_type'),
                    'severity' => (string) $sql->getValue('severity'),
                    'pattern' => $sql->getValue('email_address') ?: $sql->getValue('domain'),
                    'reason' => $sql->getValue('reason'),
                ];
            }
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }
        return null;
    }

    /**
     * Prüft IP-Adresse gegen Mail-Blocklist und IPS-Sperrliste
     */
    private static function checkIpBlocklist(string $clientIp): ?array
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery(
                'SELECT * FROM ' . rex::getTable('upkeep_mail_blocklist') . "
                 WHERE blocklist_type = 'ip'
                   AND (ip_address = ? OR (pattern IS NOT NULL AND pattern != '' AND ? LIKE REPLACE(pattern, '*', '%')))
                   AND status = 1 AND (expires_at IS NULL OR expires_at > NOW())
                 ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low') LIMIT 1",
                [$clientIp, $clientIp],
            );
            if ($sql->getRows() > 0) {
                return [
                    'type' => 'blocklisted_ip',
                    'severity' => (string) $sql->getValue('severity'),
                    'pattern' => $sql->getValue('ip_address') ?: $sql->getValue('pattern'),
                    'reason' => $sql->getValue('reason') ?: 'IP-Adresse ist gesperrt',
                    'ip' => $clientIp,
                ];
            }
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }

        if (IntrusionPrevention::isIpBlocked($clientIp)) {
            return [
                'type' => 'ips_blocked_ip',
                'severity' => 'high',
                'pattern' => $clientIp,
                'reason' => 'IP durch IPS-System gesperrt',
                'ip' => $clientIp,
            ];
        }

        return null;
    }

    /**
     * Validiert Absender-Domain
     */
    private static function validateSenderDomain(object $mailer): ?array
    {
        $fromEmail = isset($mailer->From) ? (string) $mailer->From : '';

        if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
            return ['type' => 'invalid_sender_format', 'severity' => 'medium', 'pattern' => $fromEmail];
        }

        $domain = strtolower((string) substr((string) strrchr($fromEmail, '@'), 1));
        $allowedDomains = array_map('strtolower', self::getAllowedSenderDomains());
        if ($allowedDomains !== [] && !in_array($domain, $allowedDomains, true)) {
            return ['type' => 'unauthorized_sender_domain', 'severity' => 'high', 'pattern' => $domain];
        }

        $threat = self::checkEmailBlocklist($fromEmail);
        if ($threat !== null) {
            $threat['type'] = 'blocklisted_sender_domain';
            return $threat;
        }

        return null;
    }

    /**
     * Holt erlaubte Absender-Domains aus Config (Zeilenumbruch oder Komma getrennt)
     */
    private static function getAllowedSenderDomains(): array
    {
        $domains = (string) self::getAddon()->getConfig('mail_allowed_sender_domains', '');
        if (trim($domains) === '') {
            return [];
        }
        return array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', $domains) ?: [])));
    }

    /**
     * Scannt Benutzereingaben auf Badwords
     */
    private static function scanMailContent(string $content): ?array
    {
        $cleanContent = html_entity_decode(strip_tags($content), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        foreach (self::getBadwords() as $badword) {
            $pattern = (string) $badword['pattern'];
            if ($pattern === '') {
                continue;
            }
            $isMatch = $badword['is_regex']
                ? (PatternValidator::match($pattern, $cleanContent) === true)
                : stripos($cleanContent, $pattern) !== false;

            if ($isMatch) {
                return [
                    'type' => 'badword_match',
                    'severity' => $badword['severity'],
                    'pattern' => $pattern,
                    'category' => $badword['category'] ?? 'content',
                ];
            }
        }

        return null;
    }

    /**
     * Prüft Benutzereingaben auf Spam-Patterns
     */
    private static function checkSpamPatterns(string $content): ?array
    {
        $cleanContent = html_entity_decode(strip_tags($content), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $spamPatterns = self::getDefaultMailPatterns();

        foreach (['high_spam' => 'high', 'medium_spam' => 'medium', 'low_spam' => 'low'] as $category => $severity) {
            foreach ($spamPatterns[$category] ?? [] as $pattern) {
                if (PatternValidator::match($pattern, $cleanContent) === true) {
                    return ['type' => 'spam_pattern', 'severity' => $severity, 'pattern' => $pattern, 'category' => $category];
                }
            }
        }

        return null;
    }

    /**
     * Holt Badwords aus Datenbank
     */
    public static function getBadwords(bool $forceReload = false): array
    {
        static $badwords = null;
        
        if ($badwords === null || $forceReload) {
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
     * Loggt Mail-Bedrohung in das gemeinsame Threat-Log (ohne Eskalation)
     */
    private static function logMailThreat(string $threatType, string $ip, array $threatData): void
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_ips_threat_log'));
            $sql->setValue('ip_address', $ip);
            $sql->setValue('request_uri', substr(rex_server('REQUEST_URI', 'string', '/mail-security'), 0, 2000));
            $sql->setValue('user_agent', substr(rex_server('HTTP_USER_AGENT', 'string', 'Mail Security Filter'), 0, 500));
            $sql->setValue('threat_type', 'mail_' . $threatType);
            $sql->setValue('threat_category', substr((string) ($threatData['category'] ?? 'mail_security'), 0, 100));
            $sql->setValue('pattern_matched', substr((string) ($threatData['pattern'] ?? ''), 0, 500));
            $sql->setValue('severity', in_array($threatData['severity'] ?? '', ['low', 'medium', 'high', 'critical'], true) ? $threatData['severity'] : 'medium');
            $sql->setValue('action_taken', (string) ($threatData['action'] ?? 'logged'));
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();
        } catch (\Throwable $e) {
            rex_logger::logException($e);
        }

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
     * Client-IP (echte IP über ClientIp, Proxy-Header nur bei vertrauenswürdigen Proxies)
     */
    private static function getClientIp(): string
    {
        return ClientIp::get();
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
     * Scannt Benutzereingaben auf Code-Injection (JavaScript, PHP, SQL, etc.)
     */
    private static function scanForCodeInjection(string $content): ?array
    {
        $injectionPatterns = self::getDefaultMailPatterns();

        foreach (['critical_injection' => 'critical', 'high_injection' => 'high', 'medium_injection' => 'medium'] as $category => $severity) {
            foreach ($injectionPatterns[$category] ?? [] as $pattern) {
                set_error_handler(static fn (): bool => true);
                try {
                    $res = preg_match($pattern, $content, $matches);
                } finally {
                    restore_error_handler();
                }
                if ($res === 1) {
                    return [
                        'type' => 'code_injection',
                        'severity' => $severity,
                        'pattern' => $pattern,
                        'matched_content' => substr((string) ($matches[0] ?? ''), 0, 100),
                        'injection_type' => self::getInjectionType($pattern),
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
     * Meldet eine Bedrohung an das IPS (nur für Nicht-Inhalts-Treffer verwenden)
     */
    private static function escalateToIPS(string $ip, array $threatData): void
    {
        IntrusionPrevention::reportExternalThreat(
            'mail_escalated_' . ($threatData['type'] ?? 'threat'),
            (string) ($threatData['severity'] ?? 'medium'),
            (string) ($threatData['pattern'] ?? ''),
            $ip,
        );
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
     * Fügt ein neues Badword hinzu (RegEx wird validiert)
     */
    public static function addBadword(string $pattern, string $severity = 'medium', string $category = 'general', bool $isRegex = false, string $description = ''): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '' || ($isRegex && !PatternValidator::isValid($pattern))) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_badwords'));
            $sql->setValue('pattern', $pattern);
            $sql->setValue('description', $description);
            $sql->setValue('category', $category);
            $sql->setValue('severity', self::normalizeSeverity($severity));
            $sql->setValue('is_regex', $isRegex ? 1 : 0);
            $sql->setValue('status', 1);
            $sql->setValue('is_default', 0);
            $sql->setValue('is_editable', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->setValue('edited_by', rex::getUser() ? rex::getUser()->getLogin() : '');
            $sql->insert();
            self::clearBadwordsCache();
            return true;
        } catch (\Throwable $e) {
            rex_logger::factory()->log('error', 'Mail Security addBadword failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Entfernt ein Badword
     * 
     * @param int $id Die ID des zu löschenden Badwords
     * @return bool   Erfolgsstatus
     */
    public static function removeBadword(int $id): bool
    {
        try {
            // Prüfen ob es sich um ein Standard-Badword handelt (diese können nicht gelöscht werden)
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT is_default, is_editable FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [$id]);
            
            if ($sql->getRows() > 0) {
                $isDefault = (bool) $sql->getValue('is_default');
                $isEditable = (bool) $sql->getValue('is_editable');
                
                // Nur löschbar, wenn es kein Standard-Badword ist und bearbeitbar ist
                if (!$isDefault && $isEditable) {
                    $sql->setTable(rex::getTable('upkeep_mail_badwords'));
                    $sql->setWhere(['id' => $id]);
                    $sql->delete();
                    
                    // Cache leeren
                    self::clearBadwordsCache();
                    return true;
                }
            }
            
            return false;
        } catch (Exception $e) {
            self::debugLog("Failed to remove badword: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Fügt E-Mail zur Blocklist hinzu
     */
    public static function addEmailBlocklist(string $email, string $domain = '', string $reason = '', string $severity = 'medium', string $type = 'email'): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
            $sql->setValue('email_address', $email);
            $sql->setValue('domain', $domain);
            $sql->setValue('blocklist_type', $type);
            $sql->setValue('severity', $severity);
            $sql->setValue('reason', $reason);
            $sql->setValue('status', 1);
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->setValue('updated_at', date('Y-m-d H:i:s'));
            $sql->insert();
            
            return true;
        } catch (Exception $e) {
            self::debugLog("Failed to add email blocklist: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Leert Badwords-Cache
     */
    private static function clearBadwordsCache(): void
    {
        // Cache durch erneutes Laden leeren
        self::getBadwords(true);
    }
    
    /**
     * Schaltet den Status eines Badwords um
     * 
     * @param int $id Die ID des Badwords
     * @return bool   Erfolgsstatus
     */
    public static function toggleBadwordStatus(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT status FROM " . rex::getTable('upkeep_mail_badwords') . " WHERE id = ?", [$id]);
            
            if ($sql->getRows() > 0) {
                $currentStatus = (bool) $sql->getValue('status');
                $newStatus = $currentStatus ? 0 : 1;
                
                $sql->setQuery("UPDATE " . rex::getTable('upkeep_mail_badwords') . " SET 
                               status = ?, 
                               updated_at = NOW(), 
                               edited_by = ? 
                               WHERE id = ?", 
                               [$newStatus, rex::getUser() ? rex::getUser()->getLogin() : '', $id]);
                
                // Cache leeren
                self::clearBadwordsCache();
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            self::debugLog("Failed to toggle badword status: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Aktualisiert ein Badword
     *
     * @param bool|null $isRegex null = unverändert lassen
     */
    public static function updateBadword(int $id, string $pattern, string $description, string $category, string $severity, bool $status, ?bool $isRegex = null): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT is_editable, is_regex FROM ' . rex::getTable('upkeep_mail_badwords') . ' WHERE id = ?', [$id]);
            if ($sql->getRows() === 0) {
                return false;
            }
            if (!(bool) $sql->getValue('is_editable')) {
                return self::toggleBadwordStatus($id);
            }

            $isRegex ??= (bool) $sql->getValue('is_regex');
            $pattern = trim($pattern);
            if ($pattern === '' || ($isRegex && !PatternValidator::isValid($pattern))) {
                return false;
            }

            $sql->setQuery(
                'UPDATE ' . rex::getTable('upkeep_mail_badwords') . ' SET pattern = ?, description = ?, category = ?, severity = ?, is_regex = ?, status = ?, updated_at = NOW(), edited_by = ? WHERE id = ?',
                [$pattern, $description, $category, self::normalizeSeverity($severity), $isRegex ? 1 : 0, $status ? 1 : 0, rex::getUser() ? rex::getUser()->getLogin() : '', $id],
            );
            self::clearBadwordsCache();
            return true;
        } catch (\Throwable $e) {
            self::debugLog('Failed to update badword: ' . $e->getMessage());
            return false;
        }
    }

    private static function normalizeSeverity(string $severity): string
    {
        return in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? $severity : 'medium';
    }
    
    /**
     * Entfernt ein Badword (mit Berechtigungsprüfung)
     * 
     * @param int $id Die ID des zu löschenden Badwords
     * @return bool   Erfolgsstatus
     */
    public static function deleteBadword(int $id): bool
    {
        return self::removeBadword($id);
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
            return [
                'threats_24h' => [],
                'rate_limiting' => ['unique_ips' => 0, 'total_mails' => 0],
                'active' => self::isMailSecurityActive(),
                'rate_limiting_enabled' => self::isMailRateLimitingEnabled(),
            ];
        }
    }


    /**
     * Schaltet den Status eines Standard-Patterns um
     */
    public static function toggleDefaultPatternStatus(int $id): bool
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery("SELECT status FROM " . rex::getTable('upkeep_mail_default_patterns') . " WHERE id = ?", [$id]);
            
            if ($sql->getRows() > 0) {
                $currentStatus = (bool) $sql->getValue('status');
                $newStatus = $currentStatus ? 0 : 1;
                
                $sql->setQuery("UPDATE " . rex::getTable('upkeep_mail_default_patterns') . " SET status = ?, updated_at = NOW() WHERE id = ?", [$newStatus, $id]);
                
                // Cache leeren
                self::clearDefaultPatternsCache();
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            self::debugLog("Failed to toggle default pattern status: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Aktualisiert ein Standard-Pattern (RegEx wird validiert)
     */
    public static function updateDefaultPattern(int $id, string $pattern, string $description, string $severity, bool $isRegex, bool $status): bool
    {
        $pattern = trim($pattern);
        if ($pattern === '' || ($isRegex && !PatternValidator::isValid($pattern))) {
            return false;
        }
        try {
            $sql = rex_sql::factory();
            $sql->setQuery(
                'UPDATE ' . rex::getTable('upkeep_mail_default_patterns') . ' SET pattern = ?, description = ?, severity = ?, is_regex = ?, status = ?, updated_at = NOW() WHERE id = ?',
                [$pattern, $description, self::normalizeSeverity($severity), $isRegex ? 1 : 0, $status ? 1 : 0, $id],
            );
            self::clearDefaultPatternsCache();
            return $sql->getRows() >= 0;
        } catch (\Throwable $e) {
            self::debugLog('Failed to update default pattern: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Leert den Cache für Standard-Patterns
     */
    private static function clearDefaultPatternsCache(): void
    {
        // Cache durch erneutes Laden leeren
        self::getDefaultMailPatterns();
    }
}
