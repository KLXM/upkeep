<?php
/**
 * Upkeep AddOn - Mail Reporting System
 *
 * Berichte für alle Upkeep-Komponenten:
 * - Empfehlungen (Security Advisor)
 * - IPS-Ereignisse
 * - Wartungsmodus-Änderungen
 * - Fehler aus dem REDAXO-Systemlog (im Sammelbericht)
 * - Statusberichte
 *
 * 3.0: Sofort-Mails gedrosselt, Protokolldateien begrenzt, IPS-Ereignisse stündlich
 * zusammengefasst, keine Abhängigkeit vom nicht existierenden EP SYSTEM_LOG.
 */

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_dir;
use rex_extension;
use rex_extension_point;
use rex_file;
use rex_log_file;
use rex_logger;
use rex_mailer;
use rex_markdown;
use rex_path;
use rex_sql;
use Throwable;

class MailReporting
{
    public const EMAIL_NAME = 'Upkeep Reporting';

    public const DATA_PATH = 'mail_reporting';

    /** Report types */
    public const TYPE_SECURITY_ADVISOR = 'security_advisor';
    public const TYPE_IPS_THREAT = 'ips_threat';
    public const TYPE_MAINTENANCE = 'maintenance';
    public const TYPE_ERROR = 'error';
    public const TYPE_STATUS = 'status';

    /** Severity levels */
    public const SEVERITY_INFO = 'info';
    public const SEVERITY_WARNING = 'warning';
    public const SEVERITY_ERROR = 'error';
    public const SEVERITY_CRITICAL = 'critical';

    /** Höchstzahl an Protokolldateien (älteste werden entfernt) */
    private const MAX_LOG_FILES = 500;

    /** IPS-Einträge pro Stundendatei */
    private const MAX_THREATS_PER_FILE = 200;

    /** Sofort-Mails für IPS-Ereignisse: global pro Stunde / pro IP pro Stunde */
    private const MAX_IMMEDIATE_PER_HOUR = 10;

    private static ?rex_addon $addon = null;

    private static bool $initialized = false;

    private static function addon(): rex_addon
    {
        return self::$addon ??= rex_addon::get('upkeep');
    }

    /**
     * Registriert die Extension Points. Muss in boot.php VOR IntrusionPrevention::checkRequest()
     * aufgerufen werden, sonst gehen IPS-Ereignisse des aktuellen Requests verloren.
     * Mehrfacher Aufruf ist unschädlich.
     */
    public static function init(): void
    {
        if (self::$initialized) {
            return;
        }
        self::$initialized = true;

        if (!self::isEnabled()) {
            return;
        }

        rex_extension::register('UPKEEP_SECURITY_SCAN_COMPLETED', static function (rex_extension_point $ep) {
            self::safe(static function () use ($ep) {
                if (!self::isTypeEnabled(self::TYPE_SECURITY_ADVISOR)) {
                    return;
                }
                $results = (array) $ep->getSubject();
                if (self::shouldSendImmediate(self::TYPE_SECURITY_ADVISOR)) {
                    self::sendSecurityAdvisorReport($results);
                } else {
                    self::logReport(self::TYPE_SECURITY_ADVISOR, $results);
                }
            });
        });

        rex_extension::register('UPKEEP_IPS_THREAT_DETECTED', static function (rex_extension_point $ep) {
            self::safe(static function () use ($ep) {
                if (!self::isTypeEnabled(self::TYPE_IPS_THREAT)) {
                    return;
                }
                $data = (array) $ep->getSubject();
                $severity = strtolower((string) ($data['severity'] ?? ''));
                if (self::shouldSendImmediate(self::TYPE_IPS_THREAT, $severity) && self::allowImmediateThreatMail($data)) {
                    self::sendThreatNotification($data);
                } else {
                    self::logReport(self::TYPE_IPS_THREAT, $data);
                }
            });
        });

        rex_extension::register('UPKEEP_MAINTENANCE_CHANGED', static function (rex_extension_point $ep) {
            self::safe(static function () use ($ep) {
                if (!self::isTypeEnabled(self::TYPE_MAINTENANCE)) {
                    return;
                }
                $data = (array) $ep->getSubject();
                if (self::shouldSendImmediate(self::TYPE_MAINTENANCE)) {
                    self::sendMaintenanceNotification($data);
                } else {
                    self::logReport(self::TYPE_MAINTENANCE, $data);
                }
            });
        });
    }

    private static function safe(callable $fn): void
    {
        try {
            $fn();
        } catch (Throwable $e) {
            try {
                rex_logger::logException($e);
            } catch (Throwable) {
            }
        }
    }

    public static function isEnabled(): bool
    {
        return (bool) self::addon()->getConfig('mail_reporting_enabled', 0);
    }

    /**
     * Ereignis-Schalter der Einstellungen (Abschnitt Berichte):
     * - mail_reporting_ips_threats (1): IPS-Ereignisse (Sofort-Mail, Sammelbericht, Statusbericht-Zeilen)
     * - mail_reporting_maintenance (1): Wartungsmodus-Änderungen
     * - mail_reporting_security_advisor (1): Empfehlungen (Security Advisor)
     * - mail_reporting_phpmailer_errors (1): Fehler aus dem Systemlog im Sammelbericht
     * - mail_reporting_status_reports (0): täglicher Statusbericht im Sammellauf (Cronjob/Konsole)
     * Unbekannte Typen (z. B. status, error) sind immer erlaubt.
     */
    public static function isTypeEnabled(string $type): bool
    {
        $key = match ($type) {
            self::TYPE_IPS_THREAT => 'mail_reporting_ips_threats',
            self::TYPE_MAINTENANCE => 'mail_reporting_maintenance',
            self::TYPE_SECURITY_ADVISOR => 'mail_reporting_security_advisor',
            default => null,
        };
        return $key === null || (bool) self::addon()->getConfig($key, 1);
    }

    /**
     * Standard-Intervall für den Sammelversand in Sekunden (mail_reporting_bundle_interval, 300–86400)
     */
    public static function getBundleInterval(): int
    {
        return max(300, min(86400, (int) self::addon()->getConfig('mail_reporting_bundle_interval', 3600)));
    }

    public static function getEmail(): string
    {
        $email = (string) self::addon()->getConfig('mail_reporting_email', '');
        return $email !== '' ? $email : (string) rex::getErrorEmail();
    }

    public static function getName(): string
    {
        $name = (string) self::addon()->getConfig('mail_reporting_name', '');
        return $name !== '' ? $name : self::EMAIL_NAME;
    }

    public static function getKey(): string
    {
        return (string) self::addon()->getConfig('mail_reporting_key', '');
    }

    private static function shouldSendImmediate(string $type, ?string $severity = null): bool
    {
        if (!self::isEnabled()) {
            return false;
        }

        $mode = (int) self::addon()->getConfig('mail_reporting_mode', 1); // 0=immediate, 1=bundle
        if ($mode === 0) {
            return true;
        }

        $severity = strtolower((string) $severity);
        if ($type === self::TYPE_IPS_THREAT && $severity === 'critical') {
            return true;
        }
        if ($type === self::TYPE_ERROR && in_array($severity, ['error', 'critical'], true)) {
            return true;
        }

        return false;
    }

    /**
     * Drosselt Sofort-Mails zu IPS-Ereignissen (pro IP und Typ eine Mail je Stunde, max. 10 je Stunde).
     *
     * @param array<string, mixed> $data
     */
    private static function allowImmediateThreatMail(array $data): bool
    {
        $store = new JsonStore('mail_reporting_throttle', 1000);
        $hour = date('YmdH');
        $key = 'ip:' . ($data['ip'] ?? '') . ':' . ($data['threat_type'] ?? '') . ':' . $hour;
        if ((int) $store->get($key, 0) > 0) {
            return false;
        }
        if ((int) $store->get('global:' . $hour, 0) >= self::MAX_IMMEDIATE_PER_HOUR) {
            return false;
        }
        $store->increment($key, 3600);
        $store->increment('global:' . $hour, 3600);
        return true;
    }

    private static function newMailer(): rex_mailer
    {
        $mail = new rex_mailer();
        $mail->addAddress(self::getEmail(), self::getName());
        return $mail;
    }

    private static function sendMarkdown(string $subject, string $markdown, ?callable $prepare = null): bool
    {
        $mail = self::newMailer();
        $mail->Subject = str_replace(["\r", "\n"], ' ', $subject);
        $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
        $mail->AltBody = $markdown;
        if ($prepare !== null) {
            $prepare($mail);
        }
        return $mail->send();
    }

    /**
     * Markdown-sicherer Tabellenwert (keine Pipes/Zeilenumbrüche, HTML wird vom Parser escaped)
     */
    private static function cell(mixed $value): string
    {
        $value = is_scalar($value) ? (string) $value : (string) json_encode($value);
        return str_replace(['|', "\r", "\n", '<', '>'], ['/', ' ', ' ', '&lt;', '&gt;'], mb_substr($value, 0, 500));
    }

    /**
     * @param array<string, mixed> $results
     */
    public static function sendSecurityAdvisorReport(array $results): bool
    {
        try {
            $score = (int) ($results['security_score'] ?? $results['score'] ?? 0);
            $grade = (string) ($results['security_grade'] ?? $results['grade'] ?? '');
            $critical = (int) ($results['critical_issues'] ?? 0);

            $subject = "Upkeep Empfehlungen - Score: {$score}%" . ($grade !== '' ? " ({$grade})" : '');
            if ($critical > 0) {
                $subject .= " - {$critical} kritisch";
            }
            return self::sendMarkdown($subject, self::generateSecurityAdvisorMarkdown($results));
        } catch (Throwable $e) {
            self::logError('Security Advisor Report failed', $e);
            return false;
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function sendThreatNotification(array $data): bool
    {
        try {
            $severity = strtoupper((string) ($data['severity'] ?? 'UNKNOWN'));
            $ip = (string) ($data['ip'] ?? 'unknown');
            return self::sendMarkdown("Upkeep IPS: {$severity} threat from {$ip}", self::generateThreatMarkdown($data));
        } catch (Throwable $e) {
            self::logError('Threat Notification failed', $e);
            return false;
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function sendMaintenanceNotification(array $data): bool
    {
        try {
            $type = (string) ($data['type'] ?? 'unknown');
            $status = !empty($data['status']) ? 'activated' : 'deactivated';
            return self::sendMarkdown("Upkeep Maintenance: {$type} {$status}", self::generateMaintenanceMarkdown($data));
        } catch (Throwable $e) {
            self::logError('Maintenance Notification failed', $e);
            return false;
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function sendErrorNotification(array $data): bool
    {
        try {
            $level = strtoupper((string) ($data['level'] ?? 'ERROR'));
            $message = (string) ($data['message'] ?? 'Unknown error');
            return self::sendMarkdown("Upkeep Error Report: {$level} - " . mb_substr($message, 0, 50), self::generateErrorMarkdown($data));
        } catch (Throwable $e) {
            self::logError('Error Notification failed', $e);
            return false;
        }
    }

    public static function sendTestEmail(): bool
    {
        try {
            $markdown = "# Upkeep Mail Reporting Test\n\n";
            $markdown .= '**Timestamp:** ' . date('Y-m-d H:i:s') . "\n\n";
            $markdown .= "**Message:** This is a test email from the Upkeep Mail Reporting system.\n\n";
            $markdown .= '**Server:** ' . self::cell(rex::getServerName()) . "\n\n";
            $markdown .= '**REDAXO Version:** ' . rex::getVersion() . "\n\n";
            $markdown .= '**PHP Version:** ' . PHP_VERSION . "\n\n";
            $markdown .= 'If you received this email, the Mail Reporting system is working correctly.';
            return self::sendMarkdown('Upkeep Test Email - ' . date('Y-m-d H:i:s'), $markdown);
        } catch (Throwable $e) {
            self::logError('Test Email failed', $e);
            return false;
        }
    }

    public static function sendStatusReport(): bool
    {
        try {
            $addon = self::addon();
            $advisor = (array) $addon->getConfig('advisor_results', []);
            $statusData = [
                'timestamp' => time(),
                'maintenance' => [
                    'frontend' => (bool) $addon->getConfig('frontend_active', false),
                    'backend' => (bool) $addon->getConfig('backend_active', false),
                ],
                'ips' => [
                    'active' => (bool) $addon->getConfig('ips_active', false),
                    'monitor_only' => (bool) $addon->getConfig('ips_monitor_only', false),
                    'recent_threats' => self::getRecentThreats(24),
                    'blocked_ips_count' => self::getBlockedIPsCount(),
                ],
                'security_advisor' => [
                    'last_scan' => (int) $addon->getConfig('advisor_last_check', $addon->getConfig('security_advisor_last_check', 0)),
                    'score' => (int) ($advisor['score'] ?? $advisor['security_score'] ?? $addon->getConfig('security_advisor_score', 0)),
                    'grade' => (string) ($advisor['grade'] ?? $advisor['security_grade'] ?? $addon->getConfig('security_advisor_grade', '-')),
                ],
            ];

            return self::sendMarkdown('Upkeep Status Report - ' . date('Y-m-d H:i:s'), self::generateStatusMarkdown($statusData));
        } catch (Throwable $e) {
            self::logError('Status Report failed', $e);
            return false;
        }
    }

    /**
     * Legt einen Bericht für den Sammelversand ab.
     * IPS-Ereignisse werden pro Stunde in einer Datei gesammelt (max. 200 Einträge, Rest gezählt).
     * Insgesamt höchstens 500 Dateien; die ältesten werden entfernt.
     *
     * @param array<string, mixed> $data
     */
    public static function logReport(string $type, array $data): void
    {
        try {
            $type = preg_replace('/[^a-z_]/', '', strtolower($type)) ?: 'status';

            if ($type === self::TYPE_IPS_THREAT) {
                self::appendHourlyThreat($data);
                return;
            }

            $filename = time() . '_' . $type . '_' . bin2hex(random_bytes(3)) . '.log.json';
            rex_file::put(self::getDataPath($filename), (string) json_encode([
                'type' => $type,
                'timestamp' => time(),
                'data' => $data,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR));

            self::enforceFileLimit();
        } catch (Throwable $e) {
            self::logError('logReport failed', $e);
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function appendHourlyThreat(array $data): void
    {
        $hourStart = (int) (floor(time() / 3600) * 3600);
        $file = self::getDataPath($hourStart . '_ips_threat.log.json');

        $fh = @fopen($file, 'c+');
        if ($fh === false) {
            return;
        }
        try {
            if (!flock($fh, LOCK_EX)) {
                return;
            }
            $raw = stream_get_contents($fh);
            $log = $raw ? json_decode($raw, true) : null;
            if (!is_array($log) || !isset($log['data']['entries'])) {
                $log = ['type' => self::TYPE_IPS_THREAT, 'timestamp' => $hourStart, 'data' => ['total' => 0, 'dropped' => 0, 'entries' => []]];
            }
            ++$log['data']['total'];
            if (count($log['data']['entries']) < self::MAX_THREATS_PER_FILE) {
                $log['data']['entries'][] = [
                    'timestamp' => $data['timestamp'] ?? date('Y-m-d H:i:s'),
                    'ip' => (string) ($data['ip'] ?? ''),
                    'severity' => (string) ($data['severity'] ?? ''),
                    'threat_type' => (string) ($data['threat_type'] ?? ''),
                    'pattern' => mb_substr((string) ($data['pattern'] ?? ''), 0, 200),
                    'uri' => mb_substr((string) ($data['uri'] ?? ''), 0, 300),
                ];
            } else {
                ++$log['data']['dropped'];
            }
            ftruncate($fh, 0);
            rewind($fh);
            fwrite($fh, (string) json_encode($log, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR));
            flock($fh, LOCK_UN);
        } finally {
            fclose($fh);
        }
        self::enforceFileLimit();
    }

    private static function enforceFileLimit(): void
    {
        $files = self::getLogFiles();
        if (count($files) <= self::MAX_LOG_FILES) {
            return;
        }
        sort($files, SORT_NATURAL);
        foreach (array_slice($files, 0, count($files) - self::MAX_LOG_FILES) as $file) {
            rex_file::delete(self::getDataPath($file));
        }
    }

    /**
     * Sendet gesammelte Berichte (optional inkl. Fehler aus dem Systemlog seit dem letzten Versand)
     */
    public static function sendBundleReport(int $interval = 3600): bool
    {
        $fromTime = time() - max(300, $interval);
        $sendFiles = [];
        foreach (self::getLogFiles() as $file) {
            // Abgeschaltete Ereignisarten werden nicht versendet und verworfen
            if (preg_match('/^\d+_([a-z_]+?)(?:_[0-9a-f]{6})?\.log\.json$/', $file, $m) && !self::isTypeEnabled($m[1])) {
                rex_file::delete(self::getDataPath($file));
                continue;
            }
            $ts = (int) strtok($file, '_');
            // Stundendateien beginnen vor dem Intervall, enthalten aber neue Einträge
            if ($ts > $fromTime - 3600) {
                $sendFiles[] = $file;
            }
        }

        $systemErrors = [];
        if (self::addon()->getConfig('mail_reporting_phpmailer_errors', 0)) {
            $systemErrors = self::collectSystemLogErrors((int) self::addon()->getConfig('mail_reporting_last_bundle', $fromTime));
        }

        if ($sendFiles === [] && $systemErrors === []) {
            return true;
        }

        try {
            $paths = array_map(static fn ($f) => self::getDataPath($f), $sendFiles);
            $result = self::sendMarkdown(
                'Upkeep Bundle Report - ' . count($sendFiles) . ' items',
                self::generateBundleMarkdown($sendFiles, $systemErrors),
                static function (rex_mailer $mail) use ($paths) {
                    foreach (array_slice($paths, 0, 50) as $path) {
                        if (is_file($path)) {
                            $mail->addAttachment($path);
                        }
                    }
                },
            );

            if ($result) {
                foreach ($paths as $path) {
                    rex_file::delete($path);
                }
                self::addon()->setConfig('mail_reporting_last_bundle', time());
            }
            return $result;
        } catch (Throwable $e) {
            self::logError('Bundle Report failed', $e);
            return false;
        }
    }

    /**
     * Geplanter Sammellauf (Cronjob-Typ „Upkeep: Berichte versenden“).
     * Der Cronjob darf häufiger laufen als das Intervall: gesendet wird erst, wenn seit dem letzten
     * Versand mail_reporting_bundle_interval Sekunden vergangen sind; der Bericht umfasst dann alles
     * seit dem letzten Versand. Zusätzlich ggf. der tägliche Statusbericht.
     *
     * @return array{bundle: bool|null, status: bool|null} null = nicht fällig/abgeschaltet
     */
    public static function runScheduled(): array
    {
        $result = ['bundle' => null, 'status' => null];
        if (!self::isEnabled()) {
            return $result;
        }
        $interval = self::getBundleInterval();
        $last = (int) self::addon()->getConfig('mail_reporting_last_bundle', 0);
        // auch im Sofort-Modus: gedrosselte IPS-Ereignisse landen in den Protokolldateien
        if (time() - $last >= $interval) {
            $window = $last > 0 ? max($interval, time() - $last) : $interval;
            $result['bundle'] = self::sendBundleReport(min($window, 30 * 86400));
            if ($result['bundle']) {
                // auch ohne Inhalt als Versand-Zeitpunkt merken, sonst prüft jeder Lauf erneut
                self::addon()->setConfig('mail_reporting_last_bundle', time());
            }
        }
        $result['status'] = self::maybeSendStatusReport();
        return $result;
    }

    /**
     * Statusbericht höchstens einmal pro 24 h, nur wenn mail_reporting_status_reports aktiv ist.
     * Merker: Konfiguration mail_reporting_last_status (ein Wert, kein Schlüssel pro IP).
     *
     * @return bool|null null = abgeschaltet oder noch nicht fällig
     */
    public static function maybeSendStatusReport(bool $force = false): ?bool
    {
        if (!(bool) self::addon()->getConfig('mail_reporting_status_reports', 0)) {
            return null;
        }
        $last = (int) self::addon()->getConfig('mail_reporting_last_status', 0);
        if (!$force && time() - $last < 86400) {
            return null;
        }
        $sent = self::sendStatusReport();
        if ($sent) {
            self::addon()->setConfig('mail_reporting_last_status', time());
        }
        return $sent;
    }

    /**
     * Fehler und Ausnahmen aus dem REDAXO-Systemlog seit $since (max. 20 Einträge)
     *
     * @return list<array{time: string, type: string, message: string, file: string, line: string}>
     */
    private static function collectSystemLogErrors(int $since): array
    {
        $result = [];
        try {
            $path = rex_logger::getPath();
            if (!is_file($path)) {
                return [];
            }
            $file = new rex_log_file($path);
            foreach (new \LimitIterator($file, 0, 500) as $entry) {
                if ($entry->getTimestamp() < $since) {
                    break;
                }
                $data = $entry->getData();
                $type = strtolower((string) ($data[0] ?? ''));
                if (!preg_match('/error|exception|critical|fatal/', $type)) {
                    continue;
                }
                $result[] = [
                    'time' => date('Y-m-d H:i:s', $entry->getTimestamp()),
                    'type' => (string) ($data[0] ?? ''),
                    'message' => mb_substr((string) ($data[1] ?? ''), 0, 300),
                    'file' => rex_path::relative((string) ($data[2] ?? '')),
                    'line' => (string) ($data[3] ?? ''),
                ];
                if (count($result) >= 20) {
                    break;
                }
            }
        } catch (Throwable) {
            return $result;
        }
        return $result;
    }

    /**
     * @param array<string, mixed> $results
     */
    private static function generateSecurityAdvisorMarkdown(array $results): string
    {
        $md = "# Upkeep Empfehlungen\n\n";
        $md .= "| Field | Value |\n|-------|-------|\n";
        $md .= '| **Report Key** | ' . self::cell(self::getKey()) . " |\n";
        $md .= '| **Timestamp** | ' . date('Y-m-d H:i:s') . " |\n";
        foreach (['security_score' => 'Score', 'security_grade' => 'Grade', 'critical_issues' => 'Critical', 'warning_issues' => 'Warnings', 'overall_status' => 'Status'] as $key => $label) {
            if (isset($results[$key])) {
                $md .= '| **' . $label . '** | ' . self::cell($results[$key]) . " |\n";
            }
        }
        $md .= "\n";

        if (!empty($results['checks']) && is_array($results['checks'])) {
            $md .= "## Details\n\n";
            foreach ($results['checks'] as $check) {
                if (!is_array($check)) {
                    continue;
                }
                $md .= '### ' . self::cell($check['name'] ?? '') . ' (' . self::cell($check['status'] ?? '') . ")\n";
                if (isset($check['message'])) {
                    $md .= '- ' . self::cell($check['message']) . "\n";
                }
                foreach ((array) ($check['recommendations'] ?? []) as $rec) {
                    $md .= '  - ' . self::cell($rec) . "\n";
                }
                $md .= "\n";
            }
        }

        return $md;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function generateThreatMarkdown(array $data): string
    {
        $md = "# Upkeep IPS Threat Alert\n\n";
        $md .= "| Field | Value |\n|-------|-------|\n";
        $md .= '| **Report Key** | ' . self::cell(self::getKey()) . " |\n";
        $md .= '| **Timestamp** | ' . self::cell($data['timestamp'] ?? date('Y-m-d H:i:s')) . " |\n";
        $md .= '| **IP Address** | ' . self::cell($data['ip'] ?? '') . " |\n";
        $md .= '| **Severity** | ' . self::cell($data['severity'] ?? '') . " |\n";
        $md .= '| **Threat Type** | ' . self::cell($data['threat_type'] ?? '') . " |\n";
        $md .= '| **Pattern Matched** | ' . self::cell($data['pattern'] ?? '') . " |\n";
        $md .= '| **Request URI** | ' . self::cell($data['uri'] ?? '') . " |\n";
        $md .= '| **Method** | ' . self::cell($data['method'] ?? 'GET') . " |\n";
        $md .= '| **User Agent** | ' . self::cell($data['user_agent'] ?? '') . " |\n";
        $md .= '| **Action** | ' . self::cell($data['action'] ?? '') . " |\n";
        $country = GeoIP::getCountry((string) ($data['ip'] ?? ''));
        $md .= '| **Country** | ' . self::cell($country['name'] . ' (' . $country['code'] . ')') . " |\n";
        return $md;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function generateMaintenanceMarkdown(array $data): string
    {
        $active = !empty($data['status']);
        $md = "# Upkeep Maintenance Notification\n\n";
        $md .= "| Field | Value |\n|-------|-------|\n";
        $md .= '| **Report Key** | ' . self::cell(self::getKey()) . " |\n";
        $md .= '| **Timestamp** | ' . date('Y-m-d H:i:s') . " |\n";
        $md .= '| **Type** | ' . self::cell($data['type'] ?? '') . " |\n";
        $md .= '| **Action** | ' . ($active ? 'activated' : 'deactivated') . " |\n";
        $md .= '| **Source** | ' . self::cell($data['source'] ?? '') . " |\n";
        $md .= '| **User** | ' . self::cell($data['user'] ?? 'System') . " |\n";
        if (!empty($data['ip'])) {
            $md .= '| **IP Address** | ' . self::cell($data['ip']) . " |\n";
        }
        $md .= "\n";
        $md .= $active
            ? 'The ' . self::cell($data['type'] ?? '') . " maintenance mode has been **activated**.\n"
            : 'The ' . self::cell($data['type'] ?? '') . " maintenance mode has been **deactivated**. Normal operations have resumed.\n";
        return $md;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function generateErrorMarkdown(array $data): string
    {
        $md = "# Upkeep Error Report\n\n";
        $md .= "| Field | Value |\n|-------|-------|\n";
        $md .= '| **Report Key** | ' . self::cell(self::getKey()) . " |\n";
        $md .= '| **Timestamp** | ' . date('Y-m-d H:i:s', (int) ($data['timestamp'] ?? time())) . " |\n";
        $md .= '| **Level** | ' . self::cell($data['level'] ?? '') . " |\n";
        $md .= '| **Message** | ' . self::cell($data['message'] ?? '') . " |\n";
        if (!empty($data['file'])) {
            $md .= '| **File** | ' . self::cell(rex_path::relative((string) $data['file'])) . " |\n";
        }
        if (!empty($data['line'])) {
            $md .= '| **Line** | ' . self::cell($data['line']) . " |\n";
        }
        return $md;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function generateStatusMarkdown(array $data): string
    {
        $md = "# Upkeep Status Report\n\n";
        $md .= "| Component | Status |\n|-----------|--------|\n";
        $md .= '| **Report Key** | ' . self::cell(self::getKey()) . " |\n";
        $md .= '| **Timestamp** | ' . date('Y-m-d H:i:s', (int) $data['timestamp']) . " |\n";
        if (self::isTypeEnabled(self::TYPE_MAINTENANCE)) {
            $md .= '| **Frontend Maintenance** | ' . ($data['maintenance']['frontend'] ? 'Active' : 'Inactive') . " |\n";
            $md .= '| **Backend Maintenance** | ' . ($data['maintenance']['backend'] ? 'Active' : 'Inactive') . " |\n";
        }
        $md .= '| **IPS Protection** | ' . ($data['ips']['active'] ? 'Active' : 'Inactive') . ($data['ips']['monitor_only'] ? ' (Monitor Only)' : '') . " |\n";
        if (self::isTypeEnabled(self::TYPE_IPS_THREAT)) {
            $md .= '| **Blocked IPs** | ' . (int) $data['ips']['blocked_ips_count'] . " |\n";
            $md .= '| **Threats (24h)** | ' . count($data['ips']['recent_threats']) . " |\n";
        }
        if (self::isTypeEnabled(self::TYPE_SECURITY_ADVISOR)) {
            $lastScan = $data['security_advisor']['last_scan'] > 0 ? date('Y-m-d H:i:s', (int) $data['security_advisor']['last_scan']) : 'Never';
            $md .= '| **Security Score** | ' . (int) $data['security_advisor']['score'] . '% (' . self::cell($data['security_advisor']['grade']) . ") |\n";
            $md .= '| **Last Check** | ' . $lastScan . " |\n";
        }

        $issues = [];
        if ($data['maintenance']['frontend'] || $data['maintenance']['backend']) {
            $issues[] = 'Maintenance mode active';
        }
        if (!$data['ips']['active']) {
            $issues[] = 'IPS protection disabled';
        }
        if (self::isTypeEnabled(self::TYPE_IPS_THREAT) && count($data['ips']['recent_threats']) > 10) {
            $issues[] = 'High threat activity';
        }

        $md .= "\n## System Health\n\n";
        if ($issues !== []) {
            $md .= "**Notes:**\n";
            foreach ($issues as $issue) {
                $md .= "- {$issue}\n";
            }
        } else {
            $md .= "All systems operating normally.\n";
        }
        return $md;
    }

    /**
     * @param list<string> $files
     * @param list<array<string, string>> $systemErrors
     */
    private static function generateBundleMarkdown(array $files, array $systemErrors = []): string
    {
        $md = "# Upkeep Bundle Report\n\n";
        $md .= 'This bundle contains ' . count($files) . " reports from the last reporting interval.\n\n";

        $typeCount = [];
        foreach ($files as $file) {
            if (preg_match('/^\d+_([a-z_]+?)(?:_[0-9a-f]{6})?\.log\.json$/', $file, $m)) {
                $count = 1;
                if ($m[1] === self::TYPE_IPS_THREAT) {
                    $log = json_decode((string) @file_get_contents(self::getDataPath($file)), true);
                    $count = (int) ($log['data']['total'] ?? 1);
                }
                $typeCount[$m[1]] = ($typeCount[$m[1]] ?? 0) + $count;
            }
        }

        if ($typeCount !== []) {
            $md .= "## Summary\n\n| Type | Count |\n|------|-------|\n";
            foreach ($typeCount as $type => $count) {
                $md .= '| ' . ucwords(str_replace('_', ' ', $type)) . " | {$count} |\n";
            }
            $md .= "\n";
        }

        if ($systemErrors !== []) {
            $md .= "## System log errors\n\n| Time | Type | Message | File |\n|------|------|---------|------|\n";
            foreach ($systemErrors as $err) {
                $md .= '| ' . $err['time'] . ' | ' . self::cell($err['type']) . ' | ' . self::cell($err['message']) . ' | ' . self::cell($err['file'] . ($err['line'] !== '' ? ':' . $err['line'] : '')) . " |\n";
            }
            $md .= "\n";
        }

        if ($files !== []) {
            $md .= "Detailed reports are attached as files.\n";
        }
        return $md;
    }

    /**
     * @return list<string>
     */
    public static function getLogFiles(): array
    {
        $path = self::getDataPath();
        if (!is_dir($path)) {
            return [];
        }
        $files = @scandir($path);
        if (!is_array($files)) {
            return [];
        }
        return array_values(array_filter($files, static fn ($file) => $file !== '.' && $file !== '..' && str_ends_with($file, '.log.json')));
    }

    public static function deleteLogFiles(): void
    {
        foreach (self::getLogFiles() as $file) {
            rex_file::delete(self::getDataPath($file));
        }
    }

    public static function getDataPath(string $file = ''): string
    {
        $path = self::addon()->getDataPath(self::DATA_PATH);
        if (!is_dir($path)) {
            rex_dir::create($path);
        }
        if ($file !== '') {
            $path .= '/' . basename($file);
        }
        return $path;
    }

    private static function logError(string $message, ?Throwable $e = null): void
    {
        try {
            rex_logger::logException($e ?? new \RuntimeException($message));
        } catch (Throwable) {
        }
    }

    /**
     * Letzte Bedrohungen aus der Datenbank
     *
     * @return list<array<string, mixed>>
     */
    private static function getRecentThreats(int $hours): array
    {
        try {
            return rex_sql::factory()->getArray(
                'SELECT ip_address, threat_type, severity, pattern_matched, created_at FROM ' . rex::getTable('upkeep_ips_threat_log') . " WHERE created_at >= ? AND action_taken <> 'logged_authenticated' ORDER BY created_at DESC LIMIT 50",
                [date('Y-m-d H:i:s', time() - $hours * 3600)],
            );
        } catch (Throwable) {
            return [];
        }
    }

    private static function getBlockedIPsCount(): int
    {
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT COUNT(*) as count FROM ' . rex::getTable('upkeep_ips_blocked_ips') . ' WHERE expires_at IS NULL OR expires_at > ?', [date('Y-m-d H:i:s')]);
            return (int) $sql->getValue('count');
        } catch (Throwable) {
            return 0;
        }
    }

    /**
     * Löst eine Wartungsbenachrichtigung aus (über UPKEEP_MAINTENANCE_CHANGED)
     *
     * @param array<string, mixed> $config
     */
    public static function triggerMaintenanceNotification(string $type, bool $status, array $config = []): void
    {
        Upkeep::fireMaintenanceChanged($type, $status, 'backend');
    }

    /**
     * Löst eine Benachrichtigung zu Empfehlungen aus (über UPKEEP_SECURITY_SCAN_COMPLETED)
     *
     * @param array<string, mixed> $results
     */
    public static function triggerSecurityScanNotification(array $results): void
    {
        try {
            rex_extension::registerPoint(new rex_extension_point('UPKEEP_SECURITY_SCAN_COMPLETED', $results));
        } catch (Throwable $e) {
            self::logError('triggerSecurityScanNotification failed', $e);
        }
    }
}
