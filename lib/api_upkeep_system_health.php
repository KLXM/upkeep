<?php
/**
 * Upkeep AddOn - System Health API Handler
 *
 * Aufruf: ?rex-api-call=upkeep_system_health
 * Schlüssel (Pflicht): Header "Authorization: Bearer <key>" oder "X-Upkeep-Health-Key: <key>",
 * veraltet auch Parameter "key" / "health_key".
 * Ohne gültigen Schlüssel (oder wenn die API ausgeschaltet ist) gibt es nur 403 und keine Daten.
 */

use KLXM\Upkeep\ClientIp;
use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\JsonStore;
use KLXM\Upkeep\MailReporting;

class rex_api_upkeep_system_health extends rex_api_function
{
    protected $published = true;
    protected $requires_csrf_token = false;

    private const MAX_FAILED = 20;
    private const FAILED_WINDOW = 600;

    public function execute()
    {
        try {
            $this->handle();
        } catch (Throwable $e) {
            rex_logger::logException($e);
            self::send(['status' => 'error', 'error' => 'Internal Server Error', 'timestamp' => time()], 500);
        }
        return new rex_api_result(false);
    }

    private function handle(): void
    {
        $addon = rex_addon::get('upkeep');

        $store = new JsonStore('api_auth_failures', 2000);
        $ipKey = 'health_api:' . ClientIp::get();
        if ((int) $store->get($ipKey, 0) >= self::MAX_FAILED) {
            self::send(['status' => 'forbidden', 'error' => 'Too many requests'], 429);
        }

        $healthKey = (string) $addon->getConfig('system_health_key', '');
        $providedKey = self::getProvidedKey();
        $enabled = (bool) $addon->getConfig('system_health_enabled', false);

        if (!$enabled || $healthKey === '' || $providedKey === '' || !hash_equals($healthKey, $providedKey)) {
            if ($providedKey !== '') {
                $store->increment($ipKey, self::FAILED_WINDOW);
            }
            self::send(['status' => 'forbidden', 'error' => 'Forbidden'], 403);
        }

        $format = rex_request('format', 'string', 'json');
        $detailed = rex_request('detailed', 'bool', false);

        $advisor = (array) $addon->getConfig('advisor_results', []);
        $ipsStats = IntrusionPrevention::getIndicatorStats();

        $healthData = [
            'timestamp' => time(),
            'datetime' => date('Y-m-d H:i:s'),
            'status' => 'ok',
            'upkeep' => [
                'version' => $addon->getVersion(),
                'maintenance' => [
                    'frontend' => (bool) $addon->getConfig('frontend_active', false),
                    'backend' => (bool) $addon->getConfig('backend_active', false),
                ],
                'security_advisor' => [
                    'enabled' => (bool) $addon->getConfig('advisor_active', true),
                    'last_scan' => (int) $addon->getConfig('advisor_last_check', $addon->getConfig('security_advisor_last_check', 0)),
                    'score' => (int) ($advisor['score'] ?? $advisor['security_score'] ?? $addon->getConfig('security_advisor_score', 0)),
                    'grade' => (string) ($advisor['grade'] ?? $advisor['security_grade'] ?? $addon->getConfig('security_advisor_grade', '')),
                    'critical_issues' => (int) ($advisor['critical_issues'] ?? $addon->getConfig('security_advisor_critical_issues', 0)),
                    'warning_issues' => (int) ($advisor['warning_issues'] ?? $addon->getConfig('security_advisor_warning_issues', 0)),
                ],
                'ips' => [
                    'active' => (bool) $addon->getConfig('ips_active', false),
                    'monitor_only' => (bool) $addon->getConfig('ips_monitor_only', false),
                    'blocked_ips_count' => (int) $ipsStats['blocked_ips'],
                    'recent_threats_24h' => (int) $ipsStats['threats_today'],
                ],
                'mail_reporting' => [
                    'enabled' => (bool) $addon->getConfig('mail_reporting_enabled', false),
                    'mode' => (int) $addon->getConfig('mail_reporting_mode', 1) === 0 ? 'immediate' : 'bundle',
                    'log_files_count' => count(MailReporting::getLogFiles()),
                ],
            ],
            'redaxo' => [
                'version' => rex::getVersion(),
                'safe_mode' => rex::isSafeMode(),
                'debug_mode' => rex::isDebugMode(),
                'live_mode' => method_exists(rex::class, 'isLiveMode') ? rex::isLiveMode() : !rex::isDebugMode(),
            ],
            'system' => [
                'php_version' => PHP_VERSION,
                'memory_limit' => ini_get('memory_limit'),
                'max_execution_time' => ini_get('max_execution_time'),
                'upload_max_filesize' => ini_get('upload_max_filesize'),
                'post_max_size' => ini_get('post_max_size'),
            ],
        ];

        if ($detailed) {
            $dbConnected = true;
            try {
                rex_sql::factory()->setQuery('SELECT 1');
            } catch (Throwable) {
                $dbConnected = false;
            }
            $free = @disk_free_space(rex_path::base());
            $healthData['detailed'] = [
                'https' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                'database' => ['connected' => $dbConnected],
                'disk_free_bytes' => $free !== false ? (int) $free : null,
            ];
        }

        $issues = [];
        if ($healthData['upkeep']['maintenance']['frontend'] || $healthData['upkeep']['maintenance']['backend']) {
            $issues[] = 'maintenance_mode_active';
            $healthData['status'] = 'warning';
        }
        if ($healthData['upkeep']['ips']['recent_threats_24h'] > 10) {
            $issues[] = 'high_threat_activity';
            $healthData['status'] = 'warning';
        }
        if ($healthData['upkeep']['security_advisor']['critical_issues'] > 0) {
            $issues[] = 'security_critical_issues';
            $healthData['status'] = 'critical';
        }
        if ($issues !== []) {
            $healthData['issues'] = $issues;
        }

        $store->delete($ipKey);

        if ($format === 'text' || $format === 'plain') {
            $text = "Upkeep System Health Status\n";
            $text .= "===========================\n\n";
            $text .= 'Status: ' . strtoupper($healthData['status']) . "\n";
            $text .= 'Timestamp: ' . $healthData['datetime'] . "\n\n";
            $text .= "REDAXO:\n";
            $text .= '- Version: ' . $healthData['redaxo']['version'] . "\n";
            $text .= '- Live Mode: ' . ($healthData['redaxo']['live_mode'] ? 'Yes' : 'No') . "\n";
            $text .= '- Debug Mode: ' . ($healthData['redaxo']['debug_mode'] ? 'Yes' : 'No') . "\n\n";
            $text .= "Security Advisor:\n";
            $text .= '- Score: ' . $healthData['upkeep']['security_advisor']['score'] . "\n";
            $text .= '- Critical Issues: ' . $healthData['upkeep']['security_advisor']['critical_issues'] . "\n\n";
            $text .= "IPS:\n";
            $text .= '- Active: ' . ($healthData['upkeep']['ips']['active'] ? 'Yes' : 'No') . "\n";
            $text .= '- Threats today: ' . $healthData['upkeep']['ips']['recent_threats_24h'] . "\n\n";
            if ($issues !== []) {
                $text .= "Issues:\n";
                foreach ($issues as $issue) {
                    $text .= '- ' . str_replace('_', ' ', ucfirst($issue)) . "\n";
                }
            }
            self::sendRaw($text, 'text/plain; charset=utf-8', 200);
        }

        self::send($healthData, 200);
    }

    private static function getProvidedKey(): string
    {
        $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? (function_exists('getallheaders') ? (array_change_key_case((array) getallheaders(), CASE_LOWER)['authorization'] ?? '') : ''));
        if (preg_match('/^Bearer\s+(\S+)$/i', trim($auth), $m)) {
            return $m[1];
        }
        $header = trim((string) ($_SERVER['HTTP_X_UPKEEP_HEALTH_KEY'] ?? ''));
        if ($header !== '') {
            return $header;
        }
        // Veraltet: Schlüssel als Parameter
        $key = rex_get('key', 'string', '');
        if ($key === '') {
            $key = rex_get('health_key', 'string', '');
        }
        return trim((string) $key);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function send(array $data, int $status): never
    {
        self::sendRaw((string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), 'application/json; charset=utf-8', $status);
    }

    private static function sendRaw(string $body, string $contentType, int $status): never
    {
        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: ' . $contentType);
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            header('X-Robots-Tag: noindex');
        }
        echo $body;
        exit;
    }
}
