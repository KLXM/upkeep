<?php
/**
 * Mail Security API Endpoints
 * Upkeep AddOn for REDAXO CMS
 *
 * ?rex-api-call=upkeep_mail_security&endpoint=<status|stats|badwords|blocklist|threats>[&id=<id>]
 * Authentifizierung: Header "Authorization: Bearer <api_token>" (Pflicht).
 * GET liest, POST legt an, PUT ändert, DELETE löscht. Antwort immer JSON.
 *
 * @package KLXM\Upkeep
 */

use KLXM\Upkeep\ClientIp;
use KLXM\Upkeep\JsonStore;
use KLXM\Upkeep\MailSecurityFilter;
use KLXM\Upkeep\PatternValidator;

class rex_api_upkeep_mail_security extends rex_api_function
{
    protected $published = true;
    protected $requires_csrf_token = false;

    private const MAX_FAILED = 10;
    private const FAILED_WINDOW = 600;
    private const SEVERITIES = ['low', 'medium', 'high', 'critical'];
    private const BLOCKLIST_TYPES = ['email', 'domain', 'ip', 'pattern'];

    public function execute()
    {
        try {
            $this->handle();
        } catch (Throwable $e) {
            rex_logger::logException($e);
            self::send(['status' => 'error', 'message' => 'Internal error'], 500);
        }
        return new rex_api_result(false);
    }

    private function handle(): void
    {
        $store = new JsonStore('api_auth_failures', 2000);
        $ipKey = 'mail_api:' . ClientIp::get();
        if ((int) $store->get($ipKey, 0) >= self::MAX_FAILED) {
            self::send(['status' => 'error', 'message' => 'Too many requests'], 429);
        }
        if (!self::authenticate()) {
            $store->increment($ipKey, self::FAILED_WINDOW);
            self::send(['status' => 'error', 'message' => 'Unauthorized'], 401);
        }
        $store->delete($ipKey);

        $method = strtolower(rex_server('REQUEST_METHOD', 'string', 'get'));
        $endpoint = rex_get('endpoint', 'string', '');
        $id = rex_get('id', 'int', 0);

        $data = [];
        if (in_array($method, ['post', 'put'], true)) {
            $raw = (string) file_get_contents('php://input', false, null, 0, 65536);
            $data = json_decode($raw, true);
            if (!is_array($data)) {
                self::send(['status' => 'error', 'message' => 'Invalid JSON data'], 400);
            }
        }

        match ([$method, $endpoint]) {
            ['get', 'status'] => self::getStatus(),
            ['get', 'stats'] => self::getStats(),
            ['get', 'badwords'] => self::getBadwords(),
            ['get', 'blocklist'] => self::getBlocklist(),
            ['get', 'threats'] => self::getThreats(),
            ['post', 'badwords'] => self::addBadword($data),
            ['post', 'blocklist'] => self::addToBlocklist($data),
            ['put', 'badwords'] => self::updateBadword($id, $data),
            ['put', 'blocklist'] => self::updateBlocklistEntry($id, $data),
            ['delete', 'badwords'] => self::deleteBadword($id),
            ['delete', 'blocklist'] => self::deleteBlocklistEntry($id),
            default => self::send(['status' => 'error', 'message' => 'Invalid endpoint or method'], in_array($method, ['get', 'post', 'put', 'delete'], true) ? 400 : 405),
        };
    }

    private static function authenticate(): bool
    {
        $apiToken = (string) rex_addon::get('upkeep')->getConfig('api_token', '');
        if ($apiToken === '' || strlen($apiToken) < 16) {
            return false;
        }
        $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? (function_exists('getallheaders') ? (array_change_key_case((array) getallheaders(), CASE_LOWER)['authorization'] ?? '') : ''));
        if (!preg_match('/^Bearer\s+(\S+)$/i', trim($auth), $m)) {
            return false;
        }
        return hash_equals($apiToken, $m[1]);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function send(array $data, int $status = 200): never
    {
        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
        }
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /** @return array{0: int, 1: int} */
    private static function paging(): array
    {
        return [max(1, min(500, rex_get('limit', 'int', 50))), max(0, rex_get('offset', 'int', 0))];
    }

    private static function getStatus(): never
    {
        $stats = MailSecurityFilter::getDashboardStats();
        self::send(['status' => 'success', 'data' => [
            'active' => $stats['active'],
            'threats_24h' => $stats['threats_24h'],
            'blocked_emails_24h' => $stats['blocked_emails_24h'] ?? 0,
            'badwords_count' => $stats['badwords_count'],
            'blocklist_count' => $stats['blocklist_count'],
            'rate_limit_blocks_24h' => $stats['rate_limit_blocks_24h'],
        ]]);
    }

    private static function getStats(): never
    {
        $stats = MailSecurityFilter::getDashboardStats();
        $since = date('Y-m-d H:i:s', time() - 7 * 86400);
        $sql = rex_sql::factory();
        $topThreats = $sql->getArray(
            'SELECT threat_type, COUNT(*) as count FROM ' . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail\\_%' AND created_at >= ? GROUP BY threat_type ORDER BY count DESC LIMIT 10",
            [$since],
        );
        $perDay = $sql->getArray(
            'SELECT DATE(created_at) as date, COUNT(*) as count FROM ' . rex::getTable('upkeep_ips_threat_log') . " WHERE threat_type LIKE 'mail\\_%' AND created_at >= ? GROUP BY DATE(created_at) ORDER BY date DESC",
            [$since],
        );
        self::send(['status' => 'success', 'data' => array_merge($stats, ['top_threats_7d' => $topThreats, 'threats_per_day' => $perDay])]);
    }

    private static function getBadwords(): never
    {
        [$limit, $offset] = self::paging();
        $query = 'SELECT id, pattern, description, category, severity, is_regex, status, is_default, is_editable, created_at, updated_at FROM ' . rex::getTable('upkeep_mail_badwords');
        $params = [];
        if (rex_get('status', 'string', '') !== '') {
            $query .= ' WHERE status = ?';
            $params[] = rex_get('status', 'int', 1) ? 1 : 0;
        }
        $query .= ' ORDER BY created_at DESC LIMIT ' . $limit . ' OFFSET ' . $offset;
        $rows = rex_sql::factory()->getArray($query, $params);
        self::send(['status' => 'success', 'data' => $rows, 'meta' => ['limit' => $limit, 'offset' => $offset, 'count' => count($rows)]]);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function addBadword(array $data): never
    {
        $pattern = trim((string) ($data['pattern'] ?? $data['word'] ?? ''));
        if ($pattern === '') {
            self::send(['status' => 'error', 'message' => 'pattern is required'], 400);
        }
        $isRegex = !empty($data['is_regex']);
        if ($isRegex && !PatternValidator::isValid($pattern)) {
            self::send(['status' => 'error', 'message' => 'Invalid regular expression'], 422);
        }
        $ok = MailSecurityFilter::addBadword(
            $pattern,
            in_array($data['severity'] ?? '', self::SEVERITIES, true) ? $data['severity'] : 'medium',
            substr((string) ($data['category'] ?? 'general'), 0, 100),
            $isRegex,
            (string) ($data['description'] ?? ''),
        );
        $ok ? self::send(['status' => 'success', 'message' => 'Badword added'], 201) : self::send(['status' => 'error', 'message' => 'Failed to add badword'], 500);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function updateBadword(int $id, array $data): never
    {
        if ($id <= 0) {
            self::send(['status' => 'error', 'message' => 'Invalid ID'], 400);
        }
        $current = rex_sql::factory()->getArray('SELECT * FROM ' . rex::getTable('upkeep_mail_badwords') . ' WHERE id = ?', [$id]);
        if ($current === []) {
            self::send(['status' => 'error', 'message' => 'Badword not found'], 404);
        }
        $row = $current[0];
        $isRegex = array_key_exists('is_regex', $data) ? (bool) $data['is_regex'] : (bool) $row['is_regex'];
        $ok = MailSecurityFilter::updateBadword(
            $id,
            (string) ($data['pattern'] ?? $data['word'] ?? $row['pattern']),
            (string) ($data['description'] ?? $row['description']),
            (string) ($data['category'] ?? $row['category']),
            (string) ($data['severity'] ?? $row['severity']),
            array_key_exists('status', $data) ? (bool) $data['status'] : (bool) $row['status'],
            $isRegex,
        );
        $ok ? self::send(['status' => 'success', 'message' => 'Badword updated']) : self::send(['status' => 'error', 'message' => 'Update failed (invalid pattern?)'], 422);
    }

    private static function deleteBadword(int $id): never
    {
        if ($id <= 0) {
            self::send(['status' => 'error', 'message' => 'Invalid ID'], 400);
        }
        MailSecurityFilter::removeBadword($id)
            ? self::send(['status' => 'success', 'message' => 'Badword deleted'])
            : self::send(['status' => 'error', 'message' => 'Badword not found or not deletable'], 404);
    }

    private static function getBlocklist(): never
    {
        [$limit, $offset] = self::paging();
        $where = [];
        $params = [];
        $type = rex_get('type', 'string', '');
        if (in_array($type, self::BLOCKLIST_TYPES, true)) {
            $where[] = 'blocklist_type = ?';
            $params[] = $type;
        }
        if (rex_get('status', 'string', '') !== '') {
            $where[] = 'status = ?';
            $params[] = rex_get('status', 'int', 1) ? 1 : 0;
        }
        $query = 'SELECT * FROM ' . rex::getTable('upkeep_mail_blocklist')
            . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
            . ' ORDER BY created_at DESC LIMIT ' . $limit . ' OFFSET ' . $offset;
        $rows = rex_sql::factory()->getArray($query, $params);
        self::send(['status' => 'success', 'data' => $rows, 'meta' => ['limit' => $limit, 'offset' => $offset, 'count' => count($rows)]]);
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>|null
     */
    private static function blocklistValues(array $data, bool $requireEntry): ?array
    {
        $values = [];
        if (isset($data['type'])) {
            if (!in_array($data['type'], self::BLOCKLIST_TYPES, true)) {
                return null;
            }
            $values['blocklist_type'] = $data['type'];
        }
        $entry = isset($data['entry']) ? trim((string) $data['entry']) : null;
        if ($entry !== null && $entry !== '') {
            $type = $values['blocklist_type'] ?? 'email';
            switch ($type) {
                case 'email':
                    if (!filter_var($entry, FILTER_VALIDATE_EMAIL)) {
                        return null;
                    }
                    $values['email_address'] = strtolower($entry);
                    break;
                case 'domain':
                    $values['domain'] = strtolower($entry);
                    break;
                case 'ip':
                    if (!filter_var($entry, FILTER_VALIDATE_IP)) {
                        return null;
                    }
                    $values['ip_address'] = $entry;
                    break;
                default:
                    $values['pattern'] = substr($entry, 0, 255);
            }
        } elseif ($requireEntry) {
            return null;
        }
        if (isset($data['severity'])) {
            if (!in_array($data['severity'], self::SEVERITIES, true)) {
                return null;
            }
            $values['severity'] = $data['severity'];
        }
        if (isset($data['reason'])) {
            $values['reason'] = substr((string) $data['reason'], 0, 1000);
        }
        if (isset($data['status'])) {
            $values['status'] = $data['status'] ? 1 : 0;
        }
        if (array_key_exists('expires_at', $data)) {
            $ts = $data['expires_at'] ? strtotime((string) $data['expires_at']) : null;
            if ($data['expires_at'] && $ts === false) {
                return null;
            }
            $values['expires_at'] = $ts ? date('Y-m-d H:i:s', $ts) : null;
        }
        return $values;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function addToBlocklist(array $data): never
    {
        $data['type'] ??= 'email';
        $values = self::blocklistValues($data, true);
        if ($values === null) {
            self::send(['status' => 'error', 'message' => 'Valid entry and type (email|domain|ip|pattern) are required'], 400);
        }
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
        foreach ($values + ['severity' => 'medium', 'status' => 1] as $k => $v) {
            $sql->setValue($k, $v);
        }
        $sql->setValue('created_at', date('Y-m-d H:i:s'));
        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
        $sql->insert();
        self::send(['status' => 'success', 'message' => 'Entry added', 'data' => ['id' => (int) $sql->getLastId()]], 201);
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function updateBlocklistEntry(int $id, array $data): never
    {
        if ($id <= 0) {
            self::send(['status' => 'error', 'message' => 'Invalid ID'], 400);
        }
        $values = self::blocklistValues($data, false);
        if ($values === null || $values === []) {
            self::send(['status' => 'error', 'message' => 'Invalid data'], 400);
        }
        $exists = rex_sql::factory()->getArray('SELECT id FROM ' . rex::getTable('upkeep_mail_blocklist') . ' WHERE id = ?', [$id]);
        if ($exists === []) {
            self::send(['status' => 'error', 'message' => 'Blocklist entry not found'], 404);
        }
        $sql = rex_sql::factory();
        $sql->setTable(rex::getTable('upkeep_mail_blocklist'));
        $sql->setWhere(['id' => $id]);
        foreach ($values as $k => $v) {
            $sql->setValue($k, $v);
        }
        $sql->setValue('updated_at', date('Y-m-d H:i:s'));
        $sql->update();
        self::send(['status' => 'success', 'message' => 'Blocklist entry updated']);
    }

    private static function deleteBlocklistEntry(int $id): never
    {
        if ($id <= 0) {
            self::send(['status' => 'error', 'message' => 'Invalid ID'], 400);
        }
        $sql = rex_sql::factory();
        $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_mail_blocklist') . ' WHERE id = ?', [$id]);
        $sql->getRows() > 0
            ? self::send(['status' => 'success', 'message' => 'Blocklist entry deleted'])
            : self::send(['status' => 'error', 'message' => 'Blocklist entry not found'], 404);
    }

    private static function getThreats(): never
    {
        [$limit, $offset] = self::paging();
        $where = ["threat_type LIKE 'mail\\_%'"];
        $params = [];
        $severity = rex_get('severity', 'string', '');
        if (in_array($severity, self::SEVERITIES, true)) {
            $where[] = 'severity = ?';
            $params[] = $severity;
        }
        $type = rex_get('type', 'string', '');
        if ($type !== '') {
            $where[] = 'threat_type = ?';
            $params[] = $type;
        }
        foreach (['from_date' => ['>=', ' 00:00:00'], 'to_date' => ['<=', ' 23:59:59']] as $param => [$op, $suffix]) {
            $date = rex_get($param, 'string', '');
            if ($date !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                $where[] = 'created_at ' . $op . ' ?';
                $params[] = $date . $suffix;
            }
        }
        $rows = rex_sql::factory()->getArray(
            'SELECT id, ip_address, request_uri, threat_type, threat_category, pattern_matched, severity, action_taken, created_at FROM '
            . rex::getTable('upkeep_ips_threat_log') . ' WHERE ' . implode(' AND ', $where)
            . ' ORDER BY created_at DESC LIMIT ' . $limit . ' OFFSET ' . $offset,
            $params,
        );
        self::send(['status' => 'success', 'data' => $rows, 'meta' => ['limit' => $limit, 'offset' => $offset, 'count' => count($rows)]]);
    }
}
