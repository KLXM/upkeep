<?php
/**
 * API-Klasse für das Upkeep AddOn (Wartungsmodus fernsteuern)
 * Diese Klasse muss im globalen Namespace definiert sein.
 *
 * Authentifizierung (in dieser Reihenfolge):
 * - Header "Authorization: Bearer <token>"
 * - Header "X-Upkeep-Token: <token>"
 * - Parameter "token" (veraltet, nur noch aus Kompatibilitätsgründen)
 *
 * action=status ist per GET und POST erlaubt, alle set_*-Aktionen nur per POST.
 * Fehlgeschlagene Anmeldungen werden pro IP begrenzt (10 in 10 Minuten).
 */

use KLXM\Upkeep\ClientIp;
use KLXM\Upkeep\JsonStore;
use KLXM\Upkeep\Upkeep;

class rex_api_upkeep extends rex_api_function
{
    protected $published = true;
    protected $requires_csrf_token = false;

    private const MAX_FAILED = 10;
    private const FAILED_WINDOW = 600;

    public function execute()
    {
        try {
            $this->handle();
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $this->sendJsonResponse(['success' => false, 'error' => 'Internal error'], 500);
        }
        return new rex_api_result(false);
    }

    private function handle(): void
    {
        $addon = rex_addon::get('upkeep');

        $store = new JsonStore('api_auth_failures', 2000);
        $ipKey = 'upkeep_api:' . ClientIp::get();
        if ((int) $store->get($ipKey, 0) >= self::MAX_FAILED) {
            $this->sendJsonResponse(['success' => false, 'error' => 'Too many requests'], 429, ['Retry-After' => (string) self::FAILED_WINDOW]);
        }

        $apiToken = (string) $addon->getConfig('api_token', '');
        $requestToken = self::getRequestToken();

        if ($apiToken === '' || strlen($apiToken) < 16 || $requestToken === '' || !hash_equals($apiToken, $requestToken)) {
            $store->increment($ipKey, self::FAILED_WINDOW);
            $this->sendJsonResponse(['success' => false, 'error' => 'Invalid token'], 401);
        }

        $isPost = 'POST' === strtoupper(rex_server('REQUEST_METHOD', 'string', 'GET'));
        $action = rex_request('action', 'string', 'status');
        $result = ['success' => false];

        if ($action !== 'status' && !$isPost) {
            $this->sendJsonResponse(['success' => false, 'error' => 'Method not allowed, use POST'], 405, ['Allow' => 'POST']);
        }

        switch ($action) {
            case 'status':
                $result['frontend_active'] = (bool) $addon->getConfig('frontend_active', false);
                $result['backend_active'] = (bool) $addon->getConfig('backend_active', false);
                $result['all_domains_locked'] = (bool) $addon->getConfig('all_domains_locked', false);
                $result['success'] = true;
                break;

            case 'set_frontend':
                $status = rex_request('status', 'bool', false);
                Upkeep::setMaintenance('frontend', $status, 'api');
                $result['frontend_active'] = $status;
                $result['success'] = true;
                break;

            case 'set_backend':
                $status = rex_request('status', 'bool', false);
                Upkeep::setMaintenance('backend', $status, 'api');
                $result['backend_active'] = $status;
                $result['success'] = true;
                break;

            case 'set_all_domains':
                $status = rex_request('status', 'bool', false);
                Upkeep::setMaintenance('all_domains', $status, 'api');
                $result['all_domains_locked'] = $status;
                $result['success'] = true;
                break;

            case 'set_domain':
                $domain = rex_request('domain', 'string', '');
                $status = rex_request('status', 'bool', false);

                if ($domain === '' || !rex_addon::get('yrewrite')->isAvailable()) {
                    $this->sendJsonResponse(['success' => false, 'error' => 'Invalid domain or YRewrite not available'], 400);
                }
                $domainExists = false;
                foreach (rex_yrewrite::getDomains() as $d) {
                    if ($d->getName() === $domain) {
                        $domainExists = true;
                        break;
                    }
                }
                if (!$domainExists) {
                    $this->sendJsonResponse(['success' => false, 'error' => 'Domain not found'], 404);
                }
                Upkeep::setMaintenance('domain:' . $domain, $status, 'api');
                $result['domain'] = $domain;
                $result['status'] = $status;
                $result['success'] = true;
                break;

            default:
                $this->sendJsonResponse(['success' => false, 'error' => 'Invalid action'], 400);
        }

        $store->delete($ipKey);
        $this->sendJsonResponse($result);
    }

    /**
     * Token aus Header (bevorzugt) oder Parameter "token" (veraltet).
     */
    private static function getRequestToken(): string
    {
        $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? (function_exists('getallheaders') ? (array_change_key_case((array) getallheaders(), CASE_LOWER)['authorization'] ?? '') : ''));
        if (preg_match('/^Bearer\s+(\S+)$/i', trim($auth), $m)) {
            return $m[1];
        }
        $header = trim((string) ($_SERVER['HTTP_X_UPKEEP_TOKEN'] ?? ''));
        if ($header !== '') {
            return $header;
        }
        return trim((string) rex_request('token', 'string', ''));
    }

    /**
     * Sendet eine JSON-Antwort und beendet die Ausführung
     *
     * @param array<string, mixed> $data
     * @param array<string, string> $headers
     */
    private function sendJsonResponse(array $data, int $status = 200, array $headers = []): never
    {
        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-Content-Type-Options: nosniff');
            header('X-Robots-Tag: noindex');
            foreach ($headers as $name => $value) {
                header($name . ': ' . $value);
            }
        }
        echo json_encode($data);
        exit;
    }
}
