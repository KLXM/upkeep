<?php
/**
 * Mail Security API Endpoints
 * Upkeep AddOn for REDAXO CMS
 * 
 * Provides REST API endpoints for Mail Security management
 * 
 * @package KLXM\Upkeep
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

use KLXM\Upkeep\MailSecurityFilter;

class rex_api_upkeep_mail_security extends rex_api_function
{
    protected $published = ['get', 'post', 'put', 'delete'];

    /**
     * Main execute method required by rex_api_function
     */
    public function execute(): rex_api_result
    {
        $method = strtolower(rex_request::server('REQUEST_METHOD', 'string', 'get'));
        
        switch ($method) {
            case 'get':
                return $this->get();
            case 'post':
                return $this->post();
            case 'put':
                return $this->put();
            case 'delete':
                return $this->delete();
            default:
                return $this->sendError('Method not allowed', 405);
        }
    }

    /**
     * API Authentication
     */
    private function authenticate(): bool
    {
        $addon = rex_addon::get('upkeep');
        $apiToken = $addon->getConfig('api_token');
        
        if (empty($apiToken)) {
            return false;
        }

        $authHeader = rex_request::server('HTTP_AUTHORIZATION', 'string', '');
        $token = str_replace('Bearer ', '', $authHeader);
        
        return hash_equals($apiToken, $token);
    }

    /**
     * Send JSON response
     */
    private function sendResponse(array $data, int $statusCode = 200): rex_api_result
    {
        rex_response::setHeader('Content-Type', 'application/json');
        return new rex_api_result($statusCode, $data);
    }

    /**
     * Send error response
     */
    private function sendError(string $message, int $statusCode = 400): rex_api_result
    {
        return $this->sendResponse([
            'status' => 'error',
            'message' => $message
        ], $statusCode);
    }

    /**
     * GET Requests
     */
    public function get(): rex_api_result
    {
        if (!$this->authenticate()) {
            return $this->sendError('Unauthorized', 401);
        }

        $endpoint = rex_request::get('endpoint', 'string', '');

        switch ($endpoint) {
            case 'status':
                return $this->getStatus();
            case 'badwords':
                return $this->getBadwords();
            case 'blacklist':
                return $this->getBlacklist();
            case 'threats':
                return $this->getThreats();
            case 'stats':
                return $this->getStats();
            default:
                return $this->sendError('Invalid endpoint');
        }
    }

    /**
     * POST Requests
     */
    public function post(): rex_api_result
    {
        if (!$this->authenticate()) {
            return $this->sendError('Unauthorized', 401);
        }

        $endpoint = rex_request::get('endpoint', 'string', '');
        $data = json_decode(file_get_contents('php://input'), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return $this->sendError('Invalid JSON data');
        }

        switch ($endpoint) {
            case 'badwords':
                return $this->addBadword($data);
            case 'blacklist':
                return $this->addToBlacklist($data);
            default:
                return $this->sendError('Invalid endpoint');
        }
    }

    /**
     * PUT Requests
     */
    public function put(): rex_api_result
    {
        if (!$this->authenticate()) {
            return $this->sendError('Unauthorized', 401);
        }

        $endpoint = rex_request::get('endpoint', 'string', '');
        $id = rex_request::get('id', 'int', 0);
        $data = json_decode(file_get_contents('php://input'), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return $this->sendError('Invalid JSON data');
        }

        switch ($endpoint) {
            case 'badwords':
                return $this->updateBadword($id, $data);
            case 'blacklist':
                return $this->updateBlacklistEntry($id, $data);
            default:
                return $this->sendError('Invalid endpoint');
        }
    }

    /**
     * DELETE Requests
     */
    public function delete(): rex_api_result
    {
        if (!$this->authenticate()) {
            return $this->sendError('Unauthorized', 401);
        }

        $endpoint = rex_request::get('endpoint', 'string', '');
        $id = rex_request::get('id', 'int', 0);

        switch ($endpoint) {
            case 'badwords':
                return $this->deleteBadword($id);
            case 'blacklist':
                return $this->deleteBlacklistEntry($id);
            default:
                return $this->sendError('Invalid endpoint');
        }
    }

    /**
     * Get Mail Security Status
     */
    private function getStatus(): rex_api_result
    {
        try {
            $stats = MailSecurityFilter::getDashboardStats();
            
            return $this->sendResponse([
                'status' => 'success',
                'data' => [
                    'active' => $stats['active'],
                    'threats_24h' => $stats['threats_24h'],
                    'blocked_emails_24h' => $stats['blocked_emails_24h'] ?? 0,
                    'badwords_count' => $stats['badwords_count'],
                    'blacklist_count' => $stats['blacklist_count'],
                    'rate_limit_blocks_24h' => $stats['rate_limit_blocks_24h']
                ]
            ]);
        } catch (Exception $e) {
            return $this->sendError('Failed to get status: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Get Badwords
     */
    private function getBadwords(): rex_api_result
    {
        try {
            $sql = rex_sql::factory();
            $limit = rex_request::get('limit', 'int', 50);
            $offset = rex_request::get('offset', 'int', 0);
            $status = rex_request::get('status', 'int', null);

            $query = "SELECT * FROM " . rex::getTable('upkeep_mail_badwords');
            $params = [];

            if ($status !== null) {
                $query .= " WHERE status = ?";
                $params[] = $status;
            }

            $query .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;

            $sql->setQuery($query, $params);
            $badwords = $sql->getArray();

            return $this->sendResponse([
                'status' => 'success',
                'data' => $badwords,
                'meta' => [
                    'limit' => $limit,
                    'offset' => $offset,
                    'count' => count($badwords)
                ]
            ]);
        } catch (Exception $e) {
            return $this->sendError('Failed to get badwords: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Add Badword
     */
    private function addBadword(array $data): rex_api_result
    {
        try {
            if (empty($data['word'])) {
                return $this->sendError('Word is required');
            }

            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_badwords'));
            $sql->setValue('word', $data['word']);
            $sql->setValue('is_regex', $data['is_regex'] ?? 0);
            $sql->setValue('severity', $data['severity'] ?? 'medium');
            $sql->setValue('category', $data['category'] ?? 'general');
            $sql->setValue('status', $data['status'] ?? 1);
            $sql->insert();

            return $this->sendResponse([
                'status' => 'success',
                'message' => 'Badword added successfully',
                'data' => ['id' => $sql->getLastId()]
            ], 201);
        } catch (Exception $e) {
            return $this->sendError('Failed to add badword: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Update Badword
     */
    private function updateBadword(int $id, array $data): rex_api_result
    {
        try {
            if ($id <= 0) {
                return $this->sendError('Invalid ID');
            }

            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_badwords'));
            $sql->setWhere(['id' => $id]);

            if (isset($data['word'])) $sql->setValue('word', $data['word']);
            if (isset($data['is_regex'])) $sql->setValue('is_regex', $data['is_regex']);
            if (isset($data['severity'])) $sql->setValue('severity', $data['severity']);
            if (isset($data['category'])) $sql->setValue('category', $data['category']);
            if (isset($data['status'])) $sql->setValue('status', $data['status']);

            $affected = $sql->update();

            if ($affected > 0) {
                return $this->sendResponse([
                    'status' => 'success',
                    'message' => 'Badword updated successfully'
                ]);
            } else {
                return $this->sendError('Badword not found', 404);
            }
        } catch (Exception $e) {
            return $this->sendError('Failed to update badword: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Delete Badword
     */
    private function deleteBadword(int $id): rex_api_result
    {
        try {
            if ($id <= 0) {
                return $this->sendError('Invalid ID');
            }

            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_badwords'));
            $sql->setWhere(['id' => $id]);
            $affected = $sql->delete();

            if ($affected > 0) {
                return $this->sendResponse([
                    'status' => 'success',
                    'message' => 'Badword deleted successfully'
                ]);
            } else {
                return $this->sendError('Badword not found', 404);
            }
        } catch (Exception $e) {
            return $this->sendError('Failed to delete badword: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Get Blacklist
     */
    private function getBlacklist(): rex_api_result
    {
        try {
            $sql = rex_sql::factory();
            $limit = rex_request::get('limit', 'int', 50);
            $offset = rex_request::get('offset', 'int', 0);
            $type = rex_request::get('type', 'string', null);
            $status = rex_request::get('status', 'int', null);

            $query = "SELECT * FROM " . rex::getTable('upkeep_mail_blacklist');
            $params = [];
            $where = [];

            if ($type) {
                $where[] = "type = ?";
                $params[] = $type;
            }

            if ($status !== null) {
                $where[] = "status = ?";
                $params[] = $status;
            }

            if (!empty($where)) {
                $query .= " WHERE " . implode(' AND ', $where);
            }

            $query .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;

            $sql->setQuery($query, $params);
            $blacklist = $sql->getArray();

            return $this->sendResponse([
                'status' => 'success',
                'data' => $blacklist,
                'meta' => [
                    'limit' => $limit,
                    'offset' => $offset,
                    'count' => count($blacklist)
                ]
            ]);
        } catch (Exception $e) {
            return $this->sendError('Failed to get blacklist: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Add to Blacklist
     */
    private function addToBlacklist(array $data): rex_api_result
    {
        try {
            if (empty($data['entry']) || empty($data['type'])) {
                return $this->sendError('Entry and type are required');
            }

            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
            $sql->setValue('entry', $data['entry']);
            $sql->setValue('type', $data['type']);
            $sql->setValue('reason', $data['reason'] ?? '');
            $sql->setValue('status', $data['status'] ?? 1);

            // IP-Adresse extrahieren falls vorhanden
            if ($data['type'] === 'ip' || filter_var($data['entry'], FILTER_VALIDATE_IP)) {
                $sql->setValue('ip_address', $data['entry']);
            }

            if (!empty($data['expires_at'])) {
                $sql->setValue('expires_at', $data['expires_at']);
            }

            $sql->insert();

            return $this->sendResponse([
                'status' => 'success',
                'message' => 'Entry added to blacklist successfully',
                'data' => ['id' => $sql->getLastId()]
            ], 201);
        } catch (Exception $e) {
            return $this->sendError('Failed to add to blacklist: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Update Blacklist Entry
     */
    private function updateBlacklistEntry(int $id, array $data): rex_api_result
    {
        try {
            if ($id <= 0) {
                return $this->sendError('Invalid ID');
            }

            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
            $sql->setWhere(['id' => $id]);

            if (isset($data['entry'])) $sql->setValue('entry', $data['entry']);
            if (isset($data['type'])) $sql->setValue('type', $data['type']);
            if (isset($data['reason'])) $sql->setValue('reason', $data['reason']);
            if (isset($data['status'])) $sql->setValue('status', $data['status']);
            if (isset($data['expires_at'])) $sql->setValue('expires_at', $data['expires_at']);

            $affected = $sql->update();

            if ($affected > 0) {
                return $this->sendResponse([
                    'status' => 'success',
                    'message' => 'Blacklist entry updated successfully'
                ]);
            } else {
                return $this->sendError('Blacklist entry not found', 404);
            }
        } catch (Exception $e) {
            return $this->sendError('Failed to update blacklist entry: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Delete Blacklist Entry
     */
    private function deleteBlacklistEntry(int $id): rex_api_result
    {
        try {
            if ($id <= 0) {
                return $this->sendError('Invalid ID');
            }

            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_mail_blacklist'));
            $sql->setWhere(['id' => $id]);
            $affected = $sql->delete();

            if ($affected > 0) {
                return $this->sendResponse([
                    'status' => 'success',
                    'message' => 'Blacklist entry deleted successfully'
                ]);
            } else {
                return $this->sendError('Blacklist entry not found', 404);
            }
        } catch (Exception $e) {
            return $this->sendError('Failed to delete blacklist entry: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Get Threats
     */
    private function getThreats(): rex_api_result
    {
        try {
            $sql = rex_sql::factory();
            $limit = rex_request::get('limit', 'int', 50);
            $offset = rex_request::get('offset', 'int', 0);
            $severity = rex_request::get('severity', 'string', null);
            $type = rex_request::get('type', 'string', null);
            $fromDate = rex_request::get('from_date', 'string', null);
            $toDate = rex_request::get('to_date', 'string', null);

            $query = "SELECT * FROM " . rex::getTable('upkeep_mail_threat_log');
            $params = [];
            $where = ["threat_type LIKE 'mail_%'"];

            if ($severity) {
                $where[] = "severity = ?";
                $params[] = $severity;
            }

            if ($type) {
                $where[] = "threat_type = ?";
                $params[] = $type;
            }

            if ($fromDate) {
                $where[] = "created_at >= ?";
                $params[] = $fromDate . ' 00:00:00';
            }

            if ($toDate) {
                $where[] = "created_at <= ?";
                $params[] = $toDate . ' 23:59:59';
            }

            $query .= " WHERE " . implode(' AND ', $where);
            $query .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;

            $sql->setQuery($query, $params);
            $threats = $sql->getArray();

            // JSON-Daten dekodieren
            foreach ($threats as &$threat) {
                if (!empty($threat['email_data'])) {
                    $threat['email_data'] = json_decode($threat['email_data'], true);
                }
                if (!empty($threat['threat_details'])) {
                    $threat['threat_details'] = json_decode($threat['threat_details'], true);
                }
            }

            return $this->sendResponse([
                'status' => 'success',
                'data' => $threats,
                'meta' => [
                    'limit' => $limit,
                    'offset' => $offset,
                    'count' => count($threats)
                ]
            ]);
        } catch (Exception $e) {
            return $this->sendError('Failed to get threats: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Get Statistics
     */
    private function getStats(): rex_api_result
    {
        try {
            $stats = MailSecurityFilter::getDashboardStats();
            
            // Erweiterte Statistiken
            $sql = rex_sql::factory();
            
            // Top Bedrohungstypen
            $sql->setQuery("
                SELECT threat_type, COUNT(*) as count 
                FROM " . rex::getTable('upkeep_mail_threat_log') . " 
                WHERE threat_type LIKE 'mail_%' 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY threat_type 
                ORDER BY count DESC 
                LIMIT 10
            ");
            $topThreats = $sql->getArray();

            // Bedrohungen pro Tag (letzte 7 Tage)
            $sql->setQuery("
                SELECT DATE(created_at) as date, COUNT(*) as count 
                FROM " . rex::getTable('upkeep_mail_threat_log') . " 
                WHERE threat_type LIKE 'mail_%' 
                AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                GROUP BY DATE(created_at) 
                ORDER BY date DESC
            ");
            $threatsPerDay = $sql->getArray();

            return $this->sendResponse([
                'status' => 'success',
                'data' => array_merge($stats, [
                    'top_threats' => $topThreats,
                    'threats_per_day' => $threatsPerDay
                ])
            ]);
        } catch (Exception $e) {
            return $this->sendError('Failed to get statistics: ' . $e->getMessage(), 500);
        }
    }
}