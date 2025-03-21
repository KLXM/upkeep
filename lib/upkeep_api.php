<?php
/**
 * API-Klasse für das Upkeep AddOn
 * Diese Klasse muss im globalen Namespace definiert sein
 */

use KLXM\Upkeep\Upkeep;

class rex_api_upkeep extends rex_api_function
{
    protected $published = true;
    protected $requires_csrf_token = false;

    public function execute()
    {
        $addon = rex_addon::get('upkeep');
        $result = ['success' => false];

        // API-Token prüfen
        $apiToken = $addon->getConfig('api_token', '');
        $requestToken = rex_request('token', 'string', '');

        if ($apiToken === '' || $requestToken !== $apiToken) {
            $result['error'] = 'Invalid token';
            rex_response::setStatus(rex_response::HTTP_UNAUTHORIZED);
            $this->sendJsonResponse($result);
        }

        $action = rex_request('action', 'string', 'status');

        switch ($action) {
            case 'status':
                // Status der Wartungsmodi abrufen
                $result['frontend_active'] = (bool) $addon->getConfig('frontend_active', false);
                $result['backend_active'] = (bool) $addon->getConfig('backend_active', false);
                $result['all_domains_locked'] = (bool) $addon->getConfig('all_domains_locked', false);
                $result['success'] = true;
                break;

            case 'set_frontend':
                // Frontend-Wartungsmodus setzen
                $status = rex_request('status', 'bool', false);
                $addon->setConfig('frontend_active', $status);
                $result['frontend_active'] = $status;
                $result['success'] = true;
                break;

            case 'set_backend':
                // Backend-Wartungsmodus setzen
                $status = rex_request('status', 'bool', false);
                $addon->setConfig('backend_active', $status);
                $result['backend_active'] = $status;
                $result['success'] = true;
                break;

            case 'set_all_domains':
                // Alle Domains sperren/entsperren
                $status = rex_request('status', 'bool', false);
                $addon->setConfig('all_domains_locked', $status);
                $result['all_domains_locked'] = $status;
                $result['success'] = true;
                break;

            case 'set_domain':
                // Einzelne Domain sperren/entsperren
                $domain = rex_request('domain', 'string', '');
                $status = rex_request('status', 'bool', false);
                
                if ($domain !== '' && rex_addon::get('yrewrite')->isAvailable()) {
                    $domains = rex_yrewrite::getDomains();
                    
                    // Prüfen, ob Domain existiert
                    $domainExists = false;
                    foreach ($domains as $d) {
                        if ($d->getName() === $domain) {
                            $domainExists = true;
                            break;
                        }
                    }
                    
                    if ($domainExists) {
                        $domainStatus = (array) $addon->getConfig('domain_status', []);
                        $domainStatus[$domain] = $status;
                        $addon->setConfig('domain_status', $domainStatus);
                        $result['domain'] = $domain;
                        $result['status'] = $status;
                        $result['success'] = true;
                    } else {
                        $result['error'] = 'Domain not found';
                    }
                } else {
                    $result['error'] = 'Invalid domain or YRewrite not available';
                }
                break;

            default:
                $result['error'] = 'Invalid action';
                rex_response::setStatus(rex_response::HTTP_BAD_REQUEST);
        }

        $this->sendJsonResponse($result);
    }
    
    /**
     * Sendet eine JSON-Antwort und beendet die Ausführung
     */
    private function sendJsonResponse($data)
    {
        // Alle Output-Buffer leeren
        rex_response::cleanOutputBuffers();
        
        // Content-Type setzen und JSON ausgeben
        rex_response::setHeader('Content-Type', 'application/json; charset=utf-8');
        echo json_encode($data);
        exit;
    }
}
