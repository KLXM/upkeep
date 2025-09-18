<?php
/**
 * Upkeep AddOn - Security Advisor API
 * 
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

use KLXM\Upkeep\SecurityAdvisor;

header('Content-Type: application/json');

// CSRF-Schutz
if (!rex_csrf_token::factory('upkeep-security')->isValid()) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => 'Invalid CSRF token'
    ]);
    exit;
}

// Berechtigung prüfen
if (!rex::getUser() || !rex::getUser()->hasPerm('upkeep[security]')) {
    http_response_code(403);
    echo json_encode([
        'success' => false,
        'message' => 'Access denied'
    ]);
    exit;
}

$action = rex_request::get('action', 'string', '');
$securityAdvisor = new SecurityAdvisor();

try {
    switch ($action) {
        case 'enable_live_mode':
            $result = $securityAdvisor->enableLiveMode();
            echo json_encode($result);
            break;
            
        case 'enable_csp':
            $result = $securityAdvisor->enableCSP();
            echo json_encode($result);
            break;
            
        case 'disable_csp':
            $result = $securityAdvisor->disableCSP();
            echo json_encode($result);
            break;
            
        case 'scan':
            $results = $securityAdvisor->runAllChecks();
            echo json_encode([
                'success' => true,
                'data' => $results
            ]);
            break;
            
        default:
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'message' => 'Invalid action'
            ]);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}