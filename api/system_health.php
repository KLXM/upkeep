<?php
/**
 * Upkeep AddOn - System Health API
 * 
 * URL access for system health monitoring
 * Based on Security AddOn system_health patterns
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

use KLXM\Upkeep\MailReporting;
use KLXM\Upkeep\SecurityAdvisor;
use KLXM\Upkeep\IntrusionPrevention;

// Direct health check via URL parameter (like Security AddOn)
if (!rex_request('upkeep_system_health', 'string')) {
    return; // Not a health check request
}

$addon = rex_addon::get('upkeep');

// Validate health key
$configuredKey = $addon->getConfig('system_health_key', '');
$providedKey = rex_request('health_key', 'string');

if (empty($configuredKey) || $configuredKey !== $providedKey) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'Unauthorized',
        'message' => 'Invalid or missing health key'
    ]);
    exit;
}

// Get response format
$format = rex_request('format', 'string', 'json');
$detailed = rex_request('detailed', 'bool', false);

try {
    // Collect system health data
    $healthData = [
        'timestamp' => time(),
        'datetime' => date('Y-m-d H:i:s'),
        'server' => $_SERVER['SERVER_NAME'] ?? 'localhost',
        'status' => 'ok',
        'upkeep' => [
            'version' => $addon->getVersion(),
            'maintenance' => [
                'frontend' => (bool) rex_config::get('upkeep', 'frontend_maintenance_active', false),
                'backend' => (bool) rex_config::get('upkeep', 'backend_maintenance_active', false)
            ],
            'security_advisor' => [
                'enabled' => class_exists('KLXM\Upkeep\SecurityAdvisor'),
                'last_scan' => rex_config::get('upkeep', 'security_advisor_last_check', 0),
                'score' => rex_config::get('upkeep', 'security_advisor_score', 0),
                'grade' => rex_config::get('upkeep', 'security_advisor_grade', 'F'),
                'critical_issues' => rex_config::get('upkeep', 'security_advisor_critical_issues', 0),
                'warning_issues' => rex_config::get('upkeep', 'security_advisor_warning_issues', 0)
            ],
            'ips' => [
                'enabled' => class_exists('KLXM\Upkeep\IntrusionPrevention'),
                'active' => (bool) rex_config::get('upkeep', 'ips_active', false),
                'monitor_only' => (bool) rex_config::get('upkeep', 'ips_monitor_only', false),
                'blocked_ips_count' => 0, // Placeholder for IPS blocked IPs count
                'recent_threats_24h' => 0 // Placeholder for recent threats count
            ],
            'mail_reporting' => [
                'enabled' => (bool) $addon->getConfig('mail_reporting_enabled', false),
                'mode' => (int) $addon->getConfig('mail_reporting_mode', 1) === 0 ? 'immediate' : 'bundle',
                'email' => !empty($addon->getConfig('mail_reporting_email', '')) ? 
                    $addon->getConfig('mail_reporting_email', '') : rex::getErrorEmail(),
                'log_files_count' => method_exists('KLXM\Upkeep\MailReporting', 'getLogFiles') ? 
                    count(MailReporting::getLogFiles()) : 0
            ]
        ],
        'redaxo' => [
            'version' => rex::getVersion(),
            'safe_mode' => rex::isSafeMode(),
            'debug_mode' => rex::isDebugMode(),
            'setup_mode' => !rex::isSetup(),
            'live_mode' => !rex::isDebugMode() && !rex::isSafeMode()
        ],
        'system' => [
            'php_version' => PHP_VERSION,
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size')
        ]
    ];

    // Add detailed information if requested
    if ($detailed) {
        $healthData['detailed'] = [
            'php_extensions' => get_loaded_extensions(),
            'server_info' => [
                'software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
                'protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'Unknown',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'Unknown',
                'https' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
            ],
            'database' => [
                'host' => rex::getProperty('db')[1]['host'] ?? 'localhost',
                'name' => rex::getProperty('db')[1]['name'] ?? 'unknown',
                'connected' => rex_sql::factory()->getErrno() === 0
            ]
        ];

        // Add Security Advisor details if available
        if (class_exists('KLXM\Upkeep\SecurityAdvisor') && method_exists('KLXM\Upkeep\SecurityAdvisor', 'getDashboardStats')) {
            try {
                $securityAdvisor = new SecurityAdvisor();
                $healthData['detailed']['security_advisor'] = $securityAdvisor->getDashboardStats();
            } catch (Exception $e) {
                $healthData['detailed']['security_advisor_error'] = $e->getMessage();
            }
        }
    }

    // Determine overall status
    $issues = [];
    
    // Check for critical issues
    if ($healthData['upkeep']['maintenance']['frontend'] || $healthData['upkeep']['maintenance']['backend']) {
        $issues[] = 'maintenance_mode_active';
        $healthData['status'] = 'warning';
    }
    
    if ($healthData['upkeep']['security_advisor']['critical_issues'] > 0) {
        $issues[] = 'security_critical_issues';
        $healthData['status'] = 'critical';
    }
    
    if ($healthData['upkeep']['ips']['recent_threats_24h'] > 10) {
        $issues[] = 'high_threat_activity';
        $healthData['status'] = 'warning';
    }
    
    if (!empty($issues)) {
        $healthData['issues'] = $issues;
    }

    // Output response
    if ($format === 'text' || $format === 'plain') {
        header('Content-Type: text/plain');
        
        echo "Upkeep System Health Status\n";
        echo "===========================\n\n";
        echo "Status: " . strtoupper($healthData['status']) . "\n";
        echo "Timestamp: " . $healthData['datetime'] . "\n";
        echo "Server: " . $healthData['server'] . "\n\n";
        
        echo "REDAXO:\n";
        echo "- Version: " . $healthData['redaxo']['version'] . "\n";
        echo "- Live Mode: " . ($healthData['redaxo']['live_mode'] ? 'Yes' : 'No') . "\n";
        echo "- Debug Mode: " . ($healthData['redaxo']['debug_mode'] ? 'Yes' : 'No') . "\n\n";
        
        echo "Security Advisor:\n";
        echo "- Score: " . $healthData['upkeep']['security_advisor']['score'] . "\n";
        echo "- Grade: " . $healthData['upkeep']['security_advisor']['grade'] . "\n";
        echo "- Critical Issues: " . $healthData['upkeep']['security_advisor']['critical_issues'] . "\n\n";
        
        echo "IPS:\n";
        echo "- Active: " . ($healthData['upkeep']['ips']['active'] ? 'Yes' : 'No') . "\n";
        echo "- Blocked IPs: " . $healthData['upkeep']['ips']['blocked_ips_count'] . "\n";
        echo "- Recent Threats (24h): " . $healthData['upkeep']['ips']['recent_threats_24h'] . "\n\n";
        
        if (!empty($issues)) {
            echo "Issues:\n";
            foreach ($issues as $issue) {
                echo "- " . str_replace('_', ' ', ucfirst($issue)) . "\n";
            }
        }
        
    } else {
        // JSON output (default)
        header('Content-Type: application/json');
        echo json_encode($healthData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

} catch (Exception $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => 'Internal Server Error',
        'message' => $e->getMessage(),
        'status' => 'error',
        'timestamp' => time()
    ]);
}