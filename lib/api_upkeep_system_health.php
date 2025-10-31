<?php
/**
 * Upkeep AddOn - System Health API Handler
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

use FriendsOfRedaxo\Upkeep\MailReporting;
use FriendsOfRedaxo\Upkeep\SecurityAdvisor;
use FriendsOfRedaxo\Upkeep\IntrusionPrevention;

class rex_api_upkeep_system_health extends rex_api_function
{
    protected $published = true;

    public function execute()
    {
        // Clean output buffer - REDAXO way
        rex_response::cleanOutputBuffers();
        
        $addon = rex_addon::get('upkeep');
        
        // Check if System Health API is enabled
        if (!$addon->getConfig('system_health_enabled', false)) {
            rex_response::setStatus(rex_response::HTTP_SERVICE_UNAVAILABLE);
            rex_response::setHeader('Content-Type', 'application/json');
            rex_response::sendContent(json_encode([
                'error' => 'System Health API is disabled',
                'status' => 'disabled',
                'timestamp' => time()
            ]));
        }
        
        // Validate health key if required
        $require_key = $addon->getConfig('system_health_require_key', true);
        $health_key = $addon->getConfig('system_health_key', '');
        
        if ($require_key && !empty($health_key)) {
            // Accept both 'key' and 'health_key' parameter names for compatibility
            $provided_key = rex_get('key', 'string', '') ?: rex_get('health_key', 'string', '');
            if ($provided_key !== $health_key) {
                rex_response::setStatus(rex_response::HTTP_FORBIDDEN);
                rex_response::setHeader('Content-Type', 'application/json');
                rex_response::sendContent(json_encode([
                    'error' => 'Invalid or missing health key',
                    'status' => 'forbidden',
                    'timestamp' => time(),
                    'expected_parameter' => 'key or health_key'
                ]));
            }
        }        // Get response format
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
                        'enabled' => class_exists('FriendsOfRedaxo\Upkeep\SecurityAdvisor'),
                        'last_scan' => rex_config::get('upkeep', 'security_advisor_last_check', 0),
                        'score' => rex_config::get('upkeep', 'security_advisor_score', 0),
                        'grade' => rex_config::get('upkeep', 'security_advisor_grade', 'F'),
                        'critical_issues' => rex_config::get('upkeep', 'security_advisor_critical_issues', 0),
                        'warning_issues' => rex_config::get('upkeep', 'security_advisor_warning_issues', 0)
                    ],
                    'ips' => [
                        'enabled' => class_exists('FriendsOfRedaxo\Upkeep\IntrusionPrevention'),
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
                        'log_files_count' => method_exists('FriendsOfRedaxo\Upkeep\MailReporting', 'getLogFiles') ? 
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
                if (class_exists('FriendsOfRedaxo\Upkeep\SecurityAdvisor') && method_exists('FriendsOfRedaxo\Upkeep\SecurityAdvisor', 'getDashboardStats')) {
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

            // Output response based on format
            if ($format === 'text' || $format === 'plain') {
                rex_response::setHeader('Content-Type', 'text/plain; charset=utf-8');
                $textOutput = "Upkeep System Health Status\n";
                $textOutput .= "===========================\n\n";
                $textOutput .= "Status: " . strtoupper($healthData['status']) . "\n";
                $textOutput .= "Timestamp: " . $healthData['datetime'] . "\n";
                $textOutput .= "Server: " . $healthData['server'] . "\n\n";
                
                $textOutput .= "REDAXO:\n";
                $textOutput .= "- Version: " . $healthData['redaxo']['version'] . "\n";
                $textOutput .= "- Live Mode: " . ($healthData['redaxo']['live_mode'] ? 'Yes' : 'No') . "\n";
                $textOutput .= "- Debug Mode: " . ($healthData['redaxo']['debug_mode'] ? 'Yes' : 'No') . "\n\n";
                
                $textOutput .= "Security Advisor:\n";
                $textOutput .= "- Score: " . $healthData['upkeep']['security_advisor']['score'] . "\n";
                $textOutput .= "- Grade: " . $healthData['upkeep']['security_advisor']['grade'] . "\n";
                $textOutput .= "- Critical Issues: " . $healthData['upkeep']['security_advisor']['critical_issues'] . "\n\n";
                
                $textOutput .= "IPS:\n";
                $textOutput .= "- Active: " . ($healthData['upkeep']['ips']['active'] ? 'Yes' : 'No') . "\n";
                $textOutput .= "- Recent Threats (24h): " . $healthData['upkeep']['ips']['recent_threats_24h'] . "\n\n";
                
                if (!empty($issues)) {
                    $textOutput .= "Issues:\n";
                    foreach ($issues as $issue) {
                        $textOutput .= "- " . str_replace('_', ' ', ucfirst($issue)) . "\n";
                    }
                }
                
                rex_response::sendContent($textOutput);
            } else {
                // JSON output (default)
                rex_response::setHeader('Content-Type', 'application/json; charset=utf-8');
                rex_response::sendContent(json_encode($healthData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            }

        } catch (Exception $e) {
            rex_response::setStatus(rex_response::HTTP_INTERNAL_ERROR);
            rex_response::setHeader('Content-Type', 'application/json; charset=utf-8');
            rex_response::sendContent(json_encode([
                'error' => 'Internal Server Error',
                'message' => $e->getMessage(),
                'status' => 'error',
                'timestamp' => time()
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        }
    }
}