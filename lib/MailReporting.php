<?php
/**
 * Upkeep AddOn - Mail Reporting System
 * 
 * Comprehensive mail reporting for all Upkeep components:
 * - Security Advisor reports
 * - IPS threat notifications
 * - Maintenance mode activities
 * - PHPMailer error replacement
 * - System status reports
 * 
 * Based on Security AddOn ErrorNotification patterns
 * 
 * @author KLXM Crossmedia
 * @version 1.9.0
 */

namespace FriendsOfRedaxo\Upkeep;

use Exception;
use rex;
use rex_addon;
use rex_config;
use rex_dir;
use rex_extension;
use rex_extension_point;
use rex_file;
use rex_logger;
use rex_mailer;
use rex_markdown;
use rex_path;
use rex_request;
use rex_server;
use rex_sql;
use rex_system_report;
use Throwable;

class MailReporting
{
    /** @var string */
    public const EMAIL_NAME = 'Upkeep Reporting';
    
    /** @var string */
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
    
    private static rex_addon $addon;
    
    public static function init(): void
    {
        self::$addon = rex_addon::get('upkeep');
        
        // Register extension points
        self::registerExtensionPoints();
        
        // Register PHPMailer error handler if enabled
        if (self::isEnabled() && rex_config::get('upkeep', 'mail_reporting_phpmailer_errors', 0)) {
            self::registerPHPMailerErrorHandler();
        }
    }
    
    private static function registerExtensionPoints(): void
    {
        // Security Advisor reports
        rex_extension::register('UPKEEP_SECURITY_SCAN_COMPLETED', function($ep) {
            $results = $ep->getSubject();
            if (self::shouldSendImmediate(self::TYPE_SECURITY_ADVISOR)) {
                self::sendSecurityAdvisorReport($results);
            } else {
                self::logReport(self::TYPE_SECURITY_ADVISOR, $results);
            }
        });
        
        // IPS threat notifications
        rex_extension::register('UPKEEP_IPS_THREAT_DETECTED', function($ep) {
            $data = $ep->getSubject();
            if (self::shouldSendImmediate(self::TYPE_IPS_THREAT, $data['severity'])) {
                self::sendThreatNotification($data);
            } else {
                self::logReport(self::TYPE_IPS_THREAT, $data);
            }
        });
        
        // Maintenance mode changes
        rex_extension::register('UPKEEP_MAINTENANCE_CHANGED', function($ep) {
            $data = $ep->getSubject();
            if (self::shouldSendImmediate(self::TYPE_MAINTENANCE)) {
                self::sendMaintenanceNotification($data);
            } else {
                self::logReport(self::TYPE_MAINTENANCE, $data);
            }
        });
    }
    
    private static function registerPHPMailerErrorHandler(): void
    {
        // Replace REDAXO's default error email with our system
        rex_extension::register('SYSTEM_LOG', function($ep) {
            $params = $ep->getParams();
            if (isset($params['level']) && in_array($params['level'], ['error', 'critical'])) {
                $data = [
                    'message' => $params['message'] ?? 'Unknown error',
                    'file' => $params['file'] ?? '',
                    'line' => $params['line'] ?? 0,
                    'context' => $params['context'] ?? [],
                    'level' => $params['level'],
                    'timestamp' => time()
                ];
                
                if (self::shouldSendImmediate(self::TYPE_ERROR, $params['level'])) {
                    self::sendErrorNotification($data);
                } else {
                    self::logReport(self::TYPE_ERROR, $data);
                }
            }
        });
    }
    
    public static function isEnabled(): bool
    {
        return (bool) rex_config::get('upkeep', 'mail_reporting_enabled', 0);
    }
    
    public static function getEmail(): string
    {
        $email = rex_config::get('upkeep', 'mail_reporting_email', '');
        return $email ?: rex::getErrorEmail();
    }
    
    public static function getName(): string
    {
        $name = rex_config::get('upkeep', 'mail_reporting_name', '');
        return $name ?: self::EMAIL_NAME;
    }
    
    public static function getKey(): string
    {
        return rex_config::get('upkeep', 'mail_reporting_key', '');
    }
    
    private static function shouldSendImmediate(string $type, string $severity = null): bool
    {
        if (!self::isEnabled()) {
            return false;
        }
        
        $mode = rex_config::get('upkeep', 'mail_reporting_mode', 1); // 0=immediate, 1=bundle
        if ($mode === 0) {
            return true;
        }
        
        // For bundle mode, only send critical items immediately
        if ($type === self::TYPE_IPS_THREAT && $severity === 'CRITICAL') {
            return true;
        }
        
        if ($type === self::TYPE_ERROR && in_array($severity, ['error', 'critical'])) {
            return true;
        }
        
        return false;
    }
    
    public static function sendSecurityAdvisorReport(array $results): bool
    {
        try {
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            
            $score = $results['security_score'] ?? 0;
            $grade = $results['security_grade'] ?? 'F';
            $criticalIssues = $results['critical_issues'] ?? 0;
            
            $subject = "🛡️ Upkeep Security Advisor Report - Score: {$score}% ({$grade})";
            if ($criticalIssues > 0) {
                $subject = "🚨 " . $subject . " - {$criticalIssues} Critical Issues";
            }
            
            $mail->Subject = $subject;
            
            $markdown = self::generateSecurityAdvisorMarkdown($results);
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            return $mail->send();
            
        } catch (Exception $e) {
            self::logError('Security Advisor Report failed', $e);
            return false;
        }
    }
    
    public static function sendThreatNotification(array $data): bool
    {
        try {
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            
            $severity = $data['severity'] ?? 'UNKNOWN';
            $ip = $data['ip'] ?? 'Unknown IP';
            $threatType = $data['threat_type'] ?? 'Unknown Threat';
            
            $severityEmoji = match($severity) {
                'CRITICAL' => '🚨',
                'HIGH' => '⚠️',
                'MEDIUM' => '⚡',
                'LOW' => 'ℹ️',
                default => '🛡️'
            };
            
            $mail->Subject = "{$severityEmoji} Upkeep IPS Alert: {$severity} threat from {$ip}";
            
            $markdown = self::generateThreatMarkdown($data);
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            return $mail->send();
            
        } catch (Exception $e) {
            self::logError('Threat Notification failed', $e);
            return false;
        }
    }
    
    public static function sendMaintenanceNotification(array $data): bool
    {
        try {
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            
            $type = $data['type'] ?? 'unknown';
            $action = $data['action'] ?? 'changed';
            $status = $data['status'] ? 'activated' : 'deactivated';
            
            $emoji = $data['status'] ? '🔧' : '✅';
            $mail->Subject = "{$emoji} Upkeep Maintenance: {$type} {$status}";
            
            $markdown = self::generateMaintenanceMarkdown($data);
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            return $mail->send();
            
        } catch (Exception $e) {
            self::logError('Maintenance Notification failed', $e);
            return false;
        }
    }
    
    public static function sendErrorNotification(array $data): bool
    {
        try {
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            
            $level = strtoupper($data['level'] ?? 'ERROR');
            $message = $data['message'] ?? 'Unknown error';
            
            $emoji = match($level) {
                'CRITICAL' => '💥',
                'ERROR' => '❌',
                'WARNING' => '⚠️',
                default => 'ℹ️'
            };
            
            $mail->Subject = "{$emoji} Upkeep Error Report: {$level} - " . substr($message, 0, 50);
            
            $markdown = self::generateErrorMarkdown($data);
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            return $mail->send();
            
        } catch (Exception $e) {
            self::logError('Error Notification failed', $e);
            return false;
        }
    }
    
    public static function sendTestEmail(): bool
    {
        try {
            $testData = [
                'timestamp' => time(),
                'test_message' => 'This is a test email from Upkeep Mail Reporting system.',
                'server' => $_SERVER['SERVER_NAME'] ?? 'localhost',
                'redaxo_version' => rex::getVersion(),
                'php_version' => PHP_VERSION
            ];
            
            // Log the test report
            self::logReport(self::TYPE_STATUS, $testData);
            
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            $mail->Subject = "🧪 Upkeep Test Email - " . date('Y-m-d H:i:s');
            
            $markdown = "# 🧪 Upkeep Mail Reporting Test\n\n";
            $markdown .= "**Timestamp:** " . date('Y-m-d H:i:s', $testData['timestamp']) . "\n\n";
            $markdown .= "**Message:** " . $testData['test_message'] . "\n\n";
            $markdown .= "**Server:** " . $testData['server'] . "\n\n";
            $markdown .= "**REDAXO Version:** " . $testData['redaxo_version'] . "\n\n";
            $markdown .= "**PHP Version:** " . $testData['php_version'] . "\n\n";
            $markdown .= "If you received this email, the Mail Reporting system is working correctly! ✅";
            
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            return $mail->send();
            
        } catch (Exception $e) {
            self::logError('Test Email failed', $e);
            return false;
        }
    }

    public static function sendStatusReport(): bool
    {
        try {
            // Collect status from all Upkeep components
            $statusData = [
                'timestamp' => time(),
                'maintenance' => [
                    'frontend' => (bool) rex_config::get('upkeep', 'frontend_maintenance_active', false),
                    'backend' => (bool) rex_config::get('upkeep', 'backend_maintenance_active', false)
                ],
                'ips' => [
                    'active' => (bool) rex_config::get('upkeep', 'ips_active', false),
                    'monitor_only' => (bool) rex_config::get('upkeep', 'ips_monitor_only', false),
                    'recent_threats' => self::getRecentThreats(24), // Last 24h
                    'blocked_ips_count' => self::getBlockedIPsCount()
                ],
                'security_advisor' => [
                    'last_scan' => rex_config::get('upkeep', 'security_advisor_last_check', 0),
                    'score' => rex_config::get('upkeep', 'security_advisor_score', 0),
                    'grade' => rex_config::get('upkeep', 'security_advisor_grade', 'F')
                ]
            ];
            
            // Log the status report
            self::logReport(self::TYPE_STATUS, $statusData);
            
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            $mail->Subject = "📊 Upkeep Status Report - " . date('Y-m-d H:i:s');
            
            $markdown = self::generateStatusMarkdown($statusData);
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            return $mail->send();
            
        } catch (Exception $e) {
            self::logError('Status Report failed', $e);
            return false;
        }
    }
    
    public static function logReport(string $type, array $data): void
    {
        $logData = [
            'type' => $type,
            'timestamp' => time(),
            'data' => $data
        ];
        
        $filename = time() . '_' . $type . '.log.json';
        $path = self::getDataPath($filename);
        
        rex_file::put($path, json_encode($logData, JSON_PRETTY_PRINT));
    }
    
    /**
     * Send bundled reports from log files
     */
    public static function sendBundleReport(int $interval = 3600): bool
    {
        $files = self::getLogFiles();
        $fromTime = time() - $interval;
        $sendFiles = [];
        
        foreach ($files as $file) {
            $parts = explode('_', $file);
            if (isset($parts[0]) && is_numeric($parts[0]) && $parts[0] > $fromTime) {
                $sendFiles[] = $file;
            }
        }
        
        if (empty($sendFiles)) {
            return true; // Nothing to send
        }
        
        try {
            $mail = new rex_mailer();
            $mail->addAddress(self::getEmail(), self::getName());
            $mail->Subject = "📦 Upkeep Bundle Report - " . count($sendFiles) . " items";
            
            $markdown = self::generateBundleMarkdown($sendFiles);
            $mail->msgHTML(rex_markdown::factory()->parse($markdown, true));
            $mail->AltBody = $markdown;
            
            // Attach log files
            foreach ($sendFiles as $file) {
                $mail->addAttachment(self::getDataPath($file));
            }
            
            $result = $mail->send();
            
            // Clean up sent files
            if ($result) {
                foreach ($sendFiles as $file) {
                    rex_file::delete(self::getDataPath($file));
                }
            }
            
            return $result;
            
        } catch (Exception $e) {
            self::logError('Bundle Report failed', $e);
            return false;
        }
    }
    
    private static function generateSecurityAdvisorMarkdown(array $results): string
    {
        $markdown = "# 🛡️ Upkeep Security Advisor Report\n\n";
        
        $markdown .= "| Field | Value |\n";
        $markdown .= "|-------|-------|\n";
        $markdown .= "| **Report Key** | " . self::getKey() . " |\n";
        $markdown .= "| **Timestamp** | " . date('Y-m-d H:i:s') . " |\n";
        $markdown .= "| **Security Score** | {$results['security_score']}% |\n";
        $markdown .= "| **Security Grade** | {$results['security_grade']} |\n";
        $markdown .= "| **Critical Issues** | {$results['critical_issues']} |\n";
        $markdown .= "| **Warning Issues** | {$results['warning_issues']} |\n";
        $markdown .= "| **Overall Status** | {$results['overall_status']} |\n\n";
        
        if (!empty($results['checks'])) {
            $markdown .= "## Security Checks Detail\n\n";
            foreach ($results['checks'] as $checkName => $check) {
                $statusEmoji = match($check['status']) {
                    'success' => '✅',
                    'warning' => '⚠️',
                    'error' => '❌',
                    default => 'ℹ️'
                };
                
                $markdown .= "### {$statusEmoji} {$check['name']}\n";
                $markdown .= "- **Status**: {$check['status']}\n";
                $markdown .= "- **Score**: {$check['score']}/10\n";
                $markdown .= "- **Message**: {$check['message']}\n";
                
                if (!empty($check['recommendations'])) {
                    $markdown .= "- **Recommendations**:\n";
                    foreach ($check['recommendations'] as $rec) {
                        $markdown .= "  - {$rec}\n";
                    }
                }
                $markdown .= "\n";
            }
        }
        
        return $markdown;
    }
    
    private static function generateThreatMarkdown(array $data): string
    {
        $markdown = "# 🚨 Upkeep IPS Threat Alert\n\n";
        
        $markdown .= "| Field | Value |\n";
        $markdown .= "|-------|-------|\n";
        $markdown .= "| **Report Key** | " . self::getKey() . " |\n";
        $markdown .= "| **Timestamp** | " . date('Y-m-d H:i:s', $data['timestamp'] ?? time()) . " |\n";
        $markdown .= "| **IP Address** | {$data['ip']} |\n";
        $markdown .= "| **Severity** | {$data['severity']} |\n";
        $markdown .= "| **Threat Type** | {$data['threat_type']} |\n";
        $markdown .= "| **Pattern Matched** | {$data['pattern']} |\n";
        $markdown .= "| **Request URI** | {$data['uri']} |\n";
        $markdown .= "| **User Agent** | " . ($data['user_agent'] ?? 'Unknown') . " |\n";
        
        if (isset($data['country'])) {
            $markdown .= "| **Country** | {$data['country']['name']} ({$data['country']['code']}) |\n";
        }
        
        $markdown .= "\n## Request Details\n\n";
        $markdown .= "```\n";
        $markdown .= "Method: " . ($data['method'] ?? 'GET') . "\n";
        $markdown .= "URI: {$data['uri']}\n";
        $markdown .= "Pattern: {$data['pattern']}\n";
        $markdown .= "User-Agent: " . ($data['user_agent'] ?? 'Unknown') . "\n";
        $markdown .= "```\n";
        
        return $markdown;
    }
    
    private static function generateMaintenanceMarkdown(array $data): string
    {
        $markdown = "# 🔧 Upkeep Maintenance Notification\n\n";
        
        $action = $data['status'] ? 'activated' : 'deactivated';
        $emoji = $data['status'] ? '🔧' : '✅';
        
        $markdown .= "| Field | Value |\n";
        $markdown .= "|-------|-------|\n";
        $markdown .= "| **Report Key** | " . self::getKey() . " |\n";
        $markdown .= "| **Timestamp** | " . date('Y-m-d H:i:s') . " |\n";
        $markdown .= "| **Type** | {$data['type']} |\n";
        $markdown .= "| **Action** | {$action} |\n";
        $markdown .= "| **User** | " . ($data['user'] ?? 'System') . " |\n";
        
        if (isset($data['ip'])) {
            $markdown .= "| **IP Address** | {$data['ip']} |\n";
        }
        
        $markdown .= "\n## {$emoji} Maintenance Details\n\n";
        
        if ($data['status']) {
            $markdown .= "The {$data['type']} maintenance mode has been **activated**.\n\n";
            
            if ($data['type'] === 'frontend' && !empty($data['config'])) {
                $markdown .= "### Configuration\n";
                if (!empty($data['config']['allowed_ips'])) {
                    $markdown .= "- **Allowed IPs**: " . implode(', ', explode("\n", $data['config']['allowed_ips'])) . "\n";
                }
                if (!empty($data['config']['bypass_key'])) {
                    $markdown .= "- **Bypass Key**: Configured\n";
                }
                if (!empty($data['config']['multilang'])) {
                    $markdown .= "- **Multilingual**: Yes\n";
                }
            }
        } else {
            $markdown .= "The {$data['type']} maintenance mode has been **deactivated**.\n";
            $markdown .= "Normal operations have resumed.\n";
        }
        
        return $markdown;
    }
    
    private static function generateErrorMarkdown(array $data): string
    {
        $markdown = "# ❌ Upkeep Error Report\n\n";
        
        $markdown .= "| Field | Value |\n";
        $markdown .= "|-------|-------|\n";
        $markdown .= "| **Report Key** | " . self::getKey() . " |\n";
        $markdown .= "| **Timestamp** | " . date('Y-m-d H:i:s', $data['timestamp'] ?? time()) . " |\n";
        $markdown .= "| **Level** | {$data['level']} |\n";
        $markdown .= "| **Message** | {$data['message']} |\n";
        
        if (!empty($data['file'])) {
            $markdown .= "| **File** | " . rex_path::relative($data['file']) . " |\n";
        }
        
        if (!empty($data['line'])) {
            $markdown .= "| **Line** | {$data['line']} |\n";
        }
        
        $markdown .= "\n## Error Details\n\n";
        $markdown .= "```\n";
        $markdown .= $data['message'] . "\n";
        
        if (!empty($data['context'])) {
            $markdown .= "\nContext:\n";
            $markdown .= print_r($data['context'], true);
        }
        $markdown .= "```\n";
        
        return $markdown;
    }
    
    private static function generateStatusMarkdown(array $data): string
    {
        $markdown = "# 📊 Upkeep Status Report\n\n";
        
        $markdown .= "| Component | Status |\n";
        $markdown .= "|-----------|--------|\n";
        $markdown .= "| **Report Key** | " . self::getKey() . " |\n";
        $markdown .= "| **Timestamp** | " . date('Y-m-d H:i:s', $data['timestamp']) . " |\n";
        
        // Maintenance Status
        $frontendStatus = $data['maintenance']['frontend'] ? '🔧 Active' : '✅ Inactive';
        $backendStatus = $data['maintenance']['backend'] ? '🔧 Active' : '✅ Inactive';
        $markdown .= "| **Frontend Maintenance** | {$frontendStatus} |\n";
        $markdown .= "| **Backend Maintenance** | {$backendStatus} |\n";
        
        // IPS Status
        $ipsStatus = $data['ips']['active'] ? '🛡️ Active' : '❌ Inactive';
        $monitorMode = $data['ips']['monitor_only'] ? ' (Monitor Only)' : '';
        $markdown .= "| **IPS Protection** | {$ipsStatus}{$monitorMode} |\n";
        $markdown .= "| **Blocked IPs** | {$data['ips']['blocked_ips_count']} |\n";
        $markdown .= "| **Recent Threats (24h)** | " . count($data['ips']['recent_threats']) . " |\n";
        
        // Security Advisor
        $lastScan = $data['security_advisor']['last_scan'] > 0 ? 
            date('Y-m-d H:i:s', $data['security_advisor']['last_scan']) : 'Never';
        $markdown .= "| **Security Score** | {$data['security_advisor']['score']}% ({$data['security_advisor']['grade']}) |\n";
        $markdown .= "| **Last Security Scan** | {$lastScan} |\n";
        
        $markdown .= "\n## System Health\n\n";
        
        // Overall health assessment
        $healthScore = 100;
        $issues = [];
        
        if ($data['maintenance']['frontend'] || $data['maintenance']['backend']) {
            $healthScore -= 20;
            $issues[] = 'Maintenance mode active';
        }
        
        if (!$data['ips']['active']) {
            $healthScore -= 30;
            $issues[] = 'IPS protection disabled';
        }
        
        if ($data['security_advisor']['score'] < 70) {
            $healthScore -= 25;
            $issues[] = 'Low security score';
        }
        
        if (count($data['ips']['recent_threats']) > 10) {
            $healthScore -= 15;
            $issues[] = 'High threat activity';
        }
        
        $healthEmoji = match(true) {
            $healthScore >= 90 => '🟢',
            $healthScore >= 70 => '🟡',
            $healthScore >= 50 => '🟠',
            default => '🔴'
        };
        
        $markdown .= "### {$healthEmoji} Overall Health: {$healthScore}%\n";
        
        if (!empty($issues)) {
            $markdown .= "\n**Issues detected:**\n";
            foreach ($issues as $issue) {
                $markdown .= "- {$issue}\n";
            }
        } else {
            $markdown .= "\n✅ All systems operating normally.\n";
        }
        
        return $markdown;
    }
    
    private static function generateBundleMarkdown(array $files): string
    {
        $markdown = "# 📦 Upkeep Bundle Report\n\n";
        
        $markdown .= "This bundle contains " . count($files) . " reports from the last reporting interval.\n\n";
        
        $typeCount = [];
        foreach ($files as $file) {
            $parts = explode('_', $file);
            if (isset($parts[1])) {
                $type = $parts[1];
                $typeCount[$type] = ($typeCount[$type] ?? 0) + 1;
            }
        }
        
        $markdown .= "## Report Summary\n\n";
        $markdown .= "| Type | Count |\n";
        $markdown .= "|------|-------|\n";
        
        foreach ($typeCount as $type => $count) {
            $emoji = match($type) {
                'security_advisor' => '🛡️',
                'ips_threat' => '🚨',
                'maintenance' => '🔧',
                'error' => '❌',
                'status' => '📊',
                default => 'ℹ️'
            };
            $markdown .= "| {$emoji} " . str_replace('_', ' ', ucwords($type)) . " | {$count} |\n";
        }
        
        $markdown .= "\n**Detailed reports are attached as files.**\n";
        
        return $markdown;
    }
    
    public static function getLogFiles(): array
    {
        $path = self::getDataPath();
        if (!is_dir($path)) {
            return [];
        }
        
        $files = scandir($path);
        if (!is_array($files)) {
            return [];
        }
        
        return array_filter($files, function($file) {
            return $file !== '.' && $file !== '..' && str_ends_with($file, '.log.json');
        });
    }
    
    public static function deleteLogFiles(): void
    {
        foreach (self::getLogFiles() as $file) {
            rex_file::delete(self::getDataPath($file));
        }
    }
    
    public static function getDataPath(string $file = ''): string
    {
        $path = self::$addon->getDataPath(self::DATA_PATH);
        
        // Ensure directory exists
        if (!is_dir($path)) {
            rex_dir::create($path);
        }
        
        if ($file) {
            $path .= '/' . $file;
        }
        return $path;
    }
    
    private static function logError(string $message, Exception $e = null): void
    {
        $logMessage = $message;
        if ($e) {
            $logMessage .= ': ' . $e->getMessage();
        }
        
        rex_logger::logException($e ?: new Exception($logMessage));
    }
    
    /**
     * Get recent threats from database (helper method)
     */
    private static function getRecentThreats(int $hours): array
    {
        $sql = rex_sql::factory();
        $since = time() - ($hours * 3600);
        
        try {
            $sql->setQuery('
                SELECT ip, threat_type, severity, pattern, timestamp 
                FROM rex_upkeep_ips_threat_log 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC 
                LIMIT 50
            ', [$since]);
            
            return $sql->getArray();
        } catch (Exception $e) {
            return [];
        }
    }
    
    /**
     * Get blocked IPs count (helper method)
     */
    private static function getBlockedIPsCount(): int
    {
        $sql = rex_sql::factory();
        
        try {
            $sql->setQuery('SELECT COUNT(*) as count FROM rex_upkeep_ips_blocked_ips');
            return (int) $sql->getValue('count');
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * Trigger maintenance notification
     */
    public static function triggerMaintenanceNotification(string $type, bool $status, array $config = []): void
    {
        $data = [
            'type' => $type,
            'status' => $status,
            'timestamp' => time(),
            'user' => rex::getUser()?->getLogin() ?? 'System',
            'ip' => rex_server('REMOTE_ADDR', 'string', ''),
            'config' => $config
        ];
        
        // This will trigger the registered extension points
        // The actual triggering happens in the calling code that registers these extensions
    }
    
    /**
     * Trigger security scan notification
     */
    public static function triggerSecurityScanNotification(array $results): void
    {
        // This will trigger the registered extension points
        // The actual triggering happens in the calling code that registers these extensions
    }
}