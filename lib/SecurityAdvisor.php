<?php
/**
 * Upkeep AddOn - Security Advisor
 * 
 * @author KLXM Crossmedia
 * @version 1.8.1
 */

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_yrewrite;
use rex_config;
use rex_url;
use rex_path;
use rex_sql;
use Exception;

class SecurityAdvisor
{
    private rex_addon $addon;
    private array $results = [];

    public function __construct()
    {
        $this->addon = rex_addon::get('upkeep');
    }

    /**
     * Prüft ob eine Admin-Freigabe für einen Check-Typ aktiv ist
     */
    public function isCheckReleased(string $checkType): bool
    {
        $releaseKey = "admin_release_{$checkType}";
        $releaseTimestamp = $this->addon->getConfig($releaseKey, 0);
        
        if ($releaseTimestamp === 0) {
            return false;
        }
        
        $releaseDays = $this->addon->getConfig('admin_release_days', 30);
        $expiryTimestamp = $releaseTimestamp + ($releaseDays * 24 * 60 * 60);
        
        return time() < $expiryTimestamp;
    }

    /**
     * Admin-Freigabe für einen Check-Typ setzen
     */
    public function setAdminRelease(string $checkType): void
    {
        $releaseKey = "admin_release_{$checkType}";
        $this->addon->setConfig($releaseKey, time());
    }

    /**
     * Admin-Freigabe für einen Check-Typ entfernen
     */
    public function removeAdminRelease(string $checkType): void
    {
        $releaseKey = "admin_release_{$checkType}";
        $this->addon->removeConfig($releaseKey);
    }

    /**
     * Führt alle Sicherheitsprüfungen durch
     */
    public function runAllChecks(): array
    {
        $this->results = [
            'timestamp' => time(),
            'checks' => []
        ];

        $this->checkRedaxoLiveMode();
        $this->checkServerHeaders();
        $this->checkPhpConfiguration();
        $this->checkSystemVersions();
        $this->checkWebserverVersion();
        $this->checkProductionMode();
        $this->checkDirectoryPermissions();
        $this->checkDatabaseSecurity();
        $this->checkEmailSecurity();
        $this->checkRedaxoVersion();
        $this->checkMaintenanceStatus();
        $this->checkContentSecurityPolicy();
        $this->checkPasswordPolicies();
        $this->checkSessionSecurity();
        $this->checkFilePermissions();
        $this->checkHSTS();

        // Gesamtbewertung berechnen
        $this->calculateSecurityScore();

        return $this->results;
    }

    /**
     * Prüft ob REDAXO im Live-Modus läuft
     */
    private function checkRedaxoLiveMode(): void
    {
        $isDebugOff = !rex::isDebugMode();
        $setup = rex::isSetup();
        $liveMode = rex::getProperty('live_mode', false);
        
        // Live-Mode ist aktiv wenn: Debug aus UND live_mode=true UND kein Setup
        $isProperLive = $isDebugOff && $liveMode && !$setup;

        $this->results['checks']['live_mode'] = [
            'name' => $this->addon->i18n('upkeep_check_live_mode'),
            'status' => $isProperLive ? 'success' : 'error',
            'severity' => 'high',
            'score' => $isProperLive ? 10 : 0,
            'details' => [
                'debug_mode' => rex::isDebugMode(),
                'live_mode_config' => $liveMode,
                'setup_mode' => $setup,
                'safe_mode' => rex::isSafeMode(),
                'proper_live_mode' => $isProperLive
            ],
            'recommendations' => $this->getLiveModeRecommendations($isDebugOff, $liveMode, $setup),
            'description' => $this->addon->i18n('upkeep_live_mode_description')
        ];
    }

    /**
     * Erstellt automatisches Backup der config.yml vor Änderungen
     */
    private function backupConfig(): string
    {
        $configPath = \rex_path::coreData('config.yml');
        $backupPath = \rex_path::coreData('config.yml.backup.' . date('Y-m-d_H-i-s'));
        
        if (copy($configPath, $backupPath)) {
            return $backupPath;
        }
        
        throw new Exception('Backup der config.yml konnte nicht erstellt werden');
    }

    /**
     * Aktiviert den REDAXO Live-Mode durch Anpassung der config.yml
     * Basiert auf der Security AddOn Implementierung
     * WARNUNG: Deaktivierung nur über manuelle Bearbeitung der config.yml möglich!
     */
    public function enableLiveMode(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_live_mode_warning')
        ];

        try {
            // Automatisches Backup erstellen
            $backupPath = $this->backupConfig();
            
            // Verwende die REDAXO Standard-Methode wie das Security AddOn
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));
            
            // Live-Mode aktivieren
            $config['live_mode'] = true;
            
            // Debug-Modus deaktivieren falls aktiv
            if (!isset($config['debug'])) {
                $config['debug'] = [];
            }
            $config['debug']['enabled'] = false;
            $config['debug']['throw_always_exception'] = false;
            
            // Konfiguration speichern mit REDAXO-Methode
            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_live_mode_success');
                $result['backup'] = 'Backup erstellt: ' . basename($backupPath);
                
                // Cache leeren damit Änderungen sofort wirksam werden
                rex_delete_cache();
            } else {
                $result['message'] = 'Fehler beim Speichern der config.yml';
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Aktiviert Content Security Policy Header
     * Basiert auf der Security AddOn Implementierung
     */
    public function enableCSP(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_csp_warning')
        ];

        try {
            $addon = \rex_addon::get('upkeep');
            
            // CSP in der Addon-Konfiguration aktivieren
            $addon->setConfig('csp_enabled', true);
            
            $result['success'] = true;
            $result['message'] = $this->addon->i18n('upkeep_csp_success');
        } catch (Exception $e) {
            $result['message'] = 'Fehler: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Deaktiviert Content Security Policy Header
     */
    public function disableCSP(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => ''
        ];

        try {
            $addon = \rex_addon::get('upkeep');
            
            // CSP in der Addon-Konfiguration deaktivieren
            $addon->setConfig('csp_enabled', false);
            
            $result['success'] = true;
            $result['message'] = $this->addon->i18n('upkeep_csp_disable_success');
        } catch (Exception $e) {
            $result['message'] = 'Fehler: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Generiert CSP-Header für das REDAXO Backend
     * Basiert auf dem Security AddOn mit Backend-spezifischen Anpassungen
     */
    public static function generateCSPHeader(): string
    {
        $csp = [
            'default-src' => ["'self'"],
            'base-uri' => ["'self'"],
            'img-src' => ["'self'", 'data:', 'https:'],
            'script-src' => ["'self'", "'unsafe-inline'", "'unsafe-eval'"], // Backend braucht inline scripts
            'style-src' => ["'self'", "'unsafe-inline'"], // Backend braucht inline styles
            'object-src' => ["'none'"],
            'frame-ancestors' => ["'self'"],
            'form-action' => ["'self'"],
            'connect-src' => ["'self'"] // Für AJAX-Requests
        ];
        
        $cspString = [];
        foreach ($csp as $directive => $sources) {
            $cspString[] = $directive . ' ' . implode(' ', $sources);
        }
        
        return implode('; ', $cspString);
    }

    /**
     * Prüft ein einzelnes SSL-Zertifikat
     */
    private function checkDomainSsl(string $domain): array
    {
        $result = [
            'domain' => $domain,
            'status' => 'error',
            'score' => 0,
            'valid' => false,
            'expires' => null,
            'issuer' => null,
            'days_remaining' => 0,
            'errors' => []
        ];

        try {
            $context = stream_context_create([
                'ssl' => [
                    'capture_peer_cert' => true,
                    'verify_peer' => false,
                    'verify_peer_name' => false
                ]
            ]);

            $stream = @stream_socket_client(
                "ssl://{$domain}:443", 
                $errno, 
                $errstr, 
                10, 
                STREAM_CLIENT_CONNECT, 
                $context
            );

            if ($stream) {
                $params = stream_context_get_params($stream);
                if (isset($params['options']['ssl']['peer_certificate'])) {
                    $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
                    
                    $result['valid'] = true;
                    $result['expires'] = date('Y-m-d H:i:s', $cert['validTo_time_t']);
                    $result['issuer'] = $cert['issuer']['CN'] ?? 'Unknown';
                    $result['days_remaining'] = ceil(($cert['validTo_time_t'] - time()) / 86400);
                    
                    if ($result['days_remaining'] > 30) {
                        $result['status'] = 'success';
                        $result['score'] = 10;
                    } elseif ($result['days_remaining'] > 7) {
                        $result['status'] = 'warning';
                        $result['score'] = 5;
                    } else {
                        $result['status'] = 'error';
                        $result['score'] = 0;
                        $result['errors'][] = $this->addon->i18n('upkeep_php_config_ssl_expired');
                    }
                } else {
                    $result['errors'][] = $this->addon->i18n('upkeep_php_config_no_ssl_cert');
                }
                
                fclose($stream);
            } else {
                $result['errors'][] = $this->addon->i18n('upkeep_php_config_ssl_connection_failed', $errstr);
            }
        } catch (Exception $e) {
            $result['errors'][] = $e->getMessage();
        }

        return $result;
    }

    /**
     * Prüft Server-Header auf Sicherheitslecks
     */
    private function checkServerHeaders(): void
    {
        $headers = $this->getCurrentHeaders();
        $criticalIssues = [];
        $recommendations = [];
        $score = 10;

        // KRITISCHE Probleme: Information Disclosure
        if (isset($headers['Server']) && preg_match('/\d+\.\d+/', $headers['Server'])) {
            $criticalIssues[] = $this->addon->i18n('upkeep_server_header_version_disclosed', $headers['Server']);
            $score -= 3; // Stärkere Bewertung für echte Sicherheitslecks
        }

        if (isset($headers['X-Powered-By'])) {
            $criticalIssues[] = $this->addon->i18n('upkeep_server_header_x_powered_by', $headers['X-Powered-By']);
            $score -= 3; // Stärkere Bewertung für echte Sicherheitslecks
        }

        // EMPFEHLUNGEN: Fehlende Security-Header (weniger kritisch)
        $securityHeaders = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection' => '1; mode=block',
            'Strict-Transport-Security' => null,
            'Referrer-Policy' => null
        ];

        foreach ($securityHeaders as $header => $expectedValue) {
            if (!isset($headers[$header])) {
                $recommendations[] = $this->addon->i18n('upkeep_server_header_missing_security', $header);
                $score -= 0.3; // Viel weniger Punktabzug für fehlende Header
            }
        }

        // Status-Logik: Nur kritische Probleme machen es rot
        if (!empty($criticalIssues)) {
            $status = $score > 5 ? 'warning' : 'error';
        } elseif (!empty($recommendations)) {
            $status = 'warning'; // Fehlende Header = immer nur Warnung
        } else {
            $status = 'success';
        }

        $allIssues = array_merge($criticalIssues, $recommendations);

        $this->results['checks']['server_headers'] = [
            'name' => $this->addon->i18n('upkeep_check_server_headers'),
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'headers' => $headers,
                'critical_issues' => $criticalIssues,
                'recommendations' => $recommendations,
                'issues' => $allIssues // Für Backward-Kompatibilität
            ],
            'recommendations' => $this->getHeaderRecommendations($allIssues),
            'description' => $this->addon->i18n('upkeep_server_header_description')
        ];
    }

    /**
     * Prüft PHP-Konfiguration und System-Sicherheitseinstellungen
     */
    public function checkPhpConfiguration(): array
    {
        $issues = [];
        $warnings = [];
        $score = 10;

        // 1. Potentiell gefährliche Funktionen (aber oft benötigt für REDAXO/AddOns)
        $potentiallyDangerousFunctions = [
            'eval' => 'kritisch', // eval ist wirklich gefährlich
            'exec' => 'warnung',   // oft benötigt für ffmpeg, imagemagick
            'system' => 'warnung', // oft benötigt für Tools
            'shell_exec' => 'warnung', // oft benötigt für Kommandos
            'passthru' => 'warnung',   // oft benötigt für Output-Streaming
            'popen' => 'warnung',      // oft benötigt für Prozess-Kommunikation
            'proc_open' => 'warnung'   // oft benötigt für komplexe Prozesse
        ];
        $disabled = function_exists('ini_get') ? array_map('trim', explode(',', ini_get('disable_functions'))) : [];
        
        foreach ($potentiallyDangerousFunctions as $func => $severity) {
            if (!in_array($func, $disabled) && function_exists($func)) {
                if ($severity === 'kritisch') {
                    $issues[] = $this->addon->i18n('upkeep_php_config_eval_enabled');
                    $score -= 2;
                } else {
                    $warnings[] = $this->addon->i18n('upkeep_php_config_dangerous_function', $func);
                    $score -= 0.5;
                }
            }
        }

        // 2. PHP-Grundeinstellungen - korrekte Boolean-Prüfung
        $settings = [
            'display_errors' => ['Off', $this->addon->i18n('upkeep_php_config_display_errors')],
            'expose_php' => ['Off', $this->addon->i18n('upkeep_php_config_expose_php')],
            'allow_url_fopen' => ['Off', $this->addon->i18n('upkeep_php_config_allow_url_fopen')],
            'allow_url_include' => ['Off', $this->addon->i18n('upkeep_php_config_allow_url_include')],
            'register_globals' => ['Off', $this->addon->i18n('upkeep_php_config_register_globals')]
        ];

        foreach ($settings as $setting => $config) {
            if (!function_exists('ini_get')) continue;
            $value = ini_get($setting);
            
            // Korrekte Boolean-Prüfung für PHP ini-Werte (alle Schreibweisen)
            $isActive = false;
            
            if (is_string($value)) {
                // String-Werte normalisieren und prüfen
                $normalizedValue = strtolower(trim($value));
                // Aktiviert: "1", "on", "true", "yes", "enabled"
                $isActive = in_array($normalizedValue, ['1', 'on', 'true', 'yes', 'enabled']);
            } elseif (is_numeric($value)) {
                // Numerische Werte: 1 = aktiviert, 0 = deaktiviert
                $isActive = (int) $value === 1;
            } else {
                // Boolean/andere Werte: true = aktiviert
                $isActive = (bool) $value;
            }
            
            // Nur als Problem melden wenn es aktiviert ist (aber deaktiviert sein sollte)
            if ($isActive) {
                $issues[] = $config[1];
                $score -= 1;
            }
        }

        // 3. Memory Limit (DoS-Schutz)
        if (!function_exists('ini_get')) goto skip_memory_check;
        $memoryLimit = ini_get('memory_limit');
        $memoryBytes = $this->convertToBytes($memoryLimit);
        if ($memoryBytes > 512 * 1024 * 1024) { // > 512MB
            $warnings[] = $this->addon->i18n('upkeep_php_config_memory_limit_high', $memoryLimit);
        } elseif ($memoryBytes === -1) {
            $issues[] = $this->addon->i18n('upkeep_php_config_unlimited_memory');
            $score -= 2;
        }
        skip_memory_check:

        // 4. Upload-Limits
        if (!function_exists('ini_get')) goto skip_upload_check;
        $maxFileSize = ini_get('upload_max_filesize');
        $postMaxSize = ini_get('post_max_size');
        $maxFileSizeBytes = $this->convertToBytes($maxFileSize);
        $postMaxSizeBytes = $this->convertToBytes($postMaxSize);
        
        if ($maxFileSizeBytes > 50 * 1024 * 1024) { // > 50MB
            $warnings[] = $this->addon->i18n('upkeep_php_config_upload_max_high', $maxFileSize);
        }
        if ($postMaxSizeBytes > 100 * 1024 * 1024) { // > 100MB
            $warnings[] = $this->addon->i18n('upkeep_php_config_post_max_high', $postMaxSize);
        }
        skip_upload_check:

        // 5. Open Basedir (Chroot-ähnliche Beschränkung)
        if (!function_exists('ini_get')) goto skip_basedir_check;
        $openBasedir = ini_get('open_basedir');
        if (empty($openBasedir)) {
            $warnings[] = $this->addon->i18n('upkeep_php_config_open_basedir_unset');
        }
        skip_basedir_check:

        // 6. Error Reporting in Produktion
        if (function_exists('ini_get')) {
            $errorReporting = ini_get('error_reporting');
            $logErrors = ini_get('log_errors');
                if ($errorReporting != 0 && ini_get('display_errors') == 'On') {
                $issues[] = $this->addon->i18n('upkeep_php_config_error_reporting_production');
                $score -= 1;
            }
        }
        
        // 7. PHP-Versionsprüfung
        $phpVersion = PHP_VERSION;
        $phpMajorMinor = implode('.', array_slice(explode('.', $phpVersion), 0, 2));
        
        // Definiere unterstützte/veraltete PHP-Versionen
        $unsupportedVersions = ['7.0', '7.1', '7.2', '7.3', '7.4'];
        $deprecatedVersions = ['8.0', '8.1'];
        
        if (in_array($phpMajorMinor, $unsupportedVersions)) {
            $issues[] = $this->addon->i18n('upkeep_php_config_php_version_unsupported');
            $issues[] = $this->addon->i18n('upkeep_php_config_php_update_required');
            $score -= 3;
        } elseif (in_array($phpMajorMinor, $deprecatedVersions)) {
            $warnings[] = $this->addon->i18n('upkeep_php_config_php_version_deprecated');
            $warnings[] = $this->addon->i18n('upkeep_php_config_php_update_required');
            $score -= 1;
        }
        if (!$logErrors) {
            $warnings[] = $this->addon->i18n('upkeep_php_config_error_logging_disabled');
        }

        // Status bestimmen
        $allIssues = array_merge($issues, $warnings);
        if (!empty($issues)) {
            $status = $score > 5 ? 'warning' : 'error';
        } elseif (!empty($warnings)) {
            $status = 'warning';
        } else {
            $status = 'success';
        }

        // Dashboard-kompatible Rückgabe
        $dashboardStatus = $status === 'error' ? 'critical' : ($status === 'warning' ? 'warning' : 'optimal');
        $dashboardMessage = !empty($issues) ? implode(', ', array_slice($issues, 0, 2)) : 
                           (!empty($warnings) ? implode(', ', array_slice($warnings, 0, 2)) : $this->addon->i18n('upkeep_php_config_php_optimal'));
        
        // Speichere auch im internen Format
        $this->results['checks']['php_configuration'] = [
            'name' => $this->addon->i18n('upkeep_check_php_configuration'),
            'status' => $status,
            'severity' => 'high',
            'score' => max(0, $score),
            'details' => [
                'php_version' => PHP_VERSION,
                'disabled_functions' => $disabled,
                'memory_limit' => $memoryLimit,
                'upload_max_filesize' => $maxFileSize,
                'post_max_size' => $postMaxSize,
                'open_basedir' => $openBasedir ?: 'nicht gesetzt',
                'error_reporting' => $errorReporting,
                'log_errors' => $logErrors ? 'On' : 'Off',
                'critical_issues' => $issues,
                'warnings' => $warnings
            ],
            'recommendations' => $this->getPhpConfigRecommendations($allIssues),
            'description' => $this->addon->i18n('upkeep_php_config_description')
        ];
        
        // Dashboard-Format zurückgeben
        return [
            'status' => $dashboardStatus,
            'message' => $dashboardMessage,
            'score' => max(0, $score),
            'version' => PHP_VERSION,
            'issues' => array_merge($issues, $warnings)
        ];
    }

    /**
     * Prüft Verzeichnisberechtigungen
     */
    private function checkDirectoryPermissions(): void
    {
        $directories = [
            rex_path::frontend() => 755,
            rex_path::data() => 755,
            rex_path::cache() => 755,
            rex_path::log() => 755,
            rex_path::media() => 755
        ];

        $issues = [];
        $score = 10;

        foreach ($directories as $dir => $expectedPerms) {
            if (is_dir($dir)) {
                $currentPerms = fileperms($dir) & 0777;
                if ($currentPerms > $expectedPerms) {
                    $issues[] = $this->addon->i18n('upkeep_file_permissions_too_open', basename($dir), sprintf('%o', $currentPerms), sprintf('%o', $expectedPerms));
                    $score -= 2;
                }
            }
        }

        $status = empty($issues) ? 'success' : ($score > 6 ? 'warning' : 'error');

        $this->results['checks']['directory_permissions'] = [
            'name' => $this->addon->i18n('upkeep_check_directory_permissions'),
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'checked_directories' => array_keys($directories),
                'issues' => $issues
            ],
            'recommendations' => $this->getPermissionRecommendations(),
            'description' => $this->addon->i18n('upkeep_file_permissions_description')
        ];
    }

    /**
     * Prüft Datenbank-Sicherheit
     */
    private function checkDatabaseSecurity(): void
    {
        $issues = [];
        $score = 10;

        $dbConfig = rex::getProperty('db');
        
        // Schwache Passwörter prüfen
        $password = $dbConfig[1]['password'] ?? '';
        if (strlen($password) < 8) {
            $issues[] = $this->addon->i18n('upkeep_db_password_too_short');
            $score -= 3;
        }

        // Standardbenutzer prüfen
        $username = $dbConfig[1]['login'] ?? '';
        if (in_array($username, ['root', 'admin', 'redaxo'])) {
            $issues[] = $this->addon->i18n('upkeep_db_standard_username');
            $score -= 2;
        }

        // Externe Verbindungen
        $host = $dbConfig[1]['host'] ?? '';
        if ($host !== 'localhost' && $host !== '127.0.0.1') {
            $issues[] = $this->addon->i18n('upkeep_db_external_connection');
            $score -= 1;
        }

        $status = empty($issues) ? 'success' : ($score > 6 ? 'warning' : 'error');

        $this->results['checks']['database_security'] = [
            'name' => $this->addon->i18n('upkeep_check_database_security'),
            'status' => $status,
            'severity' => 'high',
            'score' => max(0, $score),
            'details' => [
                'host' => $host,
                'username' => $username,
                'issues' => $issues
            ],
            'recommendations' => $this->getDatabaseRecommendations($issues),
            'description' => $this->addon->i18n('upkeep_db_description')
        ];
    }

    /**
     * Prüft E-Mail-Sicherheit und Übertragungsmethoden
     */
    private function checkEmailSecurity(): void
    {
        $issues = [];
        $warnings = [];
        $recommendations = [];
        $score = 10;
        $status = 'success';
        
        // PHPMailer-AddOn prüfen
        $phpmailerAddon = rex_addon::get('phpmailer');
        if (!$phpmailerAddon->isAvailable()) {
            $warnings[] = $this->addon->i18n('upkeep_email_phpmailer_unavailable');
            $score -= 1;
        } else {
            // PHPMailer-Konfiguration analysieren (korrekte Config-Keys)
            $mailerMethod = $phpmailerAddon->getConfig('mailer', 'mail');
            $smtpHost = $phpmailerAddon->getConfig('host', '');
            $smtpPort = $phpmailerAddon->getConfig('port', 25);
            $smtpSecure = $phpmailerAddon->getConfig('smtpsecure', '');
            $smtpAuth = $phpmailerAddon->getConfig('smtpauth', false);
            $securityMode = $phpmailerAddon->getConfig('security_mode', true); // AutoTLS
            
            // Mailer-Methode bewerten
            switch ($mailerMethod) {
                case 'mail':
                    // mail() Funktion ist unsicher
                    $issues[] = $this->addon->i18n('upkeep_email_unsafe_mail_function');
                    $issues[] = $this->addon->i18n('upkeep_email_header_injection_risk');
                    $recommendations[] = $this->addon->i18n('upkeep_email_smtp_recommended');
                    $score -= 4;
                    break;
                    
                case 'smtp':
                    if ($smtpSecure === 'tls' || $smtpSecure === 'ssl') {
                        // SMTP mit expliziter TLS/SSL-Konfiguration - optimal
                        if ($smtpPort == 587 && $smtpSecure === 'tls') {
                            // Port 587 mit TLS - perfekt
                            $score = 10;
                        } elseif ($smtpPort == 465 && $smtpSecure === 'ssl') {
                            // Port 465 mit SSL - auch gut
                            $score = 9;
                        } else {
                            $warnings[] = "SMTP-Konfiguration ungewöhnlich: Port {$smtpPort} mit {$smtpSecure}";
                            $score = 8;
                        }
                    } elseif ($securityMode) {
                        // AutoTLS aktiviert - versucht automatisch TLS
                        if ($smtpPort == 587 || $smtpPort == 465) {
                            $warnings[] = $this->addon->i18n('upkeep_email_auto_tls_warning', $smtpPort);
                            $warnings[] = $this->addon->i18n('upkeep_email_auto_tls_unsecure');
                            $score = 7;
                        } else {
                            $warnings[] = "AutoTLS auf Port {$smtpPort} - Verschlüsselung ungewiss";
                            $score = 6;
                        }
                        
                        // Bekannte sichere Anbieter erkennen
                        if ($smtpHost) {
                            if (stripos($smtpHost, 'smtp.gmail.com') !== false ||
                                stripos($smtpHost, 'smtp-mail.outlook.com') !== false ||
                                stripos($smtpHost, 'smtp.office365.com') !== false ||
                                stripos($smtpHost, 'outlook.office365.com') !== false ||
                                stripos($smtpHost, 'smtp.live.com') !== false ||
                                stripos($smtpHost, 'smtp.mailgun.org') !== false ||
                                stripos($smtpHost, 'smtp.sendgrid.net') !== false) {
                                // Bekannte sichere Anbieter - Bonus auch bei AutoTLS
                                $recommendations[] = "Vertrauensvoller E-Mail-Provider {$smtpHost} mit AutoTLS";
                                $score += 1; // Bonus für bekannte Provider
                            }
                        }
                        
                    } else {
                        // SMTP ohne Verschlüsselung - kritisch
                        $issues[] = $this->addon->i18n('upkeep_email_smtp_encryption_missing', $smtpPort);
                        $issues[] = $this->addon->i18n('upkeep_email_passwords_unencrypted');
                        $score = 2;
                        $status = 'error';
                    }
                    
                    if (!$smtpAuth) {
                        $warnings[] = $this->addon->i18n('upkeep_email_smtp_auth_missing');
                        $score -= 1;
                    }
                    break;
                    
                case 'microsoft365':
                    $recommendations[] = $this->addon->i18n('upkeep_email_microsoft365_optimal');
                    $recommendations[] = $this->addon->i18n('upkeep_email_microsoft365_secure');
                    $score = 10;
                    $status = 'success';
                    break;
                    
                case 'sendmail':
                    $warnings[] = $this->addon->i18n('upkeep_email_sendmail_warning');
                    $warnings[] = $this->addon->i18n('upkeep_email_sendmail_no_encryption');
                    $score = 6;
                    $status = 'warning';
                    break;
                    
                case 'mail':
                    $warnings[] = $this->addon->i18n('upkeep_email_php_mail_unsafe');
                    $warnings[] = $this->addon->i18n('upkeep_email_php_mail_no_security');
                    $warnings[] = $this->addon->i18n('upkeep_email_spam_risk');
                    $score = 4;
                    $status = 'warning';
                    break;
                    
                default:
                    $issues[] = $this->addon->i18n('upkeep_email_unknown_method', $mailerMethod);
                    $score = 3;
                    $status = 'error';
                    break;
            }
            
            $emailConfig = [
                'mailer_method' => $mailerMethod,
                'smtp_host' => $smtpHost,
                'smtp_port' => $smtpPort,
                'smtp_secure' => $smtpSecure,
                'smtp_auth' => $smtpAuth,
                'security_mode' => $securityMode // AutoTLS
            ];
        }
        
        $allIssues = array_merge($issues, $warnings, $recommendations);
        if (empty($allIssues)) {
            $allIssues[] = $this->addon->i18n('upkeep_email_secure_configured');
        }

        $this->results['checks']['email_security'] = [
            'name' => $this->addon->i18n('upkeep_check_email_security'),
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'phpmailer_available' => $phpmailerAddon->isAvailable(),
                'email_config' => $emailConfig ?? [],
                'critical_issues' => $issues,
                'warnings' => $warnings,
                'positive_points' => $recommendations
            ],
            'recommendations' => $this->getEmailSecurityRecommendations($mailerMethod ?? 'unknown'),
            'description' => $this->addon->i18n('upkeep_email_description')
        ];
    }

    /**
     * Prüft den Wartungsstatus des Systems
     */
    private function checkMaintenanceStatus(): void
    {
        $maintenanceRequired = $this->addon->getConfig('maintenance_required', false);
        $maintenanceMessage = $this->addon->getConfig('maintenance_message', '');
        $maintenanceContact = $this->addon->getConfig('maintenance_contact', '');

        $issues = [];
        $warnings = [];
        $score = 10;
        $status = 'success';

        if ($maintenanceRequired) {
            $issues[] = $this->addon->i18n('upkeep_dashboard_maintenance_required');
            if (!empty($maintenanceMessage)) {
                $issues[] = $maintenanceMessage;
            }
            if (!empty($maintenanceContact)) {
                $issues[] = $this->addon->i18n('upkeep_dashboard_contact_technical_maintainer', $maintenanceContact);
            }
            $score = 0;
            $status = 'error';
        }

        $allIssues = array_merge($issues, $warnings);
        if (empty($allIssues)) {
            $allIssues[] = $this->addon->i18n('upkeep_maintenance_not_required');
        }

        $this->results['checks']['maintenance_status'] = [
            'name' => $this->addon->i18n('upkeep_check_maintenance_status'),
            'status' => $status,
            'severity' => 'high',
            'score' => $score,
            'details' => [
                'maintenance_required' => $maintenanceRequired,
                'maintenance_message' => $maintenanceMessage,
                'maintenance_contact' => $maintenanceContact,
                'critical_issues' => $issues,
                'warnings' => $warnings
            ],
            'recommendations' => $allIssues,
            'description' => $this->addon->i18n('upkeep_maintenance_status_description')
        ];
    }
    /**
     * Prüft ob die REDAXO-Version aktuell ist
     */
    public function checkRedaxoVersion(): array
    {
        $issues = [];
        $warnings = [];
        $recommendations = [];
        $score = 10;
        $status = 'success';

        $currentVersion = rex::getVersion();
        $latestVersion = null;
        $updateAvailable = false;
        $isUnstable = false;

        try {
            // Prüfe ob Installer-AddOn verfügbar ist
            if (!rex_addon::get('install')->isAvailable()) {
                $warnings[] = $this->addon->i18n('upkeep_installer_unavailable');
                $recommendations[] = $this->addon->i18n('upkeep_installer_activate');
                $score = 8;
                $status = 'warning';
            } else {
                // Versuche aktuelle REDAXO-Version von redaxo.org zu holen
                try {
                    $versions = \rex_api_install_core_update::getVersions();

                    if (!empty($versions)) {
                        // Neueste stabile Version finden
                        $latestStable = null;
                        foreach ($versions as $version) {
                            if (!\rex_version::isUnstable($version['version'])) {
                                if ($latestStable === null || \rex_version::compare($version['version'], $latestStable, '>')) {
                                    $latestStable = $version['version'];
                                }
                            }
                        }

                        if ($latestStable) {
                            $latestVersion = $latestStable;
                            $updateAvailable = \rex_version::compare($latestVersion, $currentVersion, '>');
                        }
                    }
                } catch (\Exception $e) {
                    $warnings[] = $this->addon->i18n('upkeep_redaxo_org_offline');
                    $warnings[] = $this->addon->i18n('upkeep_check_updates_manually');
                    $score = 7;
                    $status = 'warning';
                }
            }

            // Prüfe ob aktuelle Version instabil ist
            $isUnstable = \rex_version::isUnstable($currentVersion);

            if ($isUnstable) {
                $warnings[] = $this->addon->i18n('upkeep_development_version', $currentVersion);
                $warnings[] = $this->addon->i18n('upkeep_development_not_production');
                $recommendations[] = $this->addon->i18n('upkeep_switch_stable_version');
                $score = 6;
                $status = 'warning';
            }

            if ($updateAvailable && $latestVersion) {
                $versionDiff = $this->getVersionAge($currentVersion, $latestVersion);
                $subversionDistance = $this->getSubversionDistance($currentVersion, $latestVersion);

                if ($versionDiff['major'] > 0) {
                    // Major Update verfügbar - kritisch
                    $issues[] = $this->addon->i18n('upkeep_critical_update', $currentVersion, $latestVersion);
                    $issues[] = $this->addon->i18n('upkeep_major_security_updates');
                    $recommendations[] = $this->addon->i18n('upkeep_immediate_update');
                    $score = 3;
                    $status = 'error';
                } elseif ($subversionDistance >= 3) {
                    // 3+ Subversionen zurück - kritisch (rot)
                    $issues[] = $this->addon->i18n('upkeep_severely_outdated', $currentVersion, $latestVersion, $subversionDistance);
                    $issues[] = $this->addon->i18n('upkeep_version_too_old');
                    $recommendations[] = $this->addon->i18n('upkeep_immediate_required');
                    $score = 4;
                    $status = 'error';
                } elseif ($subversionDistance >= 1) {
                    // 1-2 Subversionen zurück - Warnung (gelb)
                    $warnings[] = $this->addon->i18n('upkeep_update_available', $currentVersion, $latestVersion, $subversionDistance, ($subversionDistance > 1 ? 'en' : ''));
                    $warnings[] = $this->addon->i18n('upkeep_updates_contain_fixes');
                    $recommendations[] = $this->addon->i18n('upkeep_update_timely');
                    $score = 6;
                    $status = 'warning';
                } elseif ($versionDiff['patch'] > 0) {
                    // Nur Patch Update - Info
                    $warnings[] = $this->addon->i18n('upkeep_patch_available', $currentVersion, $latestVersion);
                    $recommendations[] = $this->addon->i18n('upkeep_security_fixes');
                    $score = 8;
                    $status = 'warning';
                }
            } elseif ($latestVersion && !$updateAvailable) {
                $recommendations[] = $this->addon->i18n('upkeep_version_current', $currentVersion);
            }

        } catch (\Exception $e) {
            $warnings[] = $this->addon->i18n('upkeep_version_check_error', $e->getMessage());
            $score = 5;
            $status = 'warning';
        }

        $versionInfo = [
            'current_version' => $currentVersion,
            'latest_version' => $latestVersion,
            'update_available' => $updateAvailable,
            'is_unstable' => $isUnstable,
            'installer_available' => rex_addon::get('install')->isAvailable()
        ];

        $allIssues = array_merge($issues, $warnings, $recommendations);
        if (empty($allIssues)) {
            $allIssues[] = $this->addon->i18n('upkeep_redaxo_version_current_final', $currentVersion);
        }

        // Dashboard-kompatible Rückgabe
        if ($updateAvailable && $status === 'error') {
            $dashboardStatus = 'critical';
        } elseif ($updateAvailable) {
            $dashboardStatus = 'outdated';
        } else {
            $dashboardStatus = 'up_to_date';
        }

        $dashboardTitle = $dashboardStatus === 'critical' ? 'REDAXO Update kritisch' :
                         ($dashboardStatus === 'outdated' ? 'REDAXO Update verfügbar' : 'REDAXO aktuell');

        $dashboardMessage = !empty($issues) ? $issues[0] : (!empty($warnings) ? $warnings[0] : $this->addon->i18n('upkeep_redaxo_version_current'));

        // Speichere auch im internen Format
        $this->results['checks']['redaxo_version'] = [
            'name' => $this->addon->i18n('upkeep_check_redaxo_version'),
            'status' => $status,
            'severity' => $updateAvailable ? 'high' : 'medium',
            'score' => max(0, $score),
            'details' => [
                'version_info' => $versionInfo,
                'critical_issues' => $issues,
                'warnings' => $warnings,
                'positive_points' => $recommendations
            ],
            'recommendations' => $this->getRedaxoVersionRecommendations($updateAvailable, $isUnstable, $latestVersion),
            'description' => $this->addon->i18n('upkeep_redaxo_version_description')
        ];

        // Dashboard-Format zurückgeben
        return [
            'status' => $dashboardStatus,
            'title' => $dashboardTitle,
            'message' => $dashboardMessage,
            'details' => [
                'version_info' => $versionInfo,
                'critical_issues' => $issues,
                'warnings' => $warnings
            ]
        ];
    }

    /**
     * Berechnet den Versionsabstand zwischen zwei Versionen
     */
    private function getVersionAge(string $currentVersion, string $latestVersion): array
    {
        $current = $this->parseVersion($currentVersion);
        $latest = $this->parseVersion($latestVersion);
        
        return [
            'major' => $latest['major'] - $current['major'],
            'minor' => $latest['minor'] - $current['minor'],
            'patch' => $latest['patch'] - $current['patch']
        ];
    }
    
    /**
     * Parst eine Versionsnummer in ihre Bestandteile
     */
    private function parseVersion(string $version): array
    {
        // Entferne Beta/Alpha/RC Suffixe für den Vergleich
        $cleanVersion = preg_replace('/-(alpha|beta|rc|dev).*$/i', '', $version);
        $parts = explode('.', $cleanVersion);
        
        return [
            'major' => (int) ($parts[0] ?? 0),
            'minor' => (int) ($parts[1] ?? 0),
            'patch' => (int) ($parts[2] ?? 0)
        ];
    }

    /**
     * Berechnet den Subversions-Abstand zwischen aktueller und neuester Version
     * Beispiel: 5.20 vs 5.17 = 3 Subversionen Abstand
     */
    private function getSubversionDistance(string $currentVersion, string $latestVersion): int
    {
        $current = $this->parseVersion($currentVersion);
        $latest = $this->parseVersion($latestVersion);
        
        // Nur Minor-Versionen-Abstand bei gleicher Major-Version berechnen
        if ($current['major'] !== $latest['major']) {
            return 999; // Große Zahl für Major-Version-Unterschiede
        }
        
        return $latest['minor'] - $current['minor'];
    }

    /**
     * Prüft Content Security Policy
     */
    private function checkContentSecurityPolicy(): void
    {
        // Prüfe ob Backend-CSP in der Upkeep-Konfiguration aktiviert ist
        $cspEnabled = \rex_addon::get('upkeep')->getConfig('csp_enabled', false);
        
        // Für Backend-only CSP zählt nur die Konfiguration
        $score = $cspEnabled ? 10 : 0;
        $status = $cspEnabled ? 'success' : 'info';

        $recommendations = [];
        if (!$cspEnabled) {
            $recommendations[] = 'Aktivieren Sie Content Security Policy für das Backend';
            $recommendations[] = 'CSP schützt das Backend vor XSS-Angriffen';
        }

        $this->results['checks']['content_security_policy'] = [
            'name' => $this->addon->i18n('upkeep_check_content_security_policy'),
            'status' => $status,
            'severity' => 'medium',
            'score' => $score,
            'details' => [
                'backend_csp_enabled' => $cspEnabled,
                'generated_csp' => $cspEnabled ? self::generateCSPHeader() : null,
                'scope' => 'Backend only - protects admin area'
            ],
            'recommendations' => $recommendations,
            'description' => 'CSP schützt das REDAXO Backend vor XSS und Code-Injection-Angriffen.'
        ];
    }

    /**
     * Prüft Passwort-Richtlinien
     */
    private function checkPasswordPolicies(): void
    {
        // Diese Prüfung ist begrenzt, da wir nicht in User-Passwörter schauen können
        $score = 5; // Neutral, da nicht vollständig prüfbar
        $recommendations = [
            'Starke Passwort-Richtlinien für alle Benutzer durchsetzen',
            'Zwei-Faktor-Authentifizierung implementieren',
            'Regelmäßige Passwort-Updates verlangen'
        ];

        $this->results['checks']['password_policies'] = [
            'name' => $this->addon->i18n('upkeep_check_password_policies'),
            'status' => 'info',
            'severity' => 'medium',
            'score' => $score,
            'details' => [
                'note' => 'Automatische Prüfung nicht vollständig möglich',
                'admin_users' => $this->countAdminUsers()
            ],
            'recommendations' => $recommendations,
            'description' => 'Starke Passwörter sind essentiell für die Sicherheit.'
        ];
    }

    /**
     * Prüft Session-Sicherheit
     */
    private function checkSessionSecurity(): void
    {
        $issues = [];
        $score = 10;

        // Session-Konfiguration prüfen
        if (!ini_get('session.cookie_httponly')) {
            $issues[] = 'Session-Cookies sind nicht HTTP-only';
            $score -= 2;
        }

        if (!ini_get('session.cookie_secure') && $this->isHttps()) {
            $issues[] = 'Session-Cookies sind nicht als secure markiert';
            $score -= 2;
        }

        if (ini_get('session.use_strict_mode') !== '1') {
            $issues[] = 'Session Strict Mode nicht aktiviert';
            $score -= 1;
        }

        $status = empty($issues) ? 'success' : ($score > 6 ? 'warning' : 'error');

        $this->results['checks']['session_security'] = [
            'name' => $this->addon->i18n('upkeep_check_session_security'),
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'cookie_httponly' => ini_get('session.cookie_httponly'),
                'cookie_secure' => ini_get('session.cookie_secure'),
                'use_strict_mode' => ini_get('session.use_strict_mode'),
                'issues' => $issues
            ],
            'recommendations' => $this->getSessionRecommendations($issues),
            'description' => $this->addon->i18n('upkeep_session_security_description')
        ];
    }

    /**
     * Prüft kritische Dateiberechtigungen
     */
    public function checkFilePermissions(): array
    {
        $criticalFiles = [
            rex_path::coreData('config.yml') => 600,
            rex_path::addon('upkeep', 'config.yml') => 600
        ];

        $issues = [];
        $score = 10;

        foreach ($criticalFiles as $file => $expectedPerms) {
            if (file_exists($file)) {
                $currentPerms = fileperms($file) & 0777;
                if ($currentPerms > $expectedPerms) {
                    $issues[] = $this->addon->i18n('upkeep_file_permissions_critical_too_open', basename($file), sprintf('%o', $currentPerms), sprintf('%o', $expectedPerms));
                    $score -= 3;
                }
            }
        }

        $status = empty($issues) ? 'success' : 'error';

        // Dashboard-kompatible Rückgabe
        $dashboardStatus = empty($issues) ? 'secure' : 'warning';
        $dashboardMessage = empty($issues) ? 'Dateiberechtigungen korrekt' : implode(', ', array_slice($issues, 0, 2));
        
        // Speichere auch im internen Format
        $this->results['checks']['file_permissions'] = [
            'name' => $this->addon->i18n('upkeep_check_file_permissions'),
            'status' => $status,
            'severity' => 'high',
            'score' => max(0, $score),
            'details' => [
                'checked_files' => array_keys($criticalFiles),
                'issues' => $issues
            ],
            'recommendations' => $this->getFilePermissionRecommendations(),
            'description' => $this->addon->i18n('upkeep_file_permissions_critical_description')
        ];
        
        // Dashboard-Format zurückgeben
        return [
            'status' => $dashboardStatus,
            'message' => $dashboardMessage,
            'issues' => $issues
        ];
    }

    /**
     * Berechnet die Gesamtsicherheitsbewertung
     */
    private function calculateSecurityScore(): void
    {
        $totalScore = 0;
        $maxScore = 0;
        $criticalIssues = 0;
        $warningIssues = 0;

        foreach ($this->results['checks'] as $check) {
            $weight = $this->getSeverityWeight($check['severity']);
            $totalScore += $check['score'] * $weight;
            $maxScore += 10 * $weight;

            if ($check['status'] === 'error') {
                $criticalIssues++;
            } elseif ($check['status'] === 'warning') {
                $warningIssues++;
            }
        }

        $percentage = $maxScore > 0 ? round(($totalScore / $maxScore) * 100) : 0;

        $this->results['summary'] = [
            'score' => $percentage,
            'grade' => $this->getSecurityGrade($percentage),
            'total_checks' => count($this->results['checks']),
            'critical_issues' => $criticalIssues,
            'warning_issues' => $warningIssues,
            'status' => $this->getOverallStatus($percentage, $criticalIssues)
        ];
    }

    // Helper-Methoden

    private function getCurrentHeaders(): array
    {
        $headers = [];
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
        } else {
            // Fallback für CLI/Test-Umgebungen
            foreach ($_SERVER as $key => $value) {
                if (strpos($key, 'HTTP_') === 0) {
                    $header = str_replace('_', '-', substr($key, 5));
                    $headers[$header] = $value;
                }
            }
        }
        return $headers;
    }

    private function isHttps(): bool
    {
        // Standard HTTPS-Checks
        if ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
            (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')) {
            return true;
        }
        
        // Port-basierte Erkennung (auch für localhost:8443)
        $port = $_SERVER['SERVER_PORT'] ?? 80;
        if ($port == 443 || $port == 8443) {
            return true;
        }
        
        // REDAXO rex::getServer() Methode als Fallback
        $serverUrl = \rex::getServer();
        if (strpos($serverUrl, 'https://') === 0) {
            return true;
        }
        
        // REQUEST_SCHEME prüfen (moderne Server)
        if (!empty($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME'] === 'https') {
            return true;
        }
        
        return false;
    }

    private function countAdminUsers(): int
    {
        $sql = rex_sql::factory();
        $sql->setQuery('SELECT COUNT(*) as count FROM rex_user WHERE admin = 1');
        return (int) $sql->getValue('count');
    }

    private function getSeverityWeight(string $severity): float
    {
        return match($severity) {
            'high' => 1.5,
            'medium' => 1.0,
            'low' => 0.5,
            default => 1.0
        };
    }

    private function getSecurityGrade(int $percentage): string
    {
        return match(true) {
            $percentage >= 90 => 'A+',
            $percentage >= 80 => 'A',
            $percentage >= 70 => 'B',
            $percentage >= 60 => 'C',
            $percentage >= 50 => 'D',
            default => 'F'
        };
    }

    private function getOverallStatus(int $percentage, int $criticalIssues): string
    {
        if ($criticalIssues > 0) {
            return 'error';
        }
        return $percentage >= 70 ? 'success' : 'warning';
    }

    // Empfehlungsmethoden

    private function getLiveModeRecommendations(bool $isDebugOff, bool $liveMode, bool $setup): array
    {
        $recommendations = [];
        if (!$isDebugOff) {
            $recommendations[] = 'Debug-Modus in der config.yml deaktivieren';
        }
        if (!$liveMode) {
            $recommendations[] = 'Live-Mode in der config.yml aktivieren (live_mode: true)';
        }
        if ($setup) {
            $recommendations[] = 'Setup-Modus beenden durch Löschen der setup-Flag';
        }
        return $recommendations;
    }



    private function getHeaderRecommendations(array $issues): array
    {
        $recommendations = [
            'Server-Header in Webserver-Konfiguration anpassen',
            'X-Powered-By Header durch expose_php=Off deaktivieren',
            'Sicherheits-Header in .htaccess oder Webserver-Konfiguration hinzufügen'
        ];
        return $recommendations;
    }

    private function getEmailSecurityRecommendations(string $mailerMethod): array
    {
        $recommendations = [];
        
        switch ($mailerMethod) {
            case 'mail':
                $recommendations[] = 'PHPMailer: Von mail() auf SMTP umstellen';
                $recommendations[] = 'SMTP bietet bessere Sicherheit und Zustellbarkeit';
                $recommendations[] = 'Header-Injection-Angriffe werden durch SMTP verhindert';
                break;
                
            case 'smtp':
                $phpmailerAddon = rex_addon::get('phpmailer');
                $smtpSecure = $phpmailerAddon->getConfig('smtpsecure', 'none');
                
                if ($smtpSecure === 'tls' || $smtpSecure === 'ssl') {
                    $recommendations[] = 'SMTP-Verschlüsselung explizit konfiguriert - optimale Sicherheit';
                    $recommendations[] = 'Sichere E-Mail-Anbieter: Gmail, Microsoft 365/Outlook, Mailgun, SendGrid empfohlen';
                } else {
                    // Leere smtpsecure bedeutet AutoTLS oder keine Verschlüsselung
                    $securityMode = $phpmailerAddon->getConfig('security_mode', true);
                    if ($securityMode) {
                        $recommendations[] = 'AutoTLS durch manuelle TLS/SSL-Konfiguration ersetzen';
                        $recommendations[] = 'PHPMailer: SMTPSecure explizit auf "tls" (Port 587) oder "ssl" (Port 465) setzen';
                        $recommendations[] = 'Manuelle Konfiguration verhindert Fallback auf unverschlüsselte Verbindung';
                    } else {
                        $recommendations[] = 'SMTP-Verschlüsselung aktivieren: TLS (Port 587) oder SSL (Port 465)';
                        $recommendations[] = 'PHPMailer: SMTPSecure auf "tls" oder "ssl" setzen';
                    }
                }
                break;
                
            case 'microsoft365':
                $recommendations[] = 'Microsoft 365 Graph API optimal konfiguriert - modernste E-Mail-Sicherheit';
                $recommendations[] = 'OAuth2-Authentifizierung bietet höchste Sicherheit ohne Passwort-Speicherung';
                break;
                
            case 'sendmail':
                $recommendations[] = 'Auf SMTP mit TLS umstellen für bessere Sicherheit und Zustellbarkeit';
                $recommendations[] = 'PHPMailer-AddOn: Mailer auf "smtp" umstellen';
                $recommendations[] = 'SMTP-Server konfigurieren (z.B. Gmail: smtp.gmail.com:587 oder Microsoft 365: smtp.office365.com:587 mit TLS)';
                break;
                
            case 'mail':
                $recommendations[] = 'PHP mail() nicht mehr verwenden - sehr unsicher und unzuverlässig';
                $recommendations[] = 'Sofort auf SMTP mit TLS umstellen';
                $recommendations[] = 'Sichere Anbieter: Gmail SMTP, Microsoft 365, oder professionelle E-Mail-Services';
                break;
                
            case 'unknown':
            default:
                $recommendations[] = 'PHPMailer-AddOn installieren und konfigurieren';
                $recommendations[] = 'SMTP mit TLS/SSL-Verschlüsselung einrichten';
                $recommendations[] = 'Empfohlene Konfiguration: SMTP, Port 587, TLS, mit Authentifizierung';
                break;
        }
        
        // Allgemeine Empfehlungen
        $recommendations[] = 'SMTP-Authentifizierung aktivieren';
        $recommendations[] = 'Regelmäßig E-Mail-Zustellbarkeit testen';
        
        return $recommendations;
    }

    private function getRedaxoVersionRecommendations(bool $updateAvailable, bool $isUnstable, ?string $latestVersion): array
    {
        $recommendations = [];
        
        if ($updateAvailable && $latestVersion) {
            $currentVersion = rex::getVersion();
            $versionDiff = $this->getVersionAge($currentVersion, $latestVersion);
            
            if ($versionDiff['major'] > 0) {
                $recommendations[] = "Kritisches Update auf REDAXO {$latestVersion} sofort durchführen";
                $recommendations[] = 'Major-Updates enthalten wichtige Sicherheitsupdates und neue Features';
                $recommendations[] = 'Backup vor Update erstellen und auf Testumgebung testen';
                $recommendations[] = 'System → Core-Update verwenden oder manuell über redaxo.org';
            } elseif ($versionDiff['minor'] > 1) {
                $recommendations[] = "Update auf REDAXO {$latestVersion} zeitnah durchführen";
                $recommendations[] = 'Minor-Updates enthalten Sicherheitsfixes und Bugfixes';
                $recommendations[] = 'Regelmäßige Updates halten das System sicher';
            } elseif ($versionDiff['minor'] > 0 || $versionDiff['patch'] > 0) {
                $recommendations[] = "Update auf REDAXO {$latestVersion} empfohlen";
                $recommendations[] = 'Aktuelle Patches enthalten wichtige Sicherheitsfixes';
            }
        }
        
        if ($isUnstable) {
            $recommendations[] = 'Auf stabile REDAXO-Version wechseln für Produktionsserver';
            $recommendations[] = 'Entwicklungsversionen nur für Test- und Entwicklungsumgebungen verwenden';
            $recommendations[] = 'Stabile Version von redaxo.org herunterladen';
        }
        
        if (!rex_addon::get('install')->isAvailable()) {
            $recommendations[] = 'Installer-AddOn aktivieren für einfache Updates';
            $recommendations[] = 'Automatische Update-Benachrichtigungen über Installer-AddOn';
        }
        
        // Allgemeine Empfehlungen
        $recommendations[] = 'Regelmäßig auf Updates prüfen (mindestens monatlich)';
        $recommendations[] = 'Update-Benachrichtigungen von REDAXO abonnieren';
        $recommendations[] = 'Vor Updates immer Backup erstellen';
        $recommendations[] = 'Updates zuerst auf Testumgebung testen';
        
        return $recommendations;
    }

    private function getPhpConfigRecommendations(array $issues): array
    {
        $recommendationFlags = [
            'eval_detected' => false,
            'system_functions_detected' => false,
            'display_errors_detected' => false,
            'expose_php_detected' => false,
            'allow_url_fopen_detected' => false,
            'allow_url_include_detected' => false,
            'memory_limit_high' => false,
            'upload_limit_high' => false,
            'post_limit_high' => false,
            'unlimited_detected' => false
        ];
        
        // Flags setzen basierend auf Issues
        foreach ($issues as $issue) {
            if (strpos($issue, 'Kritisch unsichere Funktion aktiviert: eval') !== false) {
                $recommendationFlags['eval_detected'] = true;
            }
            elseif (strpos($issue, 'Potentiell unsichere Funktion aktiviert') !== false) {
                $recommendationFlags['system_functions_detected'] = true;
            }
            elseif (strpos($issue, 'Fehlermeldungen werden angezeigt') !== false) {
                $recommendationFlags['display_errors_detected'] = true;
            }
            elseif (strpos($issue, 'PHP-Version wird preisgegeben') !== false) {
                $recommendationFlags['expose_php_detected'] = true;
            }
            elseif (strpos($issue, 'Remote URL-Includes sind erlaubt (SSRF-Risiko)') !== false) {
                $recommendationFlags['allow_url_fopen_detected'] = true;
            }
            elseif (strpos($issue, 'Remote URL-Includes sind erlaubt (RCE-Risiko)') !== false) {
                $recommendationFlags['allow_url_include_detected'] = true;
            }
            elseif (strpos($issue, 'Memory Limit sehr hoch') !== false) {
                $recommendationFlags['memory_limit_high'] = true;
            }
            elseif (strpos($issue, 'Upload max filesize sehr hoch') !== false) {
                $recommendationFlags['upload_limit_high'] = true;
            }
            elseif (strpos($issue, 'Post max size sehr hoch') !== false) {
                $recommendationFlags['post_limit_high'] = true;
            }
            elseif (strpos($issue, 'unbegrenzt') !== false) {
                $recommendationFlags['unlimited_detected'] = true;
            }
        }
        
        // Deduplizierte Empfehlungen generieren
        $recommendations = [];
        
        if ($recommendationFlags['eval_detected']) {
            $recommendations[] = 'eval() Funktion in php.ini deaktivieren (disable_functions=eval)';
        }
        if ($recommendationFlags['system_functions_detected']) {
            $recommendations[] = 'System-Funktionen nur deaktivieren wenn nicht für REDAXO/AddOns benötigt (exec, system für ffmpeg/imagemagick)';
        }
        if ($recommendationFlags['display_errors_detected']) {
            $recommendations[] = 'display_errors=Off in php.ini setzen';
        }
        if ($recommendationFlags['expose_php_detected']) {
            $recommendations[] = 'expose_php=Off in php.ini setzen';
        }
        if ($recommendationFlags['allow_url_fopen_detected']) {
            $recommendations[] = 'allow_url_fopen=Off in php.ini setzen';
        }
        if ($recommendationFlags['allow_url_include_detected']) {
            $recommendations[] = 'allow_url_include=Off in php.ini setzen';
        }
        if ($recommendationFlags['memory_limit_high']) {
            $recommendations[] = 'Memory Limit auf vernünftigen Wert reduzieren (z.B. 256M)';
        }
        if ($recommendationFlags['upload_limit_high']) {
            $recommendations[] = 'Upload-Limits reduzieren falls nicht benötigt';
        }
        if ($recommendationFlags['post_limit_high']) {
            $recommendations[] = 'POST-Limits reduzieren falls nicht benötigt';
        }
        if ($recommendationFlags['unlimited_detected']) {
            $recommendations[] = 'Unbegrenzte Limits sofort begrenzen (kritisches Sicherheitsrisiko)';
        }
        
        // Fallback falls keine spezifischen Empfehlungen gefunden
        if (empty($recommendations)) {
        $recommendations[] = $this->addon->i18n('upkeep_php_config_already_secure');
        }
        
        return $recommendations;
    }

    private function getPermissionRecommendations(): array
    {
        return [
            'Verzeichnisberechtigungen auf 755 oder restriktiver setzen',
            'Regelmäßige Überprüfung der Dateisystem-Berechtigungen',
            'Webserver-Benutzer mit minimalen Rechten betreiben'
        ];
    }

    private function getDatabaseRecommendations(array $issues): array
    {
        return [
            'Starkes, zufälliges Datenbank-Passwort verwenden',
            'Spezifischen Datenbank-Benutzer statt root verwenden',
            'Datenbank-Zugriff auf localhost beschränken',
            'Regelmäßige Datenbank-Backups erstellen'
        ];
    }

    private function getSessionRecommendations(array $issues): array
    {
        return [
            'session.cookie_httponly=1 in php.ini setzen',
            'session.cookie_secure=1 für HTTPS-Sites',
            'session.use_strict_mode=1 aktivieren',
            'Kurze Session-Timeouts konfigurieren'
        ];
    }

    private function getFilePermissionRecommendations(): array
    {
        return [
            'Kritische Konfigurationsdateien auf 600 setzen',
            'Regelmäßige Überprüfung der Dateiberechtigungen',
            'Automatisierte Berechtigungsprüfung einrichten'
        ];
    }

    /**
     * Prüft HTTPS-Konfiguration und HSTS
     */
    private function checkHSTS(): void
    {
        $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));
        
        // 1. Aktuelle Verbindung prüfen
        $currentlyHttps = $this->isHttps();
        
        // 2. REDAXO HTTPS-Konfiguration prüfen
        $httpsBackend = ($config['use_https'] ?? false) === true;
        $httpsFrontend = ($config['use_https'] ?? false) === 'frontend' || ($config['use_https'] ?? false) === true;
        
        // 3. HSTS-Konfiguration
        $hstsEnabled = $config['use_hsts'] ?? false;
        $hstsMaxAge = $config['hsts_max_age'] ?? 0;
        
        $recommendations = [];
        $issues = [];
        
        // Bewertung nur basierend auf HTTPS (HSTS ist optional/informativ)
        if (!$currentlyHttps) {
            $score = 0;
            $status = 'error';
            $issues[] = 'Keine HTTPS-Verbindung';
            $recommendations[] = 'SSL-Zertifikat installieren und HTTPS aktivieren';
        } elseif ($currentlyHttps && !$httpsBackend && !$httpsFrontend) {
            $score = 5;
            $status = 'warning';
            $issues[] = 'HTTPS in REDAXO config.yml nicht aktiviert';
            $recommendations[] = 'HTTPS in der REDAXO-Konfiguration aktivieren';
        } elseif ($currentlyHttps && ($httpsBackend || $httpsFrontend)) {
            $score = 10;
            $status = 'success';
            if (!$hstsEnabled) {
                $recommendations[] = 'HSTS für zusätzliche Sicherheit aktivieren (optional)';
            } elseif ($hstsMaxAge < 31536000) {
                $recommendations[] = 'HSTS max-age auf 1 Jahr erhöhen (empfohlen)';
            } else {
                $recommendations[] = 'HTTPS vollständig konfiguriert, HSTS optimal eingestellt';
            }
        } else {
            $score = 0;
            $status = 'error';
            $issues[] = 'HTTPS-Konfiguration unvollständig';
        }

        $this->results['checks']['hsts'] = [
            'name' => $this->addon->i18n('upkeep_check_https_hsts'),
            'status' => $status,
            'severity' => 'high',
            'score' => $score,
            'details' => [
                'current_connection' => [
                    'is_https' => $currentlyHttps,
                    'protocol' => $currentlyHttps ? 'HTTPS' : 'HTTP',
                    'port' => $_SERVER['SERVER_PORT'] ?? 'unbekannt'
                ],
                'redaxo_config' => [
                    'use_https' => $config['use_https'] ?? false,
                    'backend_https' => $httpsBackend,
                    'frontend_https' => $httpsFrontend
                ],
                'hsts_config' => [
                    'enabled' => $hstsEnabled,
                    'max_age' => $hstsMaxAge,
                    'max_age_years' => $hstsMaxAge > 0 ? round($hstsMaxAge / 31536000, 1) : 0
                ],
                'issues' => $issues,
                'https_ready_for_hsts' => $currentlyHttps && ($httpsBackend || $httpsFrontend)
            ],
            'recommendations' => $this->getHttpsHstsRecommendations($currentlyHttps, $httpsBackend, $httpsFrontend, $hstsEnabled, $hstsMaxAge),
            'description' => $this->addon->i18n('upkeep_https_hsts_description')
        ];
    }

    public function enableHttpsBackend(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_https_ssl_required')
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HTTPS für Backend aktivieren
            $config['use_https'] = true;

            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_https_backend_enabled');
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                // Cache leeren
                rex_delete_cache();
            } else {
                $result['message'] = $this->addon->i18n('upkeep_https_config_error');
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Aktiviert HTTPS für Frontend in der config.yml
     */
    public function enableHttpsFrontend(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_https_ssl_required')
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HTTPS für Frontend aktivieren
            $config['use_https'] = 'frontend';

            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_https_frontend_enabled');
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                // Cache leeren
                rex_delete_cache();
            } else {
                $result['message'] = $this->addon->i18n('upkeep_https_config_error');
            }
        } catch (Exception $e) {
            $result['message'] = $this->addon->i18n('upkeep_https_activation_error', $e->getMessage());
        }

        return $result;
    }

    /**
     * Aktiviert HTTPS für Backend und Frontend
     */
    public function enableHttpsBoth(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_https_ssl_required')
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HTTPS für beide aktivieren
            $config['use_https'] = true;

            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_https_both_enabled');
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                // Cache leeren
                rex_delete_cache();
            } else {
                $result['message'] = $this->addon->i18n('upkeep_https_config_error');
            }
        } catch (Exception $e) {
            $result['message'] = $this->addon->i18n('upkeep_https_activation_error', $e->getMessage());
        }

        return $result;
    }

    public function enableHSTS(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_hsts_warning')
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HSTS-Einstellungen setzen
            $config['use_hsts'] = true;
            $config['hsts_max_age'] = 31536000; // 1 Jahr (Standard)

            // Config.yml speichern
            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_hsts_enabled');
                $result['backup'] = 'Backup: ' . basename($backupPath);
            } else {
                $result['message'] = $this->addon->i18n('upkeep_hsts_config_error');
            }
        } catch (Exception $e) {
            $result['message'] = $this->addon->i18n('upkeep_hsts_activation_error', $e->getMessage());
        }

        return $result;
    }

    /**
     * Deaktiviert HTTP Strict Transport Security (HSTS)
     * WARNUNG: Browser können HSTS-Policy noch lange Zeit cachen!
     */
    public function disableHSTS(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_hsts_disable_warning')
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HSTS deaktivieren
            $config['use_hsts'] = false;
            // max_age auf 0 setzen um Browser mitzuteilen, dass HSTS deaktiviert wurde
            $config['hsts_max_age'] = 0;

            // Config.yml speichern
            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_hsts_disabled');
                $result['backup'] = 'Backup: ' . basename($backupPath);
            } else {
                $result['message'] = $this->addon->i18n('upkeep_hsts_config_error');
            }
        } catch (Exception $e) {
            $result['message'] = $this->addon->i18n('upkeep_hsts_deactivation_error', $e->getMessage());
        }

        return $result;
    }

    /**
     * Aktiviert Session-Sicherheitseinstellungen durch Anpassung der config.yml
     * Konfiguriert sichere Session-Parameter für das REDAXO Backend
     */
    public function enableSessionSecurity(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => $this->addon->i18n('upkeep_session_security_config_warning'),
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // Sicherstellen dass session.backend existiert
            if (!isset($config['session'])) {
                $config['session'] = [];
            }
            if (!isset($config['session']['backend'])) {
                $config['session']['backend'] = [];
            }
            if (!isset($config['session']['backend']['cookie'])) {
                $config['session']['backend']['cookie'] = [];
            }

            // Backend-Cookie-Sicherheitseinstellungen setzen
            $config['session']['backend']['cookie']['httponly'] = true;
            $config['session']['backend']['cookie']['secure'] = $this->isHttps();
            $config['session']['backend']['cookie']['samesite'] = 'Lax';

            // Config.yml speichern
            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = $this->addon->i18n('upkeep_session_security_enabled');
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                if ($this->isHttps()) {
                    $result['message'] .= $this->addon->i18n('upkeep_session_security_secure_true');
                } else {
                    $result['message'] .= $this->addon->i18n('upkeep_session_security_secure_false');
                }
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml. Überprüfen Sie die Dateiberechtigungen.';
            }
        } catch (Exception $e) {
            $result['message'] = $this->addon->i18n('upkeep_session_security_activation_error', $e->getMessage());
        }

        return $result;
    }

    private function getHttpsHstsRecommendations($currentlyHttps, $httpsBackend, $httpsFrontend, $hstsEnabled, $hstsMaxAge): array
    {
        $recommendations = [];
        
        // Schritt 1: HTTPS-Verbindung
        if (!$currentlyHttps) {
            $recommendations[] = $this->addon->i18n('upkeep_https_step1_activate');
            $recommendations[] = $this->addon->i18n('upkeep_https_ssl_certificate');
            $recommendations[] = $this->addon->i18n('upkeep_https_modern_requirement');
        }
        
        // Schritt 2: REDAXO HTTPS-Konfiguration
        if ($currentlyHttps && !$httpsBackend && !$httpsFrontend) {
            $recommendations[] = $this->addon->i18n('upkeep_https_step2_redaxo_config');
            $recommendations[] = $this->addon->i18n('upkeep_https_backend_config');
            $recommendations[] = $this->addon->i18n('upkeep_https_frontend_config');
            $recommendations[] = $this->addon->i18n('upkeep_https_cache_clear');
        }
        
        // Schritt 3: HSTS (nur wenn HTTPS läuft)
        if ($currentlyHttps && ($httpsBackend || $httpsFrontend)) {
            if (!$hstsEnabled) {
                $recommendations[] = $this->addon->i18n('upkeep_hsts_step3_activate');
                $recommendations[] = $this->addon->i18n('upkeep_hsts_browser_force');
                $recommendations[] = $this->addon->i18n('upkeep_hsts_irreversible_warning');
                $recommendations[] = $this->addon->i18n('upkeep_hsts_config_example');
            } elseif ($hstsMaxAge < 31536000) {
                $recommendations[] = $this->addon->i18n('upkeep_hsts_increase_max_age');
                $recommendations[] = $this->addon->i18n('upkeep_hsts_longer_cache_better');
            } else {
                $recommendations[] = $this->addon->i18n('upkeep_https_hsts_optimal');
            }
        }
        
        // Allgemeine Hinweise
        $recommendations[] = $this->addon->i18n('upkeep_https_hsts_general_info');
        $recommendations[] = $this->addon->i18n('upkeep_https_ssl_provider_help');
        
        return $recommendations;
    }

    /**
     * Gibt Dashboard-Statistiken zurück
     */
    public function getDashboardStats(): array
    {
        $results = $this->runAllChecks();
        
        return [
            'security_score' => $results['summary']['score'],
            'security_grade' => $results['summary']['grade'],
            'critical_issues' => $results['summary']['critical_issues'],
            'warning_issues' => $results['summary']['warning_issues'],
            'last_check' => $results['timestamp'],
            'overall_status' => $results['summary']['status']
        ];
    }

    /**
     * Prüft System-Versionen (PHP, MySQL/MariaDB) mit REDAXO Setup-Checks
     */
    private function checkSystemVersions(): void
    {
        $allIssues = [];
        $status = 'success';
        $totalScore = 10;
        
        // PHP-Sicherheitsprüfungen aus REDAXO Setup
        $phpSecurityIssues = \rex_setup::checkPhpSecurity();
        if (!empty($phpSecurityIssues)) {
            $allIssues = array_merge($allIssues, $phpSecurityIssues);
            $status = 'error';
            $totalScore = 0;
        }
        
        // PHP-Umgebungsprüfungen (Extensions, etc.)
        $envErrors = \rex_setup::checkEnvironment();
        if (!empty($envErrors)) {
            $allIssues = array_merge($allIssues, $envErrors);
            $status = 'error';
            $totalScore = 0;
        }
        
        // Datenbank-Sicherheitsprüfungen
        try {
            $dbSecurityIssues = \rex_setup::checkDbSecurity();
            if (!empty($dbSecurityIssues)) {
                $allIssues = array_merge($allIssues, $dbSecurityIssues);
                if ($status !== 'error') {
                    $status = 'warning';
                    $totalScore = 5;
                }
            }
        } catch (Exception $e) {
            $allIssues[] = $this->addon->i18n('upkeep_database_version_check_failed', $e->getMessage());
            $status = 'error';
            $totalScore = 0;
        }

        if (empty($allIssues)) {
            $allIssues[] = $this->addon->i18n('upkeep_system_versions_current_supported');
        }

        $this->results['checks']['system_versions'] = [
            'name' => $this->addon->i18n('upkeep_check_system_versions'),
            'status' => $status,
            'severity' => 'high',
            'score' => $totalScore,
            'details' => [
                'php_version' => PHP_VERSION,
                'php_min_version' => \rex_setup::MIN_PHP_VERSION,
                'php_extensions' => \rex_setup::MIN_PHP_EXTENSIONS,
                'mysql_min_version' => \rex_setup::MIN_MYSQL_VERSION,
                'mariadb_min_version' => \rex_setup::MIN_MARIADB_VERSION,
                'php_security_issues' => $phpSecurityIssues,
                'environment_errors' => $envErrors,
                'db_security_issues' => isset($dbSecurityIssues) ? $dbSecurityIssues : []
            ],
            'recommendations' => $allIssues,
            'description' => $this->addon->i18n('upkeep_system_versions_description')
        ];
    }

    /**
     * Prüft Webserver-Version auf EOL-Status
     */
    private function checkWebserverVersion(): void
    {
        $serverSoftware = $_SERVER['SERVER_SOFTWARE'] ?? 'unbekannt';
        $issues = [];
        $warnings = [];
        $score = 10;
        $status = 'success';
        
        // Server-Software analysieren
        $serverInfo = [
            'software' => $serverSoftware,
            'type' => 'unbekannt',
            'version' => 'unbekannt',
            'eol_status' => 'unbekannt'
        ];
        
        // Apache Version prüfen
        if (preg_match('/Apache\/([0-9\.]+)/i', $serverSoftware, $matches)) {
            $serverInfo['type'] = 'Apache';
            $serverInfo['version'] = $matches[1];
            
            // Apache EOL-Daten (vereinfacht)
            $apacheEol = [
                '2.2' => '2017-07-01',
                '2.4.0' => '2021-06-01', // Beispiel für ältere 2.4.x Versionen
            ];
            
            $majorMinor = preg_replace('/^(\d+\.\d+)\..*/', '$1', $serverInfo['version']);
            if (version_compare($serverInfo['version'], '2.4.0', '<')) {
                $issues[] = $this->addon->i18n('upkeep_apache_eol', $serverInfo['version']);
                $serverInfo['eol_status'] = 'EOL';
                $score = 0;
                $status = 'error';
            } elseif (version_compare($serverInfo['version'], '2.4.10', '<')) {
                $warnings[] = $this->addon->i18n('upkeep_apache_very_old_update_recommended', $serverInfo['version']);
                $serverInfo['eol_status'] = 'alt';
                $score = 5;
                $status = 'warning';
            } else {
                $serverInfo['eol_status'] = 'aktuell';
            }
        }
        
        // Nginx Version prüfen
        elseif (preg_match('/nginx\/([0-9\.]+)/i', $serverSoftware, $matches)) {
            $serverInfo['type'] = 'Nginx';
            $serverInfo['version'] = $matches[1];
            
            if (version_compare($serverInfo['version'], '1.20.0', '<')) {
                $warnings[] = $this->addon->i18n('upkeep_nginx_old_update_recommended', $serverInfo['version']);
                $serverInfo['eol_status'] = 'alt';
                $score = 7;
                $status = 'warning';
            } else {
                $serverInfo['eol_status'] = 'aktuell';
            }
        }
        
        // Unbekannter Webserver - das ist SICHER (keine Version preisgegeben)
        else {
            // Prüfen ob überhaupt ein Server-Header vorhanden ist
            if ($serverSoftware === 'unbekannt' || empty($serverSoftware)) {
                // Gar kein Server-Header - perfekt für Sicherheit
                $serverInfo['eol_status'] = 'sicher_versteckt';
                $score = 10;
                $status = 'success';
            } else {
                // Server-Header vorhanden aber ohne Versionsnummer - das ist gut
                $serverInfo['eol_status'] = 'version_versteckt';
                $score = 9;
                $status = 'success';
            }
        }
        
        // Version wird preisgegeben? Nur warnen wenn tatsächlich eine Version sichtbar ist
        $hasVersionInfo = false;
        if (!empty($serverSoftware) && $serverSoftware !== 'unbekannt') {
            // Prüfen ob der Header Versionsnummern enthält (z.B. Apache/2.4.41 oder nginx/1.18.0)
            if (preg_match('/\/[0-9]/', $serverSoftware)) {
                $hasVersionInfo = true;
                $warnings[] = $this->addon->i18n('upkeep_server_header_discloses_version', $serverSoftware);
                $score -= 1;
            }
            // Nur "Apache" oder "nginx" ohne Version ist sicher - keine Warnung
        }
        
        $allIssues = array_merge($issues, $warnings);
        if (empty($allIssues)) {
            $allIssues[] = $this->addon->i18n('upkeep_webserver_config_secure');
        }

        $this->results['checks']['webserver_version'] = [
            'name' => $this->addon->i18n('upkeep_check_webserver_version'),
            'status' => $status,
            'severity' => 'medium',
            'score' => $score,
            'details' => $serverInfo + [
                'server_header' => $serverSoftware,
                'version_disclosed' => $hasVersionInfo,
                'critical_issues' => $issues,
                'warnings' => $warnings
            ],
            'recommendations' => $allIssues,
            'description' => $this->addon->i18n('upkeep_webserver_version_description')
        ];
    }

    /**
     * Prüft REDAXO-spezifische Produktions-Sicherheit
     */
    private function checkProductionMode(): void
    {
        $issues = [];
        $warnings = [];
        $score = 10;
        $status = 'success';
        
        // 1. Setup-Modus noch aktiv?
        $setupEnabled = \rex_setup::isEnabled();
        if ($setupEnabled) {
            $issues[] = $this->addon->i18n('upkeep_setup_mode_active_security_risk');
            $score -= 5;
            $status = 'error';
        }
        
        // 2. Debug-Modus in Produktion
        $debugMode = \rex::isDebugMode();
        if ($debugMode) {
            $issues[] = $this->addon->i18n('upkeep_debug_mode_production_info_leak');
            $score -= 3;
            if ($status !== 'error') {
                $status = 'error';
            }
        }
        
        // 3. Standard-Admin-Login prüfen
        try {
            $sql = \rex_sql::factory();
            $sql->setQuery('SELECT login, password FROM ' . \rex::getTable('user') . ' WHERE login = ?', ['admin']);
            
            if ($sql->getRows() > 0) {
                $passwordHash = $sql->getValue('password');
                // Prüfen ob Standard-Passwort (admin) verwendet wird
                if (password_verify('admin', $passwordHash)) {
                    $issues[] = $this->addon->i18n('upkeep_default_admin_password_used');
                    $score -= 5;
                    $status = 'error';
                } else {
                    // Admin-Account existiert, aber mit anderem Passwort
                    $warnings[] = $this->addon->i18n('upkeep_default_admin_exists_rename');
                    $score -= 1;
                }
            }
        } catch (Exception $e) {
            $warnings[] = "Benutzer-Prüfung fehlgeschlagen: " . $e->getMessage();
        }
        
        // 4. Leere Passwörter prüfen
        try {
            $sql = \rex_sql::factory();
            $sql->setQuery('SELECT COUNT(*) as count FROM ' . \rex::getTable('user') . ' WHERE password = "" OR password IS NULL');
            $emptyPasswords = $sql->getValue('count');
            
            if ($emptyPasswords > 0) {
                $issues[] = $this->addon->i18n('upkeep_users_without_password', $emptyPasswords);
                $score -= 3;
                if ($status !== 'error') {
                    $status = 'error';
                }
            }
        } catch (Exception $e) {
            $warnings[] = "Passwort-Prüfung fehlgeschlagen: " . $e->getMessage();
        }
        
        // 5. Live-Modus prüfen
        if (!\rex::isLiveMode()) {
            $warnings[] = $this->addon->i18n('upkeep_live_mode_not_active');
            $score -= 1;
            if ($status === 'success') {
                $status = 'warning';
            }
        }
        
        // 6. Backend-Passwort-Policy prüfen
        $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));
        $passwordPolicy = $config['password_policy'] ?? [];
        if (empty($passwordPolicy['length']) || $passwordPolicy['length'] < 8) {
            $warnings[] = $this->addon->i18n('upkeep_no_password_policy_configured');
            $score -= 1;
        }

        // Status final bestimmen
        if (!empty($issues) && $status !== 'error') {
            $status = 'warning';
        } elseif (empty($issues) && empty($warnings)) {
            $status = 'success';
        }
        
        $allIssues = array_merge($issues, $warnings);
        if (empty($allIssues)) {
            $allIssues[] = $this->addon->i18n('upkeep_production_config_secure');
        }

        $this->results['checks']['production_mode'] = [
            'name' => $this->addon->i18n('upkeep_check_production_mode'),
            'status' => $status,
            'severity' => 'high',
            'score' => max(0, $score),
            'details' => [
                'setup_enabled' => $setupEnabled,
                'debug_mode' => $debugMode,
                'live_mode' => \rex::isLiveMode(),
                'admin_user_exists' => isset($sql) && $sql->getRows() > 0,
                'empty_passwords' => $emptyPasswords ?? 0,
                'password_policy' => $passwordPolicy,
                'critical_issues' => $issues,
                'warnings' => $warnings
            ],
            'recommendations' => $allIssues,
            'description' => $this->addon->i18n('upkeep_production_mode_description')
        ];
    }

    /**
     * Konvertiert PHP-Speicherwerte (z.B. "128M", "2G") in Bytes
     */
    private function convertToBytes(string $value): int
    {
        if ($value === '-1') {
            return -1;
        }
        
        $value = trim($value);
        $lastChar = strtolower($value[strlen($value) - 1]);
        $number = (int) $value;
        
        switch ($lastChar) {
            case 'g':
                return $number * 1024 * 1024 * 1024;
            case 'm':
                return $number * 1024 * 1024;
            case 'k':
                return $number * 1024;
            default:
                return $number;
        }
    }

    // =============================================================================
    // PUBLIC DASHBOARD METHODS - For Dashboard Access
    // =============================================================================

    /**
     * System Health Check
     */
    public function checkSystemHealth(): array
    {
        $score = 100;
        $issues = [];
        
        // Memory Check
        if (function_exists('memory_get_usage') && function_exists('ini_get')) {
            $memoryUsage = memory_get_usage(true);
            $memoryLimit = $this->convertToBytes(ini_get('memory_limit'));
            if ($memoryLimit > 0) {
                $memoryPercent = ($memoryUsage / $memoryLimit) * 100;
                if ($memoryPercent > 80) {
                    $score -= 20;
                    $issues[] = $this->addon->i18n('upkeep_high_memory_usage', round($memoryPercent, 1));
                }
            }
        }
        
        // Disk Space Check (simplified)
        if (function_exists('disk_free_space')) {
            $diskFree = \disk_free_space(rex_path::base());
            if ($diskFree !== false && $diskFree < 1024 * 1024 * 100) { // < 100MB
                $score -= 30;
                $issues[] = $this->addon->i18n('upkeep_low_disk_space');
            }
        }
        
        // PHP Version Check
        if (version_compare(PHP_VERSION, '8.0', '<')) {
            $score -= 25;
            $issues[] = $this->addon->i18n('upkeep_outdated_php_version', PHP_VERSION);
        }
        
        $status = $score > 80 ? 'healthy' : ($score > 60 ? 'warning' : 'critical');
        $message = empty($issues) ? $this->addon->i18n('upkeep_system_optimal') : implode(', ', $issues);
        
        return [
            'status' => $status,
            'score' => $score,
            'message' => $message,
            'issues' => $issues
        ];
    }

    /**
     * Database Status Check
     */
    public function checkDatabaseStatus(): array
    {
        try {
            $sql = \rex_sql::factory();
            $sql->setQuery('SELECT VERSION() as version');
            $dbVersion = $sql->getValue('version');
            
            // Test connection and basic query
            $sql->setQuery('SELECT COUNT(*) as count FROM ' . \rex::getTable('article'));
            $articleCount = $sql->getValue('count');
            
            // Datenbankversionsprüfung
            $status = 'healthy';
            $message = $this->addon->i18n('upkeep_database_active');
            
            // Extrahiere Hauptversion (MySQL/MariaDB)
            if (preg_match('/^(\d+\.\d+)/', $dbVersion, $matches)) {
                $majorVersion = $matches[1];
                
                // Prüfe auf veraltete MySQL-Versionen
                if (stripos($dbVersion, 'MariaDB') === false) {
                    // MySQL-Versionsprüfung
                    $unsupportedMysql = ['5.5', '5.6', '5.7'];
                    $deprecatedMysql = ['8.0'];
                    
                    if (in_array($majorVersion, $unsupportedMysql)) {
                        $status = 'critical';
                        $message = $this->addon->i18n('upkeep_database_version_unsupported');
                    } elseif (in_array($majorVersion, $deprecatedMysql)) {
                        $status = 'warning';
                        $message = $this->addon->i18n('upkeep_database_version_deprecated');
                    }
                } else {
                    // MariaDB-Versionsprüfung
                    $unsupportedMariaDB = ['10.0', '10.1', '10.2', '10.3'];
                    $deprecatedMariaDB = ['10.4', '10.5'];
                    
                    if (in_array($majorVersion, $unsupportedMariaDB)) {
                        $status = 'critical';
                        $message = $this->addon->i18n('upkeep_database_version_unsupported');
                    } elseif (in_array($majorVersion, $deprecatedMariaDB)) {
                        $status = 'warning';
                        $message = $this->addon->i18n('upkeep_database_version_deprecated');
                    }
                }
            }
            
            return [
                'status' => $status,
                'message' => $message,
                'version' => $dbVersion,
                'articles' => $articleCount
            ];
        } catch (Exception $e) {
            return [
                'status' => 'error',
                'message' => $this->addon->i18n('upkeep_database_connection_failed'),
                'version' => null,
                'articles' => 0
            ];
        }
    }

    /**
     * Mail Security Status
     */
    public function getMailSecurityStatus(): array
    {
        $active = $this->addon->getConfig('mail_security_active', false);
        
        return [
            'active' => $active,
            'message' => $active ? $this->addon->i18n('upkeep_mail_security_active') : $this->addon->i18n('upkeep_mail_security_inactive')
        ];
    }

    /**
     * PHPMailer Configuration Check
     */
    public function checkPhpMailerConfig(): array
    {
        try {
            $phpmailerAddon = \rex_addon::get('phpmailer');
            if (!$phpmailerAddon->isAvailable()) {
                return [
                    'status' => 'missing',
                    'message' => $this->addon->i18n('upkeep_phpmailer_addon_unavailable')
                ];
            }
            
            $config = $phpmailerAddon->getConfig();
            $mailerMethod = $config['mailer'] ?? 'mail';
            
            // Prüfe spezifisch für mail() Methode
            if ($mailerMethod === 'mail') {
                return [
                    'status' => 'warning',
                    'message' => $this->addon->i18n('upkeep_phpmailer_unsafe_mail_function')
                ];
            }
            
            // Für SMTP prüfe die erforderlichen Konfigurationen
            if ($mailerMethod === 'smtp') {
                $requiredKeys = ['host', 'port', 'smtpsecure', 'smtpauth'];
                $configuredKeys = array_filter($requiredKeys, fn($key) => !empty($config[$key]));
                
                if (count($configuredKeys) === count($requiredKeys)) {
                    $status = 'configured';
                    $message = $this->addon->i18n('upkeep_phpmailer_smtp_fully_configured');
                } elseif (count($configuredKeys) > 0) {
                    $status = 'partial';
                    $message = $this->addon->i18n('upkeep_phpmailer_smtp_partially_configured');
                } else {
                    $status = 'missing';
                    $message = $this->addon->i18n('upkeep_phpmailer_smtp_not_configured');
                }
            } else {
                // Andere Methoden (sendmail, etc.)
                $status = 'configured';
                $message = $this->addon->i18n('upkeep_phpmailer_configured', $mailerMethod);
            }
            
            return [
                'status' => $status,
                'message' => $message,
                'mailer_method' => $mailerMethod
            ];
        } catch (Exception $e) {
            return [
                'status' => 'error',
                'message' => $this->addon->i18n('upkeep_phpmailer_check_failed', $e->getMessage())
            ];
        }
    }

    /**
     * Security Headers Check
     */
    public function checkSecurityHeaders(): array
    {
        // Simplified check - in real implementation would check actual headers
        $headers = [
            'X-Frame-Options' => false,
            'X-Content-Type-Options' => false,
            'X-XSS-Protection' => false
        ];
        
        $secureHeaders = array_filter($headers);
        $status = count($secureHeaders) > 2 ? 'secure' : 'warning';
        $message = count($secureHeaders) > 2 ? $this->addon->i18n('upkeep_security_headers_set') : $this->addon->i18n('upkeep_security_headers_missing');
        
        return [
            'status' => $status,
            'message' => $message,
            'headers' => $headers
        ];
    }

    /**
     * Addon Security Check
     */
    public function checkAddonSecurity(): array
    {
        $addons = \rex_addon::getAvailableAddons();
        $secureAddons = array_filter($addons, function($addon) {
            return $addon->isAvailable();
        });
        
        return [
            'status' => 'secure',
            'message' => $this->addon->i18n('upkeep_addons_installed', count($secureAddons)),
            'addons' => array_keys($secureAddons)
        ];
    }
}