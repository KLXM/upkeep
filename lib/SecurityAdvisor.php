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
            'name' => 'REDAXO Live Mode',
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
            'description' => 'REDAXO sollte im Live-Modus ohne Debug-Ausgaben laufen.'
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
            'warning' => 'WARNUNG: Der Live-Mode kann nur durch manuelle Bearbeitung der config.yml wieder deaktiviert werden!'
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
                $result['message'] = 'Live-Mode erfolgreich aktiviert. Debug-Modus deaktiviert und live_mode: true gesetzt.';
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
            'warning' => 'Backend-CSP schützt nur das REDAXO Backend, nicht das Frontend!'
        ];

        try {
            $addon = \rex_addon::get('upkeep');
            
            // CSP in der Addon-Konfiguration aktivieren
            $addon->setConfig('csp_enabled', true);
            
            $result['success'] = true;
            $result['message'] = 'Backend Content Security Policy wurde aktiviert. Das REDAXO Backend ist jetzt besser geschützt.';
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
            $result['message'] = 'Backend Content Security Policy wurde deaktiviert.';
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
                        $result['errors'][] = 'Zertifikat läuft in weniger als 7 Tagen ab';
                    }
                } else {
                    $result['errors'][] = 'Kein SSL-Zertifikat gefunden';
                }
                
                fclose($stream);
            } else {
                $result['errors'][] = "SSL-Verbindung fehlgeschlagen: {$errstr}";
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
        $issues = [];
        $score = 10;

        // Server-Version verstecken
        if (isset($headers['Server']) && preg_match('/\d+\.\d+/', $headers['Server'])) {
            $issues[] = 'Server-Version wird preisgegeben';
            $score -= 2;
        }

        // PHP-Version verstecken
        if (isset($headers['X-Powered-By'])) {
            $issues[] = 'X-Powered-By Header enthüllt PHP-Version';
            $score -= 2;
        }

        // Sicherheits-Header prüfen
        $securityHeaders = [
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection' => '1; mode=block',
            'Strict-Transport-Security' => null,
            'Referrer-Policy' => null
        ];

        foreach ($securityHeaders as $header => $expectedValue) {
            if (!isset($headers[$header])) {
                $issues[] = "Fehlender Sicherheits-Header: {$header}";
                $score -= 1;
            }
        }

        $status = empty($issues) ? 'success' : ($score > 5 ? 'warning' : 'error');

        $this->results['checks']['server_headers'] = [
            'name' => 'Server Headers',
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'headers' => $headers,
                'issues' => $issues
            ],
            'recommendations' => $this->getHeaderRecommendations($issues),
            'description' => 'Server sollte keine sensiblen Informationen preisgeben und Sicherheits-Header setzen.'
        ];
    }

    /**
     * Prüft PHP-Konfiguration und System-Sicherheitseinstellungen
     */
    private function checkPhpConfiguration(): void
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
        $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
        
        foreach ($potentiallyDangerousFunctions as $func => $severity) {
            if (!in_array($func, $disabled) && function_exists($func)) {
                if ($severity === 'kritisch') {
                    $issues[] = "Kritisch unsichere Funktion aktiviert: {$func} (sollte deaktiviert werden)";
                    $score -= 2;
                } else {
                    $warnings[] = "Potentiell unsichere Funktion aktiviert: {$func} (nur deaktivieren wenn nicht benötigt)";
                    $score -= 0.5;
                }
            }
        }

        // 2. PHP-Grundeinstellungen - korrekte Boolean-Prüfung
        $settings = [
            'display_errors' => ['Off', 'Fehlermeldungen werden angezeigt (Informationsleckage)'],
            'expose_php' => ['Off', 'PHP-Version wird preisgegeben (Information Disclosure)'],
            'allow_url_fopen' => ['Off', 'Remote URL-Includes sind erlaubt (SSRF-Risiko)'],
            'allow_url_include' => ['Off', 'Remote URL-Includes sind erlaubt (RCE-Risiko)'],
            'register_globals' => ['Off', 'Register Globals aktiviert (veraltet/unsicher)']
        ];

        foreach ($settings as $setting => $config) {
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
        $memoryLimit = ini_get('memory_limit');
        $memoryBytes = $this->convertToBytes($memoryLimit);
        if ($memoryBytes > 512 * 1024 * 1024) { // > 512MB
            $warnings[] = "Memory Limit sehr hoch ({$memoryLimit}) - DoS-Risiko";
        } elseif ($memoryBytes === -1) {
            $issues[] = "Memory Limit unbegrenzt (-1) - schwerwiegendes DoS-Risiko";
            $score -= 2;
        }

        // 4. Upload-Limits
        $maxFileSize = ini_get('upload_max_filesize');
        $postMaxSize = ini_get('post_max_size');
        $maxFileSizeBytes = $this->convertToBytes($maxFileSize);
        $postMaxSizeBytes = $this->convertToBytes($postMaxSize);
        
        if ($maxFileSizeBytes > 50 * 1024 * 1024) { // > 50MB
            $warnings[] = "Upload max filesize sehr hoch ({$maxFileSize})";
        }
        if ($postMaxSizeBytes > 100 * 1024 * 1024) { // > 100MB
            $warnings[] = "Post max size sehr hoch ({$postMaxSize})";
        }

        // 5. Open Basedir (Chroot-ähnliche Beschränkung)
        $openBasedir = ini_get('open_basedir');
        if (empty($openBasedir)) {
            $warnings[] = "Open Basedir nicht gesetzt - PHP kann auf ganze Festplatte zugreifen";
        }

        // 6. Error Reporting in Produktion
        $errorReporting = ini_get('error_reporting');
        $logErrors = ini_get('log_errors');
        if ($errorReporting != 0 && ini_get('display_errors') == 'On') {
            $issues[] = "Error Reporting aktiv in Produktion (Informationsleckage)";
            $score -= 1;
        }
        if (!$logErrors) {
            $warnings[] = "Error Logging deaktiviert - Fehler werden nicht protokolliert";
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

        $this->results['checks']['php_configuration'] = [
            'name' => 'PHP & System-Sicherheit',
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
                // Debug: Aktuelle ini-Werte anzeigen
                'display_errors' => ini_get('display_errors') . ' (raw: ' . var_export(ini_get('display_errors'), true) . ')',
                'expose_php' => ini_get('expose_php') . ' (raw: ' . var_export(ini_get('expose_php'), true) . ')',
                'allow_url_fopen' => ini_get('allow_url_fopen') . ' (raw: ' . var_export(ini_get('allow_url_fopen'), true) . ')',
                'allow_url_include' => ini_get('allow_url_include') . ' (raw: ' . var_export(ini_get('allow_url_include'), true) . ')',
                'critical_issues' => $issues,
                'warnings' => $warnings
            ],
            'recommendations' => $this->getPhpConfigRecommendations($allIssues),
            'description' => 'PHP sollte sicher konfiguriert sein mit angemessenen Limits und ohne gefährliche Funktionen.'
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
                    $issues[] = sprintf(
                        'Verzeichnis %s hat zu offene Berechtigungen: %o (empfohlen: %o)',
                        basename($dir),
                        $currentPerms,
                        $expectedPerms
                    );
                    $score -= 2;
                }
            }
        }

        $status = empty($issues) ? 'success' : ($score > 6 ? 'warning' : 'error');

        $this->results['checks']['directory_permissions'] = [
            'name' => 'Verzeichnisberechtigungen',
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'checked_directories' => array_keys($directories),
                'issues' => $issues
            ],
            'recommendations' => $this->getPermissionRecommendations(),
            'description' => 'Verzeichnisse sollten minimale notwendige Berechtigungen haben.'
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
            $issues[] = 'Datenbank-Passwort ist zu kurz (< 8 Zeichen)';
            $score -= 3;
        }

        // Standardbenutzer prüfen
        $username = $dbConfig[1]['login'] ?? '';
        if (in_array($username, ['root', 'admin', 'redaxo'])) {
            $issues[] = 'Standardbenutzername für Datenbank verwendet';
            $score -= 2;
        }

        // Externe Verbindungen
        $host = $dbConfig[1]['host'] ?? '';
        if ($host !== 'localhost' && $host !== '127.0.0.1') {
            $issues[] = 'Datenbank läuft nicht auf localhost - zusätzliche Netzwerksicherheit erforderlich';
            $score -= 1;
        }

        $status = empty($issues) ? 'success' : ($score > 6 ? 'warning' : 'error');

        $this->results['checks']['database_security'] = [
            'name' => 'Datenbank-Sicherheit',
            'status' => $status,
            'severity' => 'high',
            'score' => max(0, $score),
            'details' => [
                'host' => $host,
                'username' => $username,
                'issues' => $issues
            ],
            'recommendations' => $this->getDatabaseRecommendations($issues),
            'description' => 'Datenbank-Zugangsdaten sollten sicher konfiguriert sein.'
        ];
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
            'name' => 'Content Security Policy (Backend)',
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
            'name' => 'Passwort-Richtlinien',
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
            'name' => 'Session-Sicherheit',
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
            'description' => 'Session-Einstellungen sollten sicher konfiguriert sein.'
        ];
    }

    /**
     * Prüft kritische Dateiberechtigungen
     */
    private function checkFilePermissions(): void
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
                    $issues[] = sprintf(
                        'Datei %s hat zu offene Berechtigungen: %o (empfohlen: %o)',
                        basename($file),
                        $currentPerms,
                        $expectedPerms
                    );
                    $score -= 3;
                }
            }
        }

        $status = empty($issues) ? 'success' : 'error';

        $this->results['checks']['file_permissions'] = [
            'name' => 'Dateiberechtigungen',
            'status' => $status,
            'severity' => 'high',
            'score' => max(0, $score),
            'details' => [
                'checked_files' => array_keys($criticalFiles),
                'issues' => $issues
            ],
            'recommendations' => $this->getFilePermissionRecommendations(),
            'description' => 'Kritische Dateien sollten restriktive Berechtigungen haben.'
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
            $recommendations[] = 'PHP-Konfiguration ist bereits sicher konfiguriert';
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
            'name' => 'HTTPS & HSTS',
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
            'description' => 'HTTPS verschlüsselt die Kommunikation und ist für moderne Webanwendungen erforderlich. HSTS wird informativ angezeigt (optional).'
        ];
    }

    /**
     * Aktiviert HTTPS für Backend in der config.yml
     */
    public function enableHttpsBackend(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => 'HTTPS muss auf Server-Ebene verfügbar sein (SSL-Zertifikat)!'
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HTTPS für Backend aktivieren
            $config['use_https'] = true;

            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = 'HTTPS für Backend aktiviert. Cache wird geleert...';
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                // Cache leeren
                rex_delete_cache();
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml.';
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
            'warning' => 'HTTPS muss auf Server-Ebene verfügbar sein (SSL-Zertifikat)!'
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HTTPS für Frontend aktivieren
            $config['use_https'] = 'frontend';

            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = 'HTTPS für Frontend aktiviert. Cache wird geleert...';
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                // Cache leeren
                rex_delete_cache();
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml.';
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler: ' . $e->getMessage();
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
            'warning' => 'HTTPS muss auf Server-Ebene verfügbar sein (SSL-Zertifikat)!'
        ];

        try {
            // Backup erstellen
            $backupPath = $this->backupConfig();
            
            $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));

            // HTTPS für beide aktivieren
            $config['use_https'] = true;

            if (\rex_file::putConfig(\rex_path::coreData('config.yml'), $config)) {
                $result['success'] = true;
                $result['message'] = 'HTTPS für Backend und Frontend aktiviert. Cache wird geleert...';
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                // Cache leeren
                rex_delete_cache();
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml.';
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler: ' . $e->getMessage();
        }

        return $result;
    }

    /**
     * Aktiviert HTTP Strict Transport Security (HSTS)
     */
    public function enableHSTS(): array
    {
        $result = [
            'success' => false,
            'message' => '',
            'warning' => 'HSTS zwingt Browser dauerhaft zu HTTPS. Deaktivierung kann schwierig sein!'
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
                $result['message'] = 'HSTS wurde aktiviert (max-age=31536000 / 1 Jahr). Browser werden ab sofort gezwungen, nur HTTPS zu verwenden.';
                $result['backup'] = 'Backup: ' . basename($backupPath);
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml. Überprüfen Sie die Dateiberechtigungen.';
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler beim Aktivieren von HSTS: ' . $e->getMessage();
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
            'warning' => 'WARNUNG: Browser können die HSTS-Policy noch wochenlang cachen, auch nach der Deaktivierung!'
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
                $result['message'] = 'HSTS wurde deaktiviert (max-age=0). ACHTUNG: Browser können die alte Policy noch wochenlang cachen!';
                $result['backup'] = 'Backup: ' . basename($backupPath);
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml. Überprüfen Sie die Dateiberechtigungen.';
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler beim Deaktivieren von HSTS: ' . $e->getMessage();
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
            'warning' => 'Backend-Session-Einstellungen werden in der REDAXO config.yml konfiguriert und sind sofort aktiv.'
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
                $result['message'] = 'Backend-Session-Sicherheitseinstellungen wurden erfolgreich aktiviert.';
                $result['backup'] = 'Backup: ' . basename($backupPath);
                
                if ($this->isHttps()) {
                    $result['message'] .= ' (secure=true für HTTPS)';
                } else {
                    $result['message'] .= ' (secure=false für HTTP)';
                }
            } else {
                $result['message'] = 'Fehler beim Schreiben der config.yml. Überprüfen Sie die Dateiberechtigungen.';
            }
        } catch (Exception $e) {
            $result['message'] = 'Fehler beim Aktivieren der Session-Sicherheit: ' . $e->getMessage();
        }

        return $result;
    }

    private function getHttpsHstsRecommendations($currentlyHttps, $httpsBackend, $httpsFrontend, $hstsEnabled, $hstsMaxAge): array
    {
        $recommendations = [];
        
        // Schritt 1: HTTPS-Verbindung
        if (!$currentlyHttps) {
            $recommendations[] = '🔒 Schritt 1: Auf HTTPS wechseln (SSL-Zertifikat installieren)';
            $recommendations[] = '📄 SSL/TLS-Zertifikat vom Hosting-Provider oder Let\'s Encrypt';
            $recommendations[] = '⚠️ HTTPS ist Voraussetzung für moderne Webanwendungen';
        }
        
        // Schritt 2: REDAXO HTTPS-Konfiguration
        if ($currentlyHttps && !$httpsBackend && !$httpsFrontend) {
            $recommendations[] = '⚙️ Schritt 2: HTTPS in REDAXO aktivieren';
            $recommendations[] = 'Backend: use_https: true in config.yml setzen';
            $recommendations[] = 'Frontend: use_https: "frontend" für Frontend-HTTPS';
            $recommendations[] = '🔄 Cache leeren nach Konfigurationsänderung';
        }
        
        // Schritt 3: HSTS (nur wenn HTTPS läuft)
        if ($currentlyHttps && ($httpsBackend || $httpsFrontend)) {
            if (!$hstsEnabled) {
                $recommendations[] = '🛡️ Schritt 3: HSTS aktivieren (optional aber empfohlen)';
                $recommendations[] = '💡 HSTS zwingt Browser dauerhaft zu HTTPS';
                $recommendations[] = '⚠️ WARNUNG: HSTS ist schwer rückgängig zu machen!';
                $recommendations[] = 'Aktivierung: use_hsts: true + hsts_max_age: 31536000';
            } elseif ($hstsMaxAge < 31536000) {
                $recommendations[] = '⏰ HSTS max-age auf 1 Jahr erhöhen (31536000 Sekunden)';
                $recommendations[] = 'Längere Cache-Zeit = besserer Schutz';
            } else {
                $recommendations[] = '✅ HTTPS und HSTS sind optimal konfiguriert!';
            }
        }
        
        // Allgemeine Hinweise
        $recommendations[] = '📚 HTTPS verschlüsselt Daten, HSTS verhindert Downgrades';
        $recommendations[] = '🔧 Bei Problemen: SSL-Konfiguration vom Hosting-Provider prüfen';
        
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
            $allIssues[] = 'Datenbank-Versionsprüfung fehlgeschlagen: ' . $e->getMessage();
            $status = 'error';
            $totalScore = 0;
        }

        if (empty($allIssues)) {
            $allIssues[] = 'Alle System-Versionen sind aktuell und werden unterstützt';
        }

        $this->results['checks']['system_versions'] = [
            'name' => 'System-Versionen (PHP/DB)',
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
            'description' => 'System-Versionen sollten aktuell und sicher sein. Nutzt REDAXOs integrierte EOL-Prüfungen.'
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
                $issues[] = "Apache {$serverInfo['version']} ist End-of-Life";
                $serverInfo['eol_status'] = 'EOL';
                $score = 0;
                $status = 'error';
            } elseif (version_compare($serverInfo['version'], '2.4.10', '<')) {
                $warnings[] = "Apache {$serverInfo['version']} ist sehr alt, Update empfohlen";
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
                $warnings[] = "Nginx {$serverInfo['version']} ist alt, Update empfohlen";
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
                $warnings[] = "Server-Header gibt Version preis: {$serverSoftware} (Information Disclosure)";
                $score -= 1;
            }
            // Nur "Apache" oder "nginx" ohne Version ist sicher - keine Warnung
        }
        
        $allIssues = array_merge($issues, $warnings);
        if (empty($allIssues)) {
            $allIssues[] = 'Webserver-Konfiguration erscheint sicher';
        }

        $this->results['checks']['webserver_version'] = [
            'name' => 'Webserver-Version',
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
            'description' => 'Webserver sollte aktuell sein und keine Versionsinformationen preisgeben.'
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
            $issues[] = "REDAXO Setup-Modus ist noch aktiv - schwerwiegendes Sicherheitsrisiko!";
            $score -= 5;
            $status = 'error';
        }
        
        // 2. Debug-Modus in Produktion
        $debugMode = \rex::isDebugMode();
        if ($debugMode) {
            $issues[] = "Debug-Modus in Produktion aktiv - Informationsleckage möglich";
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
                    $issues[] = "Standard-Login admin/admin wird verwendet - kritisches Sicherheitsrisiko!";
                    $score -= 5;
                    $status = 'error';
                } else {
                    // Admin-Account existiert, aber mit anderem Passwort
                    $warnings[] = "Standard-Login 'admin' existiert - sollte umbenannt werden";
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
                $issues[] = "{$emptyPasswords} Benutzer ohne Passwort gefunden";
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
            $warnings[] = "REDAXO nicht im Live-Modus - Performance und Sicherheit können beeinträchtigt sein";
            $score -= 1;
            if ($status === 'success') {
                $status = 'warning';
            }
        }
        
        // 6. Backend-Passwort-Policy prüfen
        $config = \rex_file::getConfig(\rex_path::coreData('config.yml'));
        $passwordPolicy = $config['password_policy'] ?? [];
        if (empty($passwordPolicy['length']) || $passwordPolicy['length'] < 8) {
            $warnings[] = "Keine Passwort-Policy konfiguriert - schwache Passwörter möglich";
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
            $allIssues[] = 'REDAXO-Produktions-Konfiguration ist sicher';
        }

        $this->results['checks']['production_mode'] = [
            'name' => 'REDAXO-Produktionsmodus',
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
            'description' => 'REDAXO sollte sicher für den Produktionsbetrieb konfiguriert sein.'
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
}