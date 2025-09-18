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
        $this->checkSslCertificates();
        $this->checkServerHeaders();
        $this->checkPhpConfiguration();
        $this->checkDirectoryPermissions();
        $this->checkDatabaseSecurity();
        $this->checkContentSecurityPolicy();
        $this->checkPasswordPolicies();
        $this->checkSessionSecurity();
        $this->checkFilePermissions();

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
     * Prüft SSL-Zertifikate aller Domains
     */
    private function checkSslCertificates(): void
    {
        $results = [];
        $overallStatus = 'success';
        $totalScore = 0;

        if (rex_addon::get('yrewrite')->isAvailable()) {
            $domains = rex_yrewrite::getDomains();
            
            foreach ($domains as $domain) {
                $domainName = $domain->getName();
                $sslCheck = $this->checkDomainSsl($domainName);
                $results[$domainName] = $sslCheck;
                
                if ($sslCheck['status'] !== 'success') {
                    $overallStatus = $sslCheck['status'];
                }
                
                $totalScore += $sslCheck['score'];
            }
            
            $averageScore = count($domains) > 0 ? round($totalScore / count($domains)) : 0;
        } else {
            // Fallback: Aktuelle Domain prüfen
            $currentDomain = rex::getServer();
            $sslCheck = $this->checkDomainSsl(parse_url($currentDomain, PHP_URL_HOST));
            $results[parse_url($currentDomain, PHP_URL_HOST)] = $sslCheck;
            $overallStatus = $sslCheck['status'];
            $averageScore = $sslCheck['score'];
        }

        $this->results['checks']['ssl_certificates'] = [
            'name' => 'SSL-Zertifikate',
            'status' => $overallStatus,
            'severity' => 'high',
            'score' => $averageScore,
            'details' => $results,
            'recommendations' => $this->getSslRecommendations($results),
            'description' => 'Alle Domains sollten gültige SSL-Zertifikate verwenden.'
        ];
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
     * Prüft PHP-Konfiguration
     */
    private function checkPhpConfiguration(): void
    {
        $issues = [];
        $score = 10;

        // Gefährliche Funktionen
        $dangerousFunctions = ['eval', 'exec', 'system', 'shell_exec', 'passthru'];
        $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
        
        foreach ($dangerousFunctions as $func) {
            if (!in_array($func, $disabled) && function_exists($func)) {
                $issues[] = "Gefährliche Funktion aktiviert: {$func}";
                $score -= 1;
            }
        }

        // PHP-Einstellungen prüfen
        $settings = [
            'display_errors' => ['Off', 'Fehlermeldungen werden angezeigt'],
            'expose_php' => ['Off', 'PHP-Version wird preisgegeben'],
            'allow_url_fopen' => ['Off', 'URL-Includes sind erlaubt'],
            'allow_url_include' => ['Off', 'URL-Includes sind erlaubt'],
            'register_globals' => ['Off', 'Register Globals aktiviert']
        ];

        foreach ($settings as $setting => $config) {
            $value = ini_get($setting);
            if ($value !== $config[0] && $value !== '' && $value !== false) {
                $issues[] = $config[1];
                $score -= 1;
            }
        }

        $status = empty($issues) ? 'success' : ($score > 7 ? 'warning' : 'error');

        $this->results['checks']['php_configuration'] = [
            'name' => 'PHP-Konfiguration',
            'status' => $status,
            'severity' => 'medium',
            'score' => max(0, $score),
            'details' => [
                'php_version' => PHP_VERSION,
                'disabled_functions' => $disabled,
                'issues' => $issues
            ],
            'recommendations' => $this->getPhpConfigRecommendations($issues),
            'description' => 'PHP sollte sicher konfiguriert sein ohne gefährliche Funktionen.'
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
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) ||
               (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
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

    private function getSslRecommendations(array $results): array
    {
        $recommendations = [];
        foreach ($results as $domain => $result) {
            if (!$result['valid']) {
                $recommendations[] = "SSL-Zertifikat für {$domain} installieren";
            } elseif ($result['days_remaining'] < 30) {
                $recommendations[] = "SSL-Zertifikat für {$domain} verlängern";
            }
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
        return [
            'Gefährliche Funktionen in php.ini deaktivieren',
            'display_errors=Off in Produktionsumgebung',
            'expose_php=Off setzen',
            'allow_url_fopen und allow_url_include deaktivieren'
        ];
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
}