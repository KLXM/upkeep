<?php

namespace KLXM\Upkeep;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use MaxMind\Db\Reader\InvalidDatabaseException;

/**
 * GeoIP-Funktionalität für das Upkeep AddOn
 * 
 * Nutzt die kostenlose DB-IP.com Datenbank für Länderidentifikation
 */
class GeoIP
{
    private static ?Reader $reader = null;
    private static string $databasePath = '';
    
    /**
     * Initialisiert den GeoIP-Reader
     */
    private static function initReader(): bool
    {
        if (self::$reader !== null) {
            return true;
        }
        
        // Verwende eigene Datenbank im Upkeep AddOn
        $upkeepPath = \rex_path::addonData('upkeep', 'ip2geo.mmdb');
        
        if (!file_exists($upkeepPath)) {
            // Versuche Datenbank zu downloaden
            if (!self::downloadDatabase()) {
                return false;
            }
        }
        
        self::$databasePath = $upkeepPath;
        
        try {
            self::$reader = new Reader(self::$databasePath);
            return true;
        } catch (InvalidDatabaseException $e) {
            \rex_logger::logException($e);
            return false;
        }
    }
    
    /**
     * Ermittelt das Land einer IP-Adresse
     * 
     * @param string $ip IP-Adresse
     * @return array{code: string, name: string} Land-Information oder Fallback
     */
    public static function getCountry(string $ip): array
    {
        // Fallback für lokale/private IPs
        if (self::isPrivateIP($ip)) {
            return [
                'code' => 'LOCAL',
                'name' => 'Lokales Netzwerk'
            ];
        }
        
        if (!self::initReader()) {
            return [
                'code' => 'UNKNOWN',
                'name' => 'Unbekannt'
            ];
        }
        
        try {
            $record = self::$reader->country($ip);
            return [
                'code' => $record->country->isoCode ?? 'UNKNOWN',
                'name' => $record->country->name ?? 'Unbekannt'
            ];
        } catch (AddressNotFoundException $e) {
            return [
                'code' => 'UNKNOWN', 
                'name' => 'Unbekannt'
            ];
        } catch (\Exception $e) {
            \rex_logger::logException($e);
            return [
                'code' => 'ERROR',
                'name' => 'Fehler'
            ];
        }
    }
    
    /**
     * Prüft ob IP privat/lokal ist
     */
    private static function isPrivateIP(string $ip): bool
    {
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }
    
    /**
     * Lädt GeoIP-Datenbank von DB-IP.com herunter
     */
    private static function downloadDatabase(): bool
    {
        $today = new \DateTimeImmutable();
        $dbUrl = "https://download.db-ip.com/free/dbip-country-lite-{$today->format('Y-m')}.mmdb.gz";
        $targetPath = \rex_path::addonData('upkeep', 'ip2geo.mmdb');
        
        try {
            // Erstelle data-Verzeichnis falls nötig
            $dataDir = dirname($targetPath);
            if (!is_dir($dataDir)) {
                \rex_dir::create($dataDir);
            }
            
            $socket = \rex_socket::factoryUrl($dbUrl);
            $response = $socket->doGet();
            
            if ($response->isOk()) {
                $body = $response->getBody();
                $decompressed = gzdecode($body);
                
                if ($decompressed === false) {
                    \rex_logger::factory()->log('error', 'Upkeep GeoIP: Fehler beim Dekomprimieren der Datenbank', []);
                    return false;
                }
                
                \rex_file::put($targetPath, $decompressed);
                
                // Info-Logging nur wenn IPS System-Logging nicht deaktiviert ist
                $addon = \rex_addon::get('upkeep');
                if (!$addon->getConfig('ips_disable_system_logging', false)) {
                    \rex_logger::factory()->log('info', 'Upkeep GeoIP: Datenbank erfolgreich heruntergeladen', []);
                }
                return true;
            }
            
            \rex_logger::factory()->log('error', 'Upkeep GeoIP: Download fehlgeschlagen - HTTP ' . $response->getStatusCode(), []);
            return false;
            
        } catch (\rex_socket_exception $e) {
            \rex_logger::logException($e);
            return false;
        }
    }
    
    /**
     * Aktualisiert die GeoIP-Datenbank
     */
    public static function updateDatabase(): bool
    {
        // Reset Reader für Reload
        self::$reader = null;
        return self::downloadDatabase();
    }
    
    /**
     * Status der GeoIP-Datenbank
     */
    public static function getDatabaseStatus(): array
    {
        $upkeepPath = \rex_path::addonData('upkeep', 'ip2geo.mmdb');
        
        $status = [
            'available' => false,
            'source' => 'upkeep',
            'file_date' => null,
            'file_size' => 0
        ];
        
        if (file_exists($upkeepPath)) {
            $status['available'] = true;
            $status['file_date'] = date('Y-m-d H:i:s', filemtime($upkeepPath));
            $status['file_size'] = filesize($upkeepPath);
        }
        
        return $status;
    }
}
