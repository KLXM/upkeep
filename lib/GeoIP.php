<?php

namespace KLXM\Upkeep;

use GeoIp2\Database\Reader;
use GeoIp2\Exception\AddressNotFoundException;
use rex_addon;
use rex_dir;
use rex_file;
use rex_logger;
use rex_path;
use rex_socket;
use Throwable;

/**
 * GeoIP-Funktionalität für das Upkeep AddOn
 *
 * Nutzt die kostenlose DB-IP.com Datenbank (Country Lite) für die Länderzuordnung.
 * 3.0: Kein Download beim Seitenaufruf. Die Datenbank wird nur über
 * updateDatabase() (Button, Cronjob) geladen. Fehlende Datenbank = "Unbekannt".
 */
class GeoIP
{
    private const FILE = 'ip2geo.mmdb';

    private static ?Reader $reader = null;

    /** Negativ-Cache pro Request: Reader konnte nicht geöffnet werden */
    private static bool $readerFailed = false;

    /** @var array<string, array{code: string, name: string}> */
    private static array $cache = [];

    public static function getDatabasePath(): string
    {
        return rex_path::addonData('upkeep', self::FILE);
    }

    /**
     * Initialisiert den GeoIP-Reader (nur lokale Datei)
     */
    private static function initReader(): bool
    {
        if (self::$reader !== null) {
            return true;
        }
        if (self::$readerFailed) {
            return false;
        }

        $path = self::getDatabasePath();
        if (!is_file($path)) {
            self::$readerFailed = true;
            return false;
        }

        try {
            self::$reader = new Reader($path);
            return true;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            self::$readerFailed = true;
            return false;
        }
    }

    /**
     * Ermittelt das Land einer IP-Adresse (pro Request gecacht)
     *
     * @return array{code: string, name: string}
     */
    public static function getCountry(string $ip): array
    {
        if (isset(self::$cache[$ip])) {
            return self::$cache[$ip];
        }
        if (count(self::$cache) > 5000) {
            self::$cache = [];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return self::$cache[$ip] = ['code' => 'UNKNOWN', 'name' => 'Unbekannt'];
        }
        if (self::isPrivateIP($ip)) {
            return self::$cache[$ip] = ['code' => 'LOCAL', 'name' => 'Lokales Netzwerk'];
        }
        if (!self::initReader()) {
            return self::$cache[$ip] = ['code' => 'UNKNOWN', 'name' => 'Unbekannt'];
        }

        try {
            $record = self::$reader->country($ip);
            return self::$cache[$ip] = [
                'code' => (string) ($record->country->isoCode ?? 'UNKNOWN'),
                'name' => (string) ($record->country->name ?? 'Unbekannt'),
            ];
        } catch (AddressNotFoundException) {
            return self::$cache[$ip] = ['code' => 'UNKNOWN', 'name' => 'Unbekannt'];
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return self::$cache[$ip] = ['code' => 'ERROR', 'name' => 'Fehler'];
        }
    }

    /**
     * Prüft ob IP privat/lokal ist
     */
    private static function isPrivateIP(string $ip): bool
    {
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * Lädt die GeoIP-Datenbank von DB-IP.com (aktueller, sonst Vormonat), prüft sie
     * und ersetzt die vorhandene Datei atomar. Nur für Button/Cronjob/Konsole.
     */
    public static function updateDatabase(): bool
    {
        self::$reader = null;
        self::$readerFailed = false;
        self::$cache = [];

        $target = self::getDatabasePath();
        try {
            if (!is_dir(dirname($target))) {
                rex_dir::create(dirname($target));
            }

            $months = [new \DateTimeImmutable('first day of this month'), new \DateTimeImmutable('first day of last month')];
            foreach ($months as $month) {
                $url = 'https://download.db-ip.com/free/dbip-country-lite-' . $month->format('Y-m') . '.mmdb.gz';
                try {
                    $socket = rex_socket::factoryUrl($url);
                    $socket->setTimeout(30);
                    $response = $socket->doGet();
                } catch (Throwable $e) {
                    rex_logger::logException($e);
                    continue;
                }
                if (!$response->isOk()) {
                    continue;
                }

                $body = $response->getBody();
                if (strlen($body) < 1024 || strlen($body) > 200 * 1024 * 1024) {
                    continue;
                }
                $decompressed = @gzdecode($body);
                if ($decompressed === false || strlen($decompressed) < 1024) {
                    rex_logger::factory()->log('error', 'Upkeep GeoIP: Fehler beim Dekomprimieren der Datenbank');
                    continue;
                }

                $tmp = $target . '.tmp';
                if (!rex_file::put($tmp, $decompressed)) {
                    return false;
                }
                if (!self::isValidDatabase($tmp)) {
                    rex_file::delete($tmp);
                    rex_logger::factory()->log('error', 'Upkeep GeoIP: heruntergeladene Datenbank ist ungültig');
                    continue;
                }
                if (!@rename($tmp, $target)) {
                    rex_file::delete($tmp);
                    return false;
                }

                rex_addon::get('upkeep')->setConfig('geoip_last_update', time());
                if (!rex_addon::get('upkeep')->getConfig('ips_disable_system_logging', false)) {
                    rex_logger::factory()->log('info', 'Upkeep GeoIP: Datenbank aktualisiert (' . $month->format('Y-m') . ')');
                }
                return true;
            }

            rex_logger::factory()->log('error', 'Upkeep GeoIP: Download fehlgeschlagen');
            return false;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Aktualisiert die Datenbank nur, wenn sie fehlt oder älter als $maxAgeDays ist (für Cronjobs).
     */
    public static function updateIfOutdated(int $maxAgeDays = 35): bool
    {
        $path = self::getDatabasePath();
        if (is_file($path) && (time() - (int) filemtime($path)) < $maxAgeDays * 86400) {
            return true;
        }
        return self::updateDatabase();
    }

    /**
     * Prüft, ob eine Datei eine lesbare Country-Datenbank ist.
     */
    private static function isValidDatabase(string $file): bool
    {
        try {
            $reader = new Reader($file);
            $type = (string) $reader->metadata()->databaseType;
            // Testabfrage einer öffentlichen Adresse
            try {
                $reader->country('8.8.8.8');
            } catch (AddressNotFoundException) {
            }
            $reader->close();
            return stripos($type, 'country') !== false;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Status der GeoIP-Datenbank
     *
     * @return array{available: bool, source: string, file_date: string|null, file_size: int, outdated: bool}
     */
    public static function getDatabaseStatus(): array
    {
        $path = self::getDatabasePath();
        $status = [
            'available' => false,
            'source' => 'upkeep',
            'file_date' => null,
            'file_size' => 0,
            'outdated' => true,
        ];

        if (is_file($path)) {
            $mtime = (int) filemtime($path);
            $status['available'] = true;
            $status['file_date'] = date('Y-m-d H:i:s', $mtime);
            $status['file_size'] = (int) filesize($path);
            $status['outdated'] = (time() - $mtime) > 35 * 86400;
        }

        return $status;
    }
}
