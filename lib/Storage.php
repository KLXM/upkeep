<?php

namespace KLXM\Upkeep;

use FilesystemIterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use rex;
use rex_addon;
use rex_csrf_token;
use rex_dir;
use rex_file;
use rex_i18n;
use rex_logger;
use rex_media_manager;
use rex_path;
use rex_sql;
use SplFileInfo;
use Throwable;
use UnexpectedValueException;

/**
 * Speicherübersicht (wie "Speicher" in macOS).
 *
 * Der Bericht wird nur auf ausdrückliche Anforderung berechnet (Button, Konsole, Cronjob)
 * und als JSON im Data-Ordner des AddOns abgelegt. Normale Seitenaufrufe lesen nur den Cache.
 */
final class Storage
{
    public const REPORT_VERSION = 1;
    public const DEFAULT_TIME_BUDGET = 20.0;

    /** Reihenfolge = Reihenfolge im Balken. */
    public const CATEGORIES = [
        'images',
        'videos',
        'documents',
        'audio',
        'media_other',
        'media_manager',
        'database',
        'backups',
        'logs',
        'cache',
        'system',
    ];

    private const EXTENSIONS = [
        'images' => ['jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'avif', 'svg', 'bmp', 'tif', 'tiff', 'ico', 'heic', 'heif'],
        'videos' => ['mp4', 'm4v', 'mov', 'webm', 'ogv', 'avi', 'mkv', 'wmv', 'mpg', 'mpeg', '3gp'],
        'audio' => ['mp3', 'm4a', 'wav', 'ogg', 'oga', 'flac', 'aac', 'opus', 'wma', 'mid', 'midi'],
        'documents' => ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf', 'txt', 'csv', 'pages', 'numbers', 'key', 'epub'],
    ];

    private const TOP_MEDIA_LIMIT = 10;
    private const TOP_TABLE_LIMIT = 5;

    private static float $deadline = 0.0;
    private static bool $partial = false;

    /**
     * Liefert den zuletzt berechneten Bericht aus dem Cache.
     * Ohne Cache wird ein leeres Array geliefert (nichts wird berechnet), außer $refresh ist true.
     *
     * @return array<string, mixed>
     */
    public static function getReport(bool $refresh = false): array
    {
        if ($refresh) {
            return self::refresh();
        }

        $file = self::getCacheFile();
        if (!is_file($file)) {
            return [];
        }

        try {
            $data = json_decode((string) rex_file::get($file), true, 32, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return [];
        }

        if (!is_array($data) || (int) ($data['version'] ?? 0) !== self::REPORT_VERSION) {
            return [];
        }

        return $data;
    }

    public static function hasReport(): bool
    {
        return [] !== self::getReport();
    }

    /**
     * Berechnet den Bericht neu und speichert ihn im Cache.
     *
     * @return array<string, mixed>
     */
    public static function refresh(float $timeBudget = self::DEFAULT_TIME_BUDGET): array
    {
        $lock = self::acquireLock();
        if (null === $lock) {
            // Eine andere Berechnung läuft gerade: vorhandenen Bericht liefern.
            return self::getReport();
        }

        try {
            $report = self::compute($timeBudget);
            self::writeReport($report);
            return $report;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Leert den Media-Manager-Cache und aktualisiert den Wert im gespeicherten Bericht.
     *
     * @return int Anzahl gelöschter Dateien
     */
    public static function clearMediaManagerCache(): int
    {
        if (!rex_addon::get('media_manager')->isAvailable()) {
            return 0;
        }

        $count = (int) rex_media_manager::deleteCache();

        $report = self::getReport();
        if ([] !== $report) {
            self::$deadline = microtime(true) + 5.0;
            self::$partial = false;
            $size = self::dirSize(rex_path::addonCache('media_manager'));
            foreach ($report['categories'] as $i => $cat) {
                if ('media_manager' === $cat['key']) {
                    $report['categories'][$i]['bytes'] = $size['bytes'];
                    $report['categories'][$i]['count'] = $size['count'];
                }
            }
            $report['total_bytes'] = array_sum(array_column($report['categories'], 'bytes'));
            self::writeReport($report);
        }

        return $count;
    }

    /**
     * Verarbeitet die POST-Aktionen der Speicherübersicht (nur Admins).
     * Gibt null zurück, wenn keine Aktion gesendet wurde, sonst ['type' => success|error, 'message' => string].
     *
     * @return array{type: string, message: string}|null
     */
    public static function handlePost(rex_csrf_token $csrf): ?array
    {
        if ('post' !== rex_request_method()) {
            return null;
        }
        $action = rex_post('upkeep_storage_action', 'string', '');
        if ('' === $action) {
            return null;
        }

        $user = rex::getUser();
        if (null === $user || !$user->isAdmin()) {
            return ['type' => 'error', 'message' => rex_i18n::msg('upkeep_storage_no_permission')];
        }
        if (!$csrf->isValid()) {
            return ['type' => 'error', 'message' => rex_i18n::msg('csrf_token_invalid')];
        }

        try {
            if ('refresh' === $action) {
                $report = self::refresh();
                $key = !empty($report['partial']) ? 'upkeep_storage_refreshed_partial' : 'upkeep_storage_refreshed';
                return ['type' => 'success', 'message' => rex_i18n::msg($key)];
            }
            if ('clear_media_cache' === $action) {
                $count = self::clearMediaManagerCache();
                return ['type' => 'success', 'message' => rex_i18n::msg('upkeep_storage_media_cache_cleared', (string) $count)];
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return ['type' => 'error', 'message' => rex_i18n::msg('upkeep_storage_error')];
        }

        return null;
    }

    public static function getCacheFile(): string
    {
        return rex_addon::get('upkeep')->getDataPath('storage.json');
    }

    /**
     * @return array<string, mixed>
     */
    private static function compute(float $timeBudget): array
    {
        $start = microtime(true);
        self::$deadline = $start + max(1.0, $timeBudget);
        self::$partial = false;

        $categories = [];
        foreach (self::CATEGORIES as $key) {
            $categories[$key] = ['key' => $key, 'bytes' => 0, 'count' => 0, 'partial' => false];
        }

        // 1. Medienpool (schnell, aus der Datenbank)
        $media = self::computeMedia($categories);

        // 2. Datenbank
        $database = self::computeDatabase();
        $categories['database']['bytes'] = $database['bytes'];
        $categories['database']['count'] = $database['tables'];

        // 3. Dateisystem
        $mmCache = rex_path::addonCache('media_manager');
        $dirs = [
            'media_manager' => [[$mmCache], []],
            'backups' => [[rex_path::addonData('backup')], []],
            'logs' => [[rex_path::log()], []],
            'cache' => [[rex_path::cache()], [$mmCache]],
            'system' => [[rex_path::src(), rex_path::assets()], []],
        ];
        if (null === $media) {
            // Kein Medienpool verfügbar: Medienordner als "Sonstige Medien" zählen.
            $dirs['media_other'] = [[rex_path::media()], []];
        }
        foreach ($dirs as $key => [$paths, $exclude]) {
            foreach ($paths as $path) {
                $size = self::dirSize($path, $exclude);
                $categories[$key]['bytes'] += $size['bytes'];
                $categories[$key]['count'] += $size['count'];
                $categories[$key]['partial'] = $categories[$key]['partial'] || $size['partial'];
            }
        }

        $categories = array_values($categories);

        return [
            'version' => self::REPORT_VERSION,
            'computed_at' => time(),
            'duration' => round(microtime(true) - $start, 2),
            'partial' => self::$partial,
            'total_bytes' => array_sum(array_column($categories, 'bytes')),
            'categories' => $categories,
            'disk' => self::computeDisk(),
            'database' => $database,
            'media' => $media ?? ['available' => false, 'count' => 0, 'missing' => 0, 'top' => []],
        ];
    }

    /**
     * @param array<string, array<string, mixed>> $categories
     * @return array<string, mixed>|null
     */
    private static function computeMedia(array &$categories): ?array
    {
        if (!rex_addon::get('mediapool')->isAvailable()) {
            return null;
        }

        $result = ['available' => true, 'count' => 0, 'missing' => 0, 'missing_checked' => true, 'top' => []];
        $mediaDir = rex_path::media();

        try {
            $sql = rex_sql::factory();
            $rows = $sql->getArray('SELECT filename, filetype, filesize FROM ' . rex::getTable('media'));
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return null;
        }

        foreach ($rows as $i => $row) {
            $filename = (string) $row['filename'];
            $cat = self::categorize($filename, (string) $row['filetype']);
            $categories[$cat]['bytes'] += (int) $row['filesize'];
            ++$categories[$cat]['count'];
            ++$result['count'];

            if ($result['missing_checked']) {
                if (0 === $i % 500 && self::timeUp()) {
                    $result['missing_checked'] = false;
                    continue;
                }
                if ('' === $filename || !is_file($mediaDir . $filename)) {
                    ++$result['missing'];
                }
            }
        }
        unset($rows);

        try {
            $top = $sql->getArray(
                'SELECT id, filename, title, filetype, filesize FROM ' . rex::getTable('media')
                . ' ORDER BY CAST(filesize AS UNSIGNED) DESC LIMIT ' . self::TOP_MEDIA_LIMIT,
            );
            foreach ($top as $row) {
                $result['top'][] = [
                    'id' => (int) $row['id'],
                    'filename' => (string) $row['filename'],
                    'title' => (string) $row['title'],
                    'category' => self::categorize((string) $row['filename'], (string) $row['filetype']),
                    'bytes' => (int) $row['filesize'],
                ];
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }

        return $result;
    }

    /**
     * @return array{bytes: int, tables: int, top: list<array{name: string, bytes: int, rows: int}>, available: bool}
     */
    private static function computeDatabase(): array
    {
        $result = ['available' => false, 'bytes' => 0, 'tables' => 0, 'top' => []];

        try {
            $prefix = rex::getTablePrefix();
            $like = addcslashes($prefix, '\\%_') . '%';
            $sql = rex_sql::factory();
            $rows = $sql->getArray(
                'SELECT TABLE_NAME AS name, COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0) AS bytes, COALESCE(TABLE_ROWS, 0) AS row_count
                 FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE ?
                 ORDER BY bytes DESC',
                [$like],
            );
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return $result;
        }

        $result['available'] = true;
        foreach ($rows as $row) {
            $bytes = (int) $row['bytes'];
            $result['bytes'] += $bytes;
            ++$result['tables'];
            if (count($result['top']) < self::TOP_TABLE_LIMIT) {
                $result['top'][] = ['name' => (string) $row['name'], 'bytes' => $bytes, 'rows' => (int) $row['row_count']];
            }
        }

        return $result;
    }

    /**
     * @return array{total: int, free: int}|null
     */
    private static function computeDisk(): ?array
    {
        $base = rex_path::base();
        $total = function_exists('disk_total_space') ? @disk_total_space($base) : false;
        $free = function_exists('disk_free_space') ? @disk_free_space($base) : false;
        if (!is_float($total) || !is_float($free) || $total <= 0) {
            return null;
        }

        return ['total' => (int) $total, 'free' => (int) $free];
    }

    /**
     * Summiert Dateigrößen ohne Symlinks zu folgen. Nicht lesbare Ordner werden übersprungen.
     *
     * @param list<string> $exclude absolute Ordnerpfade, die ausgelassen werden
     * @return array{bytes: int, count: int, partial: bool}
     */
    private static function dirSize(string $path, array $exclude = []): array
    {
        $result = ['bytes' => 0, 'count' => 0, 'partial' => false];
        $path = rtrim($path, '/\\');
        if ('' === $path || !is_dir($path) || is_link($path) || !is_readable($path)) {
            return $result;
        }

        $exclude = array_map(static fn (string $p): string => rtrim($p, '/\\'), $exclude);

        try {
            $dir = new RecursiveDirectoryIterator(
                $path,
                FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO,
            );
            $filter = new RecursiveCallbackFilterIterator(
                $dir,
                static function (SplFileInfo $file) use ($exclude): bool {
                    if ($file->isLink()) {
                        return false;
                    }
                    if ($exclude && $file->isDir()) {
                        return !in_array(rtrim($file->getPathname(), '/\\'), $exclude, true);
                    }
                    return true;
                },
            );
            $iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);

            $n = 0;
            foreach ($iterator as $file) {
                if (0 === (++$n % 1000) && self::timeUp()) {
                    $result['partial'] = true;
                    break;
                }
                /** @var SplFileInfo $file */
                try {
                    if ($file->isFile()) {
                        $result['bytes'] += (int) $file->getSize();
                        ++$result['count'];
                    }
                } catch (Throwable) {
                    // Datei zwischenzeitlich gelöscht oder nicht lesbar
                }
            }
        } catch (UnexpectedValueException) {
            $result['partial'] = true;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $result['partial'] = true;
        }

        if (self::timeUp()) {
            $result['partial'] = true;
        }
        if ($result['partial']) {
            self::$partial = true;
        }

        return $result;
    }

    private static function timeUp(): bool
    {
        if (microtime(true) >= self::$deadline) {
            self::$partial = true;
            return true;
        }
        return false;
    }

    private static function categorize(string $filename, string $mime): string
    {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        foreach (self::EXTENSIONS as $cat => $list) {
            if (in_array($ext, $list, true)) {
                return $cat;
            }
        }

        $mime = strtolower($mime);
        if (str_starts_with($mime, 'image/')) {
            return 'images';
        }
        if (str_starts_with($mime, 'video/')) {
            return 'videos';
        }
        if (str_starts_with($mime, 'audio/')) {
            return 'audio';
        }
        if ('application/pdf' === $mime || str_contains($mime, 'officedocument') || str_contains($mime, 'msword')
            || str_contains($mime, 'ms-excel') || str_contains($mime, 'ms-powerpoint') || str_contains($mime, 'opendocument')) {
            return 'documents';
        }

        return 'media_other';
    }

    /**
     * @param array<string, mixed> $report
     */
    private static function writeReport(array $report): void
    {
        $file = self::getCacheFile();
        rex_dir::create(dirname($file));
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (false !== file_put_contents($tmp, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))) {
            if (!@rename($tmp, $file)) {
                @unlink($tmp);
            }
        }
    }

    /**
     * @return resource|null
     */
    private static function acquireLock()
    {
        $file = rex_addon::get('upkeep')->getDataPath('storage.lock');
        rex_dir::create(dirname($file));
        $handle = @fopen($file, 'c');
        if (false === $handle) {
            return null;
        }
        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);
            return null;
        }
        return $handle;
    }
}
