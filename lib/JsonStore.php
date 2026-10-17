<?php

namespace KLXM\Upkeep;

use rex_dir;
use rex_path;
use Throwable;

/**
 * Kleiner dateibasierter Schlüssel-Wert-Speicher mit Ablaufzeit und Obergrenze.
 *
 * Für Zähler (Login-Versuche, Drosselung, DNS-Cache), die nicht in rex_config
 * gehören (rex_config wird bei jedem Request komplett geladen).
 * Schlüssel werden gehasht gespeichert. Fehler führen nie zu Ausnahmen.
 */
final class JsonStore
{
    /** @var array<string, array<string, array{v: mixed, e: int}>> */
    private static array $memory = [];

    public function __construct(
        private readonly string $name,
        private readonly int $maxEntries = 2000,
    ) {
    }

    public static function path(string $name): string
    {
        return rex_path::addonData('upkeep', 'store/' . preg_replace('/[^a-z0-9_\-]/i', '_', $name) . '.json');
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $data = $this->read();
        $hk = self::hashKey($key);
        if (isset($data[$hk]) && $data[$hk]['e'] >= time()) {
            return $data[$hk]['v'];
        }
        return $default;
    }

    public function set(string $key, mixed $value, int $ttl): void
    {
        $this->update($key, static fn () => $value, $ttl);
    }

    public function delete(string $key): void
    {
        $hk = self::hashKey($key);
        $this->transaction(static function (array $data) use ($hk): array {
            unset($data[$hk]);
            return $data;
        });
    }

    /**
     * Ändert einen Wert atomar (unter Dateisperre).
     *
     * @param callable(mixed): mixed $fn erhält den aktuellen Wert (oder null)
     */
    public function update(string $key, callable $fn, int $ttl): mixed
    {
        $hk = self::hashKey($key);
        $result = null;
        $this->transaction(static function (array $data) use ($hk, $fn, $ttl, &$result): array {
            $current = (isset($data[$hk]) && $data[$hk]['e'] >= time()) ? $data[$hk]['v'] : null;
            $result = $fn($current);
            $data[$hk] = ['v' => $result, 'e' => time() + max(1, $ttl)];
            return $data;
        });
        return $result;
    }

    /**
     * Erhöht einen Zähler innerhalb eines Zeitfensters und liefert den neuen Stand.
     */
    public function increment(string $key, int $window): int
    {
        return (int) $this->update($key, static fn ($v) => ((int) $v) + 1, $window);
    }

    public function clear(): void
    {
        $this->transaction(static fn (): array => []);
    }

    /**
     * @return array<string, array{v: mixed, e: int}>
     */
    private function read(): array
    {
        if (isset(self::$memory[$this->name])) {
            return self::$memory[$this->name];
        }
        $file = self::path($this->name);
        if (!is_file($file)) {
            return self::$memory[$this->name] = [];
        }
        try {
            $raw = @file_get_contents($file);
            $data = $raw ? json_decode($raw, true) : [];
            return self::$memory[$this->name] = is_array($data) ? $data : [];
        } catch (Throwable) {
            return self::$memory[$this->name] = [];
        }
    }

    /**
     * @param callable(array<string, array{v: mixed, e: int}>): array<string, array{v: mixed, e: int}> $fn
     */
    private function transaction(callable $fn): void
    {
        $file = self::path($this->name);
        try {
            $dir = dirname($file);
            if (!is_dir($dir)) {
                rex_dir::create($dir);
            }
            $fh = @fopen($file, 'c+');
            if ($fh === false) {
                return;
            }
            try {
                if (!flock($fh, LOCK_EX)) {
                    return;
                }
                $raw = stream_get_contents($fh);
                $data = $raw ? json_decode($raw, true) : [];
                if (!is_array($data)) {
                    $data = [];
                }
                $data = $fn($data);

                // Abgelaufene Einträge entfernen und Obergrenze einhalten
                $now = time();
                $data = array_filter($data, static fn ($entry) => is_array($entry) && ($entry['e'] ?? 0) >= $now);
                if (count($data) > $this->maxEntries) {
                    uasort($data, static fn ($a, $b) => $b['e'] <=> $a['e']);
                    $data = array_slice($data, 0, $this->maxEntries, true);
                }

                ftruncate($fh, 0);
                rewind($fh);
                fwrite($fh, (string) json_encode($data));
                fflush($fh);
                flock($fh, LOCK_UN);
                self::$memory[$this->name] = $data;
            } finally {
                fclose($fh);
            }
        } catch (Throwable) {
            // Speicher ist nur Hilfsmittel – niemals den Request stören
        }
    }

    private static function hashKey(string $key): string
    {
        return substr(hash('sha256', $key), 0, 32);
    }
}
