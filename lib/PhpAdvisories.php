<?php

namespace KLXM\Upkeep;

use rex_extension;
use rex_extension_point;

/**
 * Bekannte Sicherheitslücken in PHP selbst, mit dem ersten gefixten Patch-Release je Zweig.
 *
 * Zweige vor dem ältesten gelisteten gelten als betroffen (vom PHP-Projekt ohne Fix),
 * neuere Zweige als nicht betroffen. Distributionen spielen Fixes oft ein, ohne
 * PHP_VERSION zu ändern – deshalb lässt sich der Check im Advisor freigeben.
 *
 * Weitere Einträge über den Extension Point UPKEEP_PHP_ADVISORIES; 'title' darf "translate:"-Schlüssel nutzen.
 */
final class PhpAdvisories
{
    /**
     * @return list<array{id: string, date: string, title: string, cves: list<string>, url: string, fixed: array<string, string>, mitigations: list<string>}>
     */
    public static function all(): array
    {
        $advisories = [
            [
                'id' => '2026-10-21',
                'date' => '2026-10-21',
                'title' => 'translate:upkeep_php_advisory_2026_10_21',
                'cves' => ['CVE-2026-109618', 'CVE-2026-109619'],
                'url' => 'https://www.php.net/archive/2026.php#2026-10-21-5',
                'fixed' => ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'],
                'mitigations' => ['session_upload_progress', 'fatal_error_backtraces', 'memory_limit', 'post_max_size'],
            ],
        ];

        return rex_extension::registerPoint(new rex_extension_point('UPKEEP_PHP_ADVISORIES', $advisories));
    }

    /**
     * Advisories, von denen die übergebene PHP-Version betroffen ist.
     *
     * @return list<array{id: string, date: string, title: string, cves: list<string>, url: string, fixed: array<string, string>, mitigations: list<string>, fixed_in: ?string}>
     */
    public static function affecting(string $phpVersion = PHP_VERSION): array
    {
        $branch = self::branch($phpVersion);
        $out = [];
        foreach (self::all() as $advisory) {
            $fixed = $advisory['fixed'];
            if (isset($fixed[$branch])) {
                if (version_compare(self::numeric($phpVersion), $fixed[$branch], '<')) {
                    $out[] = $advisory + ['fixed_in' => $fixed[$branch]];
                }
                continue;
            }
            $branches = array_keys($fixed);
            usort($branches, static fn (string $a, string $b): int => version_compare($a, $b));
            if ([] !== $branches && version_compare($branch, $branches[0], '<')) {
                $out[] = $advisory + ['fixed_in' => null];
            }
        }
        return $out;
    }

    /**
     * Ist für die übergebene Version gerade eine Übergangsmaßnahme gegen OOM-Lücken empfohlen
     * (memory_limit=-1)? Dann ist ein unbegrenztes Memory Limit kein Fehler.
     */
    public static function recommendsUnlimitedMemory(string $phpVersion = PHP_VERSION): bool
    {
        foreach (self::affecting($phpVersion) as $advisory) {
            if (in_array('memory_limit', $advisory['mitigations'], true)) {
                return true;
            }
        }
        return false;
    }

    public static function branch(string $phpVersion): string
    {
        return implode('.', array_slice(explode('.', self::numeric($phpVersion)), 0, 2));
    }

    /**
     * "8.2.29-1+deb12u1" → "8.2.29"
     */
    private static function numeric(string $phpVersion): string
    {
        return preg_match('/^\d+\.\d+(?:\.\d+)?/', $phpVersion, $m) ? $m[0] : $phpVersion;
    }
}
