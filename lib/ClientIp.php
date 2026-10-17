<?php

namespace KLXM\Upkeep;

use rex_addon;
use Throwable;

/**
 * Ermittelt die echte Client-IP.
 *
 * Proxy-Header (X-Forwarded-For, CF-Connecting-IP, X-Real-IP, Forwarded) werden
 * nur ausgewertet, wenn REMOTE_ADDR in der Konfiguration `trusted_proxies`
 * steht (Liste aus IPs/CIDRs, getrennt durch Zeilenumbruch, Komma oder Leerzeichen).
 * Ohne vertrauenswürdige Proxies gilt immer REMOTE_ADDR.
 */
final class ClientIp
{
    private static ?string $cached = null;

    /**
     * Liefert die Client-IP (pro Request gecacht).
     */
    public static function get(): string
    {
        if (self::$cached !== null) {
            return self::$cached;
        }

        $remote = self::normalize((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        if ($remote === '') {
            // CLI oder unbekannt
            return self::$cached = '0.0.0.0';
        }

        $trusted = self::getTrustedProxies();
        if ($trusted === [] || !self::inList($remote, $trusted)) {
            return self::$cached = $remote;
        }

        // REMOTE_ADDR ist ein vertrauenswürdiger Proxy: Kette von rechts durchlaufen
        $chain = self::forwardedChain();
        for ($i = count($chain) - 1; $i >= 0; --$i) {
            $candidate = $chain[$i];
            if (!self::inList($candidate, $trusted)) {
                return self::$cached = $candidate;
            }
        }

        // Alle Einträge sind Proxies: linkesten gültigen Eintrag nehmen, sonst REMOTE_ADDR
        if ($chain !== []) {
            return self::$cached = $chain[0];
        }

        // Einzelwert-Header (nur hinter vertrauenswürdigem Proxy)
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $header) {
            $value = self::normalize((string) ($_SERVER[$header] ?? ''));
            if ($value !== '') {
                return self::$cached = $value;
            }
        }

        return self::$cached = $remote;
    }

    /**
     * Setzt den Cache zurück (Tests, Konfigurationsänderung).
     */
    public static function reset(): void
    {
        self::$cached = null;
    }

    /**
     * Prüft, ob eine IP in einer Liste (IPs oder CIDR-Bereiche, IPv4 + IPv6) enthalten ist.
     *
     * @param array<int, string>|string $list
     */
    public static function inList(string $ip, array|string $list): bool
    {
        $ip = self::normalize($ip);
        if ($ip === '') {
            return false;
        }
        $entries = is_array($list) ? $list : self::parseList($list);
        foreach ($entries as $entry) {
            $entry = trim((string) $entry);
            if ($entry === '') {
                continue;
            }
            if (str_contains($entry, '/')) {
                if (self::inCidr($ip, $entry)) {
                    return true;
                }
                continue;
            }
            $normalized = self::normalize($entry);
            if ($normalized !== '' && inet_pton($normalized) === inet_pton($ip)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Prüft, ob eine IP in einem CIDR-Bereich liegt (IPv4 und IPv6).
     */
    public static function inCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return false;
        }
        [$subnet, $bits] = explode('/', $cidr, 2);
        $ipBin = @inet_pton(trim($ip));
        $subnetBin = @inet_pton(trim($subnet));
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }
        if (!ctype_digit(trim($bits))) {
            return false;
        }
        $bits = (int) $bits;
        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }
        $fullBytes = intdiv($bits, 8);
        $remainder = $bits % 8;
        if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
            return false;
        }
        if ($remainder === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $remainder)) & 0xFF;
        return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
    }

    /**
     * Zerlegt eine Liste (Zeilenumbruch, Komma, Semikolon oder Leerzeichen getrennt).
     *
     * @return array<int, string>
     */
    public static function parseList(string $list): array
    {
        $parts = preg_split('/[\s,;]+/', $list) ?: [];
        return array_values(array_filter(array_map('trim', $parts), static fn ($v) => $v !== ''));
    }

    /**
     * Prüft, ob ein Listeneintrag eine gültige IP oder ein gültiger CIDR-Bereich ist.
     */
    public static function isValidEntry(string $entry): bool
    {
        $entry = trim($entry);
        if (str_contains($entry, '/')) {
            [$subnet, $bits] = explode('/', $entry, 2);
            if (filter_var($subnet, FILTER_VALIDATE_IP) === false || !ctype_digit($bits)) {
                return false;
            }
            $max = str_contains($subnet, ':') ? 128 : 32;
            return (int) $bits <= $max;
        }
        return filter_var($entry, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * @return array<int, string>
     */
    private static function getTrustedProxies(): array
    {
        try {
            $raw = rex_addon::get('upkeep')->getConfig('trusted_proxies', '');
        } catch (Throwable) {
            return [];
        }
        if (is_array($raw)) {
            $raw = implode("\n", $raw);
        }
        return self::parseList((string) $raw);
    }

    /**
     * Liefert die IP-Kette aus X-Forwarded-For bzw. Forwarded (links = Client).
     *
     * @return array<int, string>
     */
    private static function forwardedChain(): array
    {
        $chain = [];
        $xff = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($xff !== '') {
            foreach (explode(',', $xff) as $part) {
                $ip = self::normalize($part);
                if ($ip !== '') {
                    $chain[] = $ip;
                }
            }
        } elseif (!empty($_SERVER['HTTP_FORWARDED'])) {
            if (preg_match_all('/for=("?)\[?([^\]";,\s]+)\]?\1/i', (string) $_SERVER['HTTP_FORWARDED'], $m)) {
                foreach ($m[2] as $part) {
                    $ip = self::normalize($part);
                    if ($ip !== '') {
                        $chain[] = $ip;
                    }
                }
            }
        }
        // Einzelwert-Header von Cloudflare hat Vorrang vor fehlender Kette
        if ($chain === [] && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = self::normalize((string) $_SERVER['HTTP_CF_CONNECTING_IP']);
            if ($ip !== '') {
                $chain[] = $ip;
            }
        }
        return $chain;
    }

    /**
     * Bereinigt eine IP (Port, Klammern, Leerzeichen) und validiert sie.
     */
    private static function normalize(string $value): string
    {
        $value = trim($value, " \t\n\r\0\x0B\"");
        if ($value === '') {
            return '';
        }
        // [IPv6]:port
        if (preg_match('/^\[([0-9a-f:.]+)\](?::\d+)?$/i', $value, $m)) {
            $value = $m[1];
        } elseif (substr_count($value, ':') === 1 && preg_match('/^([0-9.]+):\d+$/', $value, $m)) {
            // IPv4:port
            $value = $m[1];
        }
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            return '';
        }
        // IPv4-mapped IPv6 vereinfachen
        if (stripos($value, '::ffff:') === 0) {
            $v4 = substr($value, 7);
            if (filter_var($v4, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $v4;
            }
        }
        return $value;
    }
}
