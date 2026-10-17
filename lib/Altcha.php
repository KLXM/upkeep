<?php

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_dir;
use rex_file;
use rex_logger;
use rex_response;
use Throwable;

/**
 * Self-hosted ALTCHA proof-of-work (protocol v1, algorithm SHA-256).
 *
 * challenge = sha256(salt . number), salt carries "?expires=<ts>&scope=<scope>",
 * signature = HMAC-SHA256(challenge, altcha_hmac_key).
 * Compatible with the vendored ALTCHA widget (assets/vendor/altcha, v3 understands v1 challenges)
 * and with the background solver in assets/js/form-protection.js.
 *
 * No third-party service, no cookies. Replay protection: every solved challenge is stored
 * (one marker file per challenge, atomic create) until it expires.
 */
final class Altcha
{
    public const ALGORITHM = 'SHA-256';

    /** Hard upper bound for accepted numbers (protects verify against absurd payloads). */
    private const MAX_NUMBER_LIMIT = 10_000_000;

    /** Hard upper bound for challenge lifetime. */
    private const MAX_TTL = 86400;

    private const MAX_PAYLOAD_LENGTH = 4096;

    /** Challenge endpoint: requests per IP and window. */
    private const ENDPOINT_LIMIT = 30;
    private const ENDPOINT_WINDOW = 600;

    private static ?string $key = null;

    /**
     * HMAC key from config `altcha_hmac_key`; generated once with random_bytes(32) if empty.
     */
    public static function getKey(): string
    {
        if (null !== self::$key) {
            return self::$key;
        }
        $addon = rex_addon::get('upkeep');
        $key = (string) $addon->getConfig('altcha_hmac_key', '');
        if (strlen($key) < 32) {
            $key = bin2hex(random_bytes(32));
            $addon->setConfig('altcha_hmac_key', $key);
        }
        return self::$key = $key;
    }

    /**
     * Derives a purpose-bound sub key so the ALTCHA key is never used directly for other signatures.
     */
    public static function deriveKey(string $purpose): string
    {
        return hash_hmac('sha256', 'upkeep:' . $purpose, self::getKey());
    }

    /**
     * @return array{algorithm: string, challenge: string, maxnumber: int, salt: string, signature: string}
     */
    public static function createChallenge(int $maxNumber = 100000, int $ttl = 600, string $scope = ''): array
    {
        $maxNumber = max(1000, min($maxNumber, self::MAX_NUMBER_LIMIT));
        $ttl = max(30, min($ttl, self::MAX_TTL));
        $expires = time() + $ttl;

        $query = 'expires=' . $expires;
        if ('' !== $scope) {
            $query .= '&scope=' . rawurlencode($scope);
        }
        $salt = bin2hex(random_bytes(12)) . '?' . $query;
        $number = random_int(0, $maxNumber);
        $challenge = hash('sha256', $salt . $number);

        return [
            'algorithm' => self::ALGORITHM,
            'challenge' => $challenge,
            'maxnumber' => $maxNumber,
            'salt' => $salt,
            'signature' => hash_hmac('sha256', $challenge, self::getKey()),
        ];
    }

    /**
     * Verifies a base64 encoded ALTCHA payload and consumes it (replay protection).
     * When $scope is given, the challenge must have been created for that scope.
     */
    public static function verify(string $payloadBase64, string $scope = ''): bool
    {
        try {
            $data = self::decodePayload($payloadBase64);
            if (null === $data) {
                return false;
            }

            parse_str(explode('?', $data['salt'], 2)[1] ?? '', $params);
            $expires = (int) ($params['expires'] ?? 0);
            $now = time();
            if ($expires <= $now || $expires > $now + self::MAX_TTL) {
                return false;
            }
            if ('' !== $scope && ($params['scope'] ?? '') !== $scope) {
                return false;
            }

            $expected = hash('sha256', $data['salt'] . $data['number']);
            if (!hash_equals($expected, $data['challenge'])) {
                return false;
            }
            $signature = hash_hmac('sha256', $data['challenge'], self::getKey());
            if (!hash_equals($signature, $data['signature'])) {
                return false;
            }

            // Unlock fails closed if the replay store is unusable; forms fail open (signature already verified).
            return self::consume($data['challenge'], $expires, 'form' !== ($params['scope'] ?? ''));
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * @return array{algorithm: string, challenge: string, number: int, salt: string, signature: string}|null
     */
    private static function decodePayload(string $payloadBase64): ?array
    {
        $payloadBase64 = trim($payloadBase64);
        if ('' === $payloadBase64 || strlen($payloadBase64) > self::MAX_PAYLOAD_LENGTH) {
            return null;
        }
        $json = base64_decode($payloadBase64, true);
        if (false === $json) {
            return null;
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }
        if (($data['algorithm'] ?? '') !== self::ALGORITHM) {
            return null;
        }
        foreach (['challenge', 'salt', 'signature'] as $field) {
            if (!isset($data[$field]) || !is_string($data[$field])) {
                return null;
            }
        }
        if (!preg_match('/^[a-f0-9]{64}$/', $data['challenge']) || !preg_match('/^[a-f0-9]{64}$/', $data['signature'])) {
            return null;
        }
        if (strlen($data['salt']) > 256) {
            return null;
        }
        $number = $data['number'] ?? null;
        if (!is_int($number) || $number < 0 || $number > self::MAX_NUMBER_LIMIT) {
            return null;
        }

        return [
            'algorithm' => $data['algorithm'],
            'challenge' => $data['challenge'],
            'number' => $number,
            'salt' => $data['salt'],
            'signature' => $data['signature'],
        ];
    }

    /**
     * Marks a challenge as used. Returns false if it was used before.
     * If the store is not writable: returns !$failClosed (and logs once per request).
     */
    private static function consume(string $challenge, int $expires, bool $failClosed = true): bool
    {
        $dir = self::storePath('used/' . substr($challenge, 0, 2));
        if ((!is_dir($dir) && !rex_dir::create($dir)) || !is_writable($dir)) {
            static $logged = false;
            if (!$logged) {
                $logged = true;
                rex_logger::factory()->log('warning', 'upkeep ALTCHA: replay store not writable: {dir}', ['dir' => $dir]);
            }
            return !$failClosed;
        }
        $file = $dir . '/' . $challenge;
        $handle = @fopen($file, 'x');
        if (false === $handle) {
            return false; // already used
        }
        fclose($handle);
        @touch($file, $expires);

        if (random_int(1, 50) === 1) {
            self::cleanup();
        }
        return true;
    }

    /**
     * Removes expired replay markers and stale rate-limit files. Safe to call from cron.
     *
     * @return int number of removed files
     */
    public static function cleanup(): int
    {
        $removed = 0;
        $now = time();
        $base = self::storePath('used');
        if (is_dir($base)) {
            foreach (glob($base . '/*', GLOB_ONLYDIR) ?: [] as $dir) {
                foreach (glob($dir . '/*') ?: [] as $file) {
                    $mtime = @filemtime($file);
                    if (false !== $mtime && $mtime < $now && @unlink($file)) {
                        ++$removed;
                    }
                }
            }
        }
        $rate = self::storePath('rate');
        if (is_dir($rate)) {
            foreach (glob($rate . '/*.json') ?: [] as $file) {
                $mtime = @filemtime($file);
                if (false !== $mtime && $mtime < $now - 2 * 86400 && @unlink($file)) {
                    ++$removed;
                }
            }
        }
        return $removed;
    }

    /**
     * Small file based fixed-window rate limiter (no rex_config keys, no DB).
     * Counts one hit and returns false when the limit is exceeded.
     * With $count = false it only checks.
     */
    public static function throttle(string $bucket, string $id, int $max, int $window, bool $count = true): bool
    {
        if ($max <= 0) {
            return true;
        }
        try {
            $dir = self::storePath('rate');
            if (!is_dir($dir) && !rex_dir::create($dir)) {
                return true; // fail open
            }
            $file = $dir . '/' . hash('sha256', $bucket . '|' . $id) . '.json';
            $handle = @fopen($file, 'c+');
            if (false === $handle) {
                return true;
            }
            flock($handle, LOCK_EX);
            $raw = stream_get_contents($handle);
            $state = is_string($raw) && '' !== $raw ? json_decode($raw, true) : null;
            $now = time();
            if (!is_array($state) || !isset($state['s'], $state['c']) || (int) $state['s'] + $window <= $now) {
                $state = ['s' => $now, 'c' => 0];
            }
            $allowed = (int) $state['c'] < $max;
            if ($count) {
                $state['c'] = (int) $state['c'] + 1;
                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, (string) json_encode($state));
                fflush($handle);
            }
            flock($handle, LOCK_UN);
            fclose($handle);
            return $allowed;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return true;
        }
    }

    /**
     * Number of hits in the current window (for unlock counters).
     */
    public static function throttleCount(string $bucket, string $id, int $window): int
    {
        $file = self::storePath('rate') . '/' . hash('sha256', $bucket . '|' . $id) . '.json';
        $raw = is_file($file) ? rex_file::get($file) : null;
        $state = $raw ? json_decode($raw, true) : null;
        if (!is_array($state) || (int) ($state['s'] ?? 0) + $window <= time()) {
            return 0;
        }
        return (int) ($state['c'] ?? 0);
    }

    /**
     * Whether the challenge endpoint may be served (one of the consuming modules is active).
     */
    public static function isEndpointEnabled(): bool
    {
        $addon = rex_addon::get('upkeep');
        return (bool) $addon->getConfig('ips_active', false) || (bool) $addon->getConfig('form_protection_active', false);
    }

    /**
     * Sends a fresh challenge as JSON and exits. Used by rex_api_upkeep_altcha and the block page.
     */
    public static function sendChallengeResponse(string $scope = ''): never
    {
        rex_response::cleanOutputBuffers();
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, max-age=0');
        header('X-Content-Type-Options: nosniff');
        header('X-Robots-Tag: noindex, nofollow');

        $scope = in_array($scope, ['unlock', 'form'], true) ? $scope : 'form';

        if (!self::isEndpointEnabled()) {
            http_response_code(404);
            echo '{"error":"disabled"}';
            exit;
        }
        if (!self::throttle('altcha_endpoint', self::clientIp(), self::ENDPOINT_LIMIT, self::ENDPOINT_WINDOW)) {
            http_response_code(429);
            header('Retry-After: ' . self::ENDPOINT_WINDOW);
            echo '{"error":"rate_limited"}';
            exit;
        }

        $addon = rex_addon::get('upkeep');
        if ('unlock' === $scope) {
            $challenge = self::createChallenge(100000, 600, 'unlock');
        } else {
            $challenge = self::createChallenge(
                (int) $addon->getConfig('form_protection_pow_max_number', 50000),
                (int) $addon->getConfig('form_protection_max_age', 7200),
                'form',
            );
        }
        echo json_encode($challenge, JSON_UNESCAPED_SLASHES);
        exit;
    }

    /**
     * Client IP via ClientIp (SEC), guarded fallback to REMOTE_ADDR.
     */
    public static function clientIp(): string
    {
        if (class_exists(ClientIp::class)) {
            return ClientIp::get();
        }
        $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        return false !== filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    private static function storePath(string $sub): string
    {
        return rtrim(rex_addon::get('upkeep')->getDataPath('altcha'), '/') . '/' . $sub;
    }

    /**
     * URL of the challenge endpoint (relative to the frontend).
     */
    public static function endpointUrl(string $scope = 'form'): string
    {
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php');
        $base = rtrim(str_replace('\\', '/', dirname($script)), '/');
        return $base . '/index.php?rex-api-call=upkeep_altcha&scope=' . rawurlencode($scope);
    }
}
