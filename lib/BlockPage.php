<?php

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_i18n;
use rex_logger;
use rex_response;
use rex_sql;
use rex_url;
use Throwable;

/**
 * IPS block screen with ALTCHA self-unlock.
 *
 * - send(): 403 page (no-cache, nosniff, frame deny, strict CSP with nonce, only own assets),
 *   DE/EN by Accept-Language, shows a reason category (never internal details) and contact info.
 * - handleUnlock(): verifies the ALTCHA payload server side and unlocks ONLY ClientIp::get().
 *
 * Self-unlock rules:
 * - only for an existing automatic, temporary block of exactly this IP (rate limit, repeated violations, high threats);
 *   without such a block there is nothing to unlock (no challenge, no unlock);
 * - NOT allowed for permanent blocks, IP ranges (CIDR), manual blocks and severe blocks shortly after a
 *   self-unlock (source = 'after_unlock');
 * - max `ips_unlock_max` unlocks per IP and 24 h (0 = self-unlock off), max 10 attempts per IP and 10 minutes;
 * - after success: unblock + clear threat history + mark the IP as "self-unlocked" for `ips_unlock_hours`.
 *   This is NOT a positive list: the IP stays fully monitored; a severe hit in that time blocks without self-unlock.
 */
final class BlockPage
{
    public const FIELD_PAYLOAD = 'upkeep_altcha';
    public const FIELD_ACTION = 'upkeep_unlock';

    private const ATTEMPT_LIMIT = 10;
    private const ATTEMPT_WINDOW = 600;

    /** Zähler der erfolgreichen Selbst-Entsperrungen (pro Adresse bzw. IPv6-/64 und 24 h) */
    private const UNLOCK_BUCKET = 'unlock_success';
    private const UNLOCK_WINDOW = 86400;

    private static ?bool $unlockResult = null;
    private static string $unlockError = '';

    /**
     * Renders the block screen and ends the request.
     * Also serves the ALTCHA challenge (blocked clients cannot reach the regular API) and processes unlock POSTs.
     */
    public static function send(string $reason, int $status = 403): never
    {
        try {
            if ('upkeep_altcha' === rex_get('rex-api-call', 'string', '')) {
                Altcha::sendChallengeResponse('unlock');
            }
            if (self::isUnlockRequest()) {
                self::handleUnlock(); // redirects and exits on success
            }
            $html = self::render($reason, $nonce = bin2hex(random_bytes(16)));
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $nonce = bin2hex(random_bytes(16));
            $html = '<!doctype html><html><head><meta charset="utf-8"><title>403</title></head><body><h1>403</h1></body></html>';
        }

        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            http_response_code($status >= 400 && $status < 600 ? $status : 403);
            header('Content-Type: text/html; charset=utf-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
            header('X-Content-Type-Options: nosniff');
            header('X-Frame-Options: DENY');
            header('Referrer-Policy: no-referrer');
            header('X-Robots-Tag: noindex, nofollow');
            header("Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-{$nonce}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
            if (429 === $status) {
                header('Retry-After: 600');
            }
        }
        echo $html;
        exit;
    }

    public static function isUnlockRequest(): bool
    {
        return 'POST' === strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? '')) && isset($_POST[self::FIELD_ACTION]);
    }

    /**
     * Processes a self-unlock POST. Returns false if there is nothing to do or verification failed
     * (the reason is shown on the block page). On success it redirects (303, same URL) and exits.
     * Safe to call several times per request (result is memoized, payload is consumed once).
     */
    public static function handleUnlock(): bool
    {
        if (null !== self::$unlockResult) {
            return self::$unlockResult;
        }
        self::$unlockResult = false;
        if (!self::isUnlockRequest()) {
            return false;
        }

        try {
            $addon = rex_addon::get('upkeep');
            $ip = Altcha::clientIp();

            // Zähler je Adresse, bei IPv6 je /64-Netz (sonst Umgehung durch Adresswechsel)
            $bucket = ClientIp::bucket($ip);
            if (!Altcha::throttle('unlock_attempt', $bucket, self::ATTEMPT_LIMIT, self::ATTEMPT_WINDOW)) {
                self::$unlockError = 'rate';
                return false;
            }

            $payload = (string) ($_POST[self::FIELD_PAYLOAD] ?? '');
            if (!Altcha::verify($payload, 'unlock')) {
                self::$unlockError = 'invalid';
                return false;
            }

            if (!self::canSelfUnlock($ip)) {
                self::$unlockError = 'not_allowed';
                return false;
            }

            // Prüfen und Zählen in einem Schritt (unter Dateisperre) – parallele Anfragen können das Limit nicht überholen
            $max = max(0, (int) $addon->getConfig('ips_unlock_max', 3));
            if ($max <= 0 || !Altcha::throttle(self::UNLOCK_BUCKET, $bucket, $max, self::UNLOCK_WINDOW)) {
                self::$unlockError = 'limit';
                return false;
            }

            $hours = max(1, min(720, (int) $addon->getConfig('ips_unlock_hours', 24)));
            IntrusionPrevention::unblockIp($ip);
            IntrusionPrevention::clearThreatHistory($ip);
            IntrusionPrevention::addToTemporaryPositivliste($ip, $hours, 'ALTCHA self-unlock', IntrusionPrevention::SELF_UNLOCK_CATEGORY);

            rex_logger::factory()->log('info', 'upkeep IPS: self-unlock via ALTCHA for {ip} ({hours} h)', ['ip' => $ip, 'hours' => $hours]);
            self::$unlockResult = true;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            self::$unlockError = 'invalid';
            return false;
        }

        rex_response::cleanOutputBuffers();
        if (!headers_sent()) {
            header('Cache-Control: no-store');
            header('Location: ' . self::safeReturnUrl(), true, 303);
        }
        exit;
    }

    /**
     * Whether the given IP may unlock itself (see class doc).
     */
    public static function canSelfUnlock(string $ip): bool
    {
        $addon = rex_addon::get('upkeep');
        $max = (int) $addon->getConfig('ips_unlock_max', 3);
        if ($max <= 0 || !$addon->getConfig('ips_active', false)) {
            return false;
        }
        // Tageslimit verbraucht: keine Rechenaufgabe, kein Formular
        if (Altcha::throttleCount(self::UNLOCK_BUCKET, ClientIp::bucket($ip), self::UNLOCK_WINDOW) >= $max) {
            return false;
        }
        try {
            $unlockable = false;
            $table = rex::getTable('upkeep_ips_blocked_ips');
            $sql = rex_sql::factory();
            $sql->setQuery(
                'SELECT * FROM ' . $table . " WHERE (ip_address = ? OR ip_address LIKE '%/%') AND (expires_at IS NULL OR expires_at > ?)",
                [$ip, date('Y-m-d H:i:s')],
            );
            foreach ($sql->getArray() as $row) {
                $entry = (string) $row['ip_address'];
                if (str_contains($entry, '/')) {
                    $covered = class_exists(ClientIp::class) ? ClientIp::inCidr($ip, $entry) : false;
                    if ($covered) {
                        return false;
                    }
                    continue;
                }
                if ('permanent' === ($row['block_type'] ?? '') || null === $row['expires_at']) {
                    return false;
                }
                if (in_array((string) ($row['source'] ?? ''), ['manual', IntrusionPrevention::SOURCE_AFTER_UNLOCK], true)) {
                    return false;
                }
                $unlockable = true;
            }
            // Ohne eigene, automatische Sperre gibt es nichts zu entsperren
            return $unlockable;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    /**
     * Maps an internal reason text to a public category.
     */
    public static function reasonCategory(string $reason): string
    {
        $r = mb_strtolower($reason);
        if (preg_match('/rate|too many|zu viele|burst/', $r)) {
            return 'rate_limit';
        }
        if (preg_match('/spam|mail|form/', $r)) {
            return 'spam';
        }
        if (preg_match('/threat|malicious|pattern|xmlrpc|critical|exploit|attack|verdächt|bedrohung|violation|verstoß/', $r)) {
            return 'suspicious';
        }
        return 'blocked';
    }

    /**
     * Absolute-path URL for an asset of this addon (works on deep frontend URLs).
     */
    public static function assetUrl(string $file): string
    {
        $rel = rex_url::addonAssets('upkeep', $file);
        while (str_starts_with($rel, './')) {
            $rel = substr($rel, 2);
        }
        if (!str_starts_with($rel, '/')) {
            $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php');
            $base = rtrim(str_replace('\\', '/', dirname($script)), '/');
            $rel = $base . '/' . $rel;
        }
        $path = rex_addon::get('upkeep')->getAssetsPath($file);
        $mtime = is_file($path) ? (int) filemtime($path) : 0;
        return $rel . ($mtime ? '?v=' . $mtime : '');
    }

    /**
     * Language for the block page: de or en (Accept-Language, first match wins; default de).
     */
    public static function detectLanguage(): string
    {
        $header = strtolower((string) ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
        $best = null;
        $bestQ = -1.0;
        foreach (explode(',', $header) as $i => $part) {
            $bits = explode(';', trim($part));
            $tag = trim($bits[0]);
            $q = 1.0;
            if (isset($bits[1]) && preg_match('/q=([0-9.]+)/', $bits[1], $m)) {
                $q = (float) $m[1];
            }
            $q -= $i * 0.0001;
            $lang = substr($tag, 0, 2);
            if (in_array($lang, ['de', 'en'], true) && $q > $bestQ) {
                $best = $lang;
                $bestQ = $q;
            }
        }
        return $best ?? 'de';
    }

    private static function t(string $key, string $lang, string ...$replace): string
    {
        $locale = 'en' === $lang ? 'en_gb' : 'de_de';
        return rex_i18n::rawMsgInLocale('upkeep_blockpage_' . $key, $locale, ...$replace);
    }

    private static function render(string $reason, string $nonce): string
    {
        $addon = rex_addon::get('upkeep');
        $lang = self::detectLanguage();
        $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $ip = Altcha::clientIp();
        $category = self::reasonCategory($reason);
        $canUnlock = self::canSelfUnlock($ip);

        $title = self::t('title', $lang);
        $intro = self::t('reason_' . $category, $lang);
        if ('de' === $lang) {
            $customTitle = trim((string) $addon->getConfig('ips_block_title', ''));
            if ('' !== $customTitle && 'Zugriff verweigert' !== $customTitle) {
                $title = $customTitle;
            }
        }

        $error = '';
        if ('' !== self::$unlockError) {
            $error = self::t('error_' . self::$unlockError, $lang);
        }

        $contact = trim((string) $addon->getConfig('ips_contact_info', ''));
        $contactHtml = '';
        if ('' !== $contact) {
            $contactHtml = nl2br($e($contact), false);
            $contactHtml = (string) preg_replace(
                '/([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})/i',
                '<a href="mailto:$1">$1</a>',
                $contactHtml,
            );
        }

        $css = $e(self::assetUrl('css/blockpage.css'));
        $altchaCss = $e(self::assetUrl('vendor/altcha/altcha.css'));
        $altchaJs = $e(self::assetUrl('vendor/altcha/altcha.min.js'));
        $worker = self::assetUrl('vendor/altcha/worker-sha.js');
        $endpoint = Altcha::endpointUrl('unlock');
        $action = self::safeReturnUrl();

        $strings = [
            'label' => self::t('widget_label', $lang),
            'verified' => self::t('widget_verified', $lang),
            'verifying' => self::t('widget_verifying', $lang),
            'waitAlert' => self::t('widget_wait', $lang),
            'error' => self::t('widget_error', $lang),
            'expired' => self::t('widget_expired', $lang),
            'verificationRequired' => self::t('widget_required', $lang),
            'verify' => self::t('widget_verify', $lang),
            'loading' => self::t('widget_loading', $lang),
            'reload' => self::t('widget_reload', $lang),
            'cancel' => self::t('widget_cancel', $lang),
            'footer' => '',
            'ariaLinkLabel' => 'ALTCHA',
        ];
        $jsonFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;
        $config = $e((string) json_encode(['hideFooter' => true, 'hideLogo' => true, 'minDuration' => 600], $jsonFlags));

        $h = [];
        $h[] = '<!doctype html>';
        $h[] = '<html lang="' . $e($lang) . '">';
        $h[] = '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
        $h[] = '<meta name="robots" content="noindex, nofollow"><meta name="color-scheme" content="light dark">';
        $h[] = '<title>' . $e($title) . '</title>';
        $h[] = '<link rel="stylesheet" href="' . $css . '">';
        if ($canUnlock) {
            $h[] = '<link rel="stylesheet" href="' . $altchaCss . '">';
        }
        $h[] = '</head><body class="upk-bp">';
        $h[] = '<main class="upk-bp__card" aria-labelledby="upk-bp-title">';
        $h[] = '<div class="upk-bp__icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z"/><path d="M9.5 12.5l1.8 1.8 3.4-3.6"/></svg></div>';
        $h[] = '<h1 id="upk-bp-title" class="upk-bp__title">' . $e($title) . '</h1>';
        $h[] = '<p class="upk-bp__lead">' . $e($intro) . '</p>';

        if ('' !== $error) {
            $h[] = '<p class="upk-bp__alert" role="alert">' . $e($error) . '</p>';
        }

        if ($canUnlock) {
            $h[] = '<section class="upk-bp__unlock" aria-labelledby="upk-bp-unlock">';
            $h[] = '<h2 id="upk-bp-unlock" class="upk-bp__subtitle">' . $e(self::t('unlock_title', $lang)) . '</h2>';
            $h[] = '<p class="upk-bp__text">' . $e(self::t('unlock_text', $lang)) . '</p>';
            $h[] = '<form id="upk-bp-form" class="upk-bp__form" method="post" action="' . $e($action) . '">';
            $h[] = '<input type="hidden" name="' . self::FIELD_ACTION . '" value="1">';
            $h[] = '<altcha-widget name="' . self::FIELD_PAYLOAD . '" challenge="' . $e($endpoint) . '" language="' . $e($lang) . '" type="checkbox" workers="2" configuration="' . $config . '"></altcha-widget>';
            $h[] = '<noscript><p class="upk-bp__text">' . $e(self::t('noscript', $lang)) . '</p></noscript>';
            $h[] = '<button type="submit" class="upk-bp__button" id="upk-bp-submit">' . $e(self::t('unlock_button', $lang)) . '</button>';
            $h[] = '</form>';
            $h[] = '<p class="upk-bp__hint">' . $e(self::t('privacy', $lang)) . '</p>';
            $h[] = '</section>';
        } else {
            $h[] = '<p class="upk-bp__text">' . $e(self::t('no_self_unlock', $lang)) . '</p>';
        }

        $h[] = '<dl class="upk-bp__meta">';
        $h[] = '<div><dt>' . $e(self::t('your_ip', $lang)) . '</dt><dd><code>' . $e($ip) . '</code></dd></div>';
        $h[] = '<div><dt>' . $e(self::t('time', $lang)) . '</dt><dd>' . $e(date('Y-m-d H:i')) . '</dd></div>';
        $h[] = '</dl>';

        if ('' !== $contactHtml) {
            $h[] = '<div class="upk-bp__contact"><h2 class="upk-bp__subtitle">' . $e(self::t('contact', $lang)) . '</h2><p>' . $contactHtml . '</p></div>';
        }
        $h[] = '</main>';

        if ($canUnlock) {
            $data = json_encode(['worker' => $worker, 'lang' => $lang, 'strings' => $strings], $jsonFlags);
            $h[] = '<script type="module" src="' . $altchaJs . '"></script>';
            $h[] = '<script type="module" nonce="' . $e($nonce) . '">'
                . 'const c=' . $data . ';'
                . 'const g=globalThis.$altcha;'
                . 'if(g){g.algorithms.set("SHA-256",()=>new Worker(c.worker));g.i18n.set(c.lang,c.strings);}'
                . 'const f=document.getElementById("upk-bp-form"),w=f&&f.querySelector("altcha-widget"),b=document.getElementById("upk-bp-submit");'
                . 'if(b){b.hidden=true;}'
                . 'if(w){w.addEventListener("statechange",ev=>{const s=ev.detail&&ev.detail.state;'
                . 'if(s==="verified"){if(b){b.hidden=false;b.focus();}f.submit();}'
                . 'else if(s==="error"&&b){b.hidden=true;}});}'
                . '</script>';
        }
        $h[] = '</body></html>';

        return implode("\n", $h);
    }

    /**
     * Same-origin relative return URL (path + query of the current request).
     */
    private static function safeReturnUrl(): string
    {
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        if ('' === $uri || '/' !== $uri[0] || str_starts_with($uri, '//') || str_contains($uri, '\\') || preg_match('/[\x00-\x1f]/', $uri)) {
            return '/';
        }
        // never send the browser back to the challenge endpoint
        if (str_contains($uri, 'rex-api-call=')) {
            return '/';
        }
        return $uri;
    }
}
