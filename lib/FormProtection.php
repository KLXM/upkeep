<?php

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_clang;
use rex_extension;
use rex_extension_point;
use rex_i18n;
use rex_logger;
use rex_sql;
use rex_yform;
use rex_yform_value_abstract;
use Throwable;

/**
 * Invisible spam protection for YForm frontend forms.
 *
 * Injected automatically via YFORM_GENERATE (no field in the form definition, no captcha):
 * honeypot, signed timestamp token, background ALTCHA proof-of-work, interaction signals,
 * AI/bot agent detection, content checks and a rate limit. Each check adds points;
 * score >= threshold -> neutral YForm warning, actions (mail/db) do not run.
 *
 * Opt-out per form: $yform->setObjectparams('upkeep_spam_protection', 0)
 * or the definition line objparams|upkeep_spam_protection|0
 */
final class FormProtection
{
    public const OBJPARAM = 'upkeep_spam_protection';
    public const ELEMENT = 'upkeep_protect';

    public const FIELD_TOKEN = 'upk_t';
    public const FIELD_POW = 'upk_p';
    public const FIELD_SIGNALS = 'upk_s';

    private const HONEYPOT_NAMES = ['website', 'homepage', 'url', 'company_website', 'web_address', 'contact_url'];

    /** Default configuration (keys without the "form_protection_" prefix). */
    public const DEFAULTS = [
        'active' => 0,
        'level' => 'normal',
        'threshold' => 60,
        'threshold_strict' => 40,
        'report_threshold' => 100,
        'report_ips' => 1,
        'min_time' => 3,
        'max_age' => 7200,
        'pow' => 1,
        'pow_max_number' => 50000,
        'max_links' => 3,
        'badwords' => 1,
        'script_check' => 0,
        'rate_limit' => 5,
        'rate_window' => 600,
        'exclude' => '',
        'message' => '',
        'log_days' => 30,
    ];

    private const AI_AGENTS = [
        'GPTBot', 'ChatGPT-User', 'OAI-SearchBot', 'ClaudeBot', 'Claude-User', 'Claude-SearchBot', 'claude-web', 'anthropic-ai',
        'PerplexityBot', 'Perplexity-User', 'Google-Extended', 'GoogleOther', 'Google-CloudVertexBot', 'Bytespider', 'CCBot',
        'Amazonbot', 'Applebot-Extended', 'meta-externalagent', 'meta-externalfetcher', 'FacebookBot', 'Diffbot', 'cohere-ai',
        'cohere-training-data-crawler', 'YouBot', 'MistralAI-User', 'DuckAssistBot', 'AI2Bot', 'Ai2Bot-Dolma', 'Timpibot',
        'omgili', 'ImagesiftBot', 'PetalBot', 'Kangaroo Bot', 'iaskspider', 'Novellum', 'Manus', 'Operator',
    ];

    private const HEADLESS_MARKERS = ['HeadlessChrome', 'Puppeteer', 'Playwright', 'PhantomJS', 'Selenium', 'webdriver', 'Electron/', 'jsdom'];

    private const TOOL_AGENTS = ['curl/', 'Wget/', 'python-requests', 'python-urllib', 'aiohttp', 'httpx', 'Go-http-client', 'Java/', 'okhttp',
        'libwww-perl', 'Apache-HttpClient', 'Scrapy', 'node-fetch', 'axios/', 'undici', 'PostmanRuntime', 'Guzzle', 'HTTPie', 'Ruby'];

    private static bool $scriptAdded = false;

    // ------------------------------------------------------------------ config

    public static function config(string $key): mixed
    {
        return rex_addon::get('upkeep')->getConfig('form_protection_' . $key, self::DEFAULTS[$key] ?? null);
    }

    public static function isActive(): bool
    {
        return (bool) self::config('active');
    }

    public static function isStrict(): bool
    {
        return 'strict' === self::config('level');
    }

    // ------------------------------------------------------------------ registration

    /**
     * Registers the YForm hook. Call from boot.php (cheap; does nothing in backend or when inactive).
     */
    public static function register(): void
    {
        try {
            if (!rex::isFrontend() || !self::isActive()) {
                return;
            }
            rex_extension::register('YFORM_GENERATE', [self::class, 'onGenerate']);
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * EP YFORM_GENERATE: appends the protection element to the form.
     */
    public static function onGenerate(rex_extension_point $ep): void
    {
        try {
            $yform = $ep->getSubject();
            if (!$yform instanceof rex_yform || !rex::isFrontend() || rex::isBackend()) {
                return;
            }
            $objparams = &$yform->objparams;
            if (self::isOptOut($objparams[self::OBJPARAM] ?? null)) {
                return;
            }
            if (self::isExcluded((string) ($objparams['form_name'] ?? ''))) {
                return;
            }
            foreach ((array) ($objparams['form_elements'] ?? []) as $element) {
                $type = is_array($element) ? trim((string) ($element[0] ?? '')) : '';
                if (self::ELEMENT === $type) {
                    return; // already added
                }
                if (str_starts_with($type, 'ycom_auth')) {
                    return; // login forms: password managers submit instantly
                }
            }
            $objparams['form_elements'][] = [self::ELEMENT, self::ELEMENT];
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    public static function isOptOut(mixed $value): bool
    {
        if (null === $value) {
            return false;
        }
        return false === $value || 0 === $value || '0' === $value || 'false' === $value || 'off' === $value;
    }

    private static function isExcluded(string $formName): bool
    {
        $list = preg_split('/[\s,]+/', (string) self::config('exclude'), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        return '' !== $formName && in_array($formName, $list, true);
    }

    // ------------------------------------------------------------------ value hook

    /**
     * Called by rex_yform_value_upkeep_protect::preValidateAction().
     */
    public static function process(rex_yform_value_abstract $field): void
    {
        try {
            $params = &$field->params;
            if (self::isOptOut($params[self::OBJPARAM] ?? null) || !self::isActive() || !rex::isFrontend()) {
                return;
            }

            $formName = (string) ($params['form_name'] ?? 'formular');
            $honeypot = self::honeypotName($formName, $params);
            $carryTs = null;

            if (!empty($params['send']) && $field->needsOutput()) {
                $result = self::evaluate($formName, $honeypot, $params);
                $carryTs = $result['token_ts'];
                if ($result['score'] >= self::threshold()) {
                    $params['warning'][$field->getId()] = $params['error_class'] ?? 'has-error';
                    $params['warning_messages'][$field->getId()] = self::message();
                    self::reject($formName, $result);
                    $carryTs = null;
                }
            }

            if ($field->needsOutput()) {
                $params['form_output'][$field->getId()] = self::renderFields($formName, $honeypot, (string) $field->getId(), $carryTs);
            }
        } catch (Throwable $e) {
            rex_logger::logException($e); // fail open
        }
    }

    /**
     * Called by rex_yform_value_upkeep_protect::postValidateAction(): counts the submission for the
     * rate limit only when it will actually be processed (no warnings), so humans fixing
     * validation errors do not use up their quota.
     */
    public static function countSubmission(rex_yform_value_abstract $field): void
    {
        try {
            $params = &$field->params;
            if (empty($params['send']) || self::isOptOut($params[self::OBJPARAM] ?? null) || !self::isActive()) {
                return;
            }
            if (0 === count($params['warning'] ?? []) && 0 === count($params['warning_messages'] ?? [])) {
                $formName = (string) ($params['form_name'] ?? 'formular');
                Altcha::throttle('form', ClientIp::bucket(Altcha::clientIp()) . '|' . $formName, (int) self::config('rate_limit'), (int) self::config('rate_window'));
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    public static function threshold(): int
    {
        return self::isStrict() ? (int) self::config('threshold_strict') : (int) self::config('threshold');
    }

    // ------------------------------------------------------------------ evaluation

    /**
     * Scores the current submission. Public for tests/diagnostics.
     *
     * @return array{score: int, reasons: array<string, int>, token_ts: ?int}
     */
    public static function evaluate(string $formName, string $honeypot, array $params = []): array
    {
        $strict = self::isStrict();
        $reasons = [];
        $add = static function (string $code, int $points) use (&$reasons): void {
            $reasons[$code] = ($reasons[$code] ?? 0) + $points;
        };
        $req = $_REQUEST;
        $tokenTs = null;

        // 1. honeypot
        $hp = $req[$honeypot] ?? '';
        if (is_array($hp) || '' !== trim((string) $hp)) {
            $add('honeypot', 100);
        }

        // 2. signed timestamp token
        $token = is_string($req[self::FIELD_TOKEN] ?? null) ? $req[self::FIELD_TOKEN] : '';
        if ('' === $token) {
            $add('token_missing', 70);
        } else {
            $ts = self::verifyToken($token, $formName, $honeypot);
            if (null === $ts) {
                $add('token_invalid', 70);
            } else {
                $age = time() - $ts;
                $min = max(0, (int) self::config('min_time'));
                if ($age < 1) {
                    $add('too_fast', 70);
                } elseif ($age < $min) {
                    $add('too_fast', 50);
                } elseif ($age > (int) self::config('max_age')) {
                    $add('token_expired', 40);
                } else {
                    $tokenTs = $ts;
                }
            }
        }

        // 3. background proof-of-work
        $pow = is_string($req[self::FIELD_POW] ?? null) ? $req[self::FIELD_POW] : '';
        if (self::config('pow')) {
            if ('' === $pow) {
                $add('pow_missing', 30);
            } elseif (!Altcha::verify($pow, 'form')) {
                $add('pow_invalid', 60);
            }
        }

        // 4. interaction signals (collected by form-protection.js)
        $signals = self::parseSignals(is_string($req[self::FIELD_SIGNALS] ?? null) ? $req[self::FIELD_SIGNALS] : '');
        if (null !== $signals) {
            if ($signals['w'] > 0) {
                $add('webdriver', $strict ? 60 : 40);
            }
            $interaction = $signals['k'] + $signals['i'] + $signals['p'] + $signals['t'];
            if (0 === $interaction) {
                $add('no_interaction', 30);
            } elseif (0 === $signals['k'] && $signals['c'] > 0 && 0 === $signals['p'] && 0 === $signals['t']) {
                $add('paste_only', 15);
            }
        } elseif ('' !== $pow) {
            $add('signals_missing', 20);
        }

        // 5. agents
        foreach (self::detectAgent() as $code) {
            $add($code, match ($code) {
                'signature_agent', 'ai_agent' => $strict ? 100 : 25,
                'headless' => $strict ? 100 : 50,
                'tool_agent' => $strict ? 80 : 50,
                'empty_ua' => 40,
                default => 0,
            });
        }

        // 6. content
        $text = self::collectText($params);
        if ('' !== $text) {
            foreach (self::checkContent($text) as $code => $points) {
                $add($code, $points);
            }
        }

        // 7. rate limit (checked here, counted in countSubmission())
        if (!Altcha::throttle('form', ClientIp::bucket(Altcha::clientIp()) . '|' . $formName, (int) self::config('rate_limit'), (int) self::config('rate_window'), false)) {
            $add('rate_limit', 100);
        }

        return ['score' => array_sum($reasons), 'reasons' => $reasons, 'token_ts' => $tokenTs];
    }

    /**
     * @return list<string> detected agent codes
     */
    public static function detectAgent(): array
    {
        $codes = [];
        if ('' !== (string) ($_SERVER['HTTP_SIGNATURE_AGENT'] ?? '') || str_contains((string) ($_SERVER['HTTP_SIGNATURE_INPUT'] ?? ''), 'web-bot-auth')) {
            $codes[] = 'signature_agent';
        }
        $ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
        if ('' === trim($ua)) {
            $codes[] = 'empty_ua';
            return $codes;
        }
        foreach (self::AI_AGENTS as $needle) {
            if (false !== stripos($ua, $needle)) {
                $codes[] = 'ai_agent';
                break;
            }
        }
        foreach (self::HEADLESS_MARKERS as $needle) {
            if (false !== stripos($ua, $needle)) {
                $codes[] = 'headless';
                break;
            }
        }
        foreach (self::TOOL_AGENTS as $needle) {
            if (0 === stripos($ua, $needle) || false !== stripos($ua, ' ' . $needle)) {
                $codes[] = 'tool_agent';
                break;
            }
        }
        return array_values(array_unique($codes));
    }

    /**
     * @return array<string, int>
     */
    public static function checkContent(string $text): array
    {
        $result = [];
        $text = mb_substr($text, 0, 50000);

        $links = preg_match_all('~(?:https?://|www\.|<a\s)~i', $text);
        $max = max(0, (int) self::config('max_links'));
        if ($links > $max * 3 && $links > 0) {
            $result['links'] = 70;
        } elseif ($links > $max) {
            $result['links'] = 40;
        }

        if (preg_match('~\[(?:url|link)\s*=|\[/url\]~i', $text)) {
            $result['bbcode'] = 50;
        }

        if (self::config('badwords')) {
            $points = 0;
            foreach (self::badwords() as $bw) {
                $pattern = (string) ($bw['pattern'] ?? '');
                if ('' === $pattern) {
                    continue;
                }
                if (!empty($bw['is_regex'])) {
                    $hit = class_exists(PatternValidator::class) ? PatternValidator::match($pattern, $text) : (1 === @preg_match($pattern, $text));
                } else {
                    $hit = false !== mb_stripos($text, $pattern);
                }
                if (true === $hit) {
                    $points += match ((string) ($bw['severity'] ?? 'medium')) {
                        'low' => 10,
                        'high' => 50,
                        'critical' => 80,
                        default => 25,
                    };
                }
            }
            if ($points > 0) {
                $result['badword'] = min(100, $points);
            }
        }

        if (self::config('script_check')) {
            $letters = preg_match_all('/\p{L}/u', $text);
            $foreign = preg_match_all('/[\p{Cyrillic}\p{Han}\p{Arabic}\p{Thai}\p{Hangul}]/u', $text);
            if ($letters >= 20 && $foreign / max(1, $letters) > 0.5) {
                $result['foreign_script'] = 30;
            }
        }

        return $result;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private static function badwords(): array
    {
        try {
            if (class_exists(MailSecurityFilter::class) && method_exists(MailSecurityFilter::class, 'getBadwords')) {
                return MailSecurityFilter::getBadwords();
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
        return [];
    }

    private static function collectText(array $params): string
    {
        $parts = [];
        foreach ((array) ($params['values'] ?? []) as $value) {
            if (!$value instanceof rex_yform_value_abstract || $value instanceof \rex_yform_value_upkeep_protect || $value instanceof \rex_yform_value_csrf) {
                continue;
            }
            $v = $value->getValue();
            if (is_string($v) && '' !== $v) {
                $parts[] = $v;
            } elseif (is_array($v)) {
                array_walk_recursive($v, static function ($item) use (&$parts): void {
                    if (is_string($item) && '' !== $item) {
                        $parts[] = $item;
                    }
                });
            }
        }
        return implode("\n", $parts);
    }

    /**
     * @return array{k: int, i: int, p: int, t: int, f: int, c: int, w: int}|null
     */
    public static function parseSignals(string $raw): ?array
    {
        if ('' === $raw || strlen($raw) > 200 || !str_starts_with($raw, 'v1')) {
            return null;
        }
        $out = ['k' => 0, 'i' => 0, 'p' => 0, 't' => 0, 'f' => 0, 'c' => 0, 'w' => 0];
        foreach (explode(';', $raw) as $pair) {
            if (preg_match('/^([kiptfcw])=(\d{1,6})$/', $pair, $m)) {
                $out[$m[1]] = min(100000, (int) $m[2]);
            }
        }
        return $out;
    }

    // ------------------------------------------------------------------ token

    public static function createToken(string $formName, string $honeypot, ?int $ts = null): string
    {
        $ts ??= time();
        $nonce = bin2hex(random_bytes(6));
        $sig = hash_hmac('sha256', $ts . '|' . $nonce . '|' . $formName . '|' . $honeypot, Altcha::deriveKey('form-token'));
        return $ts . '.' . $nonce . '.' . substr($sig, 0, 40);
    }

    /**
     * @return int|null timestamp when valid
     */
    public static function verifyToken(string $token, string $formName, string $honeypot): ?int
    {
        if (strlen($token) > 100 || !preg_match('/^(\d{9,11})\.([a-f0-9]{12})\.([a-f0-9]{40})$/', $token, $m)) {
            return null;
        }
        $expected = substr(hash_hmac('sha256', $m[1] . '|' . $m[2] . '|' . $formName . '|' . $honeypot, Altcha::deriveKey('form-token')), 0, 40);
        if (!hash_equals($expected, $m[3])) {
            return null;
        }
        $ts = (int) $m[1];
        return $ts > time() + 60 ? null : $ts;
    }

    private static function honeypotName(string $formName, array $params): string
    {
        $used = [];
        foreach ((array) ($params['values'] ?? []) as $value) {
            if ($value instanceof rex_yform_value_abstract) {
                $used[] = strtolower((string) $value->getName());
            }
        }
        $names = array_values(array_filter(self::HONEYPOT_NAMES, static fn (string $n): bool => !in_array($n, $used, true)));
        if (!$names) {
            $names = ['upk_hp_field'];
        }
        $index = hexdec(substr(hash_hmac('sha256', $formName, Altcha::deriveKey('honeypot')), 0, 6)) % count($names);
        return $names[$index];
    }

    // ------------------------------------------------------------------ output

    private static function renderFields(string $formName, string $honeypot, string $id, ?int $carryTs): string
    {
        $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $hpId = 'upk-' . substr(hash('sha256', $formName . '|' . $id), 0, 10);
        $token = self::createToken($formName, $honeypot, $carryTs);
        $label = self::msg('upkeep_form_protection_honeypot_label');

        $html = '<div class="upkeep-fp" aria-hidden="true" data-upkeep-fp="1" style="position:absolute!important;left:-10000px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important;clip-path:inset(50%)!important;white-space:nowrap!important;">'
            . '<label for="' . $e($hpId) . '">' . $e($label) . '</label>'
            . '<input type="text" id="' . $e($hpId) . '" name="' . $e($honeypot) . '" value="" tabindex="-1" autocomplete="off" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" data-form-type="other">'
            . '</div>'
            . '<input type="hidden" name="' . self::FIELD_TOKEN . '" value="' . $e($token) . '">';

        if (self::config('pow')) {
            $challenge = Altcha::createChallenge((int) self::config('pow_max_number'), (int) self::config('max_age'), 'form');
            $html .= '<input type="hidden" name="' . self::FIELD_POW . '" value="" data-upkeep-pow="' . $e((string) json_encode($challenge, JSON_UNESCAPED_SLASHES)) . '" data-upkeep-endpoint="' . $e(Altcha::endpointUrl('form')) . '">';
        }
        $html .= '<input type="hidden" name="' . self::FIELD_SIGNALS . '" value="" data-upkeep-signals="1">';

        if (!self::$scriptAdded) {
            self::$scriptAdded = true;
            $html .= '<script src="' . $e(BlockPage::assetUrl('js/form-protection.js')) . '" defer></script>';
        }
        return $html;
    }

    private static function message(): string
    {
        $custom = trim((string) self::config('message'));
        return '' !== $custom ? $custom : self::msg('upkeep_form_protection_message');
    }

    private static function msg(string $key): string
    {
        $locale = 'de_de';
        try {
            $clang = rex_clang::getCurrent();
            if ($clang && str_starts_with(strtolower($clang->getCode()), 'en')) {
                $locale = 'en_gb';
            }
        } catch (Throwable) {
        }
        return rex_i18n::rawMsgInLocale($key, $locale);
    }

    // ------------------------------------------------------------------ reject / log / stats

    /**
     * @param array{score: int, reasons: array<string, int>, token_ts: ?int} $result
     */
    private static function reject(string $formName, array $result): void
    {
        $ip = Altcha::clientIp();
        $codes = array_keys($result['reasons']);

        if (Altcha::throttle('form_log', $ip, 20, 600)) {
            self::log($formName, $codes, $result['score'], $ip);
        }

        $honeypot = isset($result['reasons']['honeypot']);
        if (self::config('report_ips') && ($honeypot || $result['score'] >= (int) self::config('report_threshold'))
            && method_exists(IntrusionPrevention::class, 'reportExternalThreat')) {
            $severity = $result['score'] >= 150 ? 'high' : 'medium';
            $details = 'form=' . mb_substr($formName, 0, 60) . '; score=' . $result['score'] . '; reasons=' . implode(',', $codes);
            try {
                IntrusionPrevention::reportExternalThreat('form_spam', $severity, $details, $ip);
            } catch (Throwable $e) {
                rex_logger::logException($e);
            }
        }

        try {
            rex_extension::registerPoint(new rex_extension_point('UPKEEP_FORM_SPAM_REJECTED', null, [
                'form_name' => $formName,
                'score' => $result['score'],
                'reasons' => $result['reasons'],
                'ip' => $ip,
            ]));
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * @param list<string> $codes
     */
    private static function log(string $formName, array $codes, int $score, string $ip): void
    {
        try {
            $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
            $sql = rex_sql::factory();
            $sql->setTable(rex::getTable('upkeep_form_log'));
            $sql->setValue('form_name', mb_substr($formName, 0, 191));
            $sql->setValue('reasons', mb_substr(implode(',', $codes), 0, 255));
            $sql->setValue('score', $score);
            $sql->setValue('ip_address', mb_substr($ip, 0, 45));
            $sql->setValue('user_agent', mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255));
            $sql->setValue('url', mb_substr(is_string($path) ? $path : '', 0, 255));
            $sql->setValue('created_at', date('Y-m-d H:i:s'));
            $sql->insert();

            if (random_int(1, 50) === 1) {
                self::cleanup();
            }
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
    }

    /**
     * Removes log entries older than form_protection_log_days and keeps at most 20000 rows.
     */
    public static function cleanup(): int
    {
        try {
            $days = max(1, (int) self::config('log_days'));
            $sql = rex_sql::factory();
            $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_form_log') . ' WHERE created_at < ?', [date('Y-m-d H:i:s', time() - $days * 86400)]);
            $removed = $sql->getRows();
            $sql->setQuery('SELECT id FROM ' . rex::getTable('upkeep_form_log') . ' ORDER BY id DESC LIMIT 1 OFFSET 20000');
            if ($sql->getRows() > 0) {
                $id = (int) $sql->getValue('id');
                $sql->setQuery('DELETE FROM ' . rex::getTable('upkeep_form_log') . ' WHERE id <= ?', [$id]);
                $removed += $sql->getRows();
            }
            return (int) $removed;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return 0;
        }
    }

    /**
     * @return array{days: int, total: int, by_day: array<string, int>, by_reason: array<string, int>, by_form: array<string, int>}
     */
    public static function getStats(int $days = 30): array
    {
        $days = max(1, min(365, $days));
        $stats = ['days' => $days, 'total' => 0, 'by_day' => [], 'by_reason' => [], 'by_form' => []];
        for ($i = $days - 1; $i >= 0; --$i) {
            $stats['by_day'][date('Y-m-d', strtotime('-' . $i . ' days'))] = 0;
        }
        try {
            $from = date('Y-m-d 00:00:00', strtotime('-' . ($days - 1) . ' days'));
            $sql = rex_sql::factory();
            $rows = $sql->getArray(
                'SELECT form_name, reasons, created_at FROM ' . rex::getTable('upkeep_form_log') . ' WHERE created_at >= ? ORDER BY id DESC LIMIT 20000',
                [$from],
            );
            foreach ($rows as $row) {
                ++$stats['total'];
                $day = substr((string) $row['created_at'], 0, 10);
                if (isset($stats['by_day'][$day])) {
                    ++$stats['by_day'][$day];
                }
                $form = (string) $row['form_name'];
                $stats['by_form'][$form] = ($stats['by_form'][$form] ?? 0) + 1;
                foreach (explode(',', (string) $row['reasons']) as $code) {
                    if ('' !== $code) {
                        $stats['by_reason'][$code] = ($stats['by_reason'][$code] ?? 0) + 1;
                    }
                }
            }
            arsort($stats['by_reason']);
            arsort($stats['by_form']);
        } catch (Throwable $e) {
            rex_logger::logException($e);
        }
        return $stats;
    }

    /**
     * @return list<array{id: int, form_name: string, reasons: string, score: int, ip_address: string, user_agent: string, url: string, created_at: string}>
     */
    public static function getRecent(int $limit = 50): array
    {
        try {
            $limit = max(1, min(500, $limit));
            $sql = rex_sql::factory();
            $rows = $sql->getArray('SELECT * FROM ' . rex::getTable('upkeep_form_log') . ' ORDER BY id DESC LIMIT ' . $limit);
            return array_map(static fn (array $r): array => [
                'id' => (int) $r['id'],
                'form_name' => (string) $r['form_name'],
                'reasons' => (string) $r['reasons'],
                'score' => (int) $r['score'],
                'ip_address' => (string) $r['ip_address'],
                'user_agent' => (string) $r['user_agent'],
                'url' => (string) $r['url'],
                'created_at' => (string) $r['created_at'],
            ], $rows);
        } catch (Throwable $e) {
            rex_logger::logException($e);
            return [];
        }
    }
}
