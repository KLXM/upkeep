<?php

/**
 * upkeep 3 – Boot
 *
 * Reihenfolge:
 * 1. Berichte (MailReporting) registrieren, damit Ereignisse des IPS ankommen
 * 2. IPS prüft die Anfrage (nur Frontend, fehlertolerant)
 * 3. Formularschutz für YForm registrieren
 * 4. Backend: Sperre prüfen, Styles, Menü, Cronjobs
 * 5. Nach dem Laden aller AddOns: Wartung im Frontend und Weiterleitungen (YRewrite ist dann verfügbar)
 */

use KLXM\Upkeep\FormProtection;
use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\MailReporting;
use KLXM\Upkeep\MailSecurityFilter;
use KLXM\Upkeep\Upkeep;

if (rex::isSetup()) {
    return;
}

$addon = rex_addon::get('upkeep');

$safe = static function (callable $fn): void {
    try {
        $fn();
    } catch (Throwable $e) {
        // upkeep darf eine Seite nie wegen eines eigenen Fehlers unbenutzbar machen
        rex_logger::logException($e);
    }
};

$safe(static fn () => MailReporting::init());
IntrusionPrevention::checkRequest();
$safe(static fn () => FormProtection::register());

if (rex::isBackend()) {
    rex_backend_login::createUser();
    if (rex::getUser()) {
        Upkeep::checkBackend();
    }
}

rex_extension::register('PACKAGES_INCLUDED', static function () use ($addon, $safe) {
    if (rex::isFrontend()) {
        Upkeep::checkFrontend();
        $safe(static fn () => Upkeep::checkDomainMapping());
        return;
    }

    if (!rex::isBackend()) {
        return;
    }

    rex_view::addCssFile($addon->getAssetsUrl('css/upkeep.css'));

    // Menü: nur aktive Wartung wird angezeigt – ruhig, ohne Zähler
    $page = $addon->getProperty('page');
    if (is_array($page) && isset($page['title'])) {
        $marks = [];
        if ($addon->getConfig('frontend_active', false)) {
            $marks[] = '<span class="upkeep-nav-indicator" title="' . rex_escape(rex_i18n::rawMsg('upkeep_indicator_frontend')) . '">F</span>';
        }
        if ($addon->getConfig('backend_active', false)) {
            $marks[] = '<span class="upkeep-nav-indicator" title="' . rex_escape(rex_i18n::rawMsg('upkeep_indicator_backend')) . '">B</span>';
        }
        if ($marks) {
            $page['title'] = (str_starts_with((string) $page['title'], 'translate:') ? rex_i18n::rawMsg(substr((string) $page['title'], 10)) : $page['title']) . ' ' . implode('', $marks);
            $addon->setProperty('page', $page);
        }
    }

    if (rex_addon::get('cronjob')->isAvailable() && !rex::isSafeMode()) {
        rex_cronjob_manager::registerType(rex_upkeep_ips_cleanup_cronjob::class);
        rex_cronjob_manager::registerType(rex_upkeep_storage_cronjob::class);
        rex_cronjob_manager::registerType(rex_upkeep_advisor_cronjob::class);
        rex_cronjob_manager::registerType(rex_upkeep_mail_reporting_cronjob::class);
    }
}, rex_extension::EARLY);

// Menü: Bereiche ohne erlaubte Unterseiten ausblenden (z. B. „Schutz“ für Redakteure ohne Schutz-Rechte)
if (rex::isBackend()) {
    rex_extension::register('PAGES_PREPARED', static function () {
        $main = rex_be_controller::getPageObject('upkeep');
        $user = rex::getUser();
        if (!$main || !$user) {
            return;
        }
        foreach (['maintenance', 'protection'] as $key) {
            $sub = $main->getSubpage($key);
            if (!$sub) {
                continue;
            }
            $visible = array_filter($sub->getSubpages(), static fn (rex_be_page $p) => $p->checkPermission($user));
            if ('maintenance' === $key && !rex_addon::get('yrewrite')->isAvailable()) {
                $sub->getSubpage('domains')?->setHidden(true);
                unset($visible['domains']);
            }
            if (!$visible) {
                $sub->setHidden(true);
            }
        }
    });
}

// Hinweis für Admins, die als Redakteur angemeldet sind, während das Backend gesperrt ist (einmal pro Sitzung)
if (rex::isBackend() && $addon->getConfig('backend_active', false)) {
    rex_extension::register('OUTPUT_FILTER', static function (rex_extension_point $ep) {
        $impersonator = rex::getImpersonator();
        $user = rex::getUser();
        if (!$impersonator instanceof rex_user || ($user instanceof rex_user && $user->isAdmin())) {
            return $ep->getSubject();
        }
        $title = json_encode(rex_i18n::rawMsg('upkeep_impersonate_warning_title'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        $name = $user instanceof rex_user ? ($user->getName() ?: $user->getLogin()) : '';
        $message = json_encode(rex_i18n::rawMsg('upkeep_impersonate_warning_message', $name), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        $script = '<script nonce="' . rex_response::getNonce() . '">(function(){try{if(sessionStorage.getItem("upkeep_impersonate_shown"))return;sessionStorage.setItem("upkeep_impersonate_shown","1");'
            . 'jQuery(function(){var d=jQuery("<div class=\"alert alert-warning\" role=\"alert\"></div>");d.append(jQuery("<strong></strong>").text(' . $title . '),document.createTextNode(" "+' . $message . '));jQuery("#rex-js-page-main").prepend(d);});}catch(e){}})();</script>';
        return str_replace('</body>', $script . '</body>', $ep->getSubject());
    }, rex_extension::LATE);
}

// E-Mail-Schutz (nur Frontend; Fehler im Filter blockieren den Versand nicht stillschweigend, sondern werden protokolliert)
if (rex_addon::get('phpmailer')->isAvailable()) {
    rex_extension::register('PHPMAILER_PRE_SEND', static function (rex_extension_point $ep) {
        if (!rex::isFrontend() || PHP_SAPI === 'cli') {
            return $ep->getSubject();
        }
        return MailSecurityFilter::filterMail($ep);
    });
}

// Content-Security-Policy für das Backend (wird über die Empfehlungen eingeschaltet)
if (rex::isBackend() && $addon->getConfig('csp_enabled', false)) {
    // Unverändert aus 2.x, damit bestehende Backends nach dem Update weiter funktionieren
    $rules = [
        'script-src' => ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        'style-src' => ["'self'", "'unsafe-inline'"],
        'base-uri' => ["'self'"],
        'object-src' => ["'none'"],
        'frame-ancestors' => ["'self'"],
        'form-action' => ["'self'"],
        'img-src' => ["'self'", 'data:', 'https:'],
        'connect-src' => ["'self'"],
    ];
    rex_response::setHeader('Content-Security-Policy', implode('; ', array_map(static fn ($k, $v) => $k . ' ' . implode(' ', $v), array_keys($rules), $rules)));
}
