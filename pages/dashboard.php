<?php

/**
 * Übersicht für alle: dieselbe Seite für Admins, Redakteure und Kunden.
 * Welche Kacheln erscheinen, hängt von den Rechten ab. Es wird nichts geprüft oder berechnet,
 * was Zeit kostet – alle Zahlen kommen aus Zwischenspeichern oder einfachen Zählabfragen.
 */

use KLXM\Upkeep\FormProtection;
use KLXM\Upkeep\IntrusionPrevention;
use KLXM\Upkeep\MailSecurityFilter;
use KLXM\Upkeep\SecurityAdvisor;
use KLXM\Upkeep\Storage;
use KLXM\Upkeep\Ui;
use KLXM\Upkeep\Upkeep;

$addon = rex_addon::get('upkeep');
$user = rex::requireUser();
$isAdmin = $user->isAdmin();
$can = static fn (string $perm) => $user->hasPerm('upkeep[' . $perm . ']');
$csrf = rex_csrf_token::factory('upkeep_dashboard');

// ---------- Aktionen ----------
if ('post' === rex_request_method() && '' !== rex_post('upk_action', 'string', '')) {
    if (!$csrf->isValid()) {
        echo rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        $action = rex_post('upk_action', 'string');
        if (in_array($action, ['frontend_on', 'frontend_off'], true) && $can('maintenance')) {
            $on = 'frontend_on' === $action;
            if (method_exists(Upkeep::class, 'setMaintenance')) {
                Upkeep::setMaintenance('frontend', $on, 'dashboard');
            } else {
                $addon->setConfig('frontend_active', $on ? 1 : 0);
            }
            echo rex_view::success(rex_escape(rex_i18n::rawMsg($on ? 'upkeep_dash_frontend_now_on' : 'upkeep_dash_frontend_now_off')));
        } elseif ('dismiss_notes' === $action && $isAdmin) {
            $addon->removeConfig('migration_notes');
        }
    }
}

$frontendOn = (bool) $addon->getConfig('frontend_active', false);
$backendOn = (bool) $addon->getConfig('backend_active', false);

// ---------- Hinweise nach dem Update (einmalig, nur Admins) ----------
$notes = (array) $addon->getConfig('migration_notes', []);
if ($isAdmin && $notes) {
    $items = '';
    foreach ($notes as $note) {
        $items .= '<li>' . rex_escape(rex_i18n::rawMsg('upkeep_migration_' . $note)) . '</li>';
    }
    echo '<div class="alert alert-info"><strong>' . rex_escape(rex_i18n::rawMsg('upkeep_migration_title')) . '</strong><ul>' . $items . '</ul>'
        . Ui::postButton('dismiss_notes', rex_i18n::rawMsg('upkeep_migration_dismiss'), 'upkeep_dashboard', [], 'btn-default btn-xs') . '</div>';
}

// ---------- Kopf: Status der Website ----------
if ($frontendOn) {
    $heroIcon = Ui::icon('fa-power-off', 'red');
    $heroTitle = rex_i18n::rawMsg('upkeep_dash_site_maintenance');
    $heroText = rex_i18n::rawMsg('upkeep_dash_site_maintenance_text');
} else {
    $heroIcon = Ui::icon('fa-check', 'green');
    $heroTitle = rex_i18n::rawMsg('upkeep_dash_site_online');
    $heroText = rex_i18n::rawMsg('upkeep_dash_site_online_text');
}
if ($backendOn) {
    $heroText .= ' ' . rex_i18n::rawMsg('upkeep_dash_backend_locked');
}
$heroActions = '';
if ($can('maintenance')) {
    $heroActions .= $frontendOn
        ? Ui::postButton('frontend_off', rex_i18n::rawMsg('upkeep_dash_frontend_off'), 'upkeep_dashboard', [], 'btn-primary', '', 'fa-play')
        : Ui::postButton('frontend_on', rex_i18n::rawMsg('upkeep_dash_frontend_on'), 'upkeep_dashboard', [], 'btn-default', rex_i18n::rawMsg('upkeep_dash_frontend_on_confirm'), 'fa-power-off');
    $heroActions .= '<a class="btn btn-default" href="' . rex_url::backendPage('upkeep/maintenance/status') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_maintenance_details')) . '</a>';
}
echo '<div class="upk-hero"><div class="upk-hero-main">' . $heroIcon . '<div><h2>' . rex_escape($heroTitle) . '</h2><p>' . rex_escape($heroText) . '</p></div></div>'
    . ('' !== $heroActions ? '<div class="upk-hero-actions">' . $heroActions . '</div>' : '') . '</div>';

// ---------- Kacheln ----------
$tiles = [];
$offTile = static function (string $title, string $iconHtml, string $section) use ($addon, $isAdmin): string {
    $foot = $isAdmin ? '<a href="' . rex_url::backendPage('upkeep/settings', ['section' => $section]) . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_enable')) . '</a>' : '';
    return Ui::tile($title, $iconHtml, '<div>' . Ui::badge(rex_i18n::rawMsg('upkeep_dash_off')) . '</div><p class="upk-tile-text">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_off_text')) . '</p>', $foot);
};
$safe = static function (callable $fn, mixed $fallback = null): mixed {
    try {
        return $fn();
    } catch (Throwable $e) {
        rex_logger::logException($e);
        return $fallback;
    }
};

// Schutz (IPS)
if ($can('ips')) {
    $title = rex_i18n::rawMsg('upkeep_dash_tile_ips');
    $icon = Ui::icon('fa-shield', 'blue');
    if ($addon->getConfig('ips_active', false)) {
        $stats = $safe(static fn () => IntrusionPrevention::getStatistics(), []) ?: [];
        $body = '<div class="upk-tile-value">' . (int) ($stats['threats_today'] ?? 0) . ' <small>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_today')) . '</small></div>'
            . '<ul class="upk-facts"><li><span>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_week')) . '</span><span>' . (int) ($stats['threats_week'] ?? 0) . '</span></li>'
            . '<li><span>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_blocked_ips')) . '</span><span>' . (int) ($stats['blocked_ips'] ?? 0) . '</span></li></ul>';
        $badge = $addon->getConfig('ips_monitor_only', false) ? Ui::badge(rex_i18n::rawMsg('upkeep_dash_monitor_only'), 'info') : Ui::badge(rex_i18n::rawMsg('upkeep_dash_on'), 'ok');
        $tiles[] = Ui::tile($title, $icon, $body, $badge . '<span class="upk-tile-links">'
            . ($isAdmin ? '<a href="' . rex_url::backendPage('upkeep/protection/stats') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_stats_link')) . '</a>' : '')
            . '<a href="' . rex_url::backendPage('upkeep/protection/events') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_show_events')) . '</a></span>');
    } else {
        $tiles[] = $offTile($title, $icon, 'ips');
    }
}

// Formularschutz
if ($can('forms')) {
    $title = rex_i18n::rawMsg('upkeep_dash_tile_forms');
    $icon = Ui::icon('fa-wpforms', 'green');
    if ($addon->getConfig('form_protection_active', false) && class_exists(FormProtection::class)) {
        $stats = $safe(static fn () => FormProtection::getStats(30), []) ?: [];
        $body = '<div class="upk-tile-value">' . (int) ($stats['total'] ?? 0) . ' <small>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_forms_rejected')) . '</small></div>'
            . '<p class="upk-tile-text">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_forms_text')) . '</p>';
        $tiles[] = Ui::tile($title, $icon, $body, Ui::badge(rex_i18n::rawMsg('upkeep_dash_on'), 'ok') . '<a href="' . rex_url::backendPage('upkeep/protection/forms') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_show_details')) . '</a>');
    } else {
        $tiles[] = $offTile($title, $icon, 'forms');
    }
}

// E-Mail-Schutz
if ($can('mail_security')) {
    $title = rex_i18n::rawMsg('upkeep_dash_tile_mail');
    $icon = Ui::icon('fa-envelope-o', 'teal');
    if ($addon->getConfig('mail_security_active', false)) {
        $stats = $safe(static fn () => MailSecurityFilter::getDashboardStats(), []) ?: [];
        $body = '<div class="upk-tile-value">' . (int) ($stats['blocked_emails_24h'] ?? 0) . ' <small>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_mail_blocked_24h')) . '</small></div>'
            . '<ul class="upk-facts"><li><span>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_mail_threats_24h')) . '</span><span>' . (int) ($stats['threats_24h'] ?? 0) . '</span></li></ul>';
        $tiles[] = Ui::tile($title, $icon, $body, Ui::badge(rex_i18n::rawMsg('upkeep_dash_on'), 'ok') . '<a href="' . rex_url::backendPage('upkeep/protection/mail') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_show_details')) . '</a>');
    } else {
        $tiles[] = $offTile($title, $icon, 'mail');
    }
}

// Empfehlungen
if ($can('advisor') && $addon->getConfig('advisor_active', true)) {
    $recs = (new SecurityAdvisor())->getRecommendations();
    $open = count($recs['open']);
    $high = count(array_filter($recs['open'], static fn ($r) => 'high' === $r['priority']));
    if ($recs['last_check'] > 0) {
        $body = '<div class="upk-tile-value">' . $open . ' <small>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_recs_open')) . '</small></div>'
            . '<p class="upk-tile-text">' . rex_escape($high > 0 ? rex_i18n::rawMsg('upkeep_dash_recs_high', (string) $high) : rex_i18n::rawMsg('upkeep_dash_recs_calm')) . '</p>';
        $foot = '<span class="upk-muted">' . rex_escape(Ui::date($recs['last_check'])) . '</span>';
    } else {
        $body = '<p class="upk-tile-text">' . rex_escape(rex_i18n::rawMsg('upkeep_advisor_never_checked')) . '</p>';
        $foot = '';
    }
    $tiles[] = Ui::tile(rex_i18n::rawMsg('upkeep_dash_tile_advisor'), Ui::icon('fa-lightbulb-o', 'orange'), $body,
        $foot . '<a href="' . rex_url::backendPage('upkeep/advisor') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_show_recs')) . '</a>');
}

// Weiterleitungen
if ($can('domain_mapping')) {
    $title = rex_i18n::rawMsg('upkeep_dash_tile_redirects');
    $icon = Ui::icon('fa-share', 'indigo');
    if ($addon->getConfig('domain_mapping_active', false)) {
        $count = (int) $safe(static fn () => rex_sql::factory()->getArray('SELECT COUNT(*) AS c FROM ' . rex::getTable('upkeep_domain_mapping') . ' WHERE status = 1')[0]['c'] ?? 0, 0);
        $tiles[] = Ui::tile($title, $icon, '<div class="upk-tile-value">' . $count . ' <small>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_redirects_active')) . '</small></div>',
            Ui::badge(rex_i18n::rawMsg('upkeep_dash_on'), 'ok') . '<a href="' . rex_url::backendPage('upkeep/maintenance/redirects') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_show_details')) . '</a>');
    } else {
        $tiles[] = $offTile($title, $icon, 'redirects');
    }
}

// Speicher (für alle)
$report = class_exists(Storage::class) ? $safe(static fn () => Storage::getReport(), []) : [];
if ($report) {
    $cats = array_values((array) ($report['categories'] ?? []));
    usort($cats, static fn ($a, $b) => ((int) ($b['bytes'] ?? 0)) <=> ((int) ($a['bytes'] ?? 0)));
    $facts = '';
    foreach (array_slice($cats, 0, 3) as $cat) {
        if ((int) ($cat['bytes'] ?? 0) <= 0) {
            continue;
        }
        $facts .= '<li><span>' . rex_escape(rex_i18n::rawMsg('upkeep_storage_cat_' . ($cat['key'] ?? ''))) . '</span><span>' . rex_escape(rex_formatter::bytes((int) $cat['bytes'], [1])) . '</span></li>';
    }
    $body = '<div class="upk-tile-value">' . rex_escape(rex_formatter::bytes((int) ($report['total_bytes'] ?? 0), [1])) . '</div>'
        . ('' !== $facts ? '<ul class="upk-facts">' . $facts . '</ul>' : '');
    $foot = '<span class="upk-muted">' . rex_escape(Ui::date((int) ($report['computed_at'] ?? 0))) . '</span>';
} else {
    $body = '<p class="upk-tile-text">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_storage_none')) . '</p>';
    $foot = '';
}
$tiles[] = Ui::tile(rex_i18n::rawMsg('upkeep_dash_tile_storage'), Ui::icon('fa-hdd-o', 'gray'), $body,
    $foot . '<a href="' . rex_url::backendPage('upkeep/storage') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_dash_show_storage')) . '</a>');

// System (nur Admins)
if ($isAdmin) {
    $dbVersion = (string) $safe(static fn () => rex_sql::getServerVersion(), '');
    $facts = '<ul class="upk-facts">'
        . '<li><span>REDAXO</span><span>' . rex_escape(rex::getVersion()) . '</span></li>'
        . '<li><span>PHP</span><span>' . rex_escape(PHP_VERSION) . '</span></li>'
        . ('' !== $dbVersion ? '<li><span>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_database')) . '</span><span>' . rex_escape($dbVersion) . '</span></li>' : '')
        . '<li><span>upkeep</span><span>' . rex_escape($addon->getVersion()) . '</span></li>'
        . '<li><span>' . rex_escape(rex_i18n::rawMsg('upkeep_dash_debug')) . '</span><span>' . rex_escape(rex_i18n::rawMsg(rex::isDebugMode() ? 'upkeep_dash_on' : 'upkeep_dash_off')) . '</span></li>'
        . '</ul>';
    $tiles[] = Ui::tile(rex_i18n::rawMsg('upkeep_dash_tile_system'), Ui::icon('fa-server', 'purple'), $facts,
        '<a href="' . rex_url::backendPage('upkeep/settings') . '">' . rex_escape(rex_i18n::rawMsg('upkeep_nav_settings')) . '</a>');
}

// Ansprechpartner (für alle, wenn gepflegt)
$contact = trim((string) $addon->getConfig('maintenance_contact', ''));
if ('' !== $contact) {
    $tiles[] = Ui::tile(rex_i18n::rawMsg('upkeep_dash_tile_contact'), Ui::icon('fa-life-ring', 'pink'), '<p class="upk-tile-text">' . nl2br(rex_escape($contact)) . '</p>');
}

echo '<div class="upk-tiles">' . implode('', $tiles) . '</div>';
