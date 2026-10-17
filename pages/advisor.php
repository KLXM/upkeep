<?php

/**
 * Empfehlungen (früher Security Advisor): ruhige Liste offener Punkte.
 * Geprüft wird nur auf Knopfdruck, per Cronjob oder Konsole – nie beim bloßen Aufruf der Seite.
 */

use KLXM\Upkeep\SecurityAdvisor;
use KLXM\Upkeep\Ui;

$addon = rex_addon::get('upkeep');
$user = rex::requireUser();
$isAdmin = $user->isAdmin();
$advisor = new SecurityAdvisor();
$csrf = rex_csrf_token::factory('upkeep_advisor');

// Automatische Korrekturen, die der Advisor anbietet (nur Admins)
$fixes = [
    'live_mode' => ['method' => 'enableLiveMode', 'label' => 'upkeep_advisor_fix_live_mode', 'confirm' => 'upkeep_advisor_fix_live_mode_confirm'],
    'content_security_policy' => ['method' => 'enableCSP', 'label' => 'upkeep_advisor_fix_csp', 'confirm' => ''],
    'hsts' => ['method' => 'enableHSTS', 'label' => 'upkeep_advisor_fix_hsts', 'confirm' => 'upkeep_advisor_fix_hsts_confirm'],
    'session_security' => ['method' => 'enableSessionSecurity', 'label' => 'upkeep_advisor_fix_session', 'confirm' => ''],
];

if ('post' === rex_request_method() && '' !== rex_post('upk_action', 'string', '')) {
    if (!$csrf->isValid()) {
        echo rex_view::error(rex_i18n::msg('csrf_token_invalid'));
    } else {
        $action = rex_post('upk_action', 'string');
        $check = rex_post('check', 'string', '');
        if ('export' === $action && $isAdmin && ($cached = SecurityAdvisor::getCachedResults())) {
            rex_response::cleanOutputBuffers();
            rex_response::setHeader('Content-Disposition', 'attachment; filename="upkeep-empfehlungen-' . date('Y-m-d') . '.json"');
            rex_response::sendContent((string) json_encode($cached, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), 'application/json');
            exit;
        }
        if ('scan' === $action) {
            @set_time_limit(60);
            $advisor->runAllChecks();
            echo rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_advisor_scan_done')));
        } elseif ('hide' === $action && $isAdmin && '' !== $check) {
            $advisor->setAdminRelease($check);
            echo rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_advisor_hidden', (string) (int) $addon->getConfig('admin_release_days', 30))));
        } elseif ('unhide' === $action && $isAdmin && '' !== $check) {
            $advisor->removeAdminRelease($check);
            echo rex_view::success(rex_escape(rex_i18n::rawMsg('upkeep_advisor_unhidden')));
        } elseif ('fix' === $action && $isAdmin && isset($fixes[$check])) {
            $method = $fixes[$check]['method'];
            $result = $advisor->$method();
            if (!empty($result['success'])) {
                $advisor->runAllChecks();
                echo rex_view::success(rex_escape((string) ($result['message'] ?? rex_i18n::rawMsg('upkeep_advisor_fix_done'))));
            } else {
                echo rex_view::error(rex_escape((string) ($result['message'] ?? rex_i18n::rawMsg('upkeep_advisor_fix_failed'))));
            }
        }
    }
}

$recs = $advisor->getRecommendations();

// Kopfzeile: Stand + Prüfen
$head = '<div class="upk-hero">'
    . '<div class="upk-hero-main">' . Ui::icon('fa-lightbulb-o', 'orange')
    . '<div><h2>' . rex_escape(rex_i18n::rawMsg('upkeep_advisor_title')) . '</h2>'
    . '<p>' . rex_escape($recs['last_check'] > 0
        ? rex_i18n::rawMsg('upkeep_advisor_last_check', Ui::date($recs['last_check']))
        : rex_i18n::rawMsg('upkeep_advisor_never_checked')) . '</p></div></div>'
    . '<div class="upk-hero-actions">'
    . Ui::postButton('scan', rex_i18n::rawMsg('upkeep_advisor_scan_now'), 'upkeep_advisor', [], 'btn-default', '', 'fa-refresh')
    . ($isAdmin && $recs['last_check'] > 0 ? Ui::postButton('export', rex_i18n::rawMsg('upkeep_advisor_export'), 'upkeep_advisor', [], 'btn-default', '', 'fa-download') : '')
    . '</div></div>';
echo $head;

if ($recs['last_check'] <= 0) {
    echo '<div class="upk-group"><div class="upk-empty"><i class="rex-icon fa fa-lightbulb-o"></i>'
        . rex_escape(rex_i18n::rawMsg('upkeep_advisor_empty_never')) . '</div></div>';
    return;
}

$priorityLabel = [
    'high' => ['upkeep_advisor_priority_high', 'danger'],
    'medium' => ['upkeep_advisor_priority_medium', 'warn'],
    'low' => ['upkeep_advisor_priority_low', 'info'],
];

$renderItem = static function (array $item, bool $hidden) use ($addon, $isAdmin, $fixes, $priorityLabel): string {
    $body = '<div class="upk-rec-body"><strong>' . rex_escape($item['name']) . '</strong> ';
    if (!$hidden && isset($priorityLabel[$item['priority']])) {
        $body .= Ui::badge(rex_i18n::rawMsg($priorityLabel[$item['priority']][0]), $priorityLabel[$item['priority']][1]);
    }
    if ('' !== $item['description']) {
        $body .= '<p>' . rex_escape($item['description']) . '</p>';
    }
    if ($item['recommendations']) {
        $body .= '<ul>';
        foreach (array_slice($item['recommendations'], 0, 6) as $text) {
            $body .= '<li>' . rex_escape($text) . '</li>';
        }
        $body .= '</ul>';
    }
    $body .= '</div>';

    $actions = '';
    if ($isAdmin) {
        if (!$hidden && isset($fixes[$item['key']])) {
            $fix = $fixes[$item['key']];
            $actions .= Ui::postButton('fix', rex_i18n::rawMsg($fix['label']), 'upkeep_advisor', ['check' => $item['key']], 'btn-primary btn-xs', '' !== $fix['confirm'] ? rex_i18n::rawMsg($fix['confirm']) : '');
        }
        $actions .= $hidden
            ? Ui::postButton('unhide', rex_i18n::rawMsg('upkeep_advisor_unhide'), 'upkeep_advisor', ['check' => $item['key']])
            : Ui::postButton('hide', rex_i18n::rawMsg('upkeep_advisor_hide'), 'upkeep_advisor', ['check' => $item['key']]);
    }

    return '<div class="upk-row"><div class="upk-rec">' . $body . ('' !== $actions ? '<div class="upk-rec-actions">' . $actions . '</div>' : '') . '</div></div>';
};

// Offene Empfehlungen
if ($recs['open']) {
    $rows = array_map(static fn ($i) => $renderItem($i, false), $recs['open']);
    echo Ui::group(rex_i18n::rawMsg('upkeep_advisor_open', (string) count($recs['open'])), $rows,
        $isAdmin ? rex_i18n::rawMsg('upkeep_advisor_hide_note', (string) (int) $addon->getConfig('admin_release_days', 30)) : '');
} else {
    echo Ui::group('', ['<div class="upk-empty"><i class="rex-icon fa fa-check"></i>' . rex_escape(rex_i18n::rawMsg('upkeep_advisor_all_done')) . '</div>']);
}

// Ausgeblendet / Erfüllt – eingeklappt
if ($recs['hidden']) {
    echo '<details class="upk-group"><summary>' . rex_escape(rex_i18n::rawMsg('upkeep_advisor_hidden_title', (string) count($recs['hidden']))) . '</summary>'
        . implode('', array_map(static fn ($i) => $renderItem($i, true), $recs['hidden'])) . '</details>';
}
if ($recs['passed']) {
    $rows = '';
    foreach ($recs['passed'] as $item) {
        $rows .= Ui::row($item['name'], Ui::badge(rex_i18n::rawMsg('upkeep_advisor_passed_badge'), 'ok'), $item['description']);
    }
    echo '<details class="upk-group"><summary>' . rex_escape(rex_i18n::rawMsg('upkeep_advisor_passed_title', (string) count($recs['passed']))) . '</summary>' . $rows . '</details>';
}

echo '<p class="upk-group-note">' . rex_escape(rex_i18n::rawMsg('upkeep_advisor_cron_note')) . '</p>';
