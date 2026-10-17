<?php

namespace KLXM\Upkeep;

use rex_addon;
use rex_csrf_token;

/**
 * Kleine Bausteine für die Backend-Oberfläche (gruppierte Listen, Schalter, Kacheln).
 * Alle Texte werden hier escaped – Aufrufer übergeben Rohtext, nur $html-Parameter sind fertiges HTML.
 */
final class Ui
{
    public static function t(string $key, string ...$args): string
    {
        return \rex_i18n::rawMsg($key, ...$args);
    }

    public static function icon(string $fa, string $color, string $extraClass = ''): string
    {
        return '<span class="upk-row-icon upk-c-' . rex_escape($color) . ($extraClass ? ' ' . rex_escape($extraClass) : '') . '" aria-hidden="true"><i class="rex-icon fa ' . rex_escape($fa) . '"></i></span>';
    }

    public static function badge(string $text, string $variant = 'muted'): string
    {
        return '<span class="upk-badge upk-badge--' . rex_escape($variant) . '">' . rex_escape($text) . '</span>';
    }

    /** Eine Zeile: Beschriftung links, Bedienelement rechts */
    public static function row(string $label, string $controlHtml, string $help = '', string $forId = '', string $iconHtml = '', bool $stack = false): string
    {
        $labelTag = '' !== $forId
            ? '<label for="' . rex_escape($forId) . '">' . rex_escape($label) . '</label>'
            : '<strong>' . rex_escape($label) . '</strong>';
        return '<div class="upk-row' . ($stack ? ' upk-row--stack' : '') . '">'
            . $iconHtml
            . '<div class="upk-row-label">' . $labelTag . ('' !== $help ? '<small>' . rex_escape($help) . '</small>' : '') . '</div>'
            . '<div class="upk-row-control">' . $controlHtml . '</div>'
            . '</div>';
    }

    /** @param list<string> $rowsHtml */
    public static function group(string $title, array $rowsHtml, string $note = ''): string
    {
        $rowsHtml = array_filter($rowsHtml, static fn ($r) => '' !== $r);
        if (!$rowsHtml) {
            return '';
        }
        return ('' !== $title ? '<h3 class="upk-group-title">' . rex_escape($title) . '</h3>' : '')
            . '<div class="upk-group">' . implode('', $rowsHtml) . '</div>'
            . ('' !== $note ? '<p class="upk-group-note">' . rex_escape($note) . '</p>' : '');
    }

    public static function switch(string $name, bool $checked, string $id = '', bool $disabled = false, string $label = ''): string
    {
        $id = $id ?: 'upk-' . preg_replace('/[^a-z0-9_-]/i', '-', $name);
        return '<span class="upk-switch">'
            . '<input type="hidden" name="' . rex_escape($name) . '" value="0">'
            . '<input type="checkbox" role="switch" id="' . rex_escape($id) . '" name="' . rex_escape($name) . '" value="1"'
            . ($checked ? ' checked' : '') . ($disabled ? ' disabled' : '')
            . ('' !== $label ? ' aria-label="' . rex_escape($label) . '"' : '') . '>'
            . '<span></span></span>';
    }

    /** Formular mit einem Knopf (POST + CSRF) – für Aktionen in Listen und Kacheln. $url kommt fertig escaped aus rex_url. */
    public static function postButton(string $action, string $label, string $tokenName, array $extra = [], string $btnClass = 'btn-default btn-xs', string $confirm = '', string $faIcon = '', string $url = ''): string
    {
        $html = '<form method="post" class="upk-inline-form"' . ('' !== $url ? ' action="' . $url . '"' : '') . '>'
            . rex_csrf_token::factory($tokenName)->getHiddenField()
            . '<input type="hidden" name="upk_action" value="' . rex_escape($action) . '">';
        foreach ($extra as $k => $v) {
            $html .= '<input type="hidden" name="' . rex_escape((string) $k) . '" value="' . rex_escape((string) $v) . '">';
        }
        $html .= '<button type="submit" class="btn ' . rex_escape($btnClass) . '"' . ('' !== $confirm ? ' data-confirm="' . rex_escape($confirm) . '"' : '') . '>'
            . ('' !== $faIcon ? '<i class="rex-icon fa ' . rex_escape($faIcon) . '" aria-hidden="true"></i> ' : '')
            . rex_escape($label) . '</button></form>';
        return $html;
    }

    /** Kachel für die Übersicht */
    public static function tile(string $title, string $iconHtml, string $bodyHtml, string $footHtml = '', string $extraClass = ''): string
    {
        return '<section class="upk-tile' . ($extraClass ? ' ' . rex_escape($extraClass) : '') . '">'
            . '<div class="upk-tile-head">' . $iconHtml . '<h3>' . rex_escape($title) . '</h3></div>'
            . $bodyHtml
            . ('' !== $footHtml ? '<div class="upk-tile-foot">' . $footHtml . '</div>' : '')
            . '</section>';
    }

    /** Kopf einer Seite: Symbol, Titel, eine Zeile Einleitung, rechts Status und Aktionen ($actionsHtml ist fertiges HTML) */
    public static function hero(string $title, string $intro, string $iconHtml, string $actionsHtml = ''): string
    {
        return '<div class="upk-hero"><div class="upk-hero-main">' . $iconHtml
            . '<div><h2>' . rex_escape($title) . '</h2>' . ('' !== $intro ? '<p>' . rex_escape($intro) . '</p>' : '') . '</div></div>'
            . ('' !== $actionsHtml ? '<div class="upk-hero-actions">' . $actionsHtml . '</div>' : '')
            . '</div>';
    }

    /**
     * Umschalter als Segment-Leiste (statt Bootstrap-Tabs).
     *
     * @param array<string, array{0: string, 1: string}> $items key => [Beschriftung, URL (fertig escaped aus rex_url)]
     */
    public static function segmented(array $items, string $active, string $ariaLabel): string
    {
        $html = '<nav class="upk-segmented" aria-label="' . rex_escape($ariaLabel) . '">';
        foreach ($items as $key => [$label, $url]) {
            $html .= (string) $key === $active
                ? '<a class="active" aria-current="page" href="' . $url . '">' . rex_escape($label) . '</a>'
                : '<a href="' . $url . '">' . rex_escape($label) . '</a>';
        }
        return $html . '</nav>';
    }

    /** Seitenzahlen als kleine Segment-Leiste. $link liefert die fertig escapte URL zu einer Seite. */
    public static function pager(int $current, int $pages, callable $link): string
    {
        if ($pages <= 1) {
            return '';
        }
        $html = '<nav class="upk-segmented upk-segmented--pager" aria-label="' . rex_escape(self::t('upkeep_list_pages')) . '">';
        $html .= $current > 1
            ? '<a href="' . $link($current - 1) . '" aria-label="' . rex_escape(self::t('upkeep_previous')) . '">&lsaquo;</a>'
            : '<span class="disabled" aria-hidden="true">&lsaquo;</span>';
        for ($i = max(1, $current - 3); $i <= min($pages, $current + 3); ++$i) {
            $html .= $i === $current
                ? '<a class="active" aria-current="page" href="' . $link($i) . '">' . $i . '</a>'
                : '<a href="' . $link($i) . '">' . $i . '</a>';
        }
        $html .= $current < $pages
            ? '<a href="' . $link($current + 1) . '" aria-label="' . rex_escape(self::t('upkeep_next')) . '">&rsaquo;</a>'
            : '<span class="disabled" aria-hidden="true">&rsaquo;</span>';
        return $html . '</nav>';
    }

    /** Leerer Zustand: Symbol und ein Satz */
    public static function emptyState(string $text, string $fa = 'fa-check'): string
    {
        return '<div class="upk-empty"><i class="rex-icon fa ' . rex_escape($fa) . '" aria-hidden="true"></i>' . rex_escape($text) . '</div>';
    }

    /** Schweregrad als Kennzeichen (kritisch/hoch = rot, mittel = gelb, niedrig = blau) */
    public static function severity(string $severity): string
    {
        $variant = match ($severity) {
            'critical', 'high' => 'danger',
            'medium' => 'warn',
            'low' => 'info',
            default => 'muted',
        };
        $label = in_array($severity, ['low', 'medium', 'high', 'critical'], true) ? self::t('upkeep_ips_severity_' . $severity) : ('' !== $severity ? $severity : '–');
        return self::badge($label, $variant);
    }

    /** Status aktiv/inaktiv als Kennzeichen */
    public static function status(bool $on): string
    {
        return $on ? self::badge(self::t('upkeep_active'), 'ok') : self::badge(self::t('upkeep_inactive'), 'muted');
    }

    /** Titel über einer Liste, optional mit Anzahl */
    public static function listTitle(string $title, ?int $count = null): string
    {
        return '<h3 class="upk-group-title">' . rex_escape($title)
            . (null !== $count ? ' <span class="upk-count">' . $count . '</span>' : '') . '</h3>';
    }

    /** Zelle einer .upk-table mit Beschriftung für die Kartenansicht auf dem Handy ($html ist fertiges HTML) */
    public static function td(string $label, string $html, string $class = ''): string
    {
        return '<td data-label="' . rex_escape($label) . '"' . ('' !== $class ? ' class="' . rex_escape($class) . '"' : '') . '>' . $html . '</td>';
    }

    public static function date(int $timestamp): string
    {
        return $timestamp > 0 ? \rex_formatter::intlDateTime($timestamp, [\IntlDateFormatter::MEDIUM, \IntlDateFormatter::SHORT]) : '–';
    }
}
