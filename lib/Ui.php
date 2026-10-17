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

    public static function date(int $timestamp): string
    {
        return $timestamp > 0 ? \rex_formatter::intlDateTime($timestamp, [\IntlDateFormatter::MEDIUM, \IntlDateFormatter::SHORT]) : '–';
    }
}
