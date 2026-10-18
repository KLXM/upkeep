<?php

namespace KLXM\Upkeep;

use rex_addon;

/**
 * Seiten, die nur bei eingeschaltetem Modul erreichbar sind.
 * Ausgeschaltete Module: Menüpunkt ausgeblendet, direkter Aufruf zeigt nur einen Hinweis (keine Bearbeitung).
 * Ereignisse und Statistik bleiben sichtbar – sie zeigen den bisherigen Verlauf.
 */
final class ModuleGate
{
    /** Seite (ohne „upkeep/“) => [Schalter, Standardwert, Abschnitt in den Einstellungen] */
    public const PAGES = [
        'maintenance/redirects' => ['domain_mapping_active', 0, 'redirects'],
        'protection/blocked' => ['ips_active', 0, 'ips'],
        'protection/allowlist' => ['ips_active', 0, 'ips'],
        'protection/patterns' => ['ips_active', 0, 'ips'],
        'protection/forms' => ['form_protection_active', 0, 'forms'],
        'protection/mail' => ['mail_security_active', 0, 'mail'],
        'advisor' => ['advisor_active', 1, 'advisor'],
    ];

    /** Abschnitt der Einstellungen, wenn die Seite wegen eines ausgeschalteten Moduls gesperrt ist, sonst null */
    public static function disabledSection(string $page): ?string
    {
        $page = preg_replace('#^upkeep/#', '', $page) ?? $page;
        foreach (self::PAGES as $gated => [$key, $default, $section]) {
            if (($page === $gated || str_starts_with($page, $gated . '/')) && !rex_addon::get('upkeep')->getConfig($key, $default)) {
                return $section;
            }
        }
        return null;
    }
}
