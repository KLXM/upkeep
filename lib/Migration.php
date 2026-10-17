<?php

namespace KLXM\Upkeep;

use rex;
use rex_addon;
use rex_logger;
use rex_sql;
use Throwable;

/**
 * Überführt Einstellungen, Rechte und Daten aus upkeep 2.x nach 3.x.
 * Jeder Schritt ist idempotent und darf beliebig oft laufen (install.php und update.php rufen run() auf).
 */
final class Migration
{
    /** Alte Rechte → neue Rechte */
    public const PERM_MAP = [
        'upkeep[frontend]' => ['upkeep[maintenance]'],
        'upkeep[security]' => ['upkeep[ips]', 'upkeep[forms]', 'upkeep[advisor]', 'upkeep[reporting]'],
    ];

    /** @return list<string> Hinweise für den Admin (werden nach dem Update einmal im Dashboard gezeigt) */
    public static function run(): array
    {
        $addon = rex_addon::get('upkeep');
        $notes = [];

        foreach ([
            'migrateModuleSwitches',
            'migrateFrontendPassword',
            'migrateBypassSecret',
            'migrateSecrets',
            'migrateRolePermissions',
            'migrateLegacyKeys',
        ] as $step) {
            try {
                $note = self::$step($addon);
                if (is_string($note) && '' !== $note) {
                    $notes[] = $note;
                }
            } catch (Throwable $e) {
                rex_logger::logException($e);
            }
        }

        if ($notes) {
            $addon->setConfig('migration_notes', array_values(array_unique(array_merge((array) $addon->getConfig('migration_notes', []), $notes))));
        }

        return $notes;
    }

    /**
     * 2.x hatte je Modul zwei Schalter: *_enabled (nur Menü) und *_active (Funktion).
     * 3.x hat einen Schalter je Modul. Die Funktion bleibt so, wie sie war – nur die Menü-Schalter entfallen.
     */
    private static function migrateModuleSwitches(rex_addon $addon): ?string
    {
        if ($addon->hasConfig('security_advisor_enabled') && !$addon->hasConfig('advisor_active')) {
            $addon->setConfig('advisor_active', $addon->getConfig('security_advisor_enabled') ? 1 : 0);
        }
        foreach (['ips_enabled', 'mail_security_enabled', 'reporting_enabled', 'security_advisor_enabled'] as $key) {
            $addon->removeConfig($key);
        }
        foreach (['ips_active', 'mail_security_active', 'form_protection_active', 'frontend_active', 'backend_active', 'domain_mapping_active'] as $key) {
            if (!$addon->hasConfig($key)) {
                $addon->setConfig($key, 0);
            }
        }
        if (!$addon->hasConfig('advisor_active')) {
            $addon->setConfig('advisor_active', 1);
        }
        return null;
    }

    /** Klartext-Passwort der Wartungsseite → Hash */
    private static function migrateFrontendPassword(rex_addon $addon): ?string
    {
        $plain = (string) $addon->getConfig('frontend_password', '');
        if ('' === $plain) {
            $addon->removeConfig('frontend_password');
            return null;
        }
        if ('' === (string) $addon->getConfig('frontend_password_hash', '')) {
            $addon->setConfig('frontend_password_hash', password_hash($plain, PASSWORD_DEFAULT));
        }
        $addon->removeConfig('frontend_password');
        return 'password_hashed';
    }

    /** Umgehungs-Link: 2.x akzeptierte jeden Wert (?access=1), 3.x braucht einen geheimen Wert */
    private static function migrateBypassSecret(rex_addon $addon): ?string
    {
        if ('' !== (string) $addon->getConfig('bypass_secret', '')) {
            return null;
        }
        $addon->setConfig('bypass_secret', bin2hex(random_bytes(16)));
        if ($addon->getConfig('allow_bypass_param', false)) {
            return 'bypass_secret_changed';
        }
        return null;
    }

    private static function migrateSecrets(rex_addon $addon): ?string
    {
        foreach (['altcha_hmac_key' => 32, 'form_protection_secret' => 32] as $key => $bytes) {
            if ('' === (string) $addon->getConfig($key, '')) {
                $addon->setConfig($key, bin2hex(random_bytes($bytes)));
            }
        }
        return null;
    }

    /** Rollenrechte aus 2.x übernehmen, damit Redakteure nach dem Update dieselben Bereiche sehen */
    private static function migrateRolePermissions(rex_addon $addon): ?string
    {
        $table = rex::getTable('user_role');
        $sql = rex_sql::factory();
        $roles = $sql->getArray('SELECT id, perms FROM ' . $table);
        $changed = 0;

        foreach ($roles as $role) {
            $perms = json_decode((string) $role['perms'], true);
            if (!is_array($perms) || !isset($perms['general']) || !is_string($perms['general'])) {
                continue;
            }
            $general = $perms['general'];
            $new = $general;
            foreach (self::PERM_MAP as $old => $targets) {
                if (!str_contains($new, '|' . $old . '|')) {
                    continue;
                }
                foreach ($targets as $target) {
                    if (!str_contains($new, '|' . $target . '|')) {
                        $new = rtrim($new, '|') . '|' . $target . '|';
                    }
                }
            }
            if ($new !== $general) {
                $perms['general'] = $new;
                $update = rex_sql::factory();
                $update->setTable($table);
                $update->setWhere(['id' => (int) $role['id']]);
                $update->setValue('perms', json_encode($perms));
                $update->update();
                ++$changed;
            }
        }

        return $changed > 0 ? 'roles_migrated' : null;
    }

    /** Aufräumen: alte Einzel-Schlüssel, die die Konfiguration aufblähen */
    private static function migrateLegacyKeys(rex_addon $addon): ?string
    {
        // 2.x legte je geprüfter IP einen eigenen Schlüssel an (upkeep_dns_verify_<md5>). Über die Config-API entfernen,
        // damit die in diesem Lauf bereits gesetzten Werte erhalten bleiben (kein Neuladen der Konfiguration).
        foreach (array_keys((array) \rex_config::get('upkeep')) as $key) {
            if (str_starts_with((string) $key, 'upkeep_dns_verify_')) {
                $addon->removeConfig((string) $key);
            }
        }
        // Vertrauensdauer des alten Captchas → Dauer der Selbst-Entsperrung
        if ($addon->hasConfig('ips_captcha_trust_duration') && !$addon->hasConfig('ips_unlock_hours')) {
            $addon->setConfig('ips_unlock_hours', max(1, (int) $addon->getConfig('ips_captcha_trust_duration')));
        }
        $addon->removeConfig('ips_captcha_trust_duration');
        // Ergebnis-Zeitpunkt des Advisors unter neuem Namen
        if ($addon->hasConfig('security_advisor_last_check') && !$addon->hasConfig('advisor_last_check')) {
            $addon->setConfig('advisor_last_check', (int) $addon->getConfig('security_advisor_last_check'));
        }
        return null;
    }
}
