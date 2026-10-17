<?php

namespace KLXM\Upkeep\Schema;

use rex;
use rex_sql_column;
use rex_sql_index;
use rex_sql_table;

/**
 * Tabellenänderungen der Sicherheitsmodule für 3.0 (idempotent).
 * Wird von install.php und update.php nach dem Anlegen der 2.x-Tabellen aufgerufen.
 */
final class SecuritySchema
{
    public static function ensure(): void
    {
        // Threat-Log: Zusammenfassung gleichartiger Ereignisse (hit_count/last_seen)
        $threatLog = rex_sql_table::get(rex::getTable('upkeep_ips_threat_log'));
        if ($threatLog->exists()) {
            $threatLog
                ->ensureColumn(new rex_sql_column('hit_count', 'int(11)', false, '1'), 'action_taken')
                ->ensureColumn(new rex_sql_column('last_seen', 'datetime', true), 'created_at')
                ->ensureIndex(new rex_sql_index('created_at', ['created_at']))
                ->ensureIndex(new rex_sql_index('aggregate_lookup', ['ip_address', 'threat_type', 'created_at']))
                ->alter();
        }

        // Positivliste: Kategorie als varchar, damit neue Kategorien (z. B. Selbst-Entsperrung) möglich sind
        $positiv = rex_sql_table::get(rex::getTable('upkeep_ips_positivliste'));
        if ($positiv->exists()) {
            $positiv
                ->ensureColumn(new rex_sql_column('category', 'varchar(50)', false, 'trusted'))
                ->alter();
        }

        // Gesperrte IPs: Herkunft (auto|manual|external) und Index für Ablaufbereinigung.
        // Manuelle Sperren (source = manual) sind nicht per Selbst-Entsperrung aufhebbar.
        $blocked = rex_sql_table::get(rex::getTable('upkeep_ips_blocked_ips'));
        if ($blocked->exists()) {
            $blocked
                ->ensureColumn(new rex_sql_column('source', 'varchar(20)', false, 'auto'), 'threat_level')
                ->ensureIndex(new rex_sql_index('expires_at', ['expires_at']))
                ->alter();
        }

        // Mail-Rate-Limit: Index für Bereinigung
        $mailRate = rex_sql_table::get(rex::getTable('upkeep_mail_rate_limit'));
        if ($mailRate->exists()) {
            $mailRate
                ->ensureIndex(new rex_sql_index('created_at', ['created_at']))
                ->alter();
        }
    }
}
