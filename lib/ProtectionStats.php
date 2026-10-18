<?php

namespace KLXM\Upkeep;

use rex;
use rex_i18n;
use rex_sql;
use Throwable;

/**
 * Kennzahlen für die Seite „Schutz → Statistik“: Treffer, Sperren und Arten in einem Zeitraum.
 *
 * Alle Zeitgrenzen kommen aus PHP (date()), nicht aus der Datenbank – dieselbe Uhr, mit der das IPS schreibt.
 * Treffer werden wie im IPS über IntrusionPrevention::hitExpression() gezählt (zusammengefasste Zeilen).
 */
final class ProtectionStats
{
    /** Zeitraum => Anzahl Tage (24h = stündliche Auflösung) */
    public const PERIODS = ['24h' => 1, '7d' => 7, '30d' => 30, '90d' => 90];

    public const DEFAULT_PERIOD = '7d';

    public const SEVERITIES = ['low', 'medium', 'high', 'critical'];

    /** Bekannte Ergebnisse in action_taken */
    public const ACTIONS = ['temporary_block', 'permanent_block', 'logged', 'logged_cross_site'];

    /** Bekannte Herkünfte einer Sperre */
    public const SOURCES = ['auto', 'manual', 'external', IntrusionPrevention::SOURCE_AFTER_UNLOCK];

    /**
     * Lesbare Bezeichnung einer Ereignis-Art (threat_type); unbekannte Arten bleiben unverändert.
     */
    public static function typeLabel(string $type): string
    {
        if (str_starts_with($type, 'mail_escalated_')) {
            return rex_i18n::rawMsg('upkeep_stats_type_mail_escalated') . ': ' . substr($type, 15);
        }
        return rex_i18n::hasMsg('upkeep_stats_type_' . $type) ? rex_i18n::rawMsg('upkeep_stats_type_' . $type) : $type;
    }

    public static function normalizePeriod(string $period): string
    {
        return isset(self::PERIODS[$period]) ? $period : self::DEFAULT_PERIOD;
    }

    /**
     * Zeitraum und Abschnitte der Zeitleiste.
     *
     * @return array{from: string, from_ts: int, hourly: bool, buckets: array<string, int>}
     */
    public static function range(string $period, ?int $now = null): array
    {
        $period = self::normalizePeriod($period);
        $now ??= time();
        $buckets = [];
        if ('24h' === $period) {
            $start = (int) strtotime(date('Y-m-d H:00:00', $now - 23 * 3600));
            for ($i = 0; $i < 24; ++$i) {
                $ts = $start + $i * 3600;
                $buckets[date('Y-m-d H', $ts)] = $ts;
            }
            return ['from' => date('Y-m-d H:i:s', $start), 'from_ts' => $start, 'hourly' => true, 'buckets' => $buckets];
        }
        $days = self::PERIODS[$period];
        $start = (int) strtotime(date('Y-m-d 00:00:00', (int) strtotime('-' . ($days - 1) . ' days', $now)));
        for ($i = 0; $i < $days; ++$i) {
            $ts = (int) strtotime('+' . $i . ' days', $start);
            $buckets[date('Y-m-d', $ts)] = $ts;
        }
        return ['from' => date('Y-m-d H:i:s', $start), 'from_ts' => $start, 'hourly' => false, 'buckets' => $buckets];
    }

    /**
     * @return array{
     *     ok: bool,
     *     period: string,
     *     range: array{from: string, from_ts: int, hourly: bool, buckets: array<string, int>},
     *     hits: int,
     *     by_action: array<string, int>,
     *     by_severity: array<string, int>,
     *     by_type: array<string, int>,
     *     type_count: int,
     *     timeline: array<string, array<string, int>>,
     *     timeline_max: int,
     *     blocked_now: int,
     *     blocked_by_source: array<string, int>,
     *     self_unlocks: int,
     *     forms_rejected: ?int,
     *     top_ips: list<array{ip: string, hits: int, last_seen: string, severity: string, status: string}>
     * }
     */
    public static function get(string $period): array
    {
        $period = self::normalizePeriod($period);
        $range = self::range($period);
        $now = date('Y-m-d H:i:s');
        $from = $range['from'];
        $hits = IntrusionPrevention::hitExpression();
        $log = rex::getTable('upkeep_ips_threat_log');
        $blocked = rex::getTable('upkeep_ips_blocked_ips');
        $marks = rex::getTable('upkeep_ips_positivliste');

        $stats = [
            'ok' => true,
            'period' => $period,
            'range' => $range,
            'hits' => 0,
            'by_action' => [],
            'by_severity' => array_fill_keys(self::SEVERITIES, 0),
            'by_type' => [],
            'type_count' => 0,
            'timeline' => [],
            'timeline_max' => 0,
            'blocked_now' => 0,
            'blocked_by_source' => [],
            'self_unlocks' => 0,
            'forms_rejected' => null,
            'top_ips' => [],
        ];
        foreach (array_keys($range['buckets']) as $key) {
            $stats['timeline'][$key] = array_fill_keys(self::SEVERITIES, 0);
        }

        try {
            $sql = rex_sql::factory();

            // Ergebnis (Sperre, nur protokolliert …) – daraus auch die Summe
            foreach ($sql->getArray('SELECT action_taken AS k, SUM(' . $hits . ') AS c FROM ' . $log . ' WHERE created_at >= ? GROUP BY action_taken ORDER BY c DESC', [$from]) as $row) {
                $stats['by_action'][(string) $row['k']] = (int) $row['c'];
                $stats['hits'] += (int) $row['c'];
            }

            foreach ($sql->getArray('SELECT severity AS k, SUM(' . $hits . ') AS c FROM ' . $log . ' WHERE created_at >= ? GROUP BY severity', [$from]) as $row) {
                $stats['by_severity'][(string) $row['k']] = (int) $row['c'];
            }

            foreach ($sql->getArray('SELECT threat_type AS k, SUM(' . $hits . ') AS c FROM ' . $log . ' WHERE created_at >= ? GROUP BY threat_type ORDER BY c DESC, threat_type', [$from]) as $i => $row) {
                ++$stats['type_count'];
                if ($i < 10) {
                    $stats['by_type'][(string) $row['k']] = (int) $row['c'];
                }
            }

            // Zeitleiste: pro Stunde (24 h) bzw. pro Tag, gestapelt nach Schweregrad
            $bucketExpr = $range['hourly'] ? "DATE_FORMAT(created_at, '%Y-%m-%d %H')" : "DATE_FORMAT(created_at, '%Y-%m-%d')";
            foreach ($sql->getArray('SELECT ' . $bucketExpr . ' AS b, severity AS s, SUM(' . $hits . ') AS c FROM ' . $log . ' WHERE created_at >= ? GROUP BY b, s', [$from]) as $row) {
                $b = (string) $row['b'];
                $s = (string) $row['s'];
                if (isset($stats['timeline'][$b][$s])) {
                    $stats['timeline'][$b][$s] += (int) $row['c'];
                }
            }
            foreach ($stats['timeline'] as $values) {
                $stats['timeline_max'] = max($stats['timeline_max'], array_sum($values));
            }

            // Auffälligste Adressen
            $rows = $sql->getArray(
                'SELECT ip_address, SUM(' . $hits . ') AS c, MAX(COALESCE(last_seen, created_at)) AS last_seen,'
                . " MAX(FIELD(severity, 'low', 'medium', 'high', 'critical')) AS sev"
                . ' FROM ' . $log . ' WHERE created_at >= ? GROUP BY ip_address ORDER BY c DESC, last_seen DESC LIMIT 10',
                [$from],
            );
            $ips = array_map(static fn ($r) => (string) $r['ip_address'], $rows);
            $blockedIps = [];
            $unlockedIps = [];
            if ($ips) {
                $in = implode(',', array_fill(0, count($ips), '?'));
                foreach ($sql->getArray('SELECT DISTINCT ip_address FROM ' . $blocked . ' WHERE ip_address IN (' . $in . ') AND (expires_at IS NULL OR expires_at > ?)', [...$ips, $now]) as $r) {
                    $blockedIps[(string) $r['ip_address']] = true;
                }
                foreach ($sql->getArray('SELECT DISTINCT ip_address FROM ' . $marks . ' WHERE ip_address IN (' . $in . ') AND category = ? AND status = 1 AND (expires_at IS NULL OR expires_at > ?)', [...$ips, IntrusionPrevention::SELF_UNLOCK_CATEGORY, $now]) as $r) {
                    $unlockedIps[(string) $r['ip_address']] = true;
                }
            }
            foreach ($rows as $row) {
                $ip = (string) $row['ip_address'];
                $stats['top_ips'][] = [
                    'ip' => $ip,
                    'hits' => (int) $row['c'],
                    'last_seen' => (string) $row['last_seen'],
                    'severity' => self::SEVERITIES[max(1, min(4, (int) $row['sev'])) - 1],
                    'status' => isset($blockedIps[$ip]) ? 'blocked' : (isset($unlockedIps[$ip]) ? 'unlocked' : 'free'),
                ];
            }

            // Aktuelle Sperren nach Herkunft (ohne source-Spalte: alles „auto“)
            $hasSource = false;
            try {
                $hasSource = \rex_sql_table::get($blocked)->hasColumn('source');
            } catch (Throwable) {
            }
            $sourceExpr = $hasSource ? 'source' : "'auto'";
            foreach ($sql->getArray('SELECT ' . $sourceExpr . ' AS k, COUNT(*) AS c FROM ' . $blocked . ' WHERE expires_at IS NULL OR expires_at > ? GROUP BY k ORDER BY c DESC', [$now]) as $row) {
                $stats['blocked_by_source'][(string) $row['k']] = (int) $row['c'];
                $stats['blocked_now'] += (int) $row['c'];
            }

            // Selbst-Entsperrungen im Zeitraum (Markierungen, keine Positivliste)
            $sql->setQuery('SELECT COUNT(*) AS c FROM ' . $marks . ' WHERE category = ? AND created_at >= ?', [IntrusionPrevention::SELF_UNLOCK_CATEGORY, $from]);
            $stats['self_unlocks'] = (int) $sql->getValue('c');
        } catch (Throwable $e) {
            \rex_logger::logException($e);
            $stats['ok'] = false;
            return $stats;
        }

        // Abgewiesene Formular-Einsendungen (Tabelle gibt es erst mit dem Formularschutz)
        try {
            $sql = rex_sql::factory();
            $sql->setQuery('SELECT COUNT(*) AS c FROM ' . rex::getTable('upkeep_form_log') . ' WHERE created_at >= ?', [$from]);
            $stats['forms_rejected'] = (int) $sql->getValue('c');
        } catch (Throwable) {
            $stats['forms_rejected'] = null;
        }

        return $stats;
    }
}
