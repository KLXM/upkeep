<?php

/**
 * Cronjob für die automatische Bereinigung der IPS-Daten
 * - Entfernt abgelaufene temporäre IP-Sperren
 * - Bereinigt alte Einträge aus dem Threat Log
 * - Entfernt veraltete Rate-Limiting-Einträge
 * - Bereinigt abgelaufene CAPTCHA-Vertrauenseinträge
 */
class rex_upkeep_ips_cleanup_cronjob extends rex_cronjob
{
    public function execute()
    {
        return $this->performCleanup();
    }

    public function getTypeName()
    {
        return "Upkeep IPS: Bereinigung veralteter Sicherheitsdaten (IP-Sperren, Logs, Rate-Limits)";
    }

    public function getTypeParams()
    {
        return [
            [
                'label' => 'Threat Log Aufbewahrung (Tage)',
                'name' => 'threat_log_retention_days',
                'type' => 'select',
                'options' => [
                    '7' => '7 Tage',
                    '14' => '14 Tage', 
                    '30' => '30 Tage (Standard)',
                    '60' => '60 Tage',
                    '90' => '90 Tage'
                ],
                'default' => '30'
            ]
        ];
    }

    /**
     * Führt eine angepasste Bereinigung basierend auf den Parametern durch
     */
    protected function executeWithParams()
    {
        $retentionDays = (int) $this->getParam('threat_log_retention_days', 30);
        return $this->performCleanup($retentionDays);
    }

    /**
     * Zentrale Bereinigungslogik
     */
    private function performCleanup(int $threatLogRetentionDays = 30): bool
    {
        $sql = rex_sql::factory();
        $cleanupCount = 0;

        try {
            // 1. Entferne abgelaufene temporäre IP-Sperren
            $cleanupCount += $this->cleanupExpiredBlocks($sql);

            // 2. Bereinige alte Threat Log Einträge
            $cleanupCount += $this->cleanupThreatLog($sql, $threatLogRetentionDays);

            // 3. Entferne veraltete Rate-Limiting-Einträge
            $cleanupCount += $this->cleanupRateLimitData($sql);

            // 4. Bereinige abgelaufene CAPTCHA-Vertrauenseinträge
            $cleanupCount += $this->cleanupExpiredCaptchaTrust($sql);

            // 5. Optimiere die Tabellen
            $this->optimizeTables($sql);

            // Logging für Administratoren
            if ($cleanupCount > 0) {
                $retentionInfo = $threatLogRetentionDays !== 30 ? " (Threat Log: {$threatLogRetentionDays} Tage)" : '';
                
                // Prüfe ob System-Logging für IPS deaktiviert ist
                $addon = rex_addon::get('upkeep');
                if (!$addon->getConfig('ips_disable_system_logging', false)) {
                    rex_logger::factory()->info("IPS Cleanup: {$cleanupCount} veraltete Einträge entfernt{$retentionInfo}.");
                }
            }

            return true;

        } catch (rex_sql_exception $e) {
            rex_logger::logException($e);
            return false;
        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }

    private function cleanupExpiredBlocks(rex_sql $sql): int
    {
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                       WHERE block_type = 'temporary' AND expires_at < NOW()");
        return $sql->getRows();
    }

    private function cleanupThreatLog(rex_sql $sql, int $retentionDays): int
    {
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                       WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)", [$retentionDays]);
        return $sql->getRows();
    }

    private function cleanupRateLimitData(rex_sql $sql): int
    {
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                       WHERE last_request < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        return $sql->getRows();
    }

    private function cleanupExpiredCaptchaTrust(rex_sql $sql): int
    {
        $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_positivliste') . " 
                       WHERE category = 'captcha_verified_temp' AND expires_at < NOW()");
        return $sql->getRows();
    }

    private function optimizeTables(rex_sql $sql): void
    {
        $tables = [
            'upkeep_ips_blocked_ips',
            'upkeep_ips_threat_log', 
            'upkeep_ips_rate_limit',
            'upkeep_ips_positivliste'
        ];

        foreach ($tables as $table) {
            $sql->setQuery("OPTIMIZE TABLE " . rex::getTable($table));
        }
    }
}
