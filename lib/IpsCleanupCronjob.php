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
        $sql = rex_sql::factory();
        $cleanupCount = 0;

        try {
            // 1. Entferne abgelaufene temporäre IP-Sperren
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                           WHERE block_type = 'temporary' AND expires_at < NOW()");
            $cleanupCount += $sql->getRows();

            // 2. Bereinige alte Threat Log Einträge (älter als 30 Tage)
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            $cleanupCount += $sql->getRows();

            // 3. Entferne veraltete Rate-Limiting-Einträge (älter als 24 Stunden)
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                           WHERE last_request < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $cleanupCount += $sql->getRows();

            // 4. Bereinige abgelaufene CAPTCHA-Vertrauenseinträge
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_positivliste') . " 
                           WHERE category = 'captcha_verified_temp' AND expires_at < NOW()");
            $cleanupCount += $sql->getRows();

            // 5. Optimiere die Tabellen nach der Bereinigung
            $tables = [
                'upkeep_ips_blocked_ips',
                'upkeep_ips_threat_log', 
                'upkeep_ips_rate_limit',
                'upkeep_ips_positivliste'
            ];

            foreach ($tables as $table) {
                $sql->setQuery("OPTIMIZE TABLE " . rex::getTable($table));
            }

            // Logging für Administratoren
            if ($cleanupCount > 0) {
                rex_logger::factory()->info("IPS Cleanup: {$cleanupCount} veraltete Einträge entfernt und Tabellen optimiert.");
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
        
        $sql = rex_sql::factory();
        $cleanupCount = 0;

        try {
            // Angepasste Bereinigung des Threat Logs
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_threat_log') . " 
                           WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)", [$retentionDays]);
            $cleanupCount += $sql->getRows();

            // Restliche Bereinigung wie in execute()
            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_blocked_ips') . " 
                           WHERE block_type = 'temporary' AND expires_at < NOW()");
            $cleanupCount += $sql->getRows();

            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_rate_limit') . " 
                           WHERE last_request < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            $cleanupCount += $sql->getRows();

            $sql->setQuery("DELETE FROM " . rex::getTable('upkeep_ips_positivliste') . " 
                           WHERE category = 'captcha_verified_temp' AND expires_at < NOW()");
            $cleanupCount += $sql->getRows();

            if ($cleanupCount > 0) {
                rex_logger::factory()->info("IPS Cleanup (angepasst): {$cleanupCount} veraltete Einträge entfernt (Threat Log: {$retentionDays} Tage Aufbewahrung).");
            }

            return true;

        } catch (Exception $e) {
            rex_logger::logException($e);
            return false;
        }
    }
}
