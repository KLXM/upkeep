<?php

use KLXM\Upkeep\GeoIP;
use KLXM\Upkeep\IntrusionPrevention;

/**
 * Cronjob für die automatische Bereinigung der IPS-Daten
 * - Entfernt abgelaufene temporäre IP-Sperren und Positivliste-Einträge
 * - Bereinigt alte Einträge aus dem Threat Log (Aufbewahrung einstellbar)
 * - Entfernt veraltete Rate-Limiting-Einträge (IPS und Mail)
 * - Aktualisiert optional die GeoIP-Datenbank (nur wenn älter als 35 Tage)
 */
class rex_upkeep_ips_cleanup_cronjob extends rex_cronjob
{
    public function execute()
    {
        try {
            $retentionDays = (int) $this->getParam('threat_log_retention_days', 30);
            $results = IntrusionPrevention::cleanupExpiredData($retentionDays > 0 ? $retentionDays : 30);

            $messages = [];
            $total = array_sum($results);
            $messages[] = "IPS cleanup: {$total} entries removed";

            if ('1' === (string) $this->getParam('geoip_update', '1')) {
                $messages[] = GeoIP::updateIfOutdated() ? 'GeoIP ok' : 'GeoIP update failed';
            }

            $this->setMessage(implode(', ', $messages));
            return true;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $this->setMessage('Error: ' . $e->getMessage());
            return false;
        }
    }

    public function getTypeName()
    {
        return 'Upkeep IPS: Bereinigung veralteter Sicherheitsdaten (IP-Sperren, Logs, Rate-Limits)';
    }

    public function getParamFields()
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
                    '90' => '90 Tage',
                ],
                'default' => '30',
            ],
            [
                'label' => 'GeoIP-Datenbank aktualisieren (wenn älter als 35 Tage)',
                'name' => 'geoip_update',
                'type' => 'select',
                'options' => ['1' => 'Ja', '0' => 'Nein'],
                'default' => '1',
            ],
        ];
    }

    /**
     * @deprecated 2.x-Name, REDAXO nutzt getParamFields()
     */
    public function getTypeParams()
    {
        return $this->getParamFields();
    }
}
