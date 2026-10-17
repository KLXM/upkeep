<?php

use KLXM\Upkeep\GeoIP;
use KLXM\Upkeep\IntrusionPrevention;

/**
 * Cronjob für die automatische Bereinigung der IPS-Daten
 * - Entfernt abgelaufene temporäre IP-Sperren und Positivliste-Einträge
 * - Bereinigt alte Einträge aus dem Threat Log (Aufbewahrung aus den Einstellungen: ips_threat_log_retention_days)
 * - Entfernt veraltete Rate-Limiting-Einträge (IPS und Mail)
 * - Aktualisiert optional die GeoIP-Datenbank (nur wenn älter als 35 Tage)
 */
class rex_upkeep_ips_cleanup_cronjob extends rex_cronjob
{
    public function execute()
    {
        try {
            // 3.0: Aufbewahrung kommt aus den Einstellungen (ips_threat_log_retention_days),
            // ein früher am Cronjob gespeicherter Wert wird ignoriert.
            $results = IntrusionPrevention::cleanupExpiredData();

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
