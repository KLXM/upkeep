<?php

use KLXM\Upkeep\MailReporting;

/**
 * Cronjob-Typ: versendet gesammelte Berichte (Intervall aus mail_reporting_bundle_interval)
 * und – wenn aktiviert – einmal täglich den Statusbericht.
 * Kann z. B. alle 5 Minuten laufen; versendet wird nur, wenn das Intervall abgelaufen ist.
 */
class rex_upkeep_mail_reporting_cronjob extends rex_cronjob
{
    public function execute()
    {
        try {
            if (!MailReporting::isEnabled()) {
                $this->setMessage('Mail reporting disabled');
                return true;
            }
            $result = MailReporting::runScheduled();
            $parts = [];
            $parts[] = 'bundle: ' . ($result['bundle'] === null ? 'not due' : ($result['bundle'] ? 'ok' : 'failed'));
            $parts[] = 'status: ' . ($result['status'] === null ? 'not due' : ($result['status'] ? 'ok' : 'failed'));
            $this->setMessage(implode(', ', $parts));
            return $result['bundle'] !== false && $result['status'] !== false;
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $this->setMessage('Error: ' . $e->getMessage());
            return false;
        }
    }

    public function getTypeName()
    {
        return rex_i18n::msg('upkeep_mail_reporting_cronjob_name');
    }

    public function getParamFields()
    {
        return [];
    }
}
