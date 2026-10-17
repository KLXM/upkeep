<?php

use KLXM\Upkeep\Storage;

/**
 * Cronjob-Typ: berechnet die Speicherübersicht neu.
 */
class rex_upkeep_storage_cronjob extends rex_cronjob
{
    public function execute()
    {
        try {
            $budget = max(1.0, (float) $this->getParam('time_budget', Storage::DEFAULT_TIME_BUDGET));
            $report = Storage::refresh($budget);
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $this->setMessage($e->getMessage());
            return false;
        }

        if ([] === $report) {
            $this->setMessage('Another calculation is running.');
            return false;
        }

        $this->setMessage(sprintf(
            '%s in %.1f s%s',
            rex_formatter::bytes((int) $report['total_bytes'], [1]),
            (float) $report['duration'],
            !empty($report['partial']) ? ' (partial)' : '',
        ));

        return true;
    }

    public function getTypeName()
    {
        return rex_i18n::msg('upkeep_storage_cronjob_name');
    }

    public function getParamFields()
    {
        return [
            [
                'label' => rex_i18n::msg('upkeep_storage_cronjob_budget'),
                'name' => 'time_budget',
                'type' => 'text',
                'default' => '60',
            ],
        ];
    }
}
