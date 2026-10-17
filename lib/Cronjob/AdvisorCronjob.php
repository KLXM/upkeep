<?php

use KLXM\Upkeep\SecurityAdvisor;

/**
 * Cronjob-Typ: aktualisiert die Empfehlungen (Security Advisor) im Hintergrund.
 */
class rex_upkeep_advisor_cronjob extends rex_cronjob
{
    public function execute()
    {
        try {
            $results = (new SecurityAdvisor())->runAllChecks();
        } catch (Throwable $e) {
            rex_logger::logException($e);
            $this->setMessage($e->getMessage());
            return false;
        }

        $summary = $results['summary'] ?? [];
        $this->setMessage(sprintf('%d checks, %d open', (int) ($summary['total_checks'] ?? 0), (int) ($summary['critical_issues'] ?? 0) + (int) ($summary['warning_issues'] ?? 0)));
        return true;
    }

    public function getTypeName()
    {
        return rex_i18n::msg('upkeep_advisor_cronjob_name');
    }

    public function getParamFields()
    {
        return [];
    }
}
